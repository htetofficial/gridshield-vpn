package tunnel

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/SUDOKU-ASCII/sudoku/pkg/connutil"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku"
)

type obfsUplinkMode byte

const (
	obfsUplinkPure obfsUplinkMode = iota
	obfsUplinkPacked
)

type recordingConn interface {
	net.Conn
	StopRecording()
	GetBufferedAndRecorded() []byte
}

type downlinkWriterSwitcher interface {
	ReplaceWriter(writer io.Writer, closers ...func() error)
}

type preBufferedConn struct {
	net.Conn
	buf []byte
}

func newPreBufferedConn(c net.Conn, pre []byte) net.Conn {
	if len(pre) == 0 {
		return c
	}
	return &preBufferedConn{Conn: c, buf: append([]byte(nil), pre...)}
}

func (c *preBufferedConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *preBufferedConn) CloseWrite() error { return connutil.TryCloseWrite(c.Conn) }
func (c *preBufferedConn) CloseRead() error  { return connutil.TryCloseRead(c.Conn) }

type recordedConn struct {
	net.Conn
	recorded []byte
}

func (c *recordedConn) GetBufferedAndRecorded() []byte { return c.recorded }

type prefixedRecorderConn struct {
	recordingConn
	prefix []byte
}

func (c *prefixedRecorderConn) GetBufferedAndRecorded() []byte {
	rest := c.recordingConn.GetBufferedAndRecorded()
	out := make([]byte, 0, len(c.prefix)+len(rest))
	out = append(out, c.prefix...)
	out = append(out, rest...)
	return out
}

type bufferedHeaderConn struct {
	net.Conn
	r        *bufio.Reader
	recorder *bytes.Buffer
}

func (c *bufferedHeaderConn) GetBufferedAndRecorded() []byte {
	var out []byte
	if c.recorder != nil {
		out = append(out, c.recorder.Bytes()...)
	}
	if c.r != nil && c.r.Buffered() > 0 {
		peeked, _ := c.r.Peek(c.r.Buffered())
		out = append(out, peeked...)
	}
	return out
}

// BuildTables initializes one or more Sudoku 4x4 O(1) lookup tables for key/ascii/custom layouts.
func BuildTables(key, asciiMode, customTable string, customTables []string) ([]*sudoku.Table, error) {
	patterns := customTables
	if len(patterns) == 0 && customTable != "" {
		patterns = []string{customTable}
	}
	ts, err := sudoku.NewTableSet(key, asciiMode, patterns)
	if err != nil {
		return nil, err
	}
	return ts.Tables, nil
}

func buildClientObfsConn(raw net.Conn, table *sudoku.Table, paddingMin, paddingMax int, pureDownlink bool, uplinkMode obfsUplinkMode) net.Conn {
	uplinkTable := table
	downlinkTable := table.OppositeDirection()

	var reader io.Reader
	if pureDownlink {
		reader = sudoku.NewConn(raw, downlinkTable, paddingMin, paddingMax, false)
	} else {
		reader = sudoku.NewPackedConn(raw, downlinkTable, paddingMin, paddingMax)
	}

	var writer io.Writer
	var closers []func() error
	if uplinkMode == obfsUplinkPacked {
		packed := sudoku.NewPackedConn(raw, uplinkTable, paddingMin, paddingMax)
		writer = packed
		closers = append(closers, packed.Flush)
	} else {
		writer = sudoku.NewConn(raw, uplinkTable, paddingMin, paddingMax, false)
	}

	return sudoku.NewDirectionalConn(raw, reader, writer, closers...)
}

func buildServerObfsConn(raw net.Conn, table *sudoku.Table, paddingMin, paddingMax int, pureDownlink bool, uplinkMode obfsUplinkMode, record bool) (recordingConn, net.Conn) {
	var uplink recordingConn
	if uplinkMode == obfsUplinkPacked {
		uplink = sudoku.NewPackedConnWithRecord(raw, table, paddingMin, paddingMax, record)
	} else {
		uplink = sudoku.NewConn(raw, table, paddingMin, paddingMax, record)
	}
	downlink, closers := sudoku.NewServerDownlinkWriter(raw, table.OppositeDirection(), paddingMin, paddingMax, pureDownlink)
	return uplink, sudoku.NewDirectionalConn(raw, uplink, downlink, closers...)
}

func switchDownlinkWriter(conn net.Conn, writer io.Writer, closers ...func() error) bool {
	if sw, ok := conn.(downlinkWriterSwitcher); ok {
		sw.ReplaceWriter(writer, closers...)
		return true
	}
	return false
}

type handshakeObfsSelection struct {
	Table      *sudoku.Table
	UplinkMode obfsUplinkMode
}

type handshakeObfsCandidate struct {
	table      *sudoku.Table
	uplinkMode obfsUplinkMode
}

func drainBuffered(r *bufio.Reader) ([]byte, error) {
	n := r.Buffered()
	if n <= 0 {
		return nil, nil
	}
	out := make([]byte, n)
	_, err := io.ReadFull(r, out)
	return out, err
}

func isProbeNeedMore(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func selectHandshakeObfsByProbe(r *bufio.Reader, tables []*sudoku.Table, probe func([]byte, *sudoku.Table, obfsUplinkMode) error) (*handshakeObfsSelection, []byte, error) {
	candidates := make([]handshakeObfsCandidate, 0, len(tables)*2)
	for _, t := range tables {
		if t == nil {
			continue
		}
		candidates = append(candidates,
			handshakeObfsCandidate{table: t, uplinkMode: obfsUplinkPure},
			handshakeObfsCandidate{table: t, uplinkMode: obfsUplinkPacked},
		)
	}
	if len(candidates) == 0 {
		return nil, nil, fmt.Errorf("no table candidates")
	}

	probeBytes, err := drainBuffered(r)
	if err != nil {
		return nil, nil, err
	}

	const maxProbeBytes = 64 * 1024
	var chunk []byte
	for {
		if len(candidates) == 1 {
			tail, err := drainBuffered(r)
			if err != nil {
				return nil, probeBytes, err
			}
			probeBytes = append(probeBytes, tail...)
			return &handshakeObfsSelection{Table: candidates[0].table, UplinkMode: candidates[0].uplinkMode}, probeBytes, nil
		}

		needMore := false
		next := candidates[:0]
		for _, cand := range candidates {
			err := probe(probeBytes, cand.table, cand.uplinkMode)
			if err == nil {
				tail, err := drainBuffered(r)
				if err != nil {
					return nil, probeBytes, err
				}
				probeBytes = append(probeBytes, tail...)
				return &handshakeObfsSelection{Table: cand.table, UplinkMode: cand.uplinkMode}, probeBytes, nil
			}
			if isProbeNeedMore(err) {
				needMore = true
				next = append(next, cand)
			}
		}
		candidates = next
		if len(candidates) == 0 || !needMore {
			return nil, probeBytes, fmt.Errorf("handshake table selection failed")
		}
		if len(probeBytes) >= maxProbeBytes {
			return nil, probeBytes, fmt.Errorf("handshake probe exceeded %d bytes", maxProbeBytes)
		}
		if chunk == nil {
			chunk = make([]byte, 4096)
		}
		n, err := r.Read(chunk)
		if n > 0 {
			probeBytes = append(probeBytes, chunk[:n]...)
		}
		if err != nil {
			return nil, probeBytes, err
		}
	}
}
