package tunnel

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/SUDOKU-ASCII/sudoku/pkg/connutil"
	"github.com/SUDOKU-ASCII/sudoku/pkg/crypto"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/httpmask"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku"

	"gridshield/internal/config"
)

const serverHandshakeTimeout = 6 * time.Second

// SuspiciousError carries the recorded prefix bytes for decoy fallback forwarding.
type SuspiciousError struct {
	Err  error
	Conn net.Conn
}

func (e *SuspiciousError) Error() string { return e.Err.Error() }

// HandshakeMeta stores authenticated client metadata.
type HandshakeMeta struct {
	UserHash string
}

func probeServerHandshakeBytes(probe []byte, cfg config.ServerConfig, table *sudoku.Table, uplinkMode obfsUplinkMode) error {
	ro := &connutil.ReadOnlyConn{Reader: bytes.NewReader(probe)}
	_, obfsConn := buildServerObfsConn(ro, table, cfg.PaddingMin, cfg.PaddingMax, cfg.EnablePureDownlink, uplinkMode, false)
	pskC2S, pskS2C := derivePSKDirectionalBases(cfg.Key)
	cConn, err := crypto.NewRecordConn(obfsConn, cfg.AEAD, pskS2C, pskC2S)
	if err != nil {
		return err
	}
	ch, err := readClientHello(cConn)
	if err != nil {
		return err
	}
	return checkClientHelloSkew(ch, time.Now())
}

// ServerHandshake authenticates a raw or HTTPMask-unwrapped client connection.
func ServerHandshake(rawConn net.Conn, cfg config.ServerConfig, tables []*sudoku.Table) (net.Conn, *HandshakeMeta, error) {
	if rawConn == nil {
		return nil, nil, errors.New("nil conn")
	}
	if userHash, ok := httpmask.EarlyHandshakeUserHash(rawConn); ok {
		return rawConn, &HandshakeMeta{UserHash: userHash}, nil
	}

	bufReader := bufio.NewReader(rawConn)
	_ = rawConn.SetReadDeadline(time.Now().Add(serverHandshakeTimeout))
	defer func() { _ = rawConn.SetReadDeadline(time.Time{}) }()

	var httpHeaderData []byte
	if !cfg.HTTPMask.Disable {
		peek4, _ := bufReader.Peek(4)
		if httpmask.LooksLikeHTTPRequestStart(peek4) {
			consumed, err := httpmask.ConsumeHeader(bufReader)
			if err != nil {
				rec := bytes.NewBuffer(consumed)
				return nil, nil, &SuspiciousError{
					Err:  fmt.Errorf("invalid http mask header: %w", err),
					Conn: &bufferedHeaderConn{Conn: rawConn, r: bufReader, recorder: rec},
				}
			}
			httpHeaderData = consumed
		}
	}

	selected, preRead, err := selectHandshakeObfsByProbe(bufReader, tables, func(probe []byte, table *sudoku.Table, mode obfsUplinkMode) error {
		return probeServerHandshakeBytes(probe, cfg, table, mode)
	})
	if err != nil {
		combined := make([]byte, 0, len(httpHeaderData)+len(preRead))
		combined = append(combined, httpHeaderData...)
		combined = append(combined, preRead...)
		return nil, nil, &SuspiciousError{Err: err, Conn: &recordedConn{Conn: rawConn, recorded: combined}}
	}

	baseConn := newPreBufferedConn(rawConn, preRead)
	recConn, obfsConn := buildServerObfsConn(baseConn, selected.Table, cfg.PaddingMin, cfg.PaddingMax, cfg.EnablePureDownlink, selected.UplinkMode, true)

	pskC2S, pskS2C := derivePSKDirectionalBases(cfg.Key)
	cConn, err := crypto.NewRecordConn(obfsConn, cfg.AEAD, pskS2C, pskC2S)
	if err != nil {
		return nil, nil, fmt.Errorf("server crypto setup: %w", err)
	}

	fail := func(e error) (net.Conn, *HandshakeMeta, error) {
		return nil, nil, &SuspiciousError{Err: e, Conn: &prefixedRecorderConn{recordingConn: recConn, prefix: httpHeaderData}}
	}

	_ = rawConn.SetReadDeadline(time.Now().Add(serverHandshakeTimeout))
	ch, err := readClientHello(cConn)
	if err != nil {
		return fail(err)
	}
	accepted, err := acceptClientHello(ch, cfg.Key, selected.Table, tables, AllowHandshakeReplay)
	if err != nil {
		return fail(err)
	}
	if accepted.table != selected.Table {
		downlink, closers := sudoku.NewServerDownlinkWriter(baseConn, accepted.table.OppositeDirection(), cfg.PaddingMin, cfg.PaddingMax, cfg.EnablePureDownlink)
		if !switchDownlinkWriter(obfsConn, downlink, closers...) {
			return fail(errors.New("switch downlink writer failed"))
		}
	}

	accepted.reply.SelectedFeats &= KIPFeatAll
	if err := WriteKIPMessage(cConn, KIPTypeServerHello, accepted.reply.EncodePayload()); err != nil {
		return fail(fmt.Errorf("write server hello: %w", err))
	}
	if err := cConn.Rekey(accepted.s2c, accepted.c2s); err != nil {
		return fail(fmt.Errorf("server rekey: %w", err))
	}

	recConn.StopRecording()
	return cConn, &HandshakeMeta{UserHash: accepted.userHash}, nil
}
