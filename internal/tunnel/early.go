package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"fmt"
	"net"
	"time"

	"github.com/SUDOKU-ASCII/sudoku/pkg/crypto"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/httpmask"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku"
)

type EarlyCodecConfig struct {
	PSK                string
	AEAD               string
	EnablePureDownlink bool
	PaddingMin         int
	PaddingMax         int
	PackedUplink       bool
}

type earlyMemoryConn struct {
	reader *bytes.Reader
	write  bytes.Buffer
}

func newEarlyMemoryConn(readBuf []byte) *earlyMemoryConn {
	return &earlyMemoryConn{reader: bytes.NewReader(readBuf)}
}

func (c *earlyMemoryConn) Read(p []byte) (int, error)         { return c.reader.Read(p) }
func (c *earlyMemoryConn) Write(p []byte) (int, error)        { return c.write.Write(p) }
func (c *earlyMemoryConn) Close() error                       { return nil }
func (c *earlyMemoryConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (c *earlyMemoryConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (c *earlyMemoryConn) SetDeadline(time.Time) error        { return nil }
func (c *earlyMemoryConn) SetReadDeadline(time.Time) error    { return nil }
func (c *earlyMemoryConn) SetWriteDeadline(time.Time) error   { return nil }
func (c *earlyMemoryConn) Written() []byte                    { return append([]byte(nil), c.write.Bytes()...) }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

func earlyUplinkMode(packed bool) obfsUplinkMode {
	if packed {
		return obfsUplinkPacked
	}
	return obfsUplinkPure
}

type earlyClientState struct {
	RequestPayload []byte
	cfg            EarlyCodecConfig
	table          *sudoku.Table
	nonce          [kipHelloNonceSize]byte
	ephemeral      *ecdh.PrivateKey
	sessionC2S     []byte
	sessionS2C     []byte
	responseSet    bool
}

func NewHTTPMaskClientEarlyHandshake(cfg EarlyCodecConfig, table *sudoku.Table, tableHint uint32, hasTableHint bool, userHash [kipHelloUserHashSize]byte, feats uint32) (*httpmask.ClientEarlyHandshake, error) {
	if table == nil {
		return nil, fmt.Errorf("nil table")
	}
	hello, ephemeral, err := newClientHello(userHash, feats, tableHint, hasTableHint)
	if err != nil {
		return nil, err
	}

	mem := newEarlyMemoryConn(nil)
	obfsConn := buildClientObfsConn(mem, table, cfg.PaddingMin, cfg.PaddingMax, cfg.EnablePureDownlink, earlyUplinkMode(cfg.PackedUplink))
	pskC2S, pskS2C := derivePSKDirectionalBases(cfg.PSK)
	rc, err := crypto.NewRecordConn(obfsConn, cfg.AEAD, pskC2S, pskS2C)
	if err != nil {
		return nil, fmt.Errorf("early crypto setup: %w", err)
	}
	if err := WriteKIPMessage(rc, KIPTypeClientHello, hello.EncodePayload()); err != nil {
		return nil, fmt.Errorf("write early client hello: %w", err)
	}

	st := &earlyClientState{
		RequestPayload: mem.Written(),
		cfg:            cfg,
		table:          table,
		nonce:          hello.Nonce,
		ephemeral:      ephemeral,
	}

	return &httpmask.ClientEarlyHandshake{
		RequestPayload: st.RequestPayload,
		HandleResponse: func(payload []byte) error {
			rmem := newEarlyMemoryConn(payload)
			robfs := buildClientObfsConn(rmem, st.cfg.tableOr(st.table), st.cfg.PaddingMin, st.cfg.PaddingMax, st.cfg.EnablePureDownlink, earlyUplinkMode(st.cfg.PackedUplink))
			rrc, err := crypto.NewRecordConn(robfs, st.cfg.AEAD, pskC2S, pskS2C)
			if err != nil {
				return err
			}
			sh, err := readServerHello(rrc)
			if err != nil {
				return err
			}
			st.sessionC2S, st.sessionS2C, err = deriveClientSession(st.cfg.PSK, st.ephemeral, st.nonce, sh)
			if err != nil {
				return err
			}
			st.responseSet = true
			return nil
		},
		Ready: func() bool { return st.responseSet },
		WrapConn: func(raw net.Conn) (net.Conn, error) {
			if !st.responseSet {
				return nil, fmt.Errorf("early handshake incomplete")
			}
			obfs := buildClientObfsConn(raw, st.table, st.cfg.PaddingMin, st.cfg.PaddingMax, st.cfg.EnablePureDownlink, earlyUplinkMode(st.cfg.PackedUplink))
			return crypto.NewRecordConn(obfs, st.cfg.AEAD, st.sessionC2S, st.sessionS2C)
		},
	}, nil
}

func (c EarlyCodecConfig) tableOr(t *sudoku.Table) *sudoku.Table { return t }

// NewHTTPMaskServerEarlyHandshake prepares the server-side early handshake handler for HTTPMask tunnel modes.
func NewHTTPMaskServerEarlyHandshake(cfg EarlyCodecConfig, tables []*sudoku.Table) *httpmask.TunnelServerEarlyHandshake {
	return &httpmask.TunnelServerEarlyHandshake{
		Prepare: func(payload []byte) (*httpmask.PreparedServerEarlyHandshake, error) {
			if len(payload) == 0 || len(tables) == 0 {
				return nil, fmt.Errorf("empty early payload or tables")
			}
			pskC2S, pskS2C := derivePSKDirectionalBases(cfg.PSK)
			var lastErr error
			for _, table := range tables {
				for _, uplinkMode := range []obfsUplinkMode{obfsUplinkPure, obfsUplinkPacked} {
					mem := newEarlyMemoryConn(payload)
					_, obfs := buildServerObfsConn(mem, table, cfg.PaddingMin, cfg.PaddingMax, cfg.EnablePureDownlink, uplinkMode, false)
					rc, err := crypto.NewRecordConn(obfs, cfg.AEAD, pskS2C, pskC2S)
					if err != nil {
						lastErr = err
						continue
					}
					ch, err := readClientHello(rc)
					if err != nil {
						lastErr = err
						continue
					}
					accepted, err := acceptClientHello(ch, cfg.PSK, table, tables, AllowHandshakeReplay)
					if err != nil {
						lastErr = err
						continue
					}
					accepted.reply.SelectedFeats &= KIPFeatAll

					respMem := newEarlyMemoryConn(nil)
					_, respObfs := buildServerObfsConn(respMem, accepted.table, cfg.PaddingMin, cfg.PaddingMax, cfg.EnablePureDownlink, uplinkMode, false)
					respConn, err := crypto.NewRecordConn(respObfs, cfg.AEAD, pskS2C, pskC2S)
					if err != nil {
						return nil, err
					}
					if err := WriteKIPMessage(respConn, KIPTypeServerHello, accepted.reply.EncodePayload()); err != nil {
						return nil, err
					}

					selTable := accepted.table
					selMode := uplinkMode
					c2s := accepted.c2s
					s2c := accepted.s2c

					return &httpmask.PreparedServerEarlyHandshake{
						ResponsePayload: respMem.Written(),
						UserHash:        accepted.userHash,
						WrapConn: func(raw net.Conn) (net.Conn, error) {
							_, sessObfs := buildServerObfsConn(raw, selTable, cfg.PaddingMin, cfg.PaddingMax, cfg.EnablePureDownlink, selMode, false)
							return crypto.NewRecordConn(sessObfs, cfg.AEAD, s2c, c2s)
						},
					}, nil
				}
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("early handshake rejected")
			}
			return nil, lastErr
		},
	}
}
