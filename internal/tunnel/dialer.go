package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/SUDOKU-ASCII/sudoku/pkg/crypto"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/httpmask"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku"

	"gridshield/internal/config"
)

// ClientDialer dials outbound TCP and UDP-over-TCP streams over the Sudoku 4x4 protocol.
type ClientDialer struct {
	Profile    config.Profile
	TableKey   string
	PrivateKey []byte
	Tables     []*sudoku.Table
}

// NewClientDialer compiles Sudoku lookup tables and normalizes client keys for a profile.
func NewClientDialer(p config.Profile) (*ClientDialer, error) {
	p.Normalize()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	tableKey, privKey, _ := config.NormalizeClientKey(p.Key)
	tables, err := BuildTables(tableKey, p.ASCII, p.CustomTable, p.CustomTables)
	if err != nil {
		return nil, fmt.Errorf("build sudoku tables: %w", err)
	}
	return &ClientDialer{
		Profile:    p,
		TableKey:   tableKey,
		PrivateKey: privKey,
		Tables:     tables,
	}, nil
}

func (d *ClientDialer) pickTable() (*sudoku.Table, uint32, bool) {
	if len(d.Tables) == 1 {
		return d.Tables[0], d.Tables[0].Hint(), false
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	idx := int(binary.BigEndian.Uint32(b[:])) % len(d.Tables)
	t := d.Tables[idx]
	return t, t.Hint(), true
}

func (d *ClientDialer) useHTTPMaskTunnel() bool {
	if d.Profile.HTTPMask.Disable {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(d.Profile.HTTPMask.Mode)) {
	case "ws", "stream", "poll", "auto":
		return true
	default:
		return false
	}
}

func (d *ClientDialer) clientHandshake(raw net.Conn, table *sudoku.Table, tableHint uint32, hasTableHint bool) (net.Conn, error) {
	obfsConn := buildClientObfsConn(raw, table, d.Profile.PaddingMin, d.Profile.PaddingMax, d.Profile.EnablePureDownlink, obfsUplinkPure)
	pskC2S, pskS2C := derivePSKDirectionalBases(d.TableKey)
	rc, err := crypto.NewRecordConn(obfsConn, d.Profile.AEAD, pskC2S, pskS2C)
	if err != nil {
		return nil, fmt.Errorf("crypto setup: %w", err)
	}
	userHash := kipUserHashFromPrivateKey(d.PrivateKey, d.TableKey)
	ch, ephemeral, err := newClientHello(userHash, KIPFeatAll, tableHint, hasTableHint)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	if err := WriteKIPMessage(rc, KIPTypeClientHello, ch.EncodePayload()); err != nil {
		_ = rc.Close()
		return nil, fmt.Errorf("write client hello: %w", err)
	}
	sh, err := readServerHello(rc)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	c2s, s2c, err := deriveClientSession(d.TableKey, ephemeral, ch.Nonce, sh)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	if err := rc.Rekey(c2s, s2c); err != nil {
		_ = rc.Close()
		return nil, fmt.Errorf("rekey: %w", err)
	}
	return rc, nil
}

// DialBase opens an authenticated, encrypted, Sudoku-obfuscated base tunnel to the server.
func (d *ClientDialer) DialBase(ctx context.Context) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	table, tableHint, hasTableHint := d.pickTable()

	if d.useHTTPMaskTunnel() {
		userHash := kipUserHashFromPrivateKey(d.PrivateKey, d.TableKey)
		early, err := NewHTTPMaskClientEarlyHandshake(EarlyCodecConfig{
			PSK:                d.TableKey,
			AEAD:               d.Profile.AEAD,
			EnablePureDownlink: d.Profile.EnablePureDownlink,
			PaddingMin:         d.Profile.PaddingMin,
			PaddingMax:         d.Profile.PaddingMax,
		}, table, tableHint, hasTableHint, userHash, KIPFeatAll)
		if err != nil {
			return nil, err
		}
		muxMode := d.Profile.Multiplex
		if muxMode == "" {
			muxMode = "off"
		}
		conn, err := httpmask.DialTunnel(ctx, d.Profile.ServerAddress, httpmask.TunnelDialOptions{
			Mode:           d.Profile.HTTPMask.Mode,
			TLSEnabled:     d.Profile.HTTPMask.TLS,
			HostOverride:   d.Profile.HTTPMask.Host,
			PathRoot:       d.Profile.HTTPMask.PathRoot,
			AuthKey:        d.TableKey,
			EarlyHandshake: early,
			Multiplex:      muxMode,
			Upgrade: func(raw net.Conn) (net.Conn, error) {
				return d.clientHandshake(raw, table, tableHint, hasTableHint)
			},
		})
		if err != nil {
			return nil, fmt.Errorf("dial httpmask tunnel: %w", err)
		}
		return conn, nil
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", d.Profile.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("dial server %s: %w", d.Profile.ServerAddress, err)
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	if !d.Profile.HTTPMask.Disable {
		host := d.Profile.HTTPMask.Host
		if host == "" {
			host = d.Profile.ServerAddress
		}
		if err := httpmask.WriteRandomRequestHeaderWithPathRoot(raw, host, d.Profile.HTTPMask.PathRoot); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("write legacy http mask: %w", err)
		}
	}

	conn, err := d.clientHandshake(raw, table, tableHint, hasTableHint)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// DialTCP opens a tunneled TCP stream to destAddr ("host:port").
func (d *ClientDialer) DialTCP(ctx context.Context, destAddr string) (net.Conn, error) {
	conn, err := d.DialBase(ctx)
	if err != nil {
		return nil, err
	}
	if err := WriteKIPOpenTCP(conn, destAddr); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("kip open tcp: %w", err)
	}
	return conn, nil
}

// DialUoT opens a UDP-over-TCP session over the Sudoku tunnel.
func (d *ClientDialer) DialUoT(ctx context.Context) (net.Conn, error) {
	conn, err := d.DialBase(ctx)
	if err != nil {
		return nil, err
	}
	if err := WriteKIPMessage(conn, KIPTypeStartUoT, nil); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("kip start uot: %w", err)
	}
	return conn, nil
}

// ProbeLatency performs a real Sudoku KIP handshake (with KeepAlive) and measures RTT in ms.
func (d *ClientDialer) ProbeLatency(ctx context.Context) (int, error) {
	start := time.Now()
	conn, err := d.DialBase(ctx)
	if err != nil {
		return 0, err
	}
	_ = WriteKIPMessage(conn, KIPTypeKeepAlive, nil)
	_ = conn.Close()
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}
