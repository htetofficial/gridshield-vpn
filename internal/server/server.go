package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/httpmask"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku"

	"gridshield/internal/config"
	"gridshield/internal/protocol"
	"gridshield/internal/proxy"
	"gridshield/internal/tunnel"
)

// Server is a full, wire-compatible Sudoku VPN server.
type Server struct {
	cfg     config.ServerConfig
	tables  []*sudoku.Table
	tracker *proxy.Tracker
	tmSrv   *httpmask.TunnelServer

	mu       sync.Mutex
	listener net.Listener
	closed   bool

	activeClients atomic.Int64
	totalHandled  atomic.Int64
}

func New(cfg config.ServerConfig, tracker *proxy.Tracker) (*Server, error) {
	cfg.Normalize()
	if strings.TrimSpace(cfg.Key) == "" {
		return nil, errors.New("server key (Master Public Key) is required")
	}
	tables, err := tunnel.BuildTables(cfg.Key, cfg.ASCII, cfg.CustomTable, cfg.CustomTables)
	if err != nil {
		return nil, fmt.Errorf("build server tables: %w", err)
	}

	var tmSrv *httpmask.TunnelServer
	if !cfg.HTTPMask.Disable {
		mode := strings.ToLower(strings.TrimSpace(cfg.HTTPMask.Mode))
		if mode != "" && mode != "legacy" {
			early := tunnel.NewHTTPMaskServerEarlyHandshake(tunnel.EarlyCodecConfig{
				PSK:                cfg.Key,
				AEAD:               cfg.AEAD,
				EnablePureDownlink: cfg.EnablePureDownlink,
				PaddingMin:         cfg.PaddingMin,
				PaddingMax:         cfg.PaddingMax,
			}, tables)
			tmSrv = httpmask.NewTunnelServer(httpmask.TunnelServerOptions{
				Mode:                mode,
				PathRoot:            cfg.HTTPMask.PathRoot,
				AuthKey:             cfg.Key,
				PassThroughOnReject: true,
				EarlyHandshake:      early,
			})
		}
	}

	return &Server{
		cfg:     cfg,
		tables:  tables,
		tracker: tracker,
		tmSrv:   tmSrv,
	}, nil
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("listen server :%d: %w", s.cfg.ListenPort, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.closed = false
	s.mu.Unlock()

	s.tracker.Log("INFO", "Server", "Sudoku VPN Server listening on %s (ascii=%s, aead=%s, httpmask=%s)",
		ln.Addr().String(), s.cfg.ASCII, s.cfg.AEAD, s.cfg.HTTPMask.Mode)
	go s.acceptLoop(ln)
	return nil
}

func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return fmt.Sprintf(":%d", s.cfg.ListenPort)
}

func (s *Server) Stats() (active, total int64) {
	return s.activeClients.Load(), s.totalHandled.Load()
}

func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.listener
	s.listener = nil
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if !closed {
				s.tracker.Log("WARN", "Server", "accept error: %v", err)
			}
			return
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(raw net.Conn) {
	s.activeClients.Add(1)
	s.totalHandled.Add(1)
	defer s.activeClients.Add(-1)

	conn := raw
	if s.tmSrv != nil {
		res, nextConn, err := s.tmSrv.HandleConn(raw)
		if err != nil {
			_ = raw.Close()
			return
		}
		switch res {
		case httpmask.HandleDone:
			return
		case httpmask.HandleStartTunnel, httpmask.HandlePassThrough:
			conn = nextConn
		}
	}

	tunnelConn, meta, err := tunnel.ServerHandshake(conn, s.cfg, s.tables)
	if err != nil {
		var susp *tunnel.SuspiciousError
		if errors.As(err, &susp) {
			s.handleSuspicious(susp)
			return
		}
		_ = conn.Close()
		return
	}
	defer tunnelConn.Close()

	// Dispatch KIP control message
	msg, err := tunnel.ReadKIPMessage(tunnelConn)
	if err != nil {
		return
	}

	switch msg.Type {
	case tunnel.KIPTypeOpenTCP:
		target, err := protocol.DecodeAddress(msg.Payload)
		if err != nil {
			return
		}
		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			s.tracker.Log("WARN", "Server", "[%s] dial %s failed: %v", meta.UserHash, target, err)
			return
		}
		defer remote.Close()
		if tcp, ok := remote.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
		s.relay(tunnelConn, remote)

	case tunnel.KIPTypeStartUoT:
		_ = tunnel.HandleUoTServer(tunnelConn)

	case tunnel.KIPTypeKeepAlive:
		return

	default:
		return
	}
}

func (s *Server) handleSuspicious(susp *tunnel.SuspiciousError) {
	if strings.EqualFold(s.cfg.SuspiciousAction, "fallback") && strings.TrimSpace(s.cfg.FallbackAddress) != "" {
		decoy, err := net.DialTimeout("tcp", s.cfg.FallbackAddress, 5*time.Second)
		if err != nil {
			_ = susp.Conn.Close()
			return
		}
		defer decoy.Close()
		if rec, ok := susp.Conn.(interface{ GetBufferedAndRecorded() []byte }); ok {
			if prefix := rec.GetBufferedAndRecorded(); len(prefix) > 0 {
				_, _ = decoy.Write(prefix)
			}
		}
		s.relay(susp.Conn, decoy)
		return
	}
	// Silent tarpit: briefly stall then close
	time.Sleep(150 * time.Millisecond)
	_ = susp.Conn.Close()
}

func (s *Server) relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	go cp(b, a)
	go cp(a, b)
	wg.Wait()
}
