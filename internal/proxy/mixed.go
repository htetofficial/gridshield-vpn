package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gridshield/internal/protocol"
	"gridshield/internal/tunnel"
)

// MixedServer serves both SOCKS5 (TCP + UDP ASSOCIATE via UoT) and HTTP/HTTPS proxy on one TCP port.
type MixedServer struct {
	addr    string
	dialer  *tunnel.ClientDialer
	router  *Router
	tracker *Tracker

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

func NewMixedServer(listenAddr string, dialer *tunnel.ClientDialer, router *Router, tracker *Tracker) *MixedServer {
	return &MixedServer{
		addr:    listenAddr,
		dialer:  dialer,
		router:  router,
		tracker: tracker,
	}
}

func (s *MixedServer) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen mixed proxy %s: %w", s.addr, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.closed = false
	s.mu.Unlock()

	s.tracker.Log("INFO", "Proxy", "Mixed SOCKS5/HTTP listener started on %s", ln.Addr().String())
	go s.acceptLoop(ln)
	return nil
}

func (s *MixedServer) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}

func (s *MixedServer) Close() error {
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

func (s *MixedServer) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if !closed {
				s.tracker.Log("WARN", "Proxy", "accept error: %v", err)
			}
			return
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
		go s.handleConn(conn)
	}
}

func (s *MixedServer) handleConn(conn net.Conn) {
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		_ = conn.Close()
		return
	}
	if first[0] == 0x05 {
		s.handleSOCKS5(conn, br)
		return
	}
	s.handleHTTP(conn, br)
}

func (s *MixedServer) dialOutbound(ctx context.Context, target string) (net.Conn, RouteAction, error) {
	action := s.router.Decide(target)
	if action == RouteDirect {
		d := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
		c, err := d.DialContext(ctx, "tcp", target)
		return c, RouteDirect, err
	}
	c, err := s.dialer.DialTCP(ctx, target)
	return c, RouteProxy, err
}

func (s *MixedServer) handleSOCKS5(conn net.Conn, br *bufio.Reader) {
	defer conn.Close()

	// 1. Greeting: VER | NMETHODS | METHODS...
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// No authentication required (0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
	var req [3]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}
	target, _, _, err := protocol.ReadAddress(br)
	if err != nil {
		return
	}

	switch req[1] {
	case 0x01: // CONNECT
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		remote, route, err := s.dialOutbound(ctx, target)
		cancel()
		if err != nil {
			_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			s.tracker.Log("WARN", "SOCKS5", "dial %s failed: %v", target, err)
			return
		}
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

		active, cleanup := s.tracker.TrackConn("tcp", conn.RemoteAddr().String(), target, string(route), remote)
		defer cleanup()

		wrappedClient := &bufferedConn{Conn: conn, r: br}
		RelayBidirectional(wrappedClient, remote, active, s.tracker)

	case 0x03: // UDP ASSOCIATE (relayed over Sudoku UoT)
		s.handleSOCKS5UDP(conn)

	default:
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func (s *MixedServer) handleSOCKS5UDP(tcpConn net.Conn) {
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_, _ = tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpLn.Close()

	bindAddr := udpLn.LocalAddr().(*net.UDPAddr)
	resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(bindAddr.Port >> 8), byte(bindAddr.Port)}
	if _, err := tcpConn.Write(resp); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	uotConn, err := s.dialer.DialUoT(ctx)
	cancel()
	if err != nil {
		s.tracker.Log("WARN", "UoT", "dial UoT failed: %v", err)
		return
	}
	defer uotConn.Close()

	active, cleanup := s.tracker.TrackConn("udp", tcpConn.RemoteAddr().String(), "UDP-over-TCP", string(RouteProxy), uotConn)
	defer cleanup()

	var clientAddrMu sync.Mutex
	var clientAddr *net.UDPAddr

	stop := make(chan struct{})
	var stopOnce sync.Once
	doStop := func() {
		stopOnce.Do(func() {
			close(stop)
			_ = udpLn.Close()
			_ = uotConn.Close()
		})
	}

	// Keepalive watcher on the controlling TCP connection.
	go func() {
		var tmp [1]byte
		for {
			if _, err := tcpConn.Read(tmp[:]); err != nil {
				doStop()
				return
			}
		}
	}()

	uw := tunnel.NewUoTWriter(uotConn, func(error) { doStop() })
	defer uw.Close()

	// Downlink: UoT -> local SOCKS5 UDP client
	go func() {
		ur := tunnel.NewUoTReader(uotConn)
		for {
			peerAddr, payload, err := ur.ReadDatagram()
			if err != nil {
				doStop()
				return
			}
			active.AddDown(int64(len(payload)), s.tracker)
			clientAddrMu.Lock()
			ca := clientAddr
			clientAddrMu.Unlock()
			if ca == nil {
				continue
			}
			pkt := make([]byte, 0, 3+protocol.MaxEncodedAddrLen+len(payload))
			pkt = append(pkt, 0x00, 0x00, 0x00)
			pkt, err = protocol.AppendAddress(pkt, peerAddr)
			if err != nil {
				continue
			}
			pkt = append(pkt, payload...)
			_, _ = udpLn.WriteToUDP(pkt, ca)
		}
	}()

	// Uplink: local SOCKS5 UDP client -> UoT
	buf := make([]byte, 64*1024)
	for {
		n, src, err := udpLn.ReadFromUDP(buf)
		if err != nil {
			doStop()
			return
		}
		if n < 4 || buf[2] != 0x00 { // drop fragmented
			continue
		}
		clientAddrMu.Lock()
		clientAddr = src
		clientAddrMu.Unlock()

		addrStr, hdrLen, err := parseSOCKS5UDPHeader(buf[3:n])
		if err != nil {
			continue
		}
		payload := buf[3+hdrLen : n]
		active.AddUp(int64(len(payload)), s.tracker)
		if err := uw.WriteDatagram(addrStr, payload); err != nil {
			doStop()
			return
		}
	}
}

func parseSOCKS5UDPHeader(b []byte) (string, int, error) {
	if len(b) < 4 {
		return "", 0, io.ErrUnexpectedEOF
	}
	var hdrLen int
	switch b[0] {
	case protocol.AddrTypeIPv4:
		hdrLen = 1 + 4 + 2
	case protocol.AddrTypeIPv6:
		hdrLen = 1 + 16 + 2
	case protocol.AddrTypeDomain:
		if len(b) < 2 {
			return "", 0, io.ErrUnexpectedEOF
		}
		hdrLen = 2 + int(b[1]) + 2
	default:
		return "", 0, fmt.Errorf("unknown socks5 atyp %d", b[0])
	}
	if len(b) < hdrLen {
		return "", 0, io.ErrUnexpectedEOF
	}
	addr, err := protocol.DecodeAddress(b[:hdrLen])
	return addr, hdrLen, err
}

func (s *MixedServer) handleHTTP(conn net.Conn, br *bufio.Reader) {
	defer conn.Close()

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if strings.EqualFold(req.Method, http.MethodConnect) {
		target := ensurePort(req.Host, "443")
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		remote, route, err := s.dialOutbound(ctx, target)
		cancel()
		if err != nil {
			_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			s.tracker.Log("WARN", "HTTP", "CONNECT %s failed: %v", target, err)
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

		active, cleanup := s.tracker.TrackConn("tcp", conn.RemoteAddr().String(), target, string(route), remote)
		defer cleanup()

		wrappedClient := &bufferedConn{Conn: conn, r: br}
		RelayBidirectional(wrappedClient, remote, active, s.tracker)
		return
	}

	// Plain HTTP proxy request
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	target := ensurePort(host, "80")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	remote, route, err := s.dialOutbound(ctx, target)
	cancel()
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer remote.Close()

	active, cleanup := s.tracker.TrackConn("tcp", conn.RemoteAddr().String(), target, string(route), remote)
	defer cleanup()

	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")

	if err := req.Write(remote); err != nil {
		return
	}
	wrappedClient := &bufferedConn{Conn: conn, r: br}
	RelayBidirectional(wrappedClient, remote, active, s.tracker)
}

func ensurePort(host, defaultPort string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + defaultPort
	}
	if _, err := strconv.Atoi(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, defaultPort)
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// unused import guard
var _ = binary.BigEndian
var _ = errors.New
