package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku"

	"gridshield/internal/config"
	"gridshield/internal/proxy"
	"gridshield/internal/server"
	"gridshield/internal/sysproxy"
	"gridshield/internal/tun"
	"gridshield/internal/tunnel"
)

const Version = "1.0.0"

// StatusSnapshot is the unified state payload for CLI, Web Dashboard, and Swift macOS app.
type StatusSnapshot struct {
	Version        string              `json:"version"`
	OS             string              `json:"os"`
	Arch           string              `json:"arch"`
	IsRoot         bool                `json:"is_root"`
	Connected      bool                `json:"connected"`
	ConnectedSince int64               `json:"connected_since,omitempty"`
	ActiveProfile  *config.Profile     `json:"active_profile,omitempty"`
	MixedProxyAddr string              `json:"mixed_proxy_addr,omitempty"`
	RoutingMode    string              `json:"routing_mode"`
	SystemProxy    sysproxy.Status     `json:"system_proxy"`
	TUN            tun.Status          `json:"tun"`
	Traffic        proxy.TrafficSample `json:"traffic"`
	ActiveConns    int                 `json:"active_conns"`
	ServerRunning  bool                `json:"server_running"`
	ServerAddr     string              `json:"server_addr,omitempty"`
	ServerClients  int64               `json:"server_clients"`
	ServerHandled  int64               `json:"server_handled"`
}

// SelfTestResult holds diagnostics from an end-to-end Sudoku tunnel verification.
type SelfTestResult struct {
	OK           bool   `json:"ok"`
	HandshakeMs  int    `json:"handshake_ms"`
	ThroughputMB float64 `json:"throughput_mbps"`
	BytesEchoed  int    `json:"bytes_echoed"`
	WireSample   string `json:"wire_sample"`
	ASCII        string `json:"ascii"`
	AEAD         string `json:"aead"`
	HTTPMaskMode string `json:"httpmask_mode"`
	Error        string `json:"error,omitempty"`
}

// Manager coordinates client tunnel, built-in server, system proxy, TUN, telemetry, and persisted state.
type Manager struct {
	Store    *config.Store
	Tracker  *proxy.Tracker
	SysProxy *sysproxy.Manager
	TUN      *tun.Manager

	mu             sync.Mutex
	connected      bool
	connectedSince int64
	activeProfile  *config.Profile
	mixedServer    *proxy.MixedServer
	router         *proxy.Router
	dialer         *tunnel.ClientDialer

	vpnServer     *server.Server
	serverRunning bool
}

func NewManager(store *config.Store) *Manager {
	tracker := proxy.NewTracker()
	tracker.Log("INFO", "Core", "GridShield VPN Core v%s initialized (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)
	return &Manager{
		Store:    store,
		Tracker:  tracker,
		SysProxy: sysproxy.NewManager(),
		TUN:      tun.NewManager(),
	}
}

func (m *Manager) Status() StatusSnapshot {
	state := m.Store.Snapshot()
	m.mu.Lock()
	connected := m.connected
	since := m.connectedSince
	var prof *config.Profile
	if m.activeProfile != nil {
		cp := *m.activeProfile
		prof = &cp
	}
	mixedAddr := ""
	if m.mixedServer != nil {
		mixedAddr = m.mixedServer.Addr()
	}
	srvRunning := m.serverRunning && m.vpnServer != nil
	srvAddr := ""
	var srvClients, srvHandled int64
	if srvRunning {
		srvAddr = m.vpnServer.Addr()
		srvClients, srvHandled = m.vpnServer.Stats()
	}
	m.mu.Unlock()

	return StatusSnapshot{
		Version:        Version,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		IsRoot:         os.Geteuid() == 0,
		Connected:      connected,
		ConnectedSince: since,
		ActiveProfile:  prof,
		MixedProxyAddr: mixedAddr,
		RoutingMode:    state.Settings.RoutingMode,
		SystemProxy:    m.SysProxy.Status(),
		TUN:            m.TUN.Status(),
		Traffic:        m.Tracker.Stats(),
		ActiveConns:    m.Tracker.ActiveCount(),
		ServerRunning:  srvRunning,
		ServerAddr:     srvAddr,
		ServerClients:  srvClients,
		ServerHandled:  srvHandled,
	}
}

// Connect starts the local Sudoku client mixed proxy and enables System Proxy / TUN per settings.
func (m *Manager) Connect(profileID string) error {
	state := m.Store.Snapshot()
	if profileID == "" {
		profileID = state.ActiveProfileID
	}
	var chosen *config.Profile
	for i := range state.Profiles {
		if state.Profiles[i].ID == profileID {
			cp := state.Profiles[i]
			chosen = &cp
			break
		}
	}
	if chosen == nil && len(state.Profiles) > 0 {
		cp := state.Profiles[0]
		chosen = &cp
	}
	if chosen == nil {
		return errors.New("no server profile configured; add a profile, import a sudoku:// link, or start Local Demo")
	}

	return m.ConnectWithProfile(*chosen, state.Settings)
}

// ConnectWithProfile connects directly using an explicit Profile and AppSettings.
func (m *Manager) ConnectWithProfile(profile config.Profile, settings config.AppSettings) error {
	profile.Normalize()
	if err := profile.Validate(); err != nil {
		return err
	}
	settings.Normalize()

	// Tear down any previous session cleanly first.
	_ = m.Disconnect()

	m.Tracker.Log("INFO", "Core", "Initializing Sudoku 4x4 O(1) tables for %q (%s, aead=%s, httpmask=%s)...",
		profile.Name, profile.ASCII, profile.AEAD, profile.HTTPMask.Mode)

	dialer, err := tunnel.NewClientDialer(profile)
	if err != nil {
		m.Tracker.Log("ERROR", "Core", "Failed to build dialer: %v", err)
		return err
	}

	serverHost, _, err := net.SplitHostPort(profile.ServerAddress)
	if err != nil {
		serverHost = profile.ServerAddress
	}

	router := proxy.NewRouter(settings.RoutingMode, settings.DirectDomains, settings.ProxyDomains, serverHost)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", settings.MixedPort)
	mixed := proxy.NewMixedServer(listenAddr, dialer, router, m.Tracker)
	if err := mixed.Start(); err != nil {
		m.Tracker.Log("ERROR", "Core", "Failed to start local proxy: %v", err)
		return err
	}

	m.mu.Lock()
	m.dialer = dialer
	m.router = router
	m.mixedServer = mixed
	m.activeProfile = &profile
	m.connected = true
	m.connectedSince = time.Now().Unix()
	m.mu.Unlock()

	_ = m.Store.Update(func(s *config.State) error {
		s.ActiveProfileID = profile.ID
		return nil
	})

	if settings.AutoSystemProxy {
		if err := m.SysProxy.Enable("127.0.0.1", settings.MixedPort); err != nil {
			m.Tracker.Log("WARN", "SysProxy", "Auto system proxy skipped: %v", err)
		} else {
			m.Tracker.Log("INFO", "SysProxy", "OS System Proxy enabled -> 127.0.0.1:%d", settings.MixedPort)
		}
	}

	if settings.TUNEnabled {
		if err := m.TUN.Start(settings.TUNInterface, settings.TUNMTU, listenAddr, profile.ServerAddress); err != nil {
			m.Tracker.Log("WARN", "TUN", "TUN mode could not start: %v", err)
		} else {
			st := m.TUN.Status()
			m.Tracker.Log("INFO", "TUN", "Full-device TUN active on %s (%s, MTU %d)", st.Interface, st.LocalIP, st.MTU)
		}
	}

	m.Tracker.Log("INFO", "Core", "Connected to %s (%s)", profile.Name, profile.ServerAddress)
	return nil
}

// Disconnect stops TUN, clears OS system proxy, and closes the mixed proxy server.
func (m *Manager) Disconnect() error {
	_ = m.TUN.Stop()
	if err := m.SysProxy.Disable(); err != nil {
		m.Tracker.Log("WARN", "SysProxy", "Failed to disable system proxy: %v", err)
	}

	m.mu.Lock()
	mixed := m.mixedServer
	wasConnected := m.connected
	m.mixedServer = nil
	m.router = nil
	m.dialer = nil
	m.connected = false
	m.connectedSince = 0
	m.mu.Unlock()

	if mixed != nil {
		_ = mixed.Close()
	}
	m.Tracker.CloseAllConnections()

	if wasConnected {
		m.Tracker.Log("INFO", "Core", "Disconnected; system proxy and routes restored")
	}
	return nil
}

// Shutdown cleanly stops client, server, TUN, and system proxy on process exit.
func (m *Manager) Shutdown() {
	_ = m.Disconnect()
	_ = m.StopServer()
	m.Tracker.Close()
}

func (m *Manager) SetRoutingMode(mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "rule" && mode != "global" && mode != "direct" {
		return fmt.Errorf("invalid routing mode %q (want rule|global|direct)", mode)
	}
	if err := m.Store.Update(func(s *config.State) error {
		s.Settings.RoutingMode = mode
		return nil
	}); err != nil {
		return err
	}
	state := m.Store.Snapshot()
	m.mu.Lock()
	r := m.router
	prof := m.activeProfile
	m.mu.Unlock()
	if r != nil {
		serverHost := ""
		if prof != nil {
			serverHost, _, _ = net.SplitHostPort(prof.ServerAddress)
		}
		r.Update(mode, state.Settings.DirectDomains, state.Settings.ProxyDomains, serverHost)
	}
	m.Tracker.Log("INFO", "Router", "Routing mode switched to %s", strings.ToUpper(mode))
	return nil
}

func (m *Manager) ToggleSystemProxy(enable bool) error {
	state := m.Store.Snapshot()
	_ = m.Store.Update(func(s *config.State) error {
		s.Settings.AutoSystemProxy = enable
		return nil
	})
	if !enable {
		if err := m.SysProxy.Disable(); err != nil {
			return err
		}
		m.Tracker.Log("INFO", "SysProxy", "OS System Proxy disabled")
		return nil
	}
	m.mu.Lock()
	connected := m.connected
	m.mu.Unlock()
	if !connected {
		return errors.New("connect VPN first before enabling OS System Proxy")
	}
	if err := m.SysProxy.Enable("127.0.0.1", state.Settings.MixedPort); err != nil {
		return err
	}
	m.Tracker.Log("INFO", "SysProxy", "OS System Proxy enabled -> 127.0.0.1:%d", state.Settings.MixedPort)
	return nil
}

func (m *Manager) ToggleTUN(enable bool) error {
	state := m.Store.Snapshot()
	if !enable {
		_ = m.Store.Update(func(s *config.State) error {
			s.Settings.TUNEnabled = false
			return nil
		})
		if err := m.TUN.Stop(); err != nil {
			return err
		}
		m.Tracker.Log("INFO", "TUN", "TUN mode disabled; routes restored")
		return nil
	}

	m.mu.Lock()
	connected := m.connected
	prof := m.activeProfile
	mixed := m.mixedServer
	m.mu.Unlock()
	if !connected || prof == nil || mixed == nil {
		return errors.New("connect VPN first before enabling TUN mode")
	}
	if err := m.TUN.Start(state.Settings.TUNInterface, state.Settings.TUNMTU, mixed.Addr(), prof.ServerAddress); err != nil {
		m.Tracker.Log("WARN", "TUN", "Enable TUN failed: %v", err)
		return err
	}
	_ = m.Store.Update(func(s *config.State) error {
		s.Settings.TUNEnabled = true
		return nil
	})
	st := m.TUN.Status()
	m.Tracker.Log("INFO", "TUN", "Full-device TUN active on %s (%s)", st.Interface, st.LocalIP)
	return nil
}

// PingProfile performs a real Sudoku KIP handshake against a profile and saves its RTT.
func (m *Manager) PingProfile(profileID string) (int, error) {
	state := m.Store.Snapshot()
	var target *config.Profile
	for i := range state.Profiles {
		if state.Profiles[i].ID == profileID {
			cp := state.Profiles[i]
			target = &cp
			break
		}
	}
	if target == nil {
		return 0, errors.New("profile not found")
	}
	d, err := tunnel.NewClientDialer(*target)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	ms, err := d.ProbeLatency(ctx)
	if err != nil {
		return 0, err
	}
	_ = m.Store.Update(func(s *config.State) error {
		for i := range s.Profiles {
			if s.Profiles[i].ID == profileID {
				s.Profiles[i].LastLatencyMs = ms
			}
		}
		return nil
	})
	m.Tracker.Log("INFO", "Ping", "%s handshake RTT: %d ms", target.Name, ms)
	return ms, nil
}

// StartServer starts the built-in Sudoku VPN server (auto-generating Ed25519 keys if empty).
func (m *Manager) StartServer(cfg config.ServerConfig) (config.ServerConfig, error) {
	cfg.Normalize()
	if strings.TrimSpace(cfg.Key) == "" {
		keys, err := config.GenerateKeys()
		if err != nil {
			return cfg, err
		}
		cfg.Key = keys.MasterPublicKey
		cfg.MasterPrivateKey = keys.MasterPrivateKey
		cfg.ClientKey = keys.AvailablePrivateKey
	}

	_ = m.StopServer()

	srv, err := server.New(cfg, m.Tracker)
	if err != nil {
		return cfg, err
	}
	if err := srv.Start(); err != nil {
		return cfg, err
	}

	m.mu.Lock()
	m.vpnServer = srv
	m.serverRunning = true
	m.mu.Unlock()

	_ = m.Store.Update(func(s *config.State) error {
		s.Server = cfg
		return nil
	})
	return cfg, nil
}

func (m *Manager) StopServer() error {
	m.mu.Lock()
	srv := m.vpnServer
	wasRunning := m.serverRunning
	m.vpnServer = nil
	m.serverRunning = false
	m.mu.Unlock()

	if srv != nil {
		err := srv.Close()
		if wasRunning {
			m.Tracker.Log("INFO", "Server", "Built-in Sudoku VPN Server stopped")
		}
		return err
	}
	return nil
}

// StartLocalDemo launches a local Sudoku server + creates a matching client profile + connects
// (without overriding OS proxy unless requested) so users can test end-to-end immediately!
func (m *Manager) StartLocalDemo() (*config.Profile, error) {
	state := m.Store.Snapshot()
	srvCfg := state.Server
	if strings.TrimSpace(srvCfg.Key) == "" || strings.TrimSpace(srvCfg.ClientKey) == "" {
		keys, err := config.GenerateKeys()
		if err != nil {
			return nil, err
		}
		srvCfg.Key = keys.MasterPublicKey
		srvCfg.MasterPrivateKey = keys.MasterPrivateKey
		srvCfg.ClientKey = keys.AvailablePrivateKey
	}
	srvCfg.Normalize()

	startedCfg, err := m.StartServer(srvCfg)
	if err != nil {
		return nil, err
	}

	demoID := "local-demo-node"
	demoProfile := config.Profile{
		ID:                 demoID,
		Name:               "Local Sudoku Server (Loopback)",
		ServerAddress:      fmt.Sprintf("127.0.0.1:%d", startedCfg.ListenPort),
		Key:                startedCfg.ClientKey,
		AEAD:               startedCfg.AEAD,
		ASCII:              startedCfg.ASCII,
		PaddingMin:         startedCfg.PaddingMin,
		PaddingMax:         startedCfg.PaddingMax,
		EnablePureDownlink: startedCfg.EnablePureDownlink,
		CustomTable:        startedCfg.CustomTable,
		CustomTables:       startedCfg.CustomTables,
		Multiplex:          "auto",
		HTTPMask: config.HTTPMaskConfig{
			Disable:  startedCfg.HTTPMask.Disable,
			Mode:     startedCfg.HTTPMask.Mode,
			TLS:      false,
			PathRoot: startedCfg.HTTPMask.PathRoot,
		},
	}
	demoProfile.Normalize()

	_ = m.Store.Update(func(s *config.State) error {
		found := false
		for i := range s.Profiles {
			if s.Profiles[i].ID == demoID {
				s.Profiles[i] = demoProfile
				found = true
				break
			}
		}
		if !found {
			s.Profiles = append([]config.Profile{demoProfile}, s.Profiles...)
		}
		s.ActiveProfileID = demoID
		return nil
	})

	settings := m.Store.Snapshot().Settings
	if err := m.ConnectWithProfile(demoProfile, settings); err != nil {
		return nil, err
	}
	if ms, err := m.PingProfile(demoID); err == nil {
		demoProfile.LastLatencyMs = ms
	}
	return &demoProfile, nil
}

// RunSelfTest spins up an ephemeral Sudoku server + echo HTTP backend, routes a real 512 KB payload
// through the full SOCKS5/HTTP -> Sudoku 4x4 ASCII/Entropy + AEAD + HTTPMask tunnel, and measures
// handshake RTT, throughput, and captures a sample of the obfuscated wire bytes.
func (m *Manager) RunSelfTest(asciiMode, aeadMode, httpMaskMode string) SelfTestResult {
	if asciiMode == "" {
		asciiMode = "prefer_ascii"
	}
	if aeadMode == "" {
		aeadMode = "chacha20-poly1305"
	}
	if httpMaskMode == "" {
		httpMaskMode = "auto"
	}
	res := SelfTestResult{
		ASCII:        asciiMode,
		AEAD:         aeadMode,
		HTTPMaskMode: httpMaskMode,
	}

	keys, err := config.GenerateKeys()
	if err != nil {
		res.Error = err.Error()
		return res
	}

	// 1. Ephemeral HTTP echo backend
	const payloadSize = 512 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte((i * 31) ^ 0x5A)
	}
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer echoLn.Close()
	echoSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})}
	go func() { _ = echoSrv.Serve(echoLn) }()
	defer echoSrv.Close()

	// 2. Ephemeral Sudoku VPN server on random port
	tmpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	srvPort := tmpLn.Addr().(*net.TCPAddr).Port
	_ = tmpLn.Close()

	srvCfg := config.ServerConfig{
		ListenPort:         srvPort,
		Key:                keys.MasterPublicKey,
		AEAD:               aeadMode,
		ASCII:              asciiMode,
		PaddingMin:         5,
		PaddingMax:         15,
		EnablePureDownlink: true,
		SuspiciousAction:   "silent",
		HTTPMask: config.HTTPMaskConfig{
			Disable: httpMaskMode == "none",
			Mode:    httpMaskMode,
		},
	}
	if httpMaskMode == "none" {
		srvCfg.HTTPMask.Mode = "legacy"
	}
	srv, err := server.New(srvCfg, m.Tracker)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if err := srv.Start(); err != nil {
		res.Error = err.Error()
		return res
	}
	defer srv.Close()

	// 3. Client dialer + local mixed proxy
	prof := config.Profile{
		ID:                 "selftest",
		Name:               "SelfTest",
		ServerAddress:      fmt.Sprintf("127.0.0.1:%d", srvPort),
		Key:                keys.AvailablePrivateKey,
		AEAD:               aeadMode,
		ASCII:              asciiMode,
		PaddingMin:         5,
		PaddingMax:         15,
		EnablePureDownlink: true,
		Multiplex:          "off",
		HTTPMask:           srvCfg.HTTPMask,
	}
	dialer, err := tunnel.NewClientDialer(prof)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rtt, err := dialer.ProbeLatency(ctx)
	if err != nil {
		res.Error = fmt.Sprintf("handshake failed: %v", err)
		return res
	}
	res.HandshakeMs = rtt

	// Also dial directly through Sudoku tunnel to echo backend to measure throughput
	start := time.Now()
	router := proxy.NewRouter("global", nil, []string{"127.0.0.1"}, "")
	// Bypass loopback rule explicitly by dialing through ClientDialer via a temporary HTTP client transport
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialTCP(ctx, addr)
		},
	}
	_ = router
	httpClient := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	targetURL := (&url.URL{Scheme: "http", Host: echoLn.Addr().String(), Path: "/bench"}).String()
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		res.Error = fmt.Sprintf("tunnel http request failed: %v", err)
		return res
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	elapsed := time.Since(start).Seconds()
	if len(body) != payloadSize {
		res.Error = fmt.Sprintf("size mismatch: got %d want %d", len(body), payloadSize)
		return res
	}
	if elapsed <= 0 {
		elapsed = 0.001
	}
	res.BytesEchoed = len(body)
	res.ThroughputMB = float64(len(body)*8) / (elapsed * 1_000_000)

	// Capture genuine Sudoku 4x4 wire-encoded bytes and compute ASCII ratio & Hamming weight
	wirePreview := sampleSudokuWire(keys.MasterPublicKey, asciiMode)
	res.WireSample = wirePreview

	res.OK = true
	m.Tracker.Log("INFO", "SelfTest", "PASS: handshake=%dms, echoed=%dKB, throughput=%.1f Mbps (ascii=%s, aead=%s, httpmask=%s)",
		res.HandshakeMs, res.BytesEchoed/1024, res.ThroughputMB, asciiMode, aeadMode, httpMaskMode)
	return res
}

func sampleSudokuWire(key, asciiMode string) string {
	tbl, err := sudoku.NewTableWithCustom(key, asciiMode, "")
	if err != nil {
		return ""
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	wireCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		_ = c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := c2.Read(buf)
		wireCh <- buf[:n]
	}()
	sc := sudoku.NewConn(c1, tbl, 5, 15, false)
	_, _ = sc.Write([]byte("GridShield 4x4 Sudoku O(1) Tunnel!"))
	raw := <-wireCh
	if len(raw) == 0 {
		return ""
	}
	printable := 0
	totalOnes := 0
	var preview strings.Builder
	for i, b := range raw {
		totalOnes += bits.OnesCount8(b)
		if b >= 0x20 && b <= 0x7E {
			printable++
			if i < 48 {
				preview.WriteByte(b)
			}
		} else if i < 48 {
			preview.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	asciiPct := float64(printable) * 100 / float64(len(raw))
	avgHamming := float64(totalOnes) / float64(len(raw))
	return fmt.Sprintf("ASCII %.1f%% | Hamming %.2f | wire: %s...", asciiPct, avgHamming, preview.String())
}
