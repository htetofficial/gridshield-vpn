package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// HTTPMaskConfig configures HTTP masking / tunnel disguises for Sudoku connections.
type HTTPMaskConfig struct {
	Disable  bool   `json:"disable"`
	Mode     string `json:"mode"`                // "legacy" | "ws" | "stream" | "poll" | "auto"
	TLS      bool   `json:"tls"`                 // client HTTPS in tunnel modes
	Host     string `json:"host,omitempty"`      // optional Host / SNI override
	PathRoot string `json:"path_root,omitempty"` // optional first-level path prefix
}

// Profile represents a client VPN server node configuration.
type Profile struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	ServerAddress      string         `json:"server_address"`
	Key                string         `json:"key"`
	AEAD               string         `json:"aead"`                 // "chacha20-poly1305" | "aes-128-gcm" | "none"
	ASCII              string         `json:"ascii"`                // "prefer_entropy" | "prefer_ascii" | "up_ascii_down_entropy" | "up_entropy_down_ascii"
	PaddingMin         int            `json:"padding_min"`          // 0..100
	PaddingMax         int            `json:"padding_max"`          // 0..100
	EnablePureDownlink bool           `json:"enable_pure_downlink"` // true = classic Sudoku both ways, false = packed downlink
	CustomTable        string         `json:"custom_table,omitempty"`
	CustomTables       []string       `json:"custom_tables,omitempty"`
	Multiplex          string         `json:"multiplex"` // "off" | "auto" | "on"
	HTTPMask           HTTPMaskConfig `json:"httpmask"`
	LastLatencyMs      int            `json:"last_latency_ms,omitempty"`
}

// ServerConfig configures the built-in Sudoku VPN server.
type ServerConfig struct {
	ListenPort         int            `json:"listen_port"`
	Key                string         `json:"key"` // Master Public Key (or PSK)
	MasterPrivateKey   string         `json:"master_private_key,omitempty"`
	ClientKey          string         `json:"client_key,omitempty"` // Generated Available Private Key for easy client setup
	AEAD               string         `json:"aead"`
	ASCII              string         `json:"ascii"`
	PaddingMin         int            `json:"padding_min"`
	PaddingMax         int            `json:"padding_max"`
	EnablePureDownlink bool           `json:"enable_pure_downlink"`
	CustomTable        string         `json:"custom_table,omitempty"`
	CustomTables       []string       `json:"custom_tables,omitempty"`
	SuspiciousAction   string         `json:"suspicious_action"` // "fallback" | "silent"
	FallbackAddress    string         `json:"fallback_address,omitempty"`
	HTTPMask           HTTPMaskConfig `json:"httpmask"`
}

// AppSettings holds runtime client preferences.
type AppSettings struct {
	MixedPort       int      `json:"mixed_port"`        // local SOCKS5 + HTTP proxy port (default 10808)
	DashboardAddr   string   `json:"dashboard_addr"`    // e.g. "127.0.0.1:9099"
	RoutingMode     string   `json:"routing_mode"`      // "rule" | "global" | "direct"
	AutoSystemProxy bool     `json:"auto_system_proxy"` // set OS system proxy on connect
	TUNEnabled      bool     `json:"tun_enabled"`       // enable full-device TUN mode on connect
	TUNInterface    string   `json:"tun_interface"`     // e.g. "utun" (macOS auto) or "gridshield0" (Linux)
	TUNMTU          int      `json:"tun_mtu"`
	DirectDomains   []string `json:"direct_domains"` // bypassed in "rule" mode
	ProxyDomains    []string `json:"proxy_domains"`  // forced proxy in "rule" mode
}

// State is the full persisted configuration file.
type State struct {
	ActiveProfileID string       `json:"active_profile_id"`
	Profiles        []Profile    `json:"profiles"`
	Settings        AppSettings  `json:"settings"`
	Server          ServerConfig `json:"server"`
}

// Normalize fills sensible defaults and validates fields on Profile.
func (p *Profile) Normalize() {
	if strings.TrimSpace(p.ID) == "" {
		p.ID = NewID()
	}
	if strings.TrimSpace(p.Name) == "" {
		p.Name = p.ServerAddress
		if p.Name == "" {
			p.Name = "Sudoku Node"
		}
	}
	p.ServerAddress = strings.TrimSpace(p.ServerAddress)
	p.Key = strings.TrimSpace(p.Key)
	if p.AEAD == "" {
		p.AEAD = "chacha20-poly1305"
	}
	if p.ASCII == "" {
		p.ASCII = "prefer_entropy"
	}
	if p.PaddingMin < 0 {
		p.PaddingMin = 0
	}
	if p.PaddingMax < p.PaddingMin {
		p.PaddingMax = p.PaddingMin
	}
	if p.PaddingMax == 0 && p.PaddingMin == 0 {
		p.PaddingMin = 5
		p.PaddingMax = 15
	}
	if p.PaddingMax > 100 {
		p.PaddingMax = 100
	}
	if p.Multiplex == "" {
		p.Multiplex = "off"
	}
	if p.HTTPMask.Mode == "" {
		p.HTTPMask.Mode = "auto"
	}
}

// Validate checks mandatory client profile fields.
func (p *Profile) Validate() error {
	if strings.TrimSpace(p.ServerAddress) == "" {
		return errors.New("server_address is required")
	}
	if strings.TrimSpace(p.Key) == "" {
		return errors.New("key is required")
	}
	if p.PaddingMin < 0 || p.PaddingMax > 100 || p.PaddingMax < p.PaddingMin {
		return errors.New("padding_min/padding_max must satisfy 0 <= min <= max <= 100")
	}
	return nil
}

// Normalize fills sensible defaults on ServerConfig.
func (s *ServerConfig) Normalize() {
	if s.ListenPort <= 0 || s.ListenPort > 65535 {
		s.ListenPort = 8443
	}
	if s.AEAD == "" {
		s.AEAD = "chacha20-poly1305"
	}
	if s.ASCII == "" {
		s.ASCII = "prefer_entropy"
	}
	if s.PaddingMin < 0 {
		s.PaddingMin = 0
	}
	if s.PaddingMax < s.PaddingMin {
		s.PaddingMax = s.PaddingMin
	}
	if s.PaddingMax == 0 && s.PaddingMin == 0 {
		s.PaddingMin = 5
		s.PaddingMax = 15
	}
	if s.SuspiciousAction == "" {
		s.SuspiciousAction = "silent"
	}
	if s.HTTPMask.Mode == "" {
		s.HTTPMask.Mode = "auto"
	}
}

// Normalize fills sensible defaults on AppSettings.
func (a *AppSettings) Normalize() {
	if a.MixedPort <= 0 || a.MixedPort > 65535 {
		a.MixedPort = 10808
	}
	if strings.TrimSpace(a.DashboardAddr) == "" {
		a.DashboardAddr = "127.0.0.1:9099"
	}
	switch strings.ToLower(a.RoutingMode) {
	case "rule", "global", "direct":
		a.RoutingMode = strings.ToLower(a.RoutingMode)
	default:
		a.RoutingMode = "rule"
	}
	if a.TUNMTU <= 0 {
		a.TUNMTU = 1500
	}
	if len(a.DirectDomains) == 0 {
		a.DirectDomains = []string{"localhost", "local", "lan", "home.arpa"}
	}
}

// NewID generates a random 8-byte hex identifier.
func NewID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// DefaultState returns a ready-to-use initial state.
func DefaultState() State {
	s := State{
		Settings: AppSettings{
			MixedPort:       10808,
			DashboardAddr:   "127.0.0.1:9099",
			RoutingMode:     "rule",
			AutoSystemProxy: true,
			TUNEnabled:      false,
			TUNMTU:          1500,
			DirectDomains:   []string{"localhost", "local", "lan", "home.arpa"},
		},
		Server: ServerConfig{
			ListenPort:         8443,
			AEAD:               "chacha20-poly1305",
			ASCII:              "prefer_entropy",
			PaddingMin:         5,
			PaddingMax:         15,
			EnablePureDownlink: true,
			SuspiciousAction:   "silent",
			HTTPMask: HTTPMaskConfig{
				Disable: false,
				Mode:    "auto",
			},
		},
	}
	s.Settings.Normalize()
	s.Server.Normalize()
	return s
}

// DefaultConfigPath returns ~/.config/gridshield/state.json.
func DefaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "gridshield", "state.json")
}

// Store manages thread-safe access and disk persistence for State.
type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

// LoadStore loads state from path, creating defaults if missing.
func LoadStore(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultConfigPath()
	}
	st := &Store{
		path:  path,
		state: DefaultState(),
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var loaded State
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	loaded.Settings.Normalize()
	loaded.Server.Normalize()
	for i := range loaded.Profiles {
		loaded.Profiles[i].Normalize()
	}
	st.state = loaded
	return st, nil
}

func (s *Store) Path() string { return s.path }

func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.state
	cp.Profiles = append([]Profile(nil), s.state.Profiles...)
	cp.Settings.DirectDomains = append([]string(nil), s.state.Settings.DirectDomains...)
	cp.Settings.ProxyDomains = append([]string(nil), s.state.Settings.ProxyDomains...)
	return cp
}

func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.state); err != nil {
		return err
	}
	s.state.Settings.Normalize()
	s.state.Server.Normalize()
	for i := range s.state.Profiles {
		s.state.Profiles[i].Normalize()
	}
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
