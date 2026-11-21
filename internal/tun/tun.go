package tun

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	t2stun "github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	"github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
	t2stunnel "github.com/xjasonlyu/tun2socks/v2/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	LocalTUNIP = "198.18.0.1"
	PeerTUNIP  = "198.18.0.2"
)

// Status describes the active TUN interface state.
type Status struct {
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface,omitempty"`
	LocalIP   string `json:"local_ip,omitempty"`
	MTU       int    `json:"mtu,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Manager controls the full-device TUN network interface and gVisor userspace TCP/IP stack.
type Manager struct {
	mu      sync.Mutex
	dev     device.Device
	netStk  *stack.Stack
	cleanup func()
	status  Status
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// Start creates the OS TUN device, binds gVisor netstack to socksAddr ("127.0.0.1:10808"),
// and installs safe split default routes with a bypass route for serverAddress.
func (m *Manager) Start(ifaceName string, mtu int, socksAddr string, serverAddress string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status.Enabled {
		return nil
	}
	if err := checkPrivileges(); err != nil {
		m.status = Status{Enabled: false, Error: err.Error()}
		return err
	}
	if mtu <= 0 {
		mtu = 1500
	}
	if strings.TrimSpace(ifaceName) == "" {
		ifaceName = defaultIfaceName()
	}

	s5, err := socks5.New(socksAddr, "", "")
	if err != nil {
		m.status = Status{Enabled: false, Error: err.Error()}
		return fmt.Errorf("init tun socks5 upstream: %w", err)
	}
	t2stunnel.T().SetProxy(s5)

	dev, err := t2stun.Open(ifaceName, uint32(mtu))
	if err != nil {
		m.status = Status{Enabled: false, Error: err.Error()}
		return fmt.Errorf("open tun device %q: %w", ifaceName, err)
	}

	stk, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: t2stunnel.T(),
		Options: []option.Option{
			option.WithTCPModerateReceiveBuffer(true),
		},
	})
	if err != nil {
		dev.Close()
		m.status = Status{Enabled: false, Error: err.Error()}
		return fmt.Errorf("create gvisor netstack: %w", err)
	}

	serverIPs := resolveServerIPs(serverAddress)
	cleanupRoutes, err := configurePlatformRoutes(dev.Name(), mtu, serverIPs)
	if err != nil {
		stk.Close()
		stk.Wait()
		dev.Close()
		m.status = Status{Enabled: false, Error: err.Error()}
		return fmt.Errorf("configure tun routes: %w", err)
	}

	m.dev = dev
	m.netStk = stk
	m.cleanup = cleanupRoutes
	m.status = Status{
		Enabled:   true,
		Interface: dev.Name(),
		LocalIP:   LocalTUNIP,
		MTU:       mtu,
	}
	return nil
}

// Stop tears down routes, closes gVisor netstack, and destroys the TUN device.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cleanup != nil {
		m.cleanup()
		m.cleanup = nil
	}
	if m.netStk != nil {
		m.netStk.Close()
		m.netStk.Wait()
		m.netStk = nil
	}
	if m.dev != nil {
		m.dev.Close()
		m.dev = nil
	}
	m.status = Status{}
	return nil
}

func resolveServerIPs(serverAddress string) []string {
	host, _, err := net.SplitHostPort(serverAddress)
	if err != nil {
		host = serverAddress
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
			return []string{ip4.String()}
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
			s := ip4.String()
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}
