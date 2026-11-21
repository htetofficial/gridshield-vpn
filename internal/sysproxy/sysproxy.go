package sysproxy

import "sync"

// Status describes the current OS system proxy configuration managed by GridShield.
type Status struct {
	Enabled  bool     `json:"enabled"`
	Host     string   `json:"host,omitempty"`
	Port     int      `json:"port,omitempty"`
	Services []string `json:"services,omitempty"`
}

// Manager safely toggles OS-level HTTP/HTTPS/SOCKS5 system proxy settings.
type Manager struct {
	mu     sync.Mutex
	status Status
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := m.status
	cp.Services = append([]string(nil), m.status.Services...)
	return cp
}

func (m *Manager) Enable(host string, port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	services, err := enablePlatformProxy(host, port)
	if err != nil {
		return err
	}
	m.status = Status{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Services: services,
	}
	return nil
}

func (m *Manager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Enabled {
		return nil
	}
	err := disablePlatformProxy(m.status.Services)
	m.status = Status{}
	return err
}
