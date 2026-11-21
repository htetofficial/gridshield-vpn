package proxy

import (
	"net"
	"net/netip"
	"strings"
	"sync"
)

// RouteAction decides whether a connection goes direct or through the Sudoku tunnel.
type RouteAction string

const (
	RouteProxy  RouteAction = "SUDOKU"
	RouteDirect RouteAction = "DIRECT"
)

// Router classifies destinations according to mode ("rule", "global", "direct").
type Router struct {
	mu            sync.RWMutex
	mode          string
	directDomains []string
	proxyDomains  []string
	serverHost    string
}

func NewRouter(mode string, directDomains, proxyDomains []string, serverHost string) *Router {
	r := &Router{}
	r.Update(mode, directDomains, proxyDomains, serverHost)
	return r
}

func (r *Router) Update(mode string, directDomains, proxyDomains []string, serverHost string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "global", "direct", "rule":
		r.mode = strings.ToLower(strings.TrimSpace(mode))
	default:
		r.mode = "rule"
	}
	r.directDomains = normalizeDomainList(directDomains)
	r.proxyDomains = normalizeDomainList(proxyDomains)
	r.serverHost = strings.ToLower(strings.TrimSpace(serverHost))
}

func (r *Router) Mode() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mode
}

func normalizeDomainList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

func matchDomainSuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// Decide chooses SUDOKU or DIRECT for a target "host:port".
func (r *Router) Decide(targetAddr string) RouteAction {
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
	}
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))

	r.mu.RLock()
	mode := r.mode
	serverHost := r.serverHost
	directDomains := r.directDomains
	proxyDomains := r.proxyDomains
	r.mu.RUnlock()

	// Prevent routing loop back to the VPN server itself.
	if serverHost != "" && host == serverHost {
		return RouteDirect
	}

	// Explicit mode overrides.
	if mode == "direct" {
		return RouteDirect
	}
	if mode == "global" {
		// Always bypass loopback so local dashboard & OS IPC keep working.
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
			return RouteDirect
		}
		if host == "localhost" {
			return RouteDirect
		}
		return RouteProxy
	}

	// "rule" mode: check explicit overrides first, then private/LAN bypass.
	if matchDomainSuffix(host, proxyDomains) {
		return RouteProxy
	}
	if matchDomainSuffix(host, directDomains) {
		return RouteDirect
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return RouteDirect
		}
	}
	return RouteProxy
}
