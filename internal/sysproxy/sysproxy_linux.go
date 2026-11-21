//go:build linux

package sysproxy

import (
	"fmt"
	"os/exec"
	"strconv"
)

func enablePlatformProxy(host string, port int) ([]string, error) {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return nil, fmt.Errorf("gsettings not found; export http_proxy=http://%s:%d ALL_PROXY=socks5://%s:%d", host, port, host, port)
	}
	portStr := strconv.Itoa(port)
	cmds := [][]string{
		{"set", "org.gnome.system.proxy", "mode", "manual"},
		{"set", "org.gnome.system.proxy.http", "host", host},
		{"set", "org.gnome.system.proxy.http", "port", portStr},
		{"set", "org.gnome.system.proxy.https", "host", host},
		{"set", "org.gnome.system.proxy.https", "port", portStr},
		{"set", "org.gnome.system.proxy.socks", "host", host},
		{"set", "org.gnome.system.proxy.socks", "port", portStr},
	}
	for _, args := range cmds {
		if err := exec.Command("gsettings", args...).Run(); err != nil {
			return nil, fmt.Errorf("gsettings %v: %w", args, err)
		}
	}
	return []string{"gnome-desktop"}, nil
}

func disablePlatformProxy(_ []string) error {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return nil
	}
	return exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
}
