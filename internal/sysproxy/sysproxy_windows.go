//go:build windows

package sysproxy

import (
	"fmt"
	"os/exec"
)

const regKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func enablePlatformProxy(host string, port int) ([]string, error) {
	proxyServer := fmt.Sprintf("http=%s:%d;https=%s:%d;socks=%s:%d", host, port, host, port, host, port)
	cmds := [][]string{
		{"add", regKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"},
		{"add", regKey, "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxyServer, "/f"},
		{"add", regKey, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "localhost;127.*;10.*;192.168.*;<local>", "/f"},
	}
	for _, args := range cmds {
		if err := exec.Command("reg", args...).Run(); err != nil {
			return nil, fmt.Errorf("reg %v: %w", args, err)
		}
	}
	return []string{"windows-inet"}, nil
}

func disablePlatformProxy(_ []string) error {
	return exec.Command("reg", "add", regKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f").Run()
}
