//go:build darwin

package sysproxy

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func activeMacServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("list network services: %w", err)
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		// Prefer standard active interfaces (Wi-Fi, Ethernet, Thunderbolt, USB)
		info, err := exec.Command("networksetup", "-getinfo", line).Output()
		if err != nil {
			continue
		}
		if strings.Contains(string(info), "IP address:") && !strings.Contains(string(info), "IP address: none") {
			services = append(services, line)
		}
	}
	if len(services) == 0 {
		// Fallback to Wi-Fi if present
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.EqualFold(line, "Wi-Fi") {
				services = append(services, line)
				break
			}
		}
	}
	return services, nil
}

func enablePlatformProxy(host string, port int) ([]string, error) {
	services, err := activeMacServices()
	if err != nil {
		return nil, err
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("no active macOS network services found")
	}
	portStr := strconv.Itoa(port)
	bypass := []string{"127.0.0.1", "localhost", "*.local", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

	var configured []string
	for _, svc := range services {
		cmds := [][]string{
			{"-setwebproxy", svc, host, portStr},
			{"-setwebproxystate", svc, "on"},
			{"-setsecurewebproxy", svc, host, portStr},
			{"-setsecurewebproxystate", svc, "on"},
			{"-setsocksfirewallproxy", svc, host, portStr},
			{"-setsocksfirewallproxystate", svc, "on"},
			append([]string{"-setproxybypassdomains", svc}, bypass...),
		}
		ok := true
		for _, args := range cmds {
			if out, err := exec.Command("networksetup", args...).CombinedOutput(); err != nil {
				ok = false
				_ = out
				break
			}
		}
		if ok {
			configured = append(configured, svc)
		}
	}
	if len(configured) == 0 {
		return nil, fmt.Errorf("failed to configure macOS networksetup proxy")
	}
	return configured, nil
}

func disablePlatformProxy(services []string) error {
	if len(services) == 0 {
		services, _ = activeMacServices()
	}
	var firstErr error
	for _, svc := range services {
		for _, args := range [][]string{
			{"-setwebproxystate", svc, "off"},
			{"-setsecurewebproxystate", svc, "off"},
			{"-setsocksfirewallproxystate", svc, "off"},
		} {
			if err := exec.Command("networksetup", args...).Run(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
