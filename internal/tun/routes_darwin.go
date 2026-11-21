//go:build darwin

package tun

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func defaultIfaceName() string {
	return "utun"
}

func checkPrivileges() error {
	if os.Geteuid() != 0 {
		return errors.New("TUN mode requires root privileges on macOS (run daemon with sudo, or use System Proxy mode without root)")
	}
	return nil
}

func detectDefaultGatewayMac() string {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}
	return ""
}

func configurePlatformRoutes(iface string, mtu int, serverIPs []string) (func(), error) {
	defaultGW := detectDefaultGatewayMac()

	if out, err := exec.Command("ifconfig", iface, "inet", LocalTUNIP, PeerTUNIP, "mtu", strconv.Itoa(mtu), "up").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ifconfig %s up: %v (%s)", iface, err, strings.TrimSpace(string(out)))
	}

	var addedBypass []string
	if defaultGW != "" {
		for _, ip := range serverIPs {
			if err := exec.Command("route", "-n", "add", "-host", ip, defaultGW).Run(); err == nil {
				addedBypass = append(addedBypass, ip)
			}
		}
	}

	if out, err := exec.Command("route", "-n", "add", "-net", "0.0.0.0/1", PeerTUNIP).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("add 0.0.0.0/1 route: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("route", "-n", "add", "-net", "128.0.0.0/1", PeerTUNIP).CombinedOutput(); err != nil {
		_ = exec.Command("route", "-n", "delete", "-net", "0.0.0.0/1", PeerTUNIP).Run()
		return nil, fmt.Errorf("add 128.0.0.0/1 route: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	cleanup := func() {
		_ = exec.Command("route", "-n", "delete", "-net", "0.0.0.0/1", PeerTUNIP).Run()
		_ = exec.Command("route", "-n", "delete", "-net", "128.0.0.0/1", PeerTUNIP).Run()
		for _, ip := range addedBypass {
			_ = exec.Command("route", "-n", "delete", "-host", ip).Run()
		}
	}
	return cleanup, nil
}
