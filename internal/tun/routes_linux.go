//go:build linux

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
	return "gridshield0"
}

func checkPrivileges() error {
	if os.Geteuid() != 0 {
		return errors.New("TUN mode requires root / CAP_NET_ADMIN privileges on Linux (run with sudo, or use System Proxy mode)")
	}
	return nil
}

func detectDefaultGatewayLinux() (gw, dev string) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", ""
	}
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "via" && gw == "" {
			gw = fields[i+1]
		}
		if fields[i] == "dev" && dev == "" {
			dev = fields[i+1]
		}
	}
	return gw, dev
}

func configurePlatformRoutes(iface string, mtu int, serverIPs []string) (func(), error) {
	gw, dev := detectDefaultGatewayLinux()

	if out, err := exec.Command("ip", "addr", "add", LocalTUNIP+"/30", "dev", iface).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip addr add: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "link", "set", "dev", iface, "mtu", strconv.Itoa(mtu), "up").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip link set up: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	var addedBypass []string
	if gw != "" && dev != "" {
		for _, ip := range serverIPs {
			if err := exec.Command("ip", "route", "add", ip+"/32", "via", gw, "dev", dev).Run(); err == nil {
				addedBypass = append(addedBypass, ip)
			}
		}
	}

	if out, err := exec.Command("ip", "route", "add", "0.0.0.0/1", "dev", iface).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip route add 0/1: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "route", "add", "128.0.0.0/1", "dev", iface).CombinedOutput(); err != nil {
		_ = exec.Command("ip", "route", "del", "0.0.0.0/1", "dev", iface).Run()
		return nil, fmt.Errorf("ip route add 128/1: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	cleanup := func() {
		_ = exec.Command("ip", "route", "del", "0.0.0.0/1", "dev", iface).Run()
		_ = exec.Command("ip", "route", "del", "128.0.0.0/1", "dev", iface).Run()
		for _, ip := range addedBypass {
			_ = exec.Command("ip", "route", "del", ip+"/32").Run()
		}
	}
	return cleanup, nil
}
