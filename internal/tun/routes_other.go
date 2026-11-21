//go:build !darwin && !linux

package tun

import (
	"fmt"
	"os/exec"
)

func defaultIfaceName() string {
	return "GridShield"
}

func checkPrivileges() error {
	return nil
}

func configurePlatformRoutes(iface string, _ int, _ []string) (func(), error) {
	if out, err := exec.Command("netsh", "interface", "ip", "set", "address", "name="+iface, "source=static", "addr="+LocalTUNIP, "mask=255.255.255.252", "gateway="+PeerTUNIP).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("configure windows tun interface %s (run as Administrator): %v (%s)", iface, err, string(out))
	}
	cleanup := func() {}
	return cleanup, nil
}
