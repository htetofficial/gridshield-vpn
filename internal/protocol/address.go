package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	AddrTypeIPv4   byte = 0x01
	AddrTypeDomain byte = 0x03
	AddrTypeIPv6   byte = 0x04

	MaxEncodedAddrLen = 1 + 1 + 255 + 2
)

var errEmptyDomain = errors.New("empty domain")

// AppendAddress encodes "host:port" in Sudoku/SOCKS wire format and appends it to dst.
func AppendAddress(dst []byte, rawAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(rawAddr)
	if err != nil {
		return dst, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return dst, fmt.Errorf("invalid port: %q", portStr)
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}

	if ip, ok := parseIPLiteral(host); ok {
		return AppendAddrPort(dst, netip.AddrPortFrom(ip, uint16(port))), nil
	}
	if len(host) == 0 {
		return dst, errEmptyDomain
	}
	if len(host) > 255 {
		return dst, errors.New("domain too long")
	}
	dst = append(dst, AddrTypeDomain, byte(len(host)))
	dst = append(dst, host...)
	return binary.BigEndian.AppendUint16(dst, uint16(port)), nil
}

// AppendAddrPort appends an IPv4/IPv6 AddrPort to dst in wire format.
func AppendAddrPort(dst []byte, ap netip.AddrPort) []byte {
	if ip := ap.Addr().Unmap(); ip.Is4() {
		v := ip.As4()
		dst = append(dst, AddrTypeIPv4)
		dst = append(dst, v[:]...)
	} else {
		v := ip.As16()
		dst = append(dst, AddrTypeIPv6)
		dst = append(dst, v[:]...)
	}
	return binary.BigEndian.AppendUint16(dst, ap.Port())
}

func parseIPLiteral(host string) (netip.Addr, bool) {
	if strings.IndexByte(host, ':') < 0 {
		for i := 0; i < len(host); i++ {
			if c := host[i]; (c < '0' || c > '9') && c != '.' {
				return netip.Addr{}, false
			}
		}
	}
	ip, err := netip.ParseAddr(host)
	return ip, err == nil
}

// WriteAddress writes an encoded address to w in a single Write call.
func WriteAddress(w io.Writer, rawAddr string) error {
	var buf [MaxEncodedAddrLen]byte
	b, err := AppendAddress(buf[:0], rawAddr)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// DecodeAddress decodes a single address prefix from b as "host:port".
func DecodeAddress(b []byte) (string, error) {
	if len(b) == 0 {
		return "", io.EOF
	}
	switch b[0] {
	case AddrTypeIPv4:
		if len(b) < 1+4+2 {
			return "", io.ErrUnexpectedEOF
		}
		ip := netip.AddrFrom4([4]byte(b[1:5]))
		return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[5:7])).String(), nil
	case AddrTypeIPv6:
		if len(b) < 1+16+2 {
			return "", io.ErrUnexpectedEOF
		}
		ip := netip.AddrFrom16([16]byte(b[1:17])).Unmap()
		return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[17:19])).String(), nil
	case AddrTypeDomain:
		if len(b) < 2 {
			return "", io.ErrUnexpectedEOF
		}
		n := int(b[1])
		if n == 0 {
			return "", errEmptyDomain
		}
		if len(b) < 2+n+2 {
			return "", io.ErrUnexpectedEOF
		}
		return joinDomainPort(b[2:2+n], binary.BigEndian.Uint16(b[2+n:])), nil
	default:
		return "", fmt.Errorf("unknown address type: %d", b[0])
	}
}

func joinDomainPort(host []byte, port uint16) string {
	var sb strings.Builder
	sb.Grow(len(host) + 8)
	bracket := bytes.IndexByte(host, ':') >= 0
	if bracket {
		sb.WriteByte('[')
	}
	sb.Write(host)
	if bracket {
		sb.WriteByte(']')
	}
	sb.WriteByte(':')
	var digits [5]byte
	sb.Write(strconv.AppendUint(digits[:0], uint64(port), 10))
	return sb.String()
}

// ReadAddress reads one wire-encoded address from r.
func ReadAddress(r io.Reader) (string, byte, net.IP, error) {
	var buf [MaxEncodedAddrLen]byte
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return "", 0, nil, err
	}
	n := 1
	var hostLen int
	switch buf[0] {
	case AddrTypeIPv4:
		hostLen = 4
	case AddrTypeIPv6:
		hostLen = 16
	case AddrTypeDomain:
		if _, err := io.ReadFull(r, buf[1:2]); err != nil {
			return "", 0, nil, err
		}
		n = 2
		if hostLen = int(buf[1]); hostLen == 0 {
			return "", 0, nil, errEmptyDomain
		}
	default:
		return "", 0, nil, fmt.Errorf("unknown address type: %d", buf[0])
	}
	if _, err := io.ReadFull(r, buf[n:n+hostLen]); err != nil {
		return "", 0, nil, err
	}
	n += hostLen
	if _, err := io.ReadFull(r, buf[n:n+2]); err != nil {
		return "", 0, nil, err
	}
	n += 2

	addr, err := DecodeAddress(buf[:n])
	if err != nil {
		return "", 0, nil, err
	}
	var ip net.IP
	if buf[0] != AddrTypeDomain {
		ip = append(net.IP(nil), buf[1:1+hostLen]...)
	}
	return addr, buf[0], ip, nil
}
