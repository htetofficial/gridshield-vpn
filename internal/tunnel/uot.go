package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/SUDOKU-ASCII/sudoku/pkg/connutil"

	"gridshield/internal/protocol"
)

const (
	maxUoTPayload   = 64 * 1024
	maxUoTPending   = 256 * 1024
	uotDestCacheTTL = 30 * time.Second
)

// UoTWriter coalesces UDP datagrams into framed writes over a reliable tunnel.
type UoTWriter struct {
	w       io.Writer
	onErr   func(error)
	mu      sync.Mutex
	pending []byte
	spare   []byte
	err     error
	sig     chan struct{}
	done    chan struct{}
	once    sync.Once
}

func NewUoTWriter(w io.Writer, onErr func(error)) *UoTWriter {
	u := &UoTWriter{w: w, onErr: onErr, sig: make(chan struct{}, 1), done: make(chan struct{})}
	go u.loop()
	return u
}

func (u *UoTWriter) Close() { u.once.Do(func() { close(u.done) }) }

func (u *UoTWriter) loop() {
	for {
		select {
		case <-u.sig:
		case <-u.done:
			return
		}
		for {
			u.mu.Lock()
			buf := u.pending
			if len(buf) == 0 {
				u.mu.Unlock()
				break
			}
			u.pending = u.spare[:0]
			u.spare = nil
			u.mu.Unlock()

			err := connutil.WriteFull(u.w, buf)

			u.mu.Lock()
			if cap(buf) <= 1<<20 {
				u.spare = buf[:0]
			}
			if err != nil {
				u.err = err
				u.pending = nil
			}
			u.mu.Unlock()

			if err != nil {
				if u.onErr != nil {
					u.onErr(err)
				}
				return
			}
		}
	}
}

func (u *UoTWriter) enqueue(appendAddr func([]byte) ([]byte, error), payload []byte) error {
	if len(payload) > int(^uint16(0)) {
		return fmt.Errorf("uot payload too large: %d", len(payload))
	}
	u.mu.Lock()
	if u.err != nil {
		err := u.err
		u.mu.Unlock()
		return err
	}
	if len(u.pending) >= maxUoTPending {
		u.mu.Unlock()
		return nil
	}
	start := len(u.pending)
	buf := append(u.pending, 0, 0, 0, 0)
	buf, err := appendAddr(buf)
	if err != nil {
		u.pending = buf[:start]
		u.mu.Unlock()
		return err
	}
	binary.BigEndian.PutUint16(buf[start:], uint16(len(buf)-start-4))
	binary.BigEndian.PutUint16(buf[start+2:], uint16(len(payload)))
	u.pending = append(buf, payload...)
	u.mu.Unlock()

	select {
	case u.sig <- struct{}{}:
	default:
	}
	return nil
}

func (u *UoTWriter) WriteDatagram(addr string, payload []byte) error {
	return u.enqueue(func(b []byte) ([]byte, error) { return protocol.AppendAddress(b, addr) }, payload)
}

func (u *UoTWriter) WriteAddrPort(ap netip.AddrPort, payload []byte) error {
	return u.enqueue(func(b []byte) ([]byte, error) { return protocol.AppendAddrPort(b, ap), nil }, payload)
}

// UoTReader decodes length-prefixed UoT datagrams reusing an internal buffer.
type UoTReader struct {
	r      io.Reader
	header [4]byte
	buf    []byte
}

func NewUoTReader(r io.Reader) *UoTReader { return &UoTReader{r: r} }

func (u *UoTReader) next() (addrBytes, payload []byte, err error) {
	if _, err := io.ReadFull(u.r, u.header[:]); err != nil {
		return nil, nil, err
	}
	addrLen := int(binary.BigEndian.Uint16(u.header[:2]))
	payloadLen := int(binary.BigEndian.Uint16(u.header[2:]))
	if addrLen == 0 {
		return nil, nil, fmt.Errorf("invalid uot addr len 0")
	}
	n := addrLen + payloadLen
	if cap(u.buf) < n {
		u.buf = make([]byte, max(n, 2048))
	}
	body := u.buf[:n]
	if _, err := io.ReadFull(u.r, body); err != nil {
		return nil, nil, err
	}
	return body[:addrLen], body[addrLen:], nil
}

func (u *UoTReader) ReadDatagram() (string, []byte, error) {
	addrBytes, payload, err := u.next()
	if err != nil {
		return "", nil, err
	}
	addr, err := protocol.DecodeAddress(addrBytes)
	if err != nil {
		return "", nil, err
	}
	return addr, payload, nil
}

// HandleUoTServer relays UDP datagrams from a KIP UoT tunnel stream to target UDP endpoints.
func HandleUoTServer(conn net.Conn) error {
	pConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	errCh := make(chan error, 1)
	var once sync.Once
	closeAll := func(err error) {
		once.Do(func() {
			_ = conn.Close()
			_ = pConn.Close()
			errCh <- err
		})
	}

	uw := NewUoTWriter(conn, closeAll)
	defer uw.Close()

	go func() {
		buf := make([]byte, maxUoTPayload)
		for {
			n, ap, err := pConn.ReadFromUDPAddrPort(buf)
			if err != nil {
				closeAll(err)
				return
			}
			if err := uw.WriteAddrPort(ap, buf[:n]); err != nil {
				closeAll(err)
				return
			}
		}
	}()

	go func() {
		fr := NewUoTReader(conn)
		type entry struct {
			ap  netip.AddrPort
			exp time.Time
		}
		cache := make(map[string]entry)
		for {
			addrBytes, payload, err := fr.next()
			if err != nil {
				closeAll(err)
				return
			}
			addrStr, err := protocol.DecodeAddress(addrBytes)
			if err != nil {
				continue
			}
			var ap netip.AddrPort
			if parsed, err := netip.ParseAddrPort(addrStr); err == nil {
				ap = parsed
			} else {
				now := time.Now()
				if e, ok := cache[addrStr]; ok && now.Before(e.exp) {
					ap = e.ap
				} else {
					udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
					if err != nil {
						continue
					}
					ap = udpAddr.AddrPort()
					if len(cache) > 256 {
						clear(cache)
					}
					cache[addrStr] = entry{ap: ap, exp: now.Add(uotDestCacheTTL)}
				}
			}
			if _, err := pConn.WriteToUDPAddrPort(payload, ap); err != nil {
				closeAll(err)
				return
			}
		}
	}()

	return <-errCh
}
