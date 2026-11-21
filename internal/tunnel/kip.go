package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/SUDOKU-ASCII/sudoku/pkg/connutil"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku"

	"gridshield/internal/protocol"
)

const (
	kipMagic = "kip"

	KIPTypeClientHello byte = 0x01
	KIPTypeServerHello byte = 0x02

	KIPTypeOpenTCP   byte = 0x10
	KIPTypeStartMux  byte = 0x11
	KIPTypeStartUoT  byte = 0x12
	KIPTypeStartRev  byte = 0x13
	KIPTypeKeepAlive byte = 0x14

	KIPFeatOpenTCP   uint32 = 1 << 0
	KIPFeatMux       uint32 = 1 << 1
	KIPFeatUoT       uint32 = 1 << 2
	KIPFeatReverse   uint32 = 1 << 3
	KIPFeatKeepAlive uint32 = 1 << 4
	KIPFeatAll              = KIPFeatOpenTCP | KIPFeatMux | KIPFeatUoT | KIPFeatReverse | KIPFeatKeepAlive

	kipHelloUserHashSize        = 8
	kipHelloNonceSize           = 16
	kipHelloPubSize             = 32
	kipClientHelloTableHintSize = 4
	kipMaxPayload               = 64 * 1024
	kipHeaderSize               = len(kipMagic) + 1 + 2
	kipHandshakeSkew            = 60 * time.Second
)

var errKIP = errors.New("kip protocol error")

type KIPMessage struct {
	Type    byte
	Payload []byte
}

func appendKIPHeader(dst []byte, typ byte, payloadLen int) []byte {
	dst = append(dst, kipMagic...)
	dst = append(dst, typ)
	return binary.BigEndian.AppendUint16(dst, uint16(payloadLen))
}

func WriteKIPOpenTCP(w io.Writer, addr string) error {
	buf := appendKIPHeader(make([]byte, 0, kipHeaderSize+protocol.MaxEncodedAddrLen), KIPTypeOpenTCP, 0)
	var err error
	buf, err = protocol.AppendAddress(buf, addr)
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}
	binary.BigEndian.PutUint16(buf[kipHeaderSize-2:], uint16(len(buf)-kipHeaderSize))
	return connutil.WriteFull(w, buf)
}

func WriteKIPMessage(w io.Writer, typ byte, payload []byte) error {
	if w == nil {
		return fmt.Errorf("%w: nil writer", errKIP)
	}
	if len(payload) > kipMaxPayload {
		return fmt.Errorf("%w: payload too large: %d", errKIP, len(payload))
	}
	buf := appendKIPHeader(make([]byte, 0, kipHeaderSize+len(payload)), typ, len(payload))
	return connutil.WriteFull(w, append(buf, payload...))
}

func ReadKIPMessage(r io.Reader) (*KIPMessage, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", errKIP)
	}
	var hdr [kipHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if string(hdr[:3]) != kipMagic {
		return nil, fmt.Errorf("%w: bad magic", errKIP)
	}
	typ := hdr[3]
	n := int(binary.BigEndian.Uint16(hdr[4:]))
	if n < 0 || n > kipMaxPayload {
		return nil, fmt.Errorf("%w: invalid payload len %d", errKIP, n)
	}
	var payload []byte
	if n > 0 {
		payload = make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return &KIPMessage{Type: typ, Payload: payload}, nil
}

type KIPClientHello struct {
	Timestamp    time.Time
	UserHash     [kipHelloUserHashSize]byte
	Nonce        [kipHelloNonceSize]byte
	ClientPub    [kipHelloPubSize]byte
	Features     uint32
	TableHint    uint32
	HasTableHint bool
}

type KIPServerHello struct {
	Nonce         [kipHelloNonceSize]byte
	ServerPub     [kipHelloPubSize]byte
	SelectedFeats uint32
}

func kipUserHashFromPrivateKey(privateKey []byte, fallbackPSK string) [kipHelloUserHashSize]byte {
	var out [kipHelloUserHashSize]byte
	if len(privateKey) > 0 {
		h := sha256.Sum256(privateKey)
		copy(out[:], h[:kipHelloUserHashSize])
		return out
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(fallbackPSK)))
	copy(out[:], h[:kipHelloUserHashSize])
	return out
}

func (m *KIPClientHello) EncodePayload() []byte {
	var b bytes.Buffer
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(m.Timestamp.Unix()))
	b.Write(tmp[:])
	b.Write(m.UserHash[:])
	b.Write(m.Nonce[:])
	b.Write(m.ClientPub[:])
	var f [4]byte
	binary.BigEndian.PutUint32(f[:], m.Features)
	b.Write(f[:])
	if m.HasTableHint {
		var hint [kipClientHelloTableHintSize]byte
		binary.BigEndian.PutUint32(hint[:], m.TableHint)
		b.Write(hint[:])
	}
	return b.Bytes()
}

func DecodeKIPClientHelloPayload(payload []byte) (*KIPClientHello, error) {
	const minLen = 8 + kipHelloUserHashSize + kipHelloNonceSize + kipHelloPubSize + 4
	if len(payload) < minLen {
		return nil, fmt.Errorf("%w: client hello too short", errKIP)
	}
	var h KIPClientHello
	h.Timestamp = time.Unix(int64(binary.BigEndian.Uint64(payload[:8])), 0)
	off := 8
	copy(h.UserHash[:], payload[off:off+kipHelloUserHashSize])
	off += kipHelloUserHashSize
	copy(h.Nonce[:], payload[off:off+kipHelloNonceSize])
	off += kipHelloNonceSize
	copy(h.ClientPub[:], payload[off:off+kipHelloPubSize])
	off += kipHelloPubSize
	h.Features = binary.BigEndian.Uint32(payload[off : off+4])
	off += 4
	if len(payload) >= off+kipClientHelloTableHintSize {
		h.TableHint = binary.BigEndian.Uint32(payload[off : off+kipClientHelloTableHintSize])
		h.HasTableHint = true
	}
	return &h, nil
}

func (m *KIPServerHello) EncodePayload() []byte {
	var b bytes.Buffer
	b.Write(m.Nonce[:])
	b.Write(m.ServerPub[:])
	var f [4]byte
	binary.BigEndian.PutUint32(f[:], m.SelectedFeats)
	b.Write(f[:])
	return b.Bytes()
}

func DecodeKIPServerHelloPayload(payload []byte) (*KIPServerHello, error) {
	const want = kipHelloNonceSize + kipHelloPubSize + 4
	if len(payload) != want {
		return nil, fmt.Errorf("%w: server hello bad len %d", errKIP, len(payload))
	}
	var h KIPServerHello
	copy(h.Nonce[:], payload[:kipHelloNonceSize])
	off := kipHelloNonceSize
	copy(h.ServerPub[:], payload[off:off+kipHelloPubSize])
	off += kipHelloPubSize
	h.SelectedFeats = binary.BigEndian.Uint32(payload[off : off+4])
	return &h, nil
}

type ReplayAllowFunc func(userHash string, nonce [kipHelloNonceSize]byte, now time.Time) bool

func newClientHello(userHash [kipHelloUserHashSize]byte, feats, tableHint uint32, hasTableHint bool) (*KIPClientHello, *ecdh.PrivateKey, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdh generate: %w", err)
	}
	ch := &KIPClientHello{
		Timestamp:    time.Now(),
		UserHash:     userHash,
		Features:     feats,
		TableHint:    tableHint,
		HasTableHint: hasTableHint,
	}
	if _, err := io.ReadFull(rand.Reader, ch.Nonce[:]); err != nil {
		return nil, nil, fmt.Errorf("nonce generate: %w", err)
	}
	copy(ch.ClientPub[:], ephemeral.PublicKey().Bytes())
	return ch, ephemeral, nil
}

func readClientHello(r io.Reader) (*KIPClientHello, error) {
	msg, err := ReadKIPMessage(r)
	if err != nil {
		return nil, fmt.Errorf("read client hello: %w", err)
	}
	if msg.Type != KIPTypeClientHello {
		return nil, fmt.Errorf("unexpected handshake msg type: %d", msg.Type)
	}
	return DecodeKIPClientHelloPayload(msg.Payload)
}

func readServerHello(r io.Reader) (*KIPServerHello, error) {
	msg, err := ReadKIPMessage(r)
	if err != nil {
		return nil, fmt.Errorf("read server hello: %w", err)
	}
	if msg.Type != KIPTypeServerHello {
		return nil, fmt.Errorf("unexpected handshake msg type: %d", msg.Type)
	}
	return DecodeKIPServerHelloPayload(msg.Payload)
}

func checkClientHelloSkew(ch *KIPClientHello, now time.Time) error {
	diff := now.Unix() - ch.Timestamp.Unix()
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(kipHandshakeSkew.Seconds()) {
		return errors.New("handshake time skew/replay")
	}
	return nil
}

func deriveClientSession(psk string, ephemeral *ecdh.PrivateKey, nonce [kipHelloNonceSize]byte, sh *KIPServerHello) (c2s, s2c []byte, err error) {
	if sh.Nonce != nonce {
		return nil, nil, errors.New("handshake nonce mismatch")
	}
	shared, err := x25519SharedSecret(ephemeral, sh.ServerPub[:])
	if err != nil {
		return nil, nil, err
	}
	return deriveSessionDirectionalBases(psk, shared, nonce)
}

type acceptedHello struct {
	userHash string
	table    *sudoku.Table
	reply    *KIPServerHello
	c2s, s2c []byte
}

func resolveClientHelloTable(selected *sudoku.Table, candidates []*sudoku.Table, hello *KIPClientHello) (*sudoku.Table, error) {
	if selected == nil {
		return nil, errors.New("nil selected table")
	}
	if hello == nil || !hello.HasTableHint || selected.Hint() == hello.TableHint {
		return selected, nil
	}
	for _, c := range candidates {
		if c != nil && c.Hint() == hello.TableHint {
			if c != selected && (!c.IsASCII || !selected.IsASCII) {
				return nil, fmt.Errorf("table hint %d mismatches probed uplink table", hello.TableHint)
			}
			return c, nil
		}
	}
	return nil, fmt.Errorf("unknown table hint %d", hello.TableHint)
}

func acceptClientHello(ch *KIPClientHello, psk string, probed *sudoku.Table, tables []*sudoku.Table, allow ReplayAllowFunc) (*acceptedHello, error) {
	now := time.Now()
	if err := checkClientHelloSkew(ch, now); err != nil {
		return nil, err
	}
	userHash := hex.EncodeToString(ch.UserHash[:])
	if allow != nil && !allow(userHash, ch.Nonce, now) {
		return nil, errors.New("handshake replay detected")
	}
	table, err := resolveClientHelloTable(probed, tables, ch)
	if err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdh generate: %w", err)
	}
	shared, err := x25519SharedSecret(ephemeral, ch.ClientPub[:])
	if err != nil {
		return nil, err
	}
	c2s, s2c, err := deriveSessionDirectionalBases(psk, shared, ch.Nonce)
	if err != nil {
		return nil, err
	}
	reply := &KIPServerHello{Nonce: ch.Nonce, SelectedFeats: ch.Features}
	copy(reply.ServerPub[:], ephemeral.PublicKey().Bytes())
	return &acceptedHello{userHash: userHash, table: table, reply: reply, c2s: c2s, s2c: s2c}, nil
}
