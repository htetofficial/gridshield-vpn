package config

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/SUDOKU-ASCII/sudoku/pkg/crypto"
)

// KeyBundle holds an Ed25519 master/split key set compatible with SUDOKU-ASCII/sudoku.
type KeyBundle struct {
	AvailablePrivateKey string `json:"available_private_key"`
	MasterPrivateKey    string `json:"master_private_key"`
	MasterPublicKey     string `json:"master_public_key"`
}

// GenerateKeys creates a new Ed25519 master keypair and an initial split private key for clients.
func GenerateKeys() (*KeyBundle, error) {
	pair, err := crypto.GenerateMasterKey()
	if err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	splitKey, err := crypto.SplitPrivateKey(pair.Private)
	if err != nil {
		return nil, fmt.Errorf("split private key: %w", err)
	}
	return &KeyBundle{
		AvailablePrivateKey: splitKey,
		MasterPrivateKey:    crypto.EncodeScalar(pair.Private),
		MasterPublicKey:     crypto.EncodePoint(pair.Public),
	}, nil
}

// SplitKey derives a new split client key from a master private key or existing split key.
func SplitKey(existingPrivateHex string) (string, error) {
	scalar, err := crypto.ParsePrivateScalar(strings.TrimSpace(existingPrivateHex))
	if err != nil {
		return "", err
	}
	return crypto.SplitPrivateKey(scalar)
}

// NormalizeClientKey recovers the server Master Public Key (used as PSK/table seed) from
// a client's Available Private Key (64-byte split or 32-byte master scalar).
// If key is already a plain PSK or public key, it returns (key, nil, false).
func NormalizeClientKey(rawKey string) (tableKey string, privateKeyBytes []byte, isPrivate bool) {
	rawKey = strings.TrimSpace(rawKey)
	pubPoint, err := crypto.RecoverPublicKey(rawKey)
	if err != nil {
		return rawKey, nil, false
	}
	privBytes, err := hex.DecodeString(rawKey)
	if err != nil {
		return rawKey, nil, false
	}
	return crypto.EncodePoint(pubPoint), privBytes, true
}

// shortLinkPayload matches official SUDOKU-ASCII/sudoku sudoku:// JSON schema.
type shortLinkPayload struct {
	Name            string   `json:"n,omitempty"`
	Host            string   `json:"h"`
	Port            int      `json:"p"`
	Key             string   `json:"k"`
	ASCII           string   `json:"a,omitempty"`
	AEAD            string   `json:"e,omitempty"`
	MixPort         int      `json:"m,omitempty"`
	PackedDownlink  bool     `json:"x,omitempty"`
	CustomTable     string   `json:"t,omitempty"`
	CustomTables    []string `json:"ts,omitempty"`
	DisableHTTPMask bool     `json:"hd,omitempty"`
	HTTPMaskMode    string   `json:"hm,omitempty"`
	HTTPMaskTLS     bool     `json:"ht,omitempty"`
	HTTPMaskHost    string   `json:"hh,omitempty"`
	HTTPMaskMux     string   `json:"hx,omitempty"`
	HTTPMaskPath    string   `json:"hy,omitempty"`
}

func encodeShortLinkASCII(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "prefer_ascii", "ascii":
		return "ascii"
	case "prefer_entropy", "entropy", "":
		return "entropy"
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func decodeShortLinkASCII(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ascii", "prefer_ascii":
		return "prefer_ascii"
	case "entropy", "prefer_entropy", "":
		return "prefer_entropy"
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

// ExportShortLink encodes a Profile into a standard sudoku:// share link.
func ExportShortLink(p Profile, mixPort int) (string, error) {
	p.Normalize()
	if err := p.Validate(); err != nil {
		return "", err
	}
	host, portStr, err := net.SplitHostPort(p.ServerAddress)
	if err != nil {
		return "", fmt.Errorf("invalid server_address %q: %w", p.ServerAddress, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid server port %q", portStr)
	}
	if mixPort <= 0 {
		mixPort = 10808
	}

	payload := shortLinkPayload{
		Name:            strings.TrimSpace(p.Name),
		Host:            host,
		Port:            port,
		Key:             p.Key,
		ASCII:           encodeShortLinkASCII(p.ASCII),
		AEAD:            p.AEAD,
		MixPort:         mixPort,
		PackedDownlink:  !p.EnablePureDownlink,
		CustomTable:     p.CustomTable,
		DisableHTTPMask: p.HTTPMask.Disable,
		HTTPMaskTLS:     p.HTTPMask.TLS,
		HTTPMaskHost:    strings.TrimSpace(p.HTTPMask.Host),
		HTTPMaskPath:    strings.TrimSpace(p.HTTPMask.PathRoot),
	}
	if len(p.CustomTables) > 0 {
		payload.CustomTables = append([]string(nil), p.CustomTables...)
	}
	if mode := strings.ToLower(strings.TrimSpace(p.HTTPMask.Mode)); mode != "" && mode != "legacy" {
		payload.HTTPMaskMode = mode
	}
	if mux := strings.ToLower(strings.TrimSpace(p.Multiplex)); mux != "" && mux != "off" {
		payload.HTTPMaskMux = mux
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return "sudoku://" + base64.RawURLEncoding.EncodeToString(data), nil
}

// ImportShortLink parses a standard sudoku:// share link into a Profile.
func ImportShortLink(link string) (Profile, error) {
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, "sudoku://") {
		return Profile{}, errors.New("link must start with sudoku://")
	}
	encoded := strings.TrimPrefix(link, "sudoku://")
	encoded = strings.TrimRight(encoded, "=")
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Profile{}, fmt.Errorf("invalid base64 payload: %w", err)
	}

	var payload shortLinkPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return Profile{}, fmt.Errorf("invalid JSON payload: %w", err)
	}
	if payload.Host == "" || payload.Port <= 0 || payload.Port > 65535 || payload.Key == "" {
		return Profile{}, errors.New("short link missing required host, port, or key")
	}

	mode := strings.ToLower(strings.TrimSpace(payload.HTTPMaskMode))
	if mode == "" {
		mode = "legacy"
	}
	mux := strings.ToLower(strings.TrimSpace(payload.HTTPMaskMux))
	if mux == "" {
		mux = "off"
	}

	p := Profile{
		ID:                 NewID(),
		Name:               payload.Name,
		ServerAddress:      net.JoinHostPort(payload.Host, strconv.Itoa(payload.Port)),
		Key:                payload.Key,
		AEAD:               payload.AEAD,
		ASCII:              decodeShortLinkASCII(payload.ASCII),
		PaddingMin:         5,
		PaddingMax:         15,
		EnablePureDownlink: !payload.PackedDownlink,
		CustomTable:        payload.CustomTable,
		CustomTables:       append([]string(nil), payload.CustomTables...),
		Multiplex:          mux,
		HTTPMask: HTTPMaskConfig{
			Disable:  payload.DisableHTTPMask,
			Mode:     mode,
			TLS:      payload.HTTPMaskTLS,
			Host:     payload.HTTPMaskHost,
			PathRoot: payload.HTTPMaskPath,
		},
	}
	p.Normalize()
	return p, nil
}
