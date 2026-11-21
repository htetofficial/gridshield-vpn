package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gridshield/internal/config"
	"gridshield/internal/engine"
	"gridshield/internal/protocol"
	"gridshield/internal/server"
	"gridshield/internal/tunnel"
	"gridshield/internal/web"
)

func TestKeyGenAndShortLinkRoundTrip(t *testing.T) {
	keys, err := config.GenerateKeys()
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	pubFromSplit, privBytes, isPriv := config.NormalizeClientKey(keys.AvailablePrivateKey)
	if !isPriv || len(privBytes) != 64 {
		t.Fatalf("expected 64-byte split private key, got isPriv=%v len=%d", isPriv, len(privBytes))
	}
	if pubFromSplit != keys.MasterPublicKey {
		t.Fatalf("recovered public key mismatch:\n got %s\nwant %s", pubFromSplit, keys.MasterPublicKey)
	}

	split2, err := config.SplitKey(keys.MasterPrivateKey)
	if err != nil {
		t.Fatalf("SplitKey: %v", err)
	}
	pub2, _, _ := config.NormalizeClientKey(split2)
	if pub2 != keys.MasterPublicKey {
		t.Fatalf("second split key did not recover master public key")
	}

	orig := config.Profile{
		Name:               "SG-Sudoku-01",
		ServerAddress:      "203.0.113.10:8443",
		Key:                keys.AvailablePrivateKey,
		AEAD:               "chacha20-poly1305",
		ASCII:              "up_ascii_down_entropy",
		EnablePureDownlink: false,
		CustomTable:        "xpxvvpvv",
		Multiplex:          "auto",
		HTTPMask: config.HTTPMaskConfig{
			Disable:  false,
			Mode:     "ws",
			TLS:      true,
			Host:     "cdn.example.com",
			PathRoot: "aabbcc",
		},
	}
	link, err := config.ExportShortLink(orig, 10808)
	if err != nil {
		t.Fatalf("ExportShortLink: %v", err)
	}
	if !strings.HasPrefix(link, "sudoku://") {
		t.Fatalf("unexpected short link prefix: %s", link)
	}

	parsed, err := config.ImportShortLink(link)
	if err != nil {
		t.Fatalf("ImportShortLink: %v", err)
	}
	if parsed.Name != orig.Name || parsed.ServerAddress != orig.ServerAddress || parsed.Key != orig.Key {
		t.Fatalf("round-trip core fields mismatch: got %+v", parsed)
	}
	if parsed.ASCII != orig.ASCII || parsed.EnablePureDownlink != orig.EnablePureDownlink || parsed.HTTPMask.Mode != "ws" || !parsed.HTTPMask.TLS || parsed.HTTPMask.PathRoot != "aabbcc" {
		t.Fatalf("round-trip protocol fields mismatch: got %+v", parsed)
	}
}

func TestEndToEndSelfTestModes(t *testing.T) {
	store, err := config.LoadStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	mgr := engine.NewManager(store)
	defer mgr.Shutdown()

	cases := []struct {
		ascii    string
		aead     string
		httpmask string
	}{
		{"prefer_ascii", "chacha20-poly1305", "auto"},
		{"prefer_entropy", "aes-128-gcm", "ws"},
		{"prefer_ascii", "chacha20-poly1305", "legacy"},
		{"prefer_entropy", "chacha20-poly1305", "none"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_%s_%s", tc.ascii, tc.aead, tc.httpmask), func(t *testing.T) {
			res := mgr.RunSelfTest(tc.ascii, tc.aead, tc.httpmask)
			if !res.OK {
				t.Fatalf("selftest failed: %s", res.Error)
			}
			if res.BytesEchoed != 512*1024 {
				t.Fatalf("unexpected bytes echoed: %d", res.BytesEchoed)
			}
		})
	}
}

func TestUoTAndMixedProxyAndDecoyFallback(t *testing.T) {
	store, err := config.LoadStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	mgr := engine.NewManager(store)
	defer mgr.Shutdown()

	// 1. Decoy HTTP server for anti-probing fallback test
	decoyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen decoy: %v", err)
	}
	defer decoyLn.Close()
	decoySrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "DECOY_OK")
	})}
	go func() { _ = decoySrv.Serve(decoyLn) }()
	defer decoySrv.Close()

	// 2. UDP echo server for UoT test
	udpSrv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpSrv.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udpSrv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpSrv.WriteToUDP(append([]byte("ECHO:"), buf[:n]...), addr)
		}
	}()

	// 3. Sudoku VPN Server with decoy fallback enabled
	keys, err := config.GenerateKeys()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	srvPort := tmpLn.Addr().(*net.TCPAddr).Port
	_ = tmpLn.Close()

	srvCfg := config.ServerConfig{
		ListenPort:         srvPort,
		Key:                keys.MasterPublicKey,
		AEAD:               "chacha20-poly1305",
		ASCII:              "prefer_entropy",
		PaddingMin:         5,
		PaddingMax:         15,
		EnablePureDownlink: true,
		SuspiciousAction:   "fallback",
		FallbackAddress:    decoyLn.Addr().String(),
		HTTPMask:           config.HTTPMaskConfig{Disable: false, Mode: "legacy"},
	}
	srv, err := server.New(srvCfg, mgr.Tracker)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer srv.Close()

	// Test A: Unauthorized HTTP probe hits Sudoku server -> falls back to Decoy transparently!
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", srvPort))
	if err != nil {
		t.Fatalf("decoy probe failed: %v", err)
	}
	decoyBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(decoyBody) != "DECOY_OK" {
		t.Fatalf("expected DECOY_OK fallback, got %q", string(decoyBody))
	}

	// Test B: Authenticated Sudoku UoT datagram echo
	prof := config.Profile{
		Name:               "UoT-Test",
		ServerAddress:      fmt.Sprintf("127.0.0.1:%d", srvPort),
		Key:                keys.AvailablePrivateKey,
		AEAD:               "chacha20-poly1305",
		ASCII:              "prefer_entropy",
		PaddingMin:         5,
		PaddingMax:         15,
		EnablePureDownlink: true,
		HTTPMask:           srvCfg.HTTPMask,
	}
	dialer, err := tunnel.NewClientDialer(prof)
	if err != nil {
		t.Fatalf("NewClientDialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	uotConn, err := dialer.DialUoT(ctx)
	if err != nil {
		t.Fatalf("DialUoT: %v", err)
	}
	defer uotConn.Close()

	uw := tunnel.NewUoTWriter(uotConn, nil)
	defer uw.Close()
	if err := uw.WriteDatagram(udpSrv.LocalAddr().String(), []byte("sudoku-udp-ping")); err != nil {
		t.Fatalf("WriteDatagram: %v", err)
	}
	ur := tunnel.NewUoTReader(uotConn)
	_, gotPayload, err := ur.ReadDatagram()
	if err != nil {
		t.Fatalf("ReadDatagram: %v", err)
	}
	if !bytes.Equal(gotPayload, []byte("ECHO:sudoku-udp-ping")) {
		t.Fatalf("unexpected UoT reply: %q", string(gotPayload))
	}

	// Test C: Web Dashboard HTTP API + embedded index.html
	ws := web.NewServer(mgr, "127.0.0.1:0")
	dashAddr, err := ws.Start()
	if err != nil {
		t.Fatalf("web.Start: %v", err)
	}
	defer ws.Close()

	htmlResp, err := http.Get("http://" + dashAddr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	htmlBody, _ := io.ReadAll(htmlResp.Body)
	_ = htmlResp.Body.Close()
	if htmlResp.StatusCode != 200 || !strings.Contains(string(htmlBody), "GridShield") {
		t.Fatalf("unexpected dashboard HTML status=%d", htmlResp.StatusCode)
	}

	apiResp, err := http.Get("http://" + dashAddr + "/api/status")
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	var snap engine.StatusSnapshot
	if err := json.NewDecoder(apiResp.Body).Decode(&snap); err != nil {
		t.Fatalf("decode /api/status: %v", err)
	}
	_ = apiResp.Body.Close()
	if snap.Version != engine.Version {
		t.Fatalf("version mismatch: %s", snap.Version)
	}

	// Sanity check address codec
	var enc []byte
	enc, err = protocol.AppendAddress(enc, "example.com:443")
	if err != nil {
		t.Fatalf("AppendAddress: %v", err)
	}
	dec, err := protocol.DecodeAddress(enc)
	if err != nil || dec != "example.com:443" {
		t.Fatalf("DecodeAddress got %q err=%v", dec, err)
	}
	_ = url.URL{}
}
