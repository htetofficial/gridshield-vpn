//go:debug multipathtcp=0
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"gridshield/internal/config"
	"gridshield/internal/engine"
	"gridshield/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		runDaemon(nil)
		return
	}

	switch os.Args[1] {
	case "daemon", "web", "ui":
		runDaemon(os.Args[2:])
	case "up", "connect":
		runUp(os.Args[2:])
	case "server", "serve":
		runServer(os.Args[2:])
	case "keygen":
		runKeyGen(os.Args[2:])
	case "link":
		runLink(os.Args[2:])
	case "selftest", "test":
		runSelfTest(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("GridShield VPN v%s (%s/%s, Sudoku 4x4 O(1) Protocol)\n", engine.Version, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf(`GridShield VPN v%s — High-Speed Sudoku 4x4 Obfuscated VPN (macOS / Linux / Windows)

Usage:
  gridshield <command> [flags]

Commands:
  daemon     Start VPN core + Built-in Fast Web Dashboard (default)
  up         Connect directly via CLI (supports sudoku:// link, System Proxy, & TUN)
  server     Run a wire-compatible Sudoku VPN server (auto-generates keys & share link)
  keygen     Generate Ed25519 Master + Split Private Key pair
  link       Import or inspect a sudoku:// short link
  selftest   Run a live end-to-end 4x4 Sudoku tunnel benchmark & wire inspection
  version    Print version info

Examples:
  gridshield daemon --open
  gridshield keygen
  gridshield server --port 8443 --ascii prefer_entropy --httpmask auto --public-host 1.2.3.4
  gridshield up --link "sudoku://..." --sysproxy
  sudo gridshield up --link "sudoku://..." --tun
  gridshield selftest --ascii prefer_ascii --httpmask ws
`, engine.Version)
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	cfgPath := fs.String("config", "", "Path to state.json config file")
	addr := fs.String("addr", "127.0.0.1:9099", "Dashboard & API listen address")
	openBrowser := fs.Bool("open", false, "Open the Web Dashboard in default browser")
	autoConnect := fs.Bool("connect", false, "Automatically connect active profile on startup")
	_ = fs.Parse(args)

	store, err := config.LoadStore(*cfgPath)
	if err != nil {
		fatal("load config: %v", err)
	}
	mgr := engine.NewManager(store)
	defer mgr.Shutdown()

	if *addr == "" {
		*addr = store.Snapshot().Settings.DashboardAddr
	}
	ws := web.NewServer(mgr, *addr)
	actualAddr, err := ws.Start()
	if err != nil {
		fatal("start web dashboard: %v", err)
	}
	defer ws.Close()

	dashURL := "http://" + actualAddr
	fmt.Printf("GridShield VPN Daemon v%s\n", engine.Version)
	fmt.Printf("  Dashboard & API: %s\n", dashURL)
	fmt.Printf("  Config file:     %s\n", store.Path())
	fmt.Printf("  Press Ctrl+C to stop cleanly.\n")

	if *autoConnect {
		if err := mgr.Connect(""); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] auto-connect skipped: %v\n", err)
		}
	}
	if *openBrowser {
		openURL(dashURL)
	}

	waitForSignal()
	fmt.Println("\nShutting down GridShield VPN cleanly...")
}

func runUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	cfgPath := fs.String("config", "", "Path to state.json")
	link := fs.String("link", "", "sudoku:// short link to connect")
	serverAddr := fs.String("server", "", "Server host:port")
	key := fs.String("key", "", "Client Available Private Key or PSK")
	ascii := fs.String("ascii", "prefer_entropy", "prefer_entropy | prefer_ascii | up_ascii_down_entropy | up_entropy_down_ascii")
	aead := fs.String("aead", "chacha20-poly1305", "chacha20-poly1305 | aes-128-gcm | none")
	httpMode := fs.String("httpmask", "auto", "auto | ws | stream | poll | legacy | none")
	httpTLS := fs.Bool("tls", false, "Enable HTTPS for HTTPMask tunnel")
	pureDown := fs.Bool("pure-downlink", true, "Use pure Sudoku downlink (false = packed)")
	port := fs.Int("port", 10808, "Local mixed SOCKS5/HTTP proxy port")
	mode := fs.String("mode", "rule", "Routing mode: rule | global | direct")
	sysProxy := fs.Bool("sysproxy", false, "Automatically set OS System Proxy (no root)")
	tunMode := fs.Bool("tun", false, "Enable full-device TUN VPN mode (requires sudo/admin)")
	dashAddr := fs.String("dashboard", "127.0.0.1:9099", "Embedded Web Dashboard address (empty to disable)")
	_ = fs.Parse(args)

	store, err := config.LoadStore(*cfgPath)
	if err != nil {
		fatal("load config: %v", err)
	}
	mgr := engine.NewManager(store)
	defer mgr.Shutdown()

	var profile config.Profile
	if strings.TrimSpace(*link) != "" {
		p, err := config.ImportShortLink(*link)
		if err != nil {
			fatal("parse sudoku:// link: %v", err)
		}
		profile = p
	} else if strings.TrimSpace(*serverAddr) != "" {
		profile = config.Profile{
			ID:                 "cli-node",
			Name:               "CLI Sudoku Node",
			ServerAddress:      *serverAddr,
			Key:                *key,
			AEAD:               *aead,
			ASCII:              *ascii,
			PaddingMin:         5,
			PaddingMax:         15,
			EnablePureDownlink: *pureDown,
			Multiplex:          "auto",
			HTTPMask: config.HTTPMaskConfig{
				Disable: *httpMode == "none",
				Mode:    *httpMode,
				TLS:     *httpTLS,
			},
		}
		if *httpMode == "none" {
			profile.HTTPMask.Mode = "legacy"
		}
	} else {
		st := store.Snapshot()
		if len(st.Profiles) == 0 {
			fatal("provide --link or --server + --key (or add a node in the dashboard first)")
		}
		profile = st.Profiles[0]
		for _, p := range st.Profiles {
			if p.ID == st.ActiveProfileID {
				profile = p
				break
			}
		}
	}

	settings := store.Snapshot().Settings
	settings.MixedPort = *port
	settings.RoutingMode = *mode
	settings.AutoSystemProxy = *sysProxy
	settings.TUNEnabled = *tunMode

	if err := mgr.ConnectWithProfile(profile, settings); err != nil {
		fatal("connect failed: %v", err)
	}

	var ws *web.Server
	if strings.TrimSpace(*dashAddr) != "" {
		ws = web.NewServer(mgr, *dashAddr)
		if actual, err := ws.Start(); err == nil {
			fmt.Printf("  Web Dashboard: http://%s\n", actual)
		}
	}
	if ws != nil {
		defer ws.Close()
	}

	st := mgr.Status()
	fmt.Printf("GridShield VPN Connected!\n")
	fmt.Printf("  Node:         %s (%s)\n", profile.Name, profile.ServerAddress)
	fmt.Printf("  Protocol:     Sudoku 4x4 (%s) + %s + HTTPMask(%s)\n", profile.ASCII, profile.AEAD, profile.HTTPMask.Mode)
	fmt.Printf("  Mixed Proxy:  socks5://%s  |  http://%s\n", st.MixedProxyAddr, st.MixedProxyAddr)
	fmt.Printf("  System Proxy: %v\n", st.SystemProxy.Enabled)
	if st.TUN.Enabled {
		fmt.Printf("  TUN Device:   %s (%s)\n", st.TUN.Interface, st.TUN.LocalIP)
	} else if *tunMode {
		fmt.Printf("  TUN Status:   failed (%s)\n", st.TUN.Error)
	}
	fmt.Println("Press Ctrl+C to disconnect and restore network settings.")

	waitForSignal()
	fmt.Println("\nDisconnecting...")
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	port := fs.Int("port", 8443, "Server TCP listen port")
	key := fs.String("key", "", "Master Public Key (auto-generated if empty)")
	ascii := fs.String("ascii", "prefer_entropy", "prefer_entropy | prefer_ascii | up_ascii_down_entropy | up_entropy_down_ascii")
	aead := fs.String("aead", "chacha20-poly1305", "chacha20-poly1305 | aes-128-gcm | none")
	httpMode := fs.String("httpmask", "auto", "auto | ws | stream | poll | legacy | none")
	pathRoot := fs.String("path-root", "", "Optional HTTPMask path root prefix")
	pureDown := fs.Bool("pure-downlink", true, "Pure Sudoku downlink")
	fallback := fs.String("fallback", "", "Optional decoy host:port for suspicious probes")
	publicHost := fs.String("public-host", "127.0.0.1", "Public host/IP for printing client sudoku:// link")
	_ = fs.Parse(args)

	store, _ := config.LoadStore("")
	mgr := engine.NewManager(store)
	defer mgr.Shutdown()

	srvCfg := config.ServerConfig{
		ListenPort:         *port,
		Key:                strings.TrimSpace(*key),
		AEAD:               *aead,
		ASCII:              *ascii,
		PaddingMin:         5,
		PaddingMax:         15,
		EnablePureDownlink: *pureDown,
		SuspiciousAction:   "silent",
		FallbackAddress:    strings.TrimSpace(*fallback),
		HTTPMask: config.HTTPMaskConfig{
			Disable:  *httpMode == "none",
			Mode:     *httpMode,
			PathRoot: strings.TrimSpace(*pathRoot),
		},
	}
	if srvCfg.FallbackAddress != "" {
		srvCfg.SuspiciousAction = "fallback"
	}
	if *httpMode == "none" {
		srvCfg.HTTPMask.Mode = "legacy"
	}

	started, err := mgr.StartServer(srvCfg)
	if err != nil {
		fatal("start server: %v", err)
	}

	fmt.Printf("GridShield Sudoku VPN Server listening on :%d\n", started.ListenPort)
	fmt.Printf("  Master Public Key: %s\n", started.Key)
	if started.ClientKey != "" {
		fmt.Printf("  Client Private Key: %s\n", started.ClientKey)
		clientProf := config.Profile{
			Name:               "GridShield Server",
			ServerAddress:      fmt.Sprintf("%s:%d", *publicHost, started.ListenPort),
			Key:                started.ClientKey,
			AEAD:               started.AEAD,
			ASCII:              started.ASCII,
			EnablePureDownlink: started.EnablePureDownlink,
			Multiplex:          "auto",
			HTTPMask:           started.HTTPMask,
		}
		if link, err := config.ExportShortLink(clientProf, 10808); err == nil {
			fmt.Printf("  Client Share Link:  %s\n", link)
		}
	}
	fmt.Println("Press Ctrl+C to stop server.")
	waitForSignal()
}

func runKeyGen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	more := fs.String("more", "", "Existing Master or Split private key hex to derive another split client key")
	_ = fs.Parse(args)

	if strings.TrimSpace(*more) != "" {
		split, err := config.SplitKey(*more)
		if err != nil {
			fatal("split key: %v", err)
		}
		fmt.Printf("Split Private Key: %s\n", split)
		return
	}
	keys, err := config.GenerateKeys()
	if err != nil {
		fatal("keygen: %v", err)
	}
	fmt.Printf("Available Private Key (Client): %s\n", keys.AvailablePrivateKey)
	fmt.Printf("Master Private Key (Keep Safe): %s\n", keys.MasterPrivateKey)
	fmt.Printf("Master Public Key (Server):     %s\n", keys.MasterPublicKey)
}

func runLink(args []string) {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	imp := fs.String("import", "", "Parse and save a sudoku:// link")
	_ = fs.Parse(args)

	if strings.TrimSpace(*imp) == "" {
		fatal("usage: gridshield link --import sudoku://...")
	}
	p, err := config.ImportShortLink(*imp)
	if err != nil {
		fatal("import link: %v", err)
	}
	store, err := config.LoadStore("")
	if err != nil {
		fatal("load config: %v", err)
	}
	if err := store.Update(func(s *config.State) error {
		s.Profiles = append([]config.Profile{p}, s.Profiles...)
		s.ActiveProfileID = p.ID
		return nil
	}); err != nil {
		fatal("save profile: %v", err)
	}
	fmt.Printf("Imported node %q -> %s (ascii=%s, aead=%s, httpmask=%s)\n",
		p.Name, p.ServerAddress, p.ASCII, p.AEAD, p.HTTPMask.Mode)
}

func runSelfTest(args []string) {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	ascii := fs.String("ascii", "prefer_ascii", "prefer_ascii | prefer_entropy")
	aead := fs.String("aead", "chacha20-poly1305", "chacha20-poly1305 | aes-128-gcm")
	httpMode := fs.String("httpmask", "auto", "auto | ws | legacy | none")
	_ = fs.Parse(args)

	store, _ := config.LoadStore("")
	mgr := engine.NewManager(store)
	defer mgr.Shutdown()

	fmt.Printf("Running GridShield Sudoku 4x4 end-to-end tunnel self-test (ascii=%s, aead=%s, httpmask=%s)...\n",
		*ascii, *aead, *httpMode)
	res := mgr.RunSelfTest(*ascii, *aead, *httpMode)
	if !res.OK {
		fatal("SELF-TEST FAILED: %s", res.Error)
	}
	fmt.Printf("PASS!\n")
	fmt.Printf("  Handshake RTT: %d ms\n", res.HandshakeMs)
	fmt.Printf("  Bytes Echoed:  %d bytes (bit-for-bit verified)\n", res.BytesEchoed)
	fmt.Printf("  Throughput:    %.1f Mbps\n", res.ThroughputMB)
	fmt.Printf("  Wire Obfs:     %s\n", res.WireSample)
}

func waitForSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func openURL(u string) {
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", u).Start()
	case "linux":
		_ = exec.Command("xdg-open", u).Start()
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
