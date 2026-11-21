package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gridshield/internal/config"
	"gridshield/internal/engine"
)

//go:embed assets/*
var assetsFS embed.FS

// Server serves the embedded Fast Web Dashboard and local control REST/SSE API.
type Server struct {
	mgr    *engine.Manager
	addr   string
	http   *http.Server
	actual string
}

func NewServer(mgr *engine.Manager, addr string) *Server {
	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:9099"
	}
	return &Server{mgr: mgr, addr: addr}
}

func (s *Server) Start() (string, error) {
	mux := http.NewServeMux()

	// REST API
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("POST /api/connect", s.handleConnect)
	mux.HandleFunc("POST /api/disconnect", s.handleDisconnect)
	mux.HandleFunc("POST /api/demo", s.handleDemo)
	mux.HandleFunc("POST /api/selftest", s.handleSelfTest)
	mux.HandleFunc("POST /api/routing", s.handleRouting)
	mux.HandleFunc("POST /api/sysproxy", s.handleSysProxy)
	mux.HandleFunc("POST /api/tun", s.handleTUN)
	mux.HandleFunc("PUT /api/settings", s.handleUpdateSettings)

	mux.HandleFunc("POST /api/profiles", s.handleSaveProfile)
	mux.HandleFunc("DELETE /api/profiles/{id}", s.handleDeleteProfile)
	mux.HandleFunc("POST /api/profiles/{id}/ping", s.handlePingProfile)
	mux.HandleFunc("GET /api/profiles/{id}/link", s.handleExportLink)
	mux.HandleFunc("POST /api/profiles/import", s.handleImportLink)

	mux.HandleFunc("POST /api/keygen", s.handleKeyGen)
	mux.HandleFunc("POST /api/server/start", s.handleServerStart)
	mux.HandleFunc("POST /api/server/stop", s.handleServerStop)

	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("DELETE /api/connections/{id}", s.handleCloseConnection)
	mux.HandleFunc("GET /api/logs", s.handleLogs)
	mux.HandleFunc("GET /api/traffic/history", s.handleTrafficHistory)
	mux.HandleFunc("GET /api/events", s.handleSSE)

	// Embedded Web Dashboard static files
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		return "", err
	}
	fileSrv := http.FileServer(http.FS(sub))
	mux.Handle("/", fileSrv)

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return "", fmt.Errorf("listen dashboard %s: %w", s.addr, err)
	}
	s.actual = ln.Addr().String()
	s.http = &http.Server{
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := s.http.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.mgr.Tracker.Log("ERROR", "Web", "dashboard server error: %v", err)
		}
	}()
	s.mgr.Tracker.Log("INFO", "Web", "Dashboard & API listening at http://%s", s.actual)
	return s.actual, nil
}

func (s *Server) Addr() string {
	if s.actual != "" {
		return s.actual
	}
	return s.addr
}

func (s *Server) Close() error {
	if s.http == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.http.Shutdown(ctx)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Store.Snapshot())
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ProfileID string `json:"profile_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := s.mgr.Connect(body.ProfileID); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

func (s *Server) handleDisconnect(w http.ResponseWriter, _ *http.Request) {
	if err := s.mgr.Disconnect(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

func (s *Server) handleDemo(w http.ResponseWriter, _ *http.Request) {
	prof, err := s.mgr.StartLocalDemo()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"profile": prof,
		"status":  s.mgr.Status(),
	})
}

func (s *Server) handleSelfTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ASCII        string `json:"ascii"`
		AEAD         string `json:"aead"`
		HTTPMaskMode string `json:"httpmask_mode"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	res := s.mgr.RunSelfTest(body.ASCII, body.AEAD, body.HTTPMaskMode)
	code := http.StatusOK
	if !res.OK {
		code = http.StatusBadGateway
	}
	writeJSON(w, code, res)
}

func (s *Server) handleRouting(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.SetRoutingMode(body.Mode); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

func (s *Server) handleSysProxy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.ToggleSystemProxy(body.Enabled); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

func (s *Server) handleTUN(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.ToggleTUN(body.Enabled); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var next config.AppSettings
	if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.Store.Update(func(st *config.State) error {
		st.Settings = next
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Store.Snapshot().Settings)
}

func (s *Server) handleSaveProfile(w http.ResponseWriter, r *http.Request) {
	var p config.Profile
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	p.Normalize()
	if err := p.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.Store.Update(func(st *config.State) error {
		for i := range st.Profiles {
			if st.Profiles[i].ID == p.ID {
				st.Profiles[i] = p
				return nil
			}
		}
		st.Profiles = append(st.Profiles, p)
		if st.ActiveProfileID == "" {
			st.ActiveProfileID = p.ID
		}
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.mgr.Store.Update(func(st *config.State) error {
		out := st.Profiles[:0]
		for _, p := range st.Profiles {
			if p.ID != id {
				out = append(out, p)
			}
		}
		st.Profiles = out
		if st.ActiveProfileID == id {
			if len(out) > 0 {
				st.ActiveProfileID = out[0].ID
			} else {
				st.ActiveProfileID = ""
			}
		}
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePingProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ms, err := s.mgr.PingProfile(id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"latency_ms": ms})
}

func (s *Server) handleExportLink(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st := s.mgr.Store.Snapshot()
	for _, p := range st.Profiles {
		if p.ID == id {
			link, err := config.ExportShortLink(p, st.Settings.MixedPort)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"link": link})
			return
		}
	}
	writeErr(w, http.StatusNotFound, fmt.Errorf("profile %q not found", id))
}

func (s *Server) handleImportLink(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	prof, err := config.ImportShortLink(body.Link)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.Store.Update(func(st *config.State) error {
		st.Profiles = append([]config.Profile{prof}, st.Profiles...)
		st.ActiveProfileID = prof.ID
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.mgr.Tracker.Log("INFO", "Profile", "Imported sudoku:// link as %q (%s)", prof.Name, prof.ServerAddress)
	writeJSON(w, http.StatusOK, prof)
}

func (s *Server) handleKeyGen(w http.ResponseWriter, r *http.Request) {
	var body struct {
		More string `json:"more"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if strings.TrimSpace(body.More) != "" {
		split, err := config.SplitKey(body.More)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"split_private_key": split})
		return
	}
	keys, err := config.GenerateKeys()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) handleServerStart(w http.ResponseWriter, r *http.Request) {
	var cfg config.ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		cfg = s.mgr.Store.Snapshot().Server
	}
	started, err := s.mgr.StartServer(cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"server": started,
		"status": s.mgr.Status(),
	})
}

func (s *Server) handleServerStop(w http.ResponseWriter, _ *http.Request) {
	if err := s.mgr.StopServer(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

func (s *Server) handleConnections(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Tracker.ActiveConnections())
}

func (s *Server) handleCloseConnection(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !s.mgr.Tracker.CloseConnection(id) {
		writeErr(w, http.StatusNotFound, fmt.Errorf("connection %d not found", id))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Tracker.RecentLogs(200))
}

func (s *Server) handleTrafficHistory(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Tracker.History())
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sendEvent := func(name string, payload any) {
		b, err := json.Marshal(payload)
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, b)
		flusher.Flush()
	}

	// Send initial burst
	sendEvent("status", s.mgr.Status())
	sendEvent("connections", s.mgr.Tracker.ActiveConnections())

	logCh, unsub := s.mgr.Tracker.SubscribeLogs()
	defer unsub()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case entry := <-logCh:
			sendEvent("log", entry)
		case <-ticker.C:
			sendEvent("status", s.mgr.Status())
			sendEvent("connections", s.mgr.Tracker.ActiveConnections())
		}
	}
}
