package proxy

import (
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// TrafficSample is one 1-second telemetry point.
type TrafficSample struct {
	Timestamp int64 `json:"ts"`
	UpBps     int64 `json:"up_bps"`
	DownBps   int64 `json:"down_bps"`
	UpTotal   int64 `json:"up_total"`
	DownTotal int64 `json:"down_total"`
}

// ActiveConn represents a live proxied or direct connection.
type ActiveConn struct {
	ID         uint64 `json:"id"`
	Network    string `json:"network"` // "tcp" | "udp"
	Target     string `json:"target"`
	Route      string `json:"route"` // "SUDOKU" | "DIRECT"
	Source     string `json:"source"`
	StartedAt  int64  `json:"started_at"`
	Upload     int64  `json:"upload"`
	Download   int64  `json:"download"`
	upAtomic   *atomic.Int64
	downAtomic *atomic.Int64
	closer     io.Closer
}

// LogEntry is a structured log event streamed to CLI, Web Dashboard, and macOS Swift app.
type LogEntry struct {
	ID        uint64 `json:"id"`
	Timestamp int64  `json:"ts"`
	Level     string `json:"level"` // "INFO" | "WARN" | "ERROR" | "DEBUG"
	Tag       string `json:"tag"`
	Message   string `json:"message"`
}

// Tracker aggregates real-time telemetry, active connections, and logs.
type Tracker struct {
	upTotal   atomic.Int64
	downTotal atomic.Int64
	upBps     atomic.Int64
	downBps   atomic.Int64
	nextID    atomic.Uint64
	nextLogID atomic.Uint64

	connMu sync.RWMutex
	conns  map[uint64]*ActiveConn

	histMu  sync.RWMutex
	history []TrafficSample

	logMu   sync.RWMutex
	logs    []LogEntry
	logSubs map[chan LogEntry]struct{}

	stopCh chan struct{}
	once   sync.Once
}

func NewTracker() *Tracker {
	t := &Tracker{
		conns:   make(map[uint64]*ActiveConn),
		history: make([]TrafficSample, 0, 64),
		logs:    make([]LogEntry, 0, 256),
		logSubs: make(map[chan LogEntry]struct{}),
		stopCh:  make(chan struct{}),
	}
	go t.sampleLoop()
	return t
}

func (t *Tracker) Close() {
	t.once.Do(func() {
		close(t.stopCh)
	})
}

func (t *Tracker) sampleLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var prevUp, prevDown int64
	for {
		select {
		case <-t.stopCh:
			return
		case now := <-ticker.C:
			curUp := t.upTotal.Load()
			curDown := t.downTotal.Load()
			upRate := curUp - prevUp
			downRate := curDown - prevDown
			if upRate < 0 {
				upRate = 0
			}
			if downRate < 0 {
				downRate = 0
			}
			prevUp, prevDown = curUp, curDown
			t.upBps.Store(upRate)
			t.downBps.Store(downRate)

			sample := TrafficSample{
				Timestamp: now.Unix(),
				UpBps:     upRate,
				DownBps:   downRate,
				UpTotal:   curUp,
				DownTotal: curDown,
			}
			t.histMu.Lock()
			if len(t.history) >= 60 {
				copy(t.history, t.history[1:])
				t.history[len(t.history)-1] = sample
			} else {
				t.history = append(t.history, sample)
			}
			t.histMu.Unlock()
		}
	}
}

func (t *Tracker) AddTraffic(up, down int64) {
	if up > 0 {
		t.upTotal.Add(up)
	}
	if down > 0 {
		t.downTotal.Add(down)
	}
}

func (t *Tracker) Stats() TrafficSample {
	return TrafficSample{
		Timestamp: time.Now().Unix(),
		UpBps:     t.upBps.Load(),
		DownBps:   t.downBps.Load(),
		UpTotal:   t.upTotal.Load(),
		DownTotal: t.downTotal.Load(),
	}
}

func (t *Tracker) History() []TrafficSample {
	t.histMu.RLock()
	defer t.histMu.RUnlock()
	return append([]TrafficSample(nil), t.history...)
}

func (t *Tracker) ResetTraffic() {
	t.upTotal.Store(0)
	t.downTotal.Store(0)
	t.upBps.Store(0)
	t.downBps.Store(0)
	t.histMu.Lock()
	t.history = t.history[:0]
	t.histMu.Unlock()
}

func (t *Tracker) TrackConn(network, source, target, route string, closer io.Closer) (*ActiveConn, func()) {
	id := t.nextID.Add(1)
	c := &ActiveConn{
		ID:         id,
		Network:    network,
		Target:     target,
		Route:      route,
		Source:     source,
		StartedAt:  time.Now().Unix(),
		upAtomic:   &atomic.Int64{},
		downAtomic: &atomic.Int64{},
		closer:     closer,
	}
	t.connMu.Lock()
	t.conns[id] = c
	t.connMu.Unlock()

	cleanup := func() {
		t.connMu.Lock()
		delete(t.conns, id)
		t.connMu.Unlock()
	}
	return c, cleanup
}

func (c *ActiveConn) AddUp(n int64, t *Tracker) {
	if n <= 0 {
		return
	}
	c.upAtomic.Add(n)
	t.upTotal.Add(n)
}

func (c *ActiveConn) AddDown(n int64, t *Tracker) {
	if n <= 0 {
		return
	}
	c.downAtomic.Add(n)
	t.downTotal.Add(n)
}

func (t *Tracker) ActiveConnections() []ActiveConn {
	t.connMu.RLock()
	out := make([]ActiveConn, 0, len(t.conns))
	for _, c := range t.conns {
		out = append(out, ActiveConn{
			ID:        c.ID,
			Network:   c.Network,
			Target:    c.Target,
			Route:     c.Route,
			Source:    c.Source,
			StartedAt: c.StartedAt,
			Upload:    c.upAtomic.Load(),
			Download:  c.downAtomic.Load(),
		})
	}
	t.connMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func (t *Tracker) ActiveCount() int {
	t.connMu.RLock()
	n := len(t.conns)
	t.connMu.RUnlock()
	return n
}

func (t *Tracker) CloseConnection(id uint64) bool {
	t.connMu.RLock()
	c, ok := t.conns[id]
	t.connMu.RUnlock()
	if !ok || c.closer == nil {
		return false
	}
	_ = c.closer.Close()
	return true
}

func (t *Tracker) CloseAllConnections() {
	t.connMu.RLock()
	closers := make([]io.Closer, 0, len(t.conns))
	for _, c := range t.conns {
		if c.closer != nil {
			closers = append(closers, c.closer)
		}
	}
	t.connMu.RUnlock()
	for _, cl := range closers {
		_ = cl.Close()
	}
}

func (t *Tracker) Log(level, tag, format string, args ...any) {
	entry := LogEntry{
		ID:        t.nextLogID.Add(1),
		Timestamp: time.Now().Unix(),
		Level:     level,
		Tag:       tag,
		Message:   fmt.Sprintf(format, args...),
	}
	t.logMu.Lock()
	if len(t.logs) >= 300 {
		copy(t.logs, t.logs[1:])
		t.logs[len(t.logs)-1] = entry
	} else {
		t.logs = append(t.logs, entry)
	}
	for ch := range t.logSubs {
		select {
		case ch <- entry:
		default:
		}
	}
	t.logMu.Unlock()
}

func (t *Tracker) RecentLogs(limit int) []LogEntry {
	t.logMu.RLock()
	defer t.logMu.RUnlock()
	if limit <= 0 || limit >= len(t.logs) {
		return append([]LogEntry(nil), t.logs...)
	}
	return append([]LogEntry(nil), t.logs[len(t.logs)-limit:]...)
}

func (t *Tracker) SubscribeLogs() (chan LogEntry, func()) {
	ch := make(chan LogEntry, 64)
	t.logMu.Lock()
	t.logSubs[ch] = struct{}{}
	t.logMu.Unlock()
	unsub := func() {
		t.logMu.Lock()
		delete(t.logSubs, ch)
		t.logMu.Unlock()
	}
	return ch, unsub
}

// RelayBidirectional copies traffic in both directions while updating per-connection & global counters.
func RelayBidirectional(client, remote net.Conn, active *ActiveConn, tracker *Tracker) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst, src net.Conn, isUpload bool) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if isUpload {
					active.AddUp(int64(n), tracker)
				} else {
					active.AddDown(int64(n), tracker)
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetDeadline(time.Now())
		}
	}

	go copyDir(remote, client, true)
	go copyDir(client, remote, false)
	wg.Wait()
	_ = client.Close()
	_ = remote.Close()
}
