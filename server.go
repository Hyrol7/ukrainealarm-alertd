package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"

	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// dedup пам'ятає хеші тіл webhook на ttl, щоб повтори не дублювали події.
type dedup struct {
	mu   sync.Mutex
	seen map[[32]byte]time.Time
	ttl  time.Duration
	last time.Time
}

func newDedup(ttl time.Duration) *dedup { return &dedup{seen: map[[32]byte]time.Time{}, ttl: ttl} }

func (d *dedup) firstSeen(h [32]byte, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Sub(d.last) > d.ttl/4 { // періодичне прибирання
		for k, t := range d.seen {
			if now.Sub(t) > d.ttl {
				delete(d.seen, k)
			}
		}
		d.last = now
	}
	if t, ok := d.seen[h]; ok && now.Sub(t) <= d.ttl {
		return false
	}
	d.seen[h] = now
	return true
}

// seed заповнює пам'ять дублікатів хешами з БД (після перезапуску).
func (d *dedup) seed(hashes []string, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			continue
		}
		var k [32]byte
		copy(k[:], b)
		d.seen[k] = now
	}
}

// logLimiter пропускає не більше burst записів за вікно; решту рахує і підсумовує.
type logLimiter struct {
	mu         sync.Mutex
	window     time.Duration
	burst      int
	start      time.Time
	n          int
	suppressed int
}

func (l *logLimiter) allow(now time.Time) (ok bool, suppressedBefore int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.start) >= l.window {
		suppressedBefore = l.suppressed
		l.start, l.n, l.suppressed = now, 0, 0
	}
	if l.n < l.burst {
		l.n++
		return true, suppressedBefore
	}
	l.suppressed++
	return false, suppressedBefore
}

// clean робить рядок безпечним для журналу: без керівних символів, обмеженої довжини.
func clean(s string, max int) string {
	if len(s) > max {
		s = s[:max] + "…"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// validate — другий рубіж після підпису: розумні межі полів webhook.
func validate(m *webhookMsg) error {
	id := string(m.RegionID)
	if id == "" || len(id) > 16 {
		return fmt.Errorf("bad regionId %q", clean(id, 32))
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return fmt.Errorf("non-numeric regionId %q", clean(id, 32))
		}
	}
	if len(m.AlarmType) > 32 || len(m.Status) > 32 || len(m.AlertLevel) > 32 {
		return errors.New("field too long")
	}
	if len(m.Reason) > 1024 {
		m.Reason = m.Reason[:1024]
	}
	if len(m.ActiveAlertLevels) > 64 {
		return fmt.Errorf("too many activeAlertLevels: %d", len(m.ActiveAlertLevels))
	}
	for i := range m.ActiveAlertLevels {
		l := &m.ActiveAlertLevels[i]
		if len(l.Level) > 32 {
			return errors.New("alertLevel too long")
		}
		if len(l.Reason) > 1024 {
			l.Reason = l.Reason[:1024]
		}
	}
	return nil
}

// latencies — кільцевий буфер останніх значень для p50/p99.
type latencies struct {
	mu  sync.Mutex
	buf []time.Duration
	pos int
	n   int
}

func newLatencies(size int) *latencies { return &latencies{buf: make([]time.Duration, size)} }

func (l *latencies) add(d time.Duration) {
	l.mu.Lock()
	l.buf[l.pos] = d
	l.pos = (l.pos + 1) % len(l.buf)
	if l.n < len(l.buf) {
		l.n++
	}
	l.mu.Unlock()
}

func (l *latencies) summary() map[string]string {
	l.mu.Lock()
	vals := append([]time.Duration(nil), l.buf[:l.n]...)
	l.mu.Unlock()
	if len(vals) == 0 {
		return map[string]string{"count": "0"}
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	q := func(p float64) string { return vals[int(p*float64(len(vals)-1))].String() }
	return map[string]string{"count": strconv.Itoa(len(vals)), "p50": q(0.5), "p90": q(0.9), "p99": q(0.99), "max": vals[len(vals)-1].String()}
}

type Server struct {
	cfg      Config
	state    *State
	store    *Store
	verifier *Verifier
	dd       *dedup
	started  time.Time

	handleLat *latencies // скільки ми обробляли запит
	sourceLag *latencies // receivedAt - createdAt: затримка на боці ukrainealarm + мережа

	rejectLog *logLimiter
	up        *Upstream

	lastPauseLogged atomic.Int64
	lastMissUnix    atomic.Int64 // коли востаннє підтвердився пропущений webhook
	misses          atomic.Int64 // підтверджені пропуски webhook (див. missGrace)
	pendMu          sync.Mutex
	pending         map[key]time.Time // виправлення звірки, які ще може підтвердити webhook

	accepted, duplicates, rejected, badJSON atomic.Int64
	reconcileFixes                          atomic.Int64
	lastHookUnix                            atomic.Int64
	lastActionIndex                         atomic.Int64
	lastSyncUnix                            atomic.Int64
	upstreamErr                             atomic.Value
}

func NewServer(cfg Config, state *State, store *Store, v *Verifier) *Server {
	s := &Server{cfg: cfg, state: state, store: store, verifier: v, dd: newDedup(15 * time.Minute),
		started: time.Now(), handleLat: newLatencies(4096), sourceLag: newLatencies(4096),
		rejectLog: &logLimiter{window: time.Minute, burst: 10}}
	s.upstreamErr.Store("")
	return s
}

const maxBody = 256 << 10

// recoverPages: аварія в обробнику → сторінка 500 і подробиці в журнал, а не обірване з'єднання.
func recoverPages(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				logf("panic in %s %s: %v", r.Method, clean(r.URL.Path, 64), v)
				errorPage(w, r, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// HookHandler — усе, що бачить світ (reverse proxy передає сюди весь сайт):
// GET|HEAD /  → головна з індикатором; GET /s → три слова стану для індикатора;
// POST /hook/<секрет> → webhook; решта → 404.
func (s *Server) HookHandler() http.Handler {
	return recoverPages(s.hookHandler())
}

func (s *Server) hookHandler() http.Handler {
	prefix := "/hook/"
	secret := []byte(s.cfg.HookSecret)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			switch r.URL.Path {
			case "/":
				s.serveIndex(w, r)
				return
			case "/s":
				s.serveStatus(w, r)
				return
			}
		}
		// Будь-що інше, крім POST на правильний секрет, — однакове 404: зовні не видно,
		// чи вгадано секрет або метод.
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.URL.Path, prefix)), secret) != 1 {
			errorPage(w, r, http.StatusNotFound)
			return
		}
		// Ліміт тіла: за заголовком відмовляємо одразу, не читаючи; без заголовка — обрізаємо на maxBody.
		if r.ContentLength > maxBody {
			s.rejected.Add(1)
			w.Header().Set("Connection", "close")
			errorPage(w, r, http.StatusRequestEntityTooLarge)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			s.rejected.Add(1)
			w.Header().Set("Connection", "close")
			errorPage(w, r, http.StatusRequestEntityTooLarge)
			return
		}
		// Ключа ще немає (старт) — 503, щоб відправник повторив, а не вважав підпис хибним.
		if !s.verifier.HasKey() {
			w.Header().Set("Retry-After", "10")
			errorPage(w, r, http.StatusServiceUnavailable)
			return
		}
		if err := s.verifier.Verify(r.Header, body); err != nil {
			s.rejected.Add(1)
			if ok, sup := s.rejectLog.allow(t0); ok {
				if sup > 0 {
					logf("(%d more rejected webhooks were not logged)", sup)
				}
				logf("rejected webhook from %s: %v", clean(clientIP(r), 64), err)
			}
			errorPage(w, r, http.StatusUnauthorized)
			return
		}
		h := sha256.Sum256(body)
		if !s.dd.firstSeen(h, t0) {
			s.duplicates.Add(1)
			plain(w, "dup")
			return
		}
		var m webhookMsg
		err = json.Unmarshal(body, &m)
		if err == nil {
			err = validate(&m)
		}
		if err != nil {
			s.badJSON.Add(1)
			logf("bad webhook payload: %v: %s", err, clean(string(body), 300))
			// 200, щоб джерело не повторювало те, що ми однаково не розберемо; тіло лишається в журналі
			plain(w, "ignored")
			return
		}
		now := time.Now().UTC()
		ev := s.state.Apply(Event{
			ReceivedAt: flexTime{now}, CreatedAt: m.CreatedAt, RegionID: string(m.RegionID),
			AlarmType: normType(m.AlarmType), Status: normStatus(m.Status), AlertLevel: m.AlertLevel,
			Reason: m.Reason, Active: m.ActiveAlertLevels, Source: "webhook", hash: hex.EncodeToString(h[:]),
		})
		s.accepted.Add(1)
		s.lastHookUnix.Store(now.Unix())
		s.confirmPending(key{ev.RegionID, ev.AlarmType})
		if !m.CreatedAt.IsZero() {
			s.sourceLag.add(now.Sub(m.CreatedAt.Time))
		}
		plain(w, "ok")
		s.handleLat.add(time.Since(t0))
		if s.cfg.LogEvents && ev.Change != ChangeNone {
			logf("event #%d %s %s %s %s/%s → %s [%s → %s]", ev.Seq, ev.Source, ev.RegionID, clean(ev.AlarmType, 32),
				clean(ev.Status, 32), clean(ev.AlertLevel, 32), ev.Change, strings.Join(ev.PrevLevels, "+"), strings.Join(ev.Levels, "+"))
		}
	})
}

// plain — коротка службова відповідь для відправника webhook.
func plain(w http.ResponseWriter, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, msg)
}

// Пропущені webhook. Звірка часто бачить зміну раніше за webhook (вони запізнюються на
// секунди), тож виправлення звірки — це лише «кандидат у пропуск». Пропуском він стає,
// якщо за missGrace webhook для цього регіону так і не прийшов.
const missGrace = 3 * time.Minute

func (s *Server) notePending(fixes []Event, at time.Time) {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	if s.pending == nil {
		s.pending = map[key]time.Time{}
	}
	for _, ev := range fixes {
		k := key{ev.RegionID, ev.AlarmType}
		if _, ok := s.pending[k]; !ok {
			s.pending[k] = at
		}
	}
}

func (s *Server) confirmPending(k key) {
	s.pendMu.Lock()
	delete(s.pending, k)
	s.pendMu.Unlock()
}

// expirePending: кандидати, старші за missGrace, — справжні пропуски.
func (s *Server) expirePending(now time.Time) int {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	n := 0
	for k, t := range s.pending {
		if now.Sub(t) >= missGrace {
			delete(s.pending, k)
			n++
		}
	}
	if n > 0 {
		s.misses.Add(int64(n))
		s.lastMissUnix.Store(now.Unix())
	}
	return n
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("Cf-Connecting-Ip"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	return r.RemoteAddr
}

// LocalHandler — лише 127.0.0.1: стан, потік подій, здоров'я. Для роздавальника та діагностики.
func (s *Server) LocalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /stats", s.handleStats)
	mux.HandleFunc("GET /state", s.handleState)
	mux.HandleFunc("GET /events", s.handleSSE)
	mux.HandleFunc("GET /regions", s.handleRegions)
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	lastSync := s.lastSyncUnix.Load()
	ok := lastSync > 0 && time.Since(time.Unix(lastSync, 0)) < 4*s.cfg.SyncInterval+3*time.Minute && s.verifier.HasKey()
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"ok":%t,"key":%t,"lastSync":%d,"lastWebhook":%d}`+"\n", ok, s.verifier.HasKey(), lastSync, s.lastHookUnix.Load())
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	seq, active := s.state.Snapshot()
	unix := func(v int64) any {
		if v == 0 {
			return nil
		}
		return time.Unix(v, 0).UTC().Format(time.RFC3339)
	}
	writeJSON(w, map[string]any{
		"version":        version,
		"api":            apiVersion,
		"epoch":          s.epoch(),
		"uptime":         time.Since(s.started).Round(time.Second).String(),
		"seq":            seq,
		"activeAlerts":   len(active),
		"regionsKnown":   s.state.RegionCount(),
		"signingKey":     s.verifier.HasKey(),
		"subscribers":    s.state.Subscribers(),
		"webhooks":       map[string]int64{"accepted": s.accepted.Load(), "duplicates": s.duplicates.Load(), "rejected": s.rejected.Load(), "badJSON": s.badJSON.Load()},
		"lastWebhook":    unix(s.lastHookUnix.Load()),
		"lastSync":       unix(s.lastSyncUnix.Load()),
		"reconcileFixes": s.reconcileFixes.Load(),
		"webhookMisses":  s.misses.Load(),
		"massEndHeld":    massEndHeld(s.state),
		"upstreamError":  s.upstreamErr.Load(),
		"apiCalls1m":     s.apiCalls(),
		"apiPausedUntil": s.apiPaused(),
		"db":             map[string]any{"written": s.store.written.Load(), "dropped": s.store.dropped.Load(), "batches": s.store.batches.Load(), "queued": len(s.store.queue), "lastError": s.store.lastErr.Load()},
		"handleLatency":  s.handleLat.summary(),
		"sourceLag":      s.sourceLag.summary(),
	})
}

func massEndHeld(st *State) int64 { _, n := st.MassEnd(); return n }

func (s *Server) apiCalls() int {
	if s.up == nil {
		return 0
	}
	return s.up.CallsLastMinute()
}

func (s *Server) apiPaused() any {
	if s.up == nil {
		return nil
	}
	if p := s.up.PausedUntil(); time.Now().Before(p) {
		return p.UTC().Format(time.RFC3339)
	}
	return nil
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	seq, items := s.state.Snapshot()
	if st := r.URL.Query().Get("state"); st != "" { // фільтр за областю
		f := items[:0]
		for _, it := range items {
			if it.StateID == st || it.RegionID == st {
				f = append(f, it)
			}
		}
		items = f
	}
	writeJSON(w, map[string]any{"api": apiVersion, "epoch": s.epoch(), "seq": seq, "active": items})
}

func (s *Server) handleRegions(w http.ResponseWriter, r *http.Request) {
	s.state.mu.Lock()
	out := make([]Region, 0, len(s.state.regions))
	for _, rg := range s.state.regions {
		out = append(out, rg)
	}
	s.state.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].StateID != out[j].StateID {
			return out[i].StateID < out[j].StateID
		}
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		return out[i].Name < out[j].Name
	})
	writeJSON(w, out)
}

const maxSubscribers = 64

// apiVersion — версія контракту локального API (docs/api.md). Зростає лише при несумісних змінах.
const apiVersion = 1

func (s *Server) epoch() string {
	if s.store == nil {
		return ""
	}
	return s.store.Epoch()
}

// handleSSE — потік подій (Server-Sent Events). Підтримує Last-Event-ID / ?after=seq:
// після перепідключення віддає пропущені події з кільцевого буфера. Якщо буфер їх уже
// не містить, надсилає подію "resync": клієнт має перечитати /state.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	after, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
	if v := r.URL.Query().Get("after"); v != "" {
		after, _ = strconv.ParseInt(v, 10, 64)
	}
	onlyChanges := r.URL.Query().Get("all") == ""
	ch, backlog, seq := s.state.Subscribe(after, maxSubscribers)
	if ch == nil {
		http.Error(w, "too many subscribers", http.StatusServiceUnavailable)
		return
	}
	defer s.state.Unsubscribe(ch)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "retry: 1000\n\n")
	// hello — першою подією: версія API, ідентифікатор БД і поточний seq.
	fmt.Fprintf(w, "event: hello\ndata: {\"api\":%d,\"epoch\":%q,\"seq\":%d}\n\n", apiVersion, s.epoch(), seq)

	send := func(ev Event) error {
		if onlyChanges && (ev.Change == ChangeNone || ev.Change == ChangeStale) {
			return nil
		}
		b := ev.wire
		if b == nil {
			b, _ = json.Marshal(ev)
		}
		_, err := fmt.Fprintf(w, "id: %d\nevent: alert\ndata: %s\n\n", ev.Seq, b)
		return err
	}
	if after > 0 {
		// resync: пропущені події вже випали з буфера, або клієнт знає номер, якого в нас немає
		// (наприклад, після очищення БД) — клієнт має перечитати /state.
		if after > seq || (after < seq && (len(backlog) == 0 || backlog[0].Seq != after+1)) {
			fmt.Fprintf(w, "event: resync\ndata: {\"seq\":%d}\n\n", seq)
		}
	}
	for _, ev := range backlog {
		if send(ev) != nil {
			return
		}
	}
	fl.Flush()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return // нас від'єднали як повільного
			}
			if send(ev) != nil {
				return
			}
			// дозбираємо все, що вже в каналі, і віддаємо одним flush
			for more := true; more; {
				select {
				case ev, ok := <-ch:
					if !ok {
						fl.Flush()
						return
					}
					if send(ev) != nil {
						return
					}
				default:
					more = false
				}
			}
			fl.Flush()
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		}
	}
}
