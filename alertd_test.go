package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testKey(t testing.TB) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(k *rsa.PrivateKey, ts int64, body []byte) http.Header {
	h := sha256.Sum256(append([]byte(strconv.FormatInt(ts, 10)+"."), body...))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	hd := http.Header{}
	hd.Set("X-Webhook-Signature", base64.StdEncoding.EncodeToString(sig))
	hd.Set("X-Webhook-Timestamp", strconv.FormatInt(ts, 10))
	hd.Set("X-Webhook-Key-Id", "test")
	hd.Set("X-Webhook-Signature-Alg", "rsa-sha256")
	return hd
}

func certPEM(t testing.TB, k *rsa.PrivateKey) []byte {
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "webhook"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParseKeyFormats(t *testing.T) {
	k := testKey(t)
	pkix, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	for name, data := range map[string][]byte{
		"cert":  certPEM(t, k),
		"pkix":  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}),
		"pkcs1": pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&k.PublicKey)}),
	} {
		got, err := parsePublicKey(data)
		if err != nil || got.N.Cmp(k.N) != 0 {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestVerifier(t *testing.T) {
	k := testKey(t)
	v := NewVerifier(&k.PublicKey, 5*time.Minute, nil)
	body := []byte(`{"status":"Activate","regionId":14}`)
	now := time.Now().Unix()
	if err := v.Verify(sign(k, now, body), body); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := v.Verify(sign(k, now, body), append(body, ' ')); err == nil {
		t.Fatal("tampered body accepted")
	}
	if err := v.Verify(sign(k, now-600, body), body); err != errBadTimestamp {
		t.Fatalf("old timestamp: %v", err)
	}
	other := testKey(t)
	if err := v.Verify(sign(other, now, body), body); err == nil {
		t.Fatal("foreign key accepted")
	}
	hd := sign(k, now, body)
	hd.Set("X-Webhook-Signature-Alg", "hmac-sha256")
	if err := v.Verify(hd, body); err != errBadAlg {
		t.Fatalf("alg: %v", err)
	}
	if err := v.Verify(http.Header{}, body); err != errNoSignature {
		t.Fatalf("no headers: %v", err)
	}
	// Ротація ключа: старий ключ у пам'яті, новий підтягується через reload.
	reloaded := 0
	v2 := NewVerifier(&other.PublicKey, 5*time.Minute, func() (*rsa.PublicKey, error) { reloaded++; return &k.PublicKey, nil })
	if err := v2.Verify(sign(k, now, body), body); err != nil || reloaded != 1 {
		t.Fatalf("rotation: %v reloaded=%d", err, reloaded)
	}
}

func lv(level, reason string) Level { return Level{Level: level, Reason: reason} }

func newTestState() (*State, chan Event) {
	q := make(chan Event, 1000)
	s := NewState(q, 100)
	s.SetRegions(map[string]Region{"14": {ID: "14", Name: "Київська область", StateID: "14"}})
	return s, q
}

func at(min int) flexTime { return flexTime{time.Date(2026, 9, 7, 12, min, 0, 0, time.UTC)} }

func TestStateTransitionsFromDocs(t *testing.T) {
	s, _ := newTestState()
	ap := func(status string, min int, active ...Level) Event {
		return s.Apply(Event{ReceivedAt: at(min), CreatedAt: at(min), RegionID: "14", AlarmType: "AIR", Status: status, Active: active, Source: "webhook"})
	}
	if e := ap("ACTIVATE", 0, lv("Yellow", "UAV activity")); e.Change != ChangeStart || e.RegionName != "Київська область" {
		t.Fatalf("start: %+v", e)
	}
	if e := ap("ACTIVATE", 5, lv("Yellow", "UAV activity"), lv("Red", "Missile threat")); e.Change != ChangeUpdate || e.MaxLevel != "Red" {
		t.Fatalf("update: %+v", e)
	}
	// Приклад з документації: DEACTIVATE однієї причини, але тривога триває.
	if e := ap("DEACTIVATE", 10, lv("Yellow", "UAV activity")); e.Change != ChangeUpdate || e.MaxLevel != "Red" {
		t.Fatalf("partial deactivate must keep alert: %+v", e)
	}
	// Застаріла подія (createdAt раніше за вже застосовану) не змінює стан.
	if e := ap("ACTIVATE", 3, lv("Red", "Old")); e.Change != ChangeStale {
		t.Fatalf("stale: %+v", e)
	}
	if e := ap("DEACTIVATE", 15); e.Change != ChangeEnd || e.SessionFrom.Time != at(0).Time {
		t.Fatalf("end: %+v", e)
	}
	if e := ap("DEACTIVATE", 16); e.Change != ChangeNone {
		t.Fatalf("repeat end: %+v", e)
	}
	_, items := s.Snapshot()
	if len(items) != 0 {
		t.Fatalf("expected empty state, got %+v", items)
	}
}

func TestReconcile(t *testing.T) {
	s, _ := newTestState()
	s.Apply(Event{ReceivedAt: at(0), CreatedAt: at(0), RegionID: "14", AlarmType: "AIR", Active: []Level{lv("Red", "x")}, Source: "webhook"})
	s.Apply(Event{ReceivedAt: at(0), CreatedAt: at(0), RegionID: "9", AlarmType: "AIR", Active: []Level{lv("Red", "y")}, Source: "webhook"})
	// Знімок: 14 зник (пропущений відбій), з'явився 22 (пропущений старт), 9 без змін.
	snap := map[key][]Level{{"9", "AIR"}: {lv("Red", "y")}, {"22", "ARTILLERY"}: {lv("Red", "")}}
	if n := len(s.Reconcile(snap, time.Time{}, at(30).Time, time.Second, "poll", false)); n != 2 {
		t.Fatalf("fixes=%d", n)
	}
	_, items := s.Snapshot()
	got := []string{}
	for _, it := range items {
		got = append(got, it.RegionID+"/"+it.AlarmType)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "22/ARTILLERY,9/AIR" {
		t.Fatalf("state after reconcile: %v", got)
	}
	// Запис, оновлений webhook під час запиту знімка, не перезаписується старішим знімком.
	s.Apply(Event{ReceivedAt: flexTime{time.Now()}, CreatedAt: flexTime{time.Now()}, RegionID: "5", AlarmType: "AIR", Active: []Level{lv("Red", "z")}, Source: "webhook"})
	if n := len(s.Reconcile(snap, time.Time{}, time.Now().Add(-time.Millisecond), time.Second, "poll", false)); n != 0 {
		t.Fatalf("fresh webhook overwritten, fixes=%d", n)
	}
}

func TestFlexParsing(t *testing.T) {
	var m webhookMsg
	err := json.Unmarshal([]byte(`{"status":"DEACTIVATE","regionId":14,"alarmType":"AIR","createdAt":"2026-09-07T12:32:00",
		"alertLevel":"Yellow","reason":"UAV activity","activeAlertLevels":[]}`), &m)
	if err != nil || m.RegionID != "14" || m.CreatedAt.Time != at(32).Time {
		t.Fatalf("%v %+v", err, m)
	}
	var a apiAlert
	if err := json.Unmarshal([]byte(`{"regionId":"1293","type":"AIR","lastUpdate":"2026-09-07T12:00:00.123Z"}`), &a); err != nil || a.RegionID != "1293" {
		t.Fatalf("%v %+v", err, a)
	}
}

// ---------- наскрізний тест: справжній бінарник, імітація API, підписані webhook ----------

type mockAPI struct {
	pemFail atomic.Int32 // скільки перших запитів ключа відповісти 503
	pem403  atomic.Bool  // ключ завжди 403 (як з VPS)

	limit    int // ліміт запитів до /api за вікно (0 — без ліміту)
	window   time.Duration
	apiTimes []time.Time
	apiTotal atomic.Int64
	api429   atomic.Int64
	mu       sync.Mutex
	idx      int64
	alerts   []apiAlertRegion
	pem      []byte
	hooks    []string
}

func (m *mockAPI) handler(t testing.TB) http.Handler {
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "test-token" {
			http.Error(w, "unauthorized", 401)
			return false
		}
		m.apiTotal.Add(1)
		if m.limit > 0 {
			m.mu.Lock()
			now := time.Now()
			i := 0
			for i < len(m.apiTimes) && now.Sub(m.apiTimes[i]) > m.window {
				i++
			}
			m.apiTimes = append(m.apiTimes[i:], now)
			over := len(m.apiTimes) > m.limit
			m.mu.Unlock()
			if over {
				m.api429.Add(1)
				w.WriteHeader(429)
				w.Write([]byte("The number of requests in 1 minute has been exceeded. Please wait 2 seconds and try again"))
				return false
			}
		}
		return true
	}
	mux.HandleFunc("/webhook-public.pem", func(w http.ResponseWriter, r *http.Request) {
		if m.pem403.Load() {
			http.Error(w, "forbidden", 403)
			return
		}
		if m.pemFail.Add(-1) >= 0 {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Write(m.pem)
	})
	mux.HandleFunc("/api/v3/regions", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		// 25 областей × 4 райони × 10 громад
		var states []map[string]any
		for o := 1; o <= 25; o++ {
			var ds []map[string]any
			for d := 1; d <= 4; d++ {
				var cs []map[string]any
				for c := 1; c <= 10; c++ {
					cs = append(cs, map[string]any{"regionId": fmt.Sprint(o*1000 + d*100 + c), "regionName": fmt.Sprintf("Громада %d-%d-%d", o, d, c), "regionType": "Community"})
				}
				ds = append(ds, map[string]any{"regionId": fmt.Sprint(o*1000 + d*100), "regionName": fmt.Sprintf("Район %d-%d", o, d), "regionType": "District", "regionChildIds": cs})
			}
			states = append(states, map[string]any{"regionId": fmt.Sprint(o), "regionName": fmt.Sprintf("Область %d", o), "regionType": "State", "regionChildIds": ds})
		}
		json.NewEncoder(w).Encode(map[string]any{"states": states})
	})
	mux.HandleFunc("/api/v3/alerts/status", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		fmt.Fprintf(w, `{"lastActionIndex":%d}`, m.idx)
	})
	mux.HandleFunc("/api/v3/alerts", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		json.NewEncoder(w).Encode(m.alerts)
	})
	mux.HandleFunc("/api/v3/webhook", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		m.mu.Lock()
		m.hooks = append(m.hooks, r.Method+" "+b["webHookUrl"])
		m.mu.Unlock()
		w.Write([]byte(`{"webHookUrl":"` + b["webHookUrl"] + `"}`))
	})
	return mux
}

func freePort(t testing.TB) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type harness struct {
	t        testing.TB
	key      *rsa.PrivateKey
	api      *mockAPI
	apiSrv   *httptest.Server
	hookURL  string
	localURL string
	dbPath   string
	cmd      *exec.Cmd
	env      []string
	logBuf   *syncBuf
	secret   string
	client   *http.Client
	extraEnv []string
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newHarness(t testing.TB) *harness { return newHarnessOpt(t, 0) }

func newHarnessOpt(t testing.TB, pemFailures int32, opts ...func(*harness)) *harness {
	bin := os.Getenv("ALERTD_BIN")
	if bin == "" {
		t.Skip("ALERTD_BIN not set")
	}
	h := &harness{t: t, key: testKey(t), api: &mockAPI{idx: 100}, secret: "s3cr3t-0123456789abcdef0123456789",
		client: &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64}, Timeout: 10 * time.Second}}
	h.api.pem = certPEM(t, h.key)
	h.api.pemFail.Store(pemFailures)
	// як у справжньому /alerts: районна тривога повторюється в записах області, району й громади
	art := apiAlert{RegionID: "3100", Type: "ARTILLERY", Levels: []Level{{Level: "Red", Reason: "Shelling", CreatedAt: at(1)}}}
	h.api.alerts = []apiAlertRegion{
		{RegionID: "3", ActiveAlerts: []apiAlert{
			{RegionID: "3", Type: "AIR", Levels: []Level{{Level: "Yellow", Reason: "UAV activity", CreatedAt: at(0)}}}, art}},
		{RegionID: "3100", ActiveAlerts: []apiAlert{art}},
		{RegionID: "3101", ActiveAlerts: []apiAlert{art}},
	}
	for _, o := range opts {
		o(h)
	}
	h.apiSrv = httptest.NewServer(h.api.handler(t))
	t.Cleanup(h.apiSrv.Close)
	h.dbPath = filepath.Join(t.TempDir(), "alerts.db")
	hook, local := freePort(t), freePort(t)
	h.hookURL = "http://" + hook + "/hook/" + h.secret
	h.localURL = "http://" + local
	h.env = append(os.Environ(),
		"UA_TOKEN=test-token", "UA_API_BASE="+h.apiSrv.URL, "HOOK_SECRET="+h.secret,
		"PUBLIC_HOOK_URL=https://alerts.example/hook/"+h.secret,
		"HOOK_LISTEN="+hook, "LOCAL_LISTEN="+local, "DB_PATH="+h.dbPath,
		"POLL_INTERVAL=1s", "LOG_EVENTS=0", "API_MIN_GAP=0")
	h.env = append(h.env, h.extraEnv...)
	h.start()
	return h
}

func (h *harness) start() { h.startWait(true) }

func (h *harness) startWait(healthy bool) {
	h.logBuf = &syncBuf{}
	h.cmd = exec.Command(os.Getenv("ALERTD_BIN"), "run")
	h.cmd.Env = h.env
	h.cmd.Stdout, h.cmd.Stderr = h.logBuf, h.logBuf
	if err := h.cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(h.stop)
	t0 := time.Now()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(h.localURL + "/health"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 || !healthy {
				h.t.Logf("service up in %s", time.Since(t0).Round(time.Millisecond))
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("service did not become healthy:\n%s", h.logBuf.String())
}

func (h *harness) stop() {
	defer func() {
		if h.logBuf != nil && strings.Contains(h.logBuf.String(), "DATA RACE") {
			h.t.Errorf("data race in service:\n%s", h.logBuf.String())
		}
	}()
	if h.cmd != nil && h.cmd.Process != nil && h.cmd.ProcessState == nil {
		h.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { h.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			h.cmd.Process.Kill()
			<-done
		}
	}
}

func (h *harness) post(body []byte, hd http.Header) (int, time.Duration) {
	req, _ := http.NewRequest("POST", h.hookURL, bytes.NewReader(body))
	for k, v := range hd {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	t0 := time.Now()
	resp, err := h.client.Do(req)
	d := time.Since(t0)
	if err != nil {
		h.t.Errorf("post: %v", err)
		return 0, d
	}
	resp.Body.Close()
	return resp.StatusCode, d
}

func hookBody(status string, region int, typ string, created time.Time, level, reason string, active ...Level) []byte {
	if active == nil {
		active = []Level{}
	}
	b, _ := json.Marshal(map[string]any{"status": status, "regionId": region, "alarmType": typ,
		"createdAt": created.UTC().Format("2006-01-02T15:04:05.000Z"), "alertLevel": level, "reason": reason, "activeAlertLevels": active})
	return b
}

func (h *harness) db() *sql.DB {
	db, err := sql.Open("sqlite3", "file:"+h.dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { db.Close() })
	return db
}

func (h *harness) waitFor(what string, cond func() bool) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("timeout waiting for %s\n%s", what, h.logBuf.String())
}

func count(db *sql.DB, q string, args ...any) int {
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		return -1
	}
	return n
}

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)
	db := h.db()

	// 1. Стартова звірка: два активні з імітованого API потрапили в стан і в БД.
	h.waitFor("startup sync", func() bool { return count(db, `SELECT COUNT(*) FROM active_state`) == 2 })
	if n := count(db, `SELECT COUNT(*) FROM regions`); n != 25+100+1000 {
		t.Fatalf("regions=%d", n)
	}
	if st := count(db, `SELECT COUNT(*) FROM active_state WHERE region_id='3100' AND state_id='3'`); st != 1 {
		t.Fatalf("state_id for district not resolved")
	}

	// 2. Потік подій для роздавальника: підписуємось до надсилання webhook.
	sseReq, _ := http.NewRequest("GET", h.localURL+"/events", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sseResp, err := http.DefaultClient.Do(sseReq.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	gotSSE := make(chan string, 100)
	go func() {
		buf := make([]byte, 64<<10)
		var acc string
		for {
			n, err := sseResp.Body.Read(buf)
			acc += string(buf[:n])
			for {
				i := strings.Index(acc, "\n\n")
				if i < 0 {
					break
				}
				if strings.Contains(acc[:i], "event: alert") {
					gotSSE <- acc[:i]
				}
				acc = acc[i+2:]
			}
			if err != nil {
				return
			}
		}
	}()

	// 3. Сценарій із документації для регіону 14.
	now := time.Now().UTC().Truncate(time.Millisecond)
	steps := []struct {
		body   []byte
		change string
	}{
		{hookBody("Activate", 14, "AIR", now, "Yellow", "UAV activity", lv("Yellow", "UAV activity")), ChangeStart},
		{hookBody("Activate", 14, "AIR", now.Add(time.Second), "Red", "Missile threat", lv("Yellow", "UAV activity"), lv("Red", "Missile threat")), ChangeUpdate},
		{hookBody("DEACTIVATE", 14, "AIR", now.Add(2*time.Second), "Red", "Missile threat", lv("Yellow", "UAV activity")), ChangeUpdate},
		{hookBody("DEACTIVATE", 14, "AIR", now.Add(3*time.Second), "Yellow", "UAV activity"), ChangeEnd},
	}
	for i, st := range steps {
		code, _ := h.post(st.body, sign(h.key, time.Now().Unix(), st.body))
		if code != 200 {
			t.Fatalf("step %d: HTTP %d", i, code)
		}
		select {
		case ev := <-gotSSE:
			if !strings.Contains(ev, `"change":"`+st.change+`"`) {
				t.Fatalf("step %d: want %s, got %s", i, st.change, ev)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("step %d: no SSE event", i)
		}
	}
	// Повтор того самого тіла — дублікат, нової події немає.
	code, _ := h.post(steps[0].body, sign(h.key, time.Now().Unix(), steps[0].body))
	if code != 200 {
		t.Fatalf("dup: %d", code)
	}
	// Підробки та чужі адреси.
	if code, _ := h.post(steps[0].body, sign(testKey(t), time.Now().Unix(), steps[0].body)); code != 401 {
		t.Fatalf("forged: %d", code)
	}
	if resp, err := h.client.Post(strings.Replace(h.hookURL, h.secret, "wrong", 1), "application/json", nil); err != nil || resp.StatusCode != 404 {
		t.Fatalf("wrong secret not 404: %v", err)
	}

	h.waitFor("session closed", func() bool {
		return count(db, `SELECT COUNT(*) FROM sessions WHERE region_id='14' AND ended_ms IS NOT NULL AND max_level='Red'`) == 1
	})
	if n := count(db, `SELECT COUNT(*) FROM events WHERE region_id='14' AND source='webhook'`); n != 4 {
		t.Fatalf("events for 14 = %d (dup must be ignored)", n)
	}
	var reasons string
	db.QueryRow(`SELECT reasons FROM sessions WHERE region_id='14'`).Scan(&reasons)
	if reasons != "UAV activity; Missile threat" {
		t.Fatalf("session reasons=%q", reasons)
	}

	// 4. Пропущений webhook: API змінює стан без webhook → звірка за lastActionIndex.
	h.api.mu.Lock()
	h.api.alerts = append(h.api.alerts, apiAlertRegion{RegionID: "7", ActiveAlerts: []apiAlert{{RegionID: "7", Type: "AIR",
		Levels: []Level{{Level: "Red", Reason: "Ballistic missile threat", CreatedAt: flexTime{time.Now().UTC()}}}}}})
	h.api.idx++
	h.api.mu.Unlock()
	h.waitFor("reconcile picks missed alert", func() bool {
		return count(db, `SELECT COUNT(*) FROM active_state WHERE region_id='7'`) == 1
	})
	if n := count(db, `SELECT COUNT(*) FROM events WHERE region_id='7' AND source='poll' AND change='start'`); n != 1 {
		t.Fatalf("poll event missing: %d", n)
	}

	// 5. Перезапуск: стан відновлюється з БД без хибних подій.
	before := count(db, `SELECT COUNT(*) FROM events`)
	h.stop()
	h.start()
	time.Sleep(500 * time.Millisecond)
	if after := count(db, `SELECT COUNT(*) FROM events`); after != before {
		t.Fatalf("restart produced %d spurious events\n%s", after-before, h.logBuf.String())
	}
	var st struct {
		Seq    int64        `json:"seq"`
		Active []ActiveItem `json:"active"`
	}
	resp, _ := http.Get(h.localURL + "/state")
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if len(st.Active) != 3 || st.Seq < int64(before) {
		t.Fatalf("state after restart: seq=%d active=%d", st.Seq, len(st.Active))
	}
}

// TestBurst — «тривога по всій країні»: тисячі підписаних webhook паралельно.
func TestBurst(t *testing.T) {
	h := newHarness(t)
	db := h.db()
	h.waitFor("startup", func() bool { return count(db, `SELECT COUNT(*) FROM regions`) > 0 })

	// Спершу «тиха» ситуація: поодинокі webhook по одному, як у звичайний день.
	single := make([]time.Duration, 0, 200)
	for i := 0; i < 200; i++ {
		b := hookBody("Activate", 25000+i, "INFO", time.Now(), "Yellow", "test", lv("Yellow", "test"))
		code, d := h.post(b, sign(h.key, time.Now().Unix(), b))
		if code != 200 {
			t.Fatalf("single %d: %d", i, code)
		}
		single = append(single, d)
	}
	sort.Slice(single, func(i, j int) bool { return single[i] < single[j] })
	t.Logf("single webhook round-trip (keep-alive): p50 %s  p99 %s", single[100], single[198])

	n := 3000
	if v, _ := strconv.Atoi(os.Getenv("BURST")); v > 0 {
		n = v
	}
	type item struct {
		body []byte
		hd   http.Header
	}
	base := time.Now().UTC()
	items := make([]item, n)
	for i := range items { // підпис готуємо заздалегідь: вимірюємо лише сервіс
		region := (i/2)%25*1000 + 1000 + ((i/2)/25%4+1)*100 + ((i/2)/100)%10 + 1
		var b []byte
		if i%2 == 0 {
			b = hookBody("Activate", region, "AIR", base.Add(time.Duration(i)*time.Millisecond), "Red", "Missile threat", lv("Red", "Missile threat"))
		} else {
			b = hookBody("Activate", region, "AIR", base.Add(time.Duration(i)*time.Millisecond), "Yellow", "UAV activity", lv("Red", "Missile threat"), lv("Yellow", "UAV activity"))
		}
		items[i] = item{b, sign(h.key, time.Now().Unix(), b)}
	}
	var next atomic.Int64
	lat := make([]time.Duration, n)
	workers := 64
	var wg sync.WaitGroup
	t0 := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				code, d := h.post(items[i].body, items[i].hd)
				if code != 200 {
					t.Errorf("item %d: %d", i, code)
				}
				lat[i] = d
			}
		}()
	}
	wg.Wait()
	wall := time.Since(t0)
	h.waitFor("all burst events in db", func() bool {
		return count(db, `SELECT COUNT(*) FROM events WHERE source='webhook'`) == n+200
	})
	dbDone := time.Since(t0)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	q := func(p float64) time.Duration { return lat[int(p*float64(n-1))] }
	t.Logf("burst %d webhooks, %d parallel: wall %s (%.0f req/s), all in DB after %s", n, workers, wall.Round(time.Millisecond), float64(n)/wall.Seconds(), dbDone.Round(time.Millisecond))
	t.Logf("HTTP round-trip incl. signature check: p50 %s  p90 %s  p99 %s  max %s", q(.5), q(.9), q(.99), lat[n-1])
	resp, _ := http.Get(h.localURL + "/stats")
	var stats map[string]any
	json.NewDecoder(resp.Body).Decode(&stats)
	resp.Body.Close()
	t.Logf("server-side handling: %v; db: %v", stats["handleLatency"], stats["db"])
	if count(db, `SELECT COUNT(*) FROM sessions WHERE ended_ms IS NULL AND alarm_type='AIR'`) == 0 {
		t.Fatal("no open sessions after burst")
	}
}

func TestRealUkraineAlarmKey(t *testing.T) {
	b, err := os.ReadFile("testdata/ukrainealarm-webhook-public.pem")
	if err != nil {
		t.Skip(err)
	}
	k, err := parsePublicKey(b)
	if err != nil || k.N.BitLen() != 2048 {
		t.Fatalf("real key: %v", err)
	}
}

func TestKeyChecks(t *testing.T) {
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	v := NewVerifier(nil, time.Minute, nil)
	if err := v.SetKey(&weak.PublicKey); err == nil {
		t.Fatal("1024-bit key accepted")
	}
	if v.HasKey() {
		t.Fatal("weak key stored")
	}
	k := testKey(t)
	if err := v.SetKey(&k.PublicKey); err != nil || !v.HasKey() || len(keyFingerprint(&k.PublicKey)) != 32 {
		t.Fatalf("good key: %v", err)
	}
	// Без ключа будь-який підпис відхиляється, а не пропускається.
	empty := NewVerifier(nil, time.Minute, nil)
	body := []byte(`{}`)
	if err := empty.Verify(sign(k, time.Now().Unix(), body), body); err == nil {
		t.Fatal("verifier without key accepted a webhook")
	}
}

func TestValidateAndClean(t *testing.T) {
	ok := webhookMsg{RegionID: "1234", AlarmType: "AIR", Reason: strings.Repeat("x", 5000),
		ActiveAlertLevels: []Level{{Level: "Red", Reason: strings.Repeat("y", 5000)}}}
	if err := validate(&ok); err != nil || len(ok.Reason) != 1024 || len(ok.ActiveAlertLevels[0].Reason) != 1024 {
		t.Fatalf("valid msg: %v", err)
	}
	for name, m := range map[string]webhookMsg{
		"empty id":    {RegionID: ""},
		"text id":     {RegionID: "12a"},
		"long id":     {RegionID: flexID(strings.Repeat("1", 17))},
		"long type":   {RegionID: "1", AlarmType: strings.Repeat("A", 33)},
		"many levels": {RegionID: "1", ActiveAlertLevels: make([]Level, 65)},
	} {
		if validate(&m) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if got := clean("a\nb\r\x1b[31mc", 100); strings.ContainsAny(got, "\n\r\x1b") {
		t.Fatalf("clean left control chars: %q", got)
	}
}

func TestLogLimiter(t *testing.T) {
	l := &logLimiter{window: time.Minute, burst: 3}
	now := time.Now()
	n := 0
	for i := 0; i < 100; i++ {
		if ok, _ := l.allow(now); ok {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("allowed %d", n)
	}
	ok, sup := l.allow(now.Add(time.Minute))
	if !ok || sup != 97 {
		t.Fatalf("next window ok=%v suppressed=%d", ok, sup)
	}
}

func TestStateCloseNoPanic(t *testing.T) {
	q := make(chan Event, 10)
	s := NewState(q, 10)
	ch, _, _ := s.Subscribe(0, 0)
	s.Close()
	close(q) // як при зупинці: черга БД закрита
	if _, ok := <-ch; ok {
		t.Fatal("subscriber not closed")
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("apply after close panicked: %v", r)
		}
	}()
	s.Apply(Event{RegionID: "1", AlarmType: "AIR", Active: []Level{lv("Red", "x")}})
	s.Reconcile(map[key][]Level{{"2", "AIR"}: {lv("Red", "")}}, time.Time{}, time.Now(), time.Second, "poll", true)
}

func TestRegionBackfill(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "b.db"), 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	ev := Event{Seq: 1, ReceivedAt: at(0), CreatedAt: at(0), RegionID: "1234", AlarmType: "AIR", Status: "ACTIVATE",
		Active: []Level{lv("Red", "x")}, Change: ChangeStart, Source: "webhook", SessionFrom: at(0), MaxLevel: "Red"}
	if err := st.writeBatch([]Event{ev}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveRegions(map[string]Region{"1234": {ID: "1234", Name: "Громада", StateID: "4", ParentID: "44", Depth: 2}}); err != nil {
		t.Fatal(err)
	}
	for _, tb := range []string{"events", "sessions", "active_state"} {
		if n := count(st.db, `SELECT COUNT(*) FROM `+tb+` WHERE state_id='4'`); n != 1 {
			t.Fatalf("%s not backfilled: %d", tb, n)
		}
	}
}

// Ключ ukrainealarm недоступний на старті: сервіс усе одно стартує, звіряє стан,
// webhook отримують 401, доки ключ не завантажиться у фоні.
func TestStartWithoutKey(t *testing.T) {
	bin := os.Getenv("ALERTD_BIN")
	if bin == "" {
		t.Skip("ALERTD_BIN not set")
	}
	h := newHarnessOpt(t, 2) // перші дві спроби отримати ключ — 503
	db := h.db()
	h.waitFor("startup sync without key", func() bool { return count(db, `SELECT COUNT(*) FROM active_state`) == 2 })
	h.waitFor("key loaded in background", func() bool {
		resp, err := http.Get(h.localURL + "/health")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var v struct{ Key bool }
		json.NewDecoder(resp.Body).Decode(&v)
		return v.Key
	})
	b := hookBody("Activate", 14, "AIR", time.Now(), "Red", "x", lv("Red", "x"))
	if code, _ := h.post(b, sign(h.key, time.Now().Unix(), b)); code != 200 {
		t.Fatalf("after key load: %d\n%s", code, h.logBuf.String())
	}
	// Журнал не має містити сирих керівних символів із чужих запитів.
	evil := []byte(`{"status":"Activate","regionId":14}`)
	hd := sign(testKey(t), time.Now().Unix(), evil)
	for i := 0; i < 50; i++ {
		h.post(evil, hd)
	}
	logs := h.logBuf.String()
	if n := strings.Count(logs, "rejected webhook"); n > 10 {
		t.Fatalf("reject log not rate-limited: %d lines", n)
	}
}

// TestPublicSurface — усе, що панель передає на alertd з інтернету.
func TestPublicSurface(t *testing.T) {
	h := newHarness(t)
	base := strings.TrimSuffix(h.hookURL, "/hook/"+h.secret)
	do := func(method, url string, body io.Reader, cl int64) (*http.Response, []byte) {
		req, _ := http.NewRequest(method, url, body)
		if cl >= 0 {
			req.ContentLength = cl
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, url, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}
	resp, b := do("GET", base+"/", nil, -1)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "Тут тихо.") || !strings.Contains(string(b), `data-code="200"`) ||
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") ||
		resp.Header.Get("X-Robots-Tag") == "" {
		t.Fatalf("stub: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, b := do("HEAD", base+"/", nil, -1); resp.StatusCode != 200 || len(b) != 0 {
		t.Fatalf("HEAD stub: %d len=%d", resp.StatusCode, len(b))
	}
	for _, c := range []struct{ m, path string }{
		{"POST", "/"}, {"GET", "/hook/" + h.secret}, {"PUT", "/hook/" + h.secret}, {"GET", "/index.html"},
		{"GET", "/stats"}, {"GET", "/events"}, {"POST", "/hook/" + h.secret + "/x"}, {"POST", "/hook/"},
	} {
		if resp, b := do(c.m, base+c.path, strings.NewReader("{}"), -1); resp.StatusCode != 404 || !strings.Contains(string(b), `data-code="404"`) {
			t.Errorf("%s %s: %d, want 404 page", c.m, c.path, resp.StatusCode)
		}
	}
	// Заявлене завелике тіло — відмова до читання.
	t0 := time.Now()
	big := bytes.Repeat([]byte("x"), 1<<20)
	if resp, _ := do("POST", h.hookURL, bytes.NewReader(big), int64(len(big))); resp.StatusCode != 413 {
		t.Fatalf("big body with length: %d", resp.StatusCode)
	}
	// Без Content-Length (chunked) — обрізається на 256 КБ.
	if resp, _ := do("POST", h.hookURL, io.MultiReader(bytes.NewReader(big)), 0); resp.StatusCode != 413 {
		t.Fatalf("big chunked body: %d", resp.StatusCode)
	}
	t.Logf("oversize rejections took %s", time.Since(t0).Round(time.Millisecond))
}

// API з лімітом «1 запит на вікно», як у ukrainealarm: alertd має вкластися без жодного 429,
// а ключ береться з файлу, навіть якщо сервер ключа відповідає 403 (як із VPS).
func TestRateLimitAndPinnedKey(t *testing.T) {
	if os.Getenv("ALERTD_BIN") == "" {
		t.Skip("ALERTD_BIN not set")
	}
	keyFile := filepath.Join(t.TempDir(), "pub.pem")
	h := newHarnessOpt(t, 0, func(h *harness) {
		h.api.limit, h.api.window = 1, 2*time.Second
		h.api.pem403.Store(true)
		os.WriteFile(keyFile, h.api.pem, 0o644)
		h.extraEnv = []string{"PUBKEY_FILE=" + keyFile, "POLL_INTERVAL=1s", "API_MIN_GAP=2100ms"}
	})
	db := h.db()
	h.waitFor("startup sync under 1-per-window limit", func() bool { return count(db, `SELECT COUNT(*) FROM active_state`) == 2 })
	time.Sleep(7 * time.Second) // кілька циклів звірки
	total, got429 := h.api.apiTotal.Load(), h.api.api429.Load()
	t.Logf("startup + 7 s: %d API requests, %d got 429", total, got429)
	if got429 != 0 {
		t.Fatalf("alertd exceeded the API limit: %d × 429\n%s", got429, h.logBuf.String())
	}
	// Перезапуск одразу після запиту до API: новий процес пам'ятає час останнього запиту
	// (БД) і не порушує ліміт — жодного 429.
	for i := 0; i < 3; i++ {
		h.stop()
		h.start()
		if i == 0 { // check одразу після старту: ✓ або ⚠ (служба чекає черги до API), але не ✗
			cmd := exec.Command(os.Getenv("ALERTD_BIN"), "check")
			cmd.Env = append(h.env, "PUBLIC_HOOK_URL=", "ENV_FILE=/nonexistent")
			out, err := cmd.CombinedOutput()
			if err != nil || strings.Contains(string(out), "✗") || !strings.Contains(string(out), " API (зі служби)") {
				t.Fatalf("check right after restart: %v\n%q", err, out)
			}
		}
		time.Sleep(2500 * time.Millisecond)
	}
	if n := h.api.api429.Load(); n != 0 {
		t.Fatalf("429 after restart: %d\n%s", n, h.logBuf.String())
	}
	// Пропущений webhook (тривога лише в знімку) підхоплюється наступною звіркою.
	h.api.mu.Lock()
	h.api.alerts = append(h.api.alerts, apiAlertRegion{RegionID: "7", ActiveAlerts: []apiAlert{{RegionID: "7", Type: "AIR",
		Levels: []Level{{Level: "Red", Reason: "missed", CreatedAt: flexTime{time.Now().UTC()}}}}}})
	h.api.mu.Unlock()
	h.waitFor("missed alert via periodic sync", func() bool { return count(db, `SELECT COUNT(*) FROM active_state WHERE region_id='7'`) == 1 })
	b := hookBody("Activate", 14, "AIR", time.Now(), "Red", "x", lv("Red", "x"))
	if code, _ := h.post(b, sign(h.key, time.Now().Unix(), b)); code != 200 {
		t.Fatalf("pinned key not used: %d\n%s", code, h.logBuf.String())
	}
}

// alertd check при запущеній службі не робить жодного запиту до API.
func TestCheckUsesService(t *testing.T) {
	if os.Getenv("ALERTD_BIN") == "" {
		t.Skip("ALERTD_BIN not set")
	}
	h := newHarness(t)
	db := h.db()
	h.waitFor("startup", func() bool { return count(db, `SELECT COUNT(*) FROM active_state`) == 2 })
	time.Sleep(1500 * time.Millisecond) // дочекатися хоча б одного опитування статусу
	before := h.api.apiTotal.Load()
	cmd := exec.Command(os.Getenv("ALERTD_BIN"), "check")
	cmd.Env = append(h.env, "PUBLIC_HOOK_URL=") // публічну адресу тут не перевіряємо
	out, err := cmd.CombinedOutput()
	after := h.api.apiTotal.Load()
	t.Logf("check output:\n%s", out)
	if err != nil || !strings.Contains(string(out), "✓ API (зі служби)") {
		t.Fatalf("check via service failed: %v", err)
	}
	// служба сама може зробити 1–2 опитування за цей час, але не 3 запити check
	if after-before > 2 {
		t.Fatalf("check hit the API directly: %d requests", after-before)
	}
}

// Очікування черги довше за тайм-аут виклику не має ламати наступні запити.
func TestQueueWaitLongerThanCallerTimeout(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"lastActionIndex":1}`))
	}))
	defer srv.Close()
	u := NewUpstream(srv.URL, "t")
	u.SetMinGap(400 * time.Millisecond)
	if _, err := u.Status(context.Background()); err != nil { // займає слот
		t.Fatal(err)
	}
	// Кілька викликів із коротким тайм-аутом, які не дочікуються слоту, — не мають відсувати чергу.
	for i := 0; i < 5; i++ {
		ctx, c := context.WithTimeout(context.Background(), 50*time.Millisecond)
		if _, err := u.Status(ctx); err == nil {
			t.Fatal("expected timeout while queued")
		}
		c()
	}
	t0 := time.Now()
	if _, err := u.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > 600*time.Millisecond {
		t.Fatalf("queue drifted: next call waited %s (want ≤ ~400ms)", d)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits=%d", hits.Load())
	}
}

// Кілька циклів звірки при незмінних даних (з повторами в /alerts) — жодної події від звірки.
func TestNoPollChurn(t *testing.T) {
	if os.Getenv("ALERTD_BIN") == "" {
		t.Skip("ALERTD_BIN not set")
	}
	h := newHarness(t)
	db := h.db()
	h.waitFor("startup", func() bool { return count(db, `SELECT COUNT(*) FROM active_state`) == 2 })
	before := h.api.apiTotal.Load()
	time.Sleep(4 * time.Second) // POLL_INTERVAL=1s у тестах → кілька звірок
	if h.api.apiTotal.Load()-before < 3 {
		t.Fatal("sync did not run")
	}
	if n := count(db, `SELECT COUNT(*) FROM events WHERE source='poll'`); n != 0 {
		t.Fatalf("%d spurious poll events with unchanged data", n)
	}
	var lv int
	db.QueryRow(`SELECT json_array_length(active) FROM active_state WHERE region_id='3100'`).Scan(&lv)
	if lv != 1 {
		t.Fatalf("district alert stored with %d levels", lv)
	}
}
