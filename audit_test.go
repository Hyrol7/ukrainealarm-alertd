package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// №1. Виправлення звірки — лише кандидат у пропуск; webhook протягом missGrace його знімає.
func TestMissOnlyWhenWebhookNeverComes(t *testing.T) {
	u := newUnitSrv(t, true)
	t0 := time.Now()
	fixes := []Event{{RegionID: "1", AlarmType: "AIR"}, {RegionID: "2", AlarmType: "AIR"}}
	u.srv.notePending(fixes, t0)
	// для регіону 1 webhook таки прийшов (через HTTP, як насправді)
	b := hookBody("Activate", 1, "AIR", time.Now(), "Red", "", lv("Red", ""))
	if code, _ := u.send(t, "POST", u.url, b, sign(u.key, time.Now().Unix(), b)); code != 200 {
		t.Fatal(code)
	}
	if n := u.srv.expirePending(t0.Add(time.Minute)); n != 0 {
		t.Fatalf("expired too early: %d", n)
	}
	if n := u.srv.expirePending(t0.Add(missGrace)); n != 1 || u.srv.misses.Load() != 1 || u.srv.lastMissUnix.Load() == 0 {
		t.Fatalf("misses after grace: n=%d total=%d", n, u.srv.misses.Load())
	}
	// індикатор: свіжий пропуск після останнього webhook → жовта крапка webhook
	u.srv.lastSyncUnix.Store(time.Now().Unix())
	u.srv.lastHookUnix.Store(time.Now().Add(-time.Minute).Unix())
	u.srv.lastMissUnix.Store(time.Now().Unix())
	if h := u.srv.health(time.Now()); h.Hook != "warn" {
		t.Fatalf("health after a real miss: %+v", h)
	}
	// без пропусків, лише «випередження» звіркою — зелена
	u.srv.lastMissUnix.Store(0)
	u.srv.notePending(fixes[:1], time.Now())
	b = hookBody("DEACTIVATE", 1, "AIR", time.Now().Add(time.Second), "Red", "")
	u.send(t, "POST", u.url, b, sign(u.key, time.Now().Unix(), b))
	u.srv.expirePending(time.Now().Add(missGrace))
	if h := u.srv.health(time.Now()); h.Hook != "ok" {
		t.Fatalf("sync-first but webhook later must stay ok: %+v", h)
	}
}

// №2. Стартова звірка не перезаписує webhook, отриманий під час завантаження знімка.
func TestStrictStartupKeepsWebhookDuringFetch(t *testing.T) {
	q := make(chan Event, 100)
	s := NewState(q, 10)
	fetchStart := time.Now()
	s.Apply(Event{ReceivedAt: flexTime{fetchStart.Add(100 * time.Millisecond)}, CreatedAt: flexTime{time.Now()},
		RegionID: "1", AlarmType: "AIR", Active: []Level{lv("Red", "")}, Source: "webhook"})
	// відновлений з БД запис (SeenAt нульовий) — strict його виправляє
	s.Restore("2", "AIR", []Level{lv("Yellow", "")}, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour), "Yellow", nil)
	fixes := s.Reconcile(map[key][]Level{}, time.Time{}, fetchStart, time.Second, "startup", true)
	if hasRegion(fixes, "1") {
		t.Fatal("startup sync overwrote a webhook received during the fetch")
	}
	if !hasRegion(fixes, "2") {
		t.Fatal("startup sync did not correct a restored entry")
	}
}

// №3. Час із «майбутнього» від джерела не блокує регіон.
func TestFutureTimestampsDoNotBlock(t *testing.T) {
	q := make(chan Event, 100)
	s := NewState(q, 10)
	now := time.Now().UTC()
	future := now.Add(2 * time.Hour)
	// знімок із рівнем із майбутнього
	s.Reconcile(map[key][]Level{{"9", "AIR"}: {lvAt("Red", future)}}, future, now, time.Second, "poll", false)
	if s.watermark.After(now.Add(time.Second)) {
		t.Fatalf("watermark jumped to the future: %v", s.watermark)
	}
	// webhook із майбутнім createdAt
	s.Apply(Event{ReceivedAt: flexTime{now}, CreatedAt: flexTime{future}, RegionID: "1", AlarmType: "AIR",
		Active: []Level{lv("Yellow", "")}, Source: "webhook"})
	// наступний справжній webhook за 10 с має застосуватися
	ev := s.Apply(Event{ReceivedAt: flexTime{now.Add(10 * time.Second)}, CreatedAt: flexTime{now.Add(10 * time.Second)},
		RegionID: "1", AlarmType: "AIR", Source: "webhook"})
	if ev.Change != ChangeEnd {
		t.Fatalf("region blocked by a future timestamp: %s", ev.Change)
	}
	// звичайний webhook у тому ж регіоні після знімка з майбутнього
	ev = s.Apply(Event{ReceivedAt: flexTime{now.Add(20 * time.Second)}, CreatedAt: flexTime{now.Add(20 * time.Second)},
		RegionID: "9", AlarmType: "AIR", Source: "webhook"})
	if ev.Change != ChangeEnd {
		t.Fatalf("snapshot-region blocked: %s", ev.Change)
	}
}

// №4. Нормалізація рівнів: регістр, повтори, невідомі й порожні назви.
func TestLevelNormalization(t *testing.T) {
	for _, c := range []struct {
		a, b []Level
		same bool
	}{
		{[]Level{{Level: "red"}}, []Level{{Level: "Red"}}, true},
		{[]Level{{Level: "Red"}, {Level: "RED"}}, []Level{{Level: "Red"}}, true},
		{[]Level{{Level: "Red", Reason: "a"}}, []Level{{Level: "Red", Reason: "b"}}, false},
		{[]Level{{Level: "Orange"}, {Level: "Blue"}}, []Level{{Level: "Blue"}, {Level: "Orange"}}, true},
		{[]Level{{Level: "Yellow"}, {Level: "Red"}}, []Level{{Level: "Red"}}, false},
	} {
		if got := sameLevels(canonLevels(c.a), canonLevels(c.b)); got != c.same {
			t.Errorf("%v vs %v: %v", c.a, c.b, got)
		}
	}
	// порожня назва з причиною — тривога лишається активною з рівнем Unknown
	q := make(chan Event, 10)
	s := NewState(q, 10)
	ev := s.Apply(Event{ReceivedAt: flexTime{time.Now()}, RegionID: "1", AlarmType: "AIR", Active: []Level{{Level: "", Reason: "x"}}, Source: "webhook"})
	if ev.Change != ChangeStart || strings.Join(ev.Levels, ",") != "Unknown" {
		t.Fatalf("unknown level: %s %v", ev.Change, ev.Levels)
	}
	if levelRank("Unknown") >= levelRank("Yellow") {
		t.Fatal("Unknown must rank below Yellow and Red")
	}
	// і порядок у множині: Red, Yellow, далі невідомі
	if got := strings.Join(levelSet([]Level{{Level: "x"}, {Level: "yellow"}, {Level: "red"}}), ","); got != "Red,Yellow,x" {
		t.Fatalf("levelSet order: %s", got)
	}
}

// №5. Загрози, з якими тривога почалась, мають той самий початок, що й тривога (навіть коли її знайшла звірка).
func TestLevelStartEqualsSessionStart(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "l.db"), 100)
	if err != nil {
		t.Fatal(err)
	}
	go st.Run()
	s := NewState(st.Queue(), 10)
	alertStart := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	s.Reconcile(map[key][]Level{{"1", "AIR"}: {lvAt("Red", alertStart)}}, alertStart, time.Now(), time.Second, "poll", false)
	s.Close()
	st.Close()
	db, _ := sqlOpenRO(t, st)
	var sess, lvl int64
	db.QueryRow(`SELECT started_ms FROM sessions`).Scan(&sess)
	db.QueryRow(`SELECT started_ms FROM level_sessions`).Scan(&lvl)
	if sess != alertStart.UnixMilli() || lvl != sess {
		t.Fatalf("session %d, level %d, want %d", sess, lvl, alertStart.UnixMilli())
	}
}

// №6. Повтор перехопленого webhook одразу після перезапуску — дублікат.
func TestReplayAfterRestartIsDuplicate(t *testing.T) {
	h := newHarness(t)
	db := h.db()
	h.waitFor("startup", func() bool { return count(db, `SELECT COUNT(*) FROM active_state`) == 2 })
	b := hookBody("Activate", 14, "AIR", time.Now(), "Red", "", lv("Red", ""))
	hd := sign(h.key, time.Now().Unix(), b)
	if code, _ := h.post(b, hd); code != 200 {
		t.Fatal("first")
	}
	h.waitFor("in db", func() bool { return count(db, `SELECT COUNT(*) FROM events WHERE region_id='14'`) == 1 })
	h.stop()
	h.start()
	time.Sleep(300 * time.Millisecond)
	req, _ := http.NewRequest("POST", h.hookURL, strings.NewReader(string(b)))
	for k, v := range hd {
		req.Header[k] = v
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "dup" {
		t.Fatalf("replay after restart: %d %q", resp.StatusCode, body)
	}
}

// №7. Токен не йде за перенаправленням.
func TestUpstreamDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		w.Write([]byte(`[]`))
	}))
	defer evil.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer api.Close()
	u := NewUpstream(api.URL, "secret-token")
	if _, _, err := u.Alerts(context.Background()); err == nil {
		t.Fatal("redirect accepted as a valid answer")
	}
	if leaked.Load() {
		t.Fatal("token sent to the redirect target")
	}
}

// №7–9. Налаштування, які могли б щось відкрити назовні.
func TestValidateConfig(t *testing.T) {
	good := Config{HookSecret: strings.Repeat("ab", 24), LocalListen: "127.0.0.1:8788", APIBase: "https://api.ukrainealarm.com",
		SyncInterval: 90 * time.Second, APIMinGap: 61 * time.Second}
	if err := validateConfig(good); err != nil {
		t.Fatalf("good config: %v", err)
	}
	for name, f := range map[string]func(*Config){
		"short secret":      func(c *Config) { c.HookSecret = "abc" },
		"secret with /":     func(c *Config) { c.HookSecret = strings.Repeat("a", 30) + "/x" },
		"secret with ?":     func(c *Config) { c.HookSecret = strings.Repeat("a", 30) + "?x" },
		"public local api":  func(c *Config) { c.LocalListen = "0.0.0.0:8788" },
		"external local":    func(c *Config) { c.LocalListen = "203.0.113.10:8788" },
		"wildcard local":    func(c *Config) { c.LocalListen = ":8788" },
		"plain http api":    func(c *Config) { c.APIBase = "http://api.ukrainealarm.com" },
		"garbage api":       func(c *Config) { c.APIBase = "::" },
		"too frequent sync": func(c *Config) { c.SyncInterval = 100 * time.Millisecond },
		"long site title":   func(c *Config) { c.SiteTitle = strings.Repeat("я", 65) },
		"control in title":  func(c *Config) { c.SiteTitle = "a\nb" },
	} {
		c := good
		f(&c)
		if validateConfig(c) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, ok := range []string{"localhost:1", "[::1]:8788", "127.0.0.5:9"} {
		c := good
		c.LocalListen = ok
		if err := validateConfig(c); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	c := good
	c.APIBase = "http://127.0.0.1:18080" // лише для тестів
	if validateConfig(c) != nil {
		t.Error("loopback http rejected")
	}
}

// №10. Одна «погана» подія не губить решту пачки.
func TestBadEventDoesNotDropBatch(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "b.db"), 100)
	if err != nil {
		t.Fatal(err)
	}
	st.db.Exec(`CREATE TRIGGER boom BEFORE INSERT ON events WHEN NEW.region_id = 'bad' BEGIN SELECT RAISE(ABORT, 'boom'); END`)
	for i := 1; i <= 10; i++ {
		r := fmt.Sprint(i)
		if i == 5 {
			r = "bad"
		}
		st.Queue() <- Event{Seq: int64(i), ReceivedAt: flexTime{time.Now()}, RegionID: r, AlarmType: "AIR", Change: ChangeNone, Source: "webhook"}
	}
	go st.Run()
	deadline := time.Now().Add(10 * time.Second)
	for st.written.Load()+st.dropped.Load() < 10 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if st.written.Load() != 9 || st.dropped.Load() != 1 {
		t.Fatalf("written=%d dropped=%d", st.written.Load(), st.dropped.Load())
	}
	st.Close()
}

// №12. Потік подій: без хибного resync, ліміт підписників атомарний.
func TestSSENoSpuriousResyncAndLimit(t *testing.T) {
	q := make(chan Event, 1000)
	s := NewState(q, 100)
	for i := 0; i < 3; i++ {
		s.Apply(Event{ReceivedAt: flexTime{time.Now()}, RegionID: fmt.Sprint(i), AlarmType: "AIR", Active: []Level{lv("Red", "")}, Source: "webhook"})
	}
	cfg := Config{HookSecret: strings.Repeat("a", 24), SyncInterval: 90 * time.Second}
	srv := NewServer(cfg, s, &Store{queue: make(chan Event, 1)}, NewVerifier(nil, time.Minute, nil))
	hs := httptest.NewServer(srv.LocalHandler())
	defer hs.Close()
	// клієнт знає актуальний seq=3 → жодного resync, перша подія — нова
	go func() {
		time.Sleep(200 * time.Millisecond)
		s.Apply(Event{ReceivedAt: flexTime{time.Now()}, RegionID: "9", AlarmType: "AIR", Active: []Level{lv("Red", "")}, Source: "webhook"})
	}()
	evs := readSSE(t, hs.URL+"/events?after=3", nil, 1, 3*time.Second)
	if len(evs) != 1 || strings.Contains(evs[0], "resync") || !strings.Contains(evs[0], "id: 4") {
		t.Fatalf("got %v", evs)
	}
	// ліміт: 64 підписники, 65-й — 503. Спершу дочекатися, поки сервер відпустить
	// попереднього клієнта (від'єднання він помічає асинхронно).
	for deadline := time.Now().Add(3 * time.Second); s.Subscribers() != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("previous subscriber not released: %d", s.Subscribers())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < maxSubscribers; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", hs.URL+"/events", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("subscriber %d: %v", i, err)
		}
		defer resp.Body.Close()
	}
	resp, err := http.Get(hs.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("65th subscriber: %d", resp.StatusCode)
	}
}

// Відповіді API, з якими ми не впораємося, не ламають стан.
func TestUpstreamGarbage(t *testing.T) {
	for name, body := range map[string]string{
		"html":      "<html>oops</html>",
		"truncated": `[{"regionId":"1","activeAlerts":[{"regionId":"1","type":"AIR"`,
		"object":    `{"error":"x"}`,
		"huge ids":  `[{"regionId":"` + strings.Repeat("9", 5000) + `","activeAlerts":[]}]`,
		"null":      `null`,
		"spaces":    "  \n ",
	} {
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		u := NewUpstream(api.URL, "t")
		snap, _, err := u.Alerts(context.Background())
		api.Close()
		if name == "huge ids" {
			if err != nil || len(snap) != 0 {
				t.Errorf("%s: %v %v", name, err, snap)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: garbage accepted as a snapshot (%d entries)", name, len(snap))
		}
	}
	// 5xx і порожня відповідь — помилка, а не «тривог немає»
	for _, code := range []int{500, 502, 503} {
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		u := NewUpstream(api.URL, "t")
		if _, _, err := u.Alerts(context.Background()); err == nil {
			t.Errorf("HTTP %d accepted", code)
		}
		api.Close()
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer api.Close()
	if snap, _, err := NewUpstream(api.URL, "t").Alerts(context.Background()); err == nil {
		t.Errorf("empty 200 body treated as 'no alerts' (%d)", len(snap))
	}
}

var _ = json.Marshal
var _ = os.Getenv
var _ sql.DB

// Знімок, що раптом прибирає більшість тривог (збій API), застосовується лише після підтвердження.
func TestMassEndNeedsConfirmation(t *testing.T) {
	q := make(chan Event, 1000)
	s := NewState(q, 10)
	old := time.Now().Add(-time.Hour)
	for i := 0; i < 30; i++ {
		s.Apply(Event{ReceivedAt: flexTime{old}, CreatedAt: flexTime{old}, RegionID: fmt.Sprint(100 + i), AlarmType: "AIR",
			Active: []Level{lv("Red", "")}, Source: "webhook"})
	}
	partial := map[key][]Level{{"100", "AIR"}: {lv("Red", "")}, {"999", "AIR"}: {lv("Yellow", "")}}
	fixes := s.Reconcile(partial, time.Time{}, time.Now(), time.Second, "poll", false)
	if len(fixes) != 1 || fixes[0].RegionID != "999" || fixes[0].Change != ChangeStart {
		t.Fatalf("first suspicious snapshot: %d fixes (new alerts must still apply, mass end must wait)", len(fixes))
	}
	if _, items := s.Snapshot(); len(items) != 31 {
		t.Fatalf("alerts ended on an unconfirmed snapshot: %d left", len(items))
	}
	// підтвердження наступним знімком — застосовується
	fixes = s.Reconcile(partial, time.Time{}, time.Now(), time.Second, "poll", false)
	if len(fixes) != 29 {
		t.Fatalf("confirmed mass end: %d fixes", len(fixes))
	}
	// дрібні відбої (≤10) застосовуються одразу
	for i := 0; i < 5; i++ {
		s.Apply(Event{ReceivedAt: flexTime{old}, CreatedAt: flexTime{old}, RegionID: fmt.Sprint(200 + i), AlarmType: "AIR",
			Active: []Level{lv("Red", "")}, Source: "webhook"})
	}
	if fixes = s.Reconcile(partial, time.Time{}, time.Now(), time.Second, "poll", false); len(fixes) != 5 {
		t.Fatalf("small end delayed: %d", len(fixes))
	}
}

// №1 наскрізно: звірка випередила webhook (як у реальних даних) — це не пропуск.
func TestSyncAheadOfWebhookIsNotAMiss(t *testing.T) {
	u := newUnitSrv(t, true)
	created := time.Now().UTC().Add(-2 * time.Second)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]apiAlertRegion{{RegionID: "7", ActiveAlerts: []apiAlert{
			{RegionID: "7", Type: "AIR", Levels: []Level{lvAt("Yellow", created)}}}}})
	}))
	defer api.Close()
	if err := u.srv.fullSync(context.Background(), NewUpstream(api.URL, "t"), "poll", false); err != nil {
		t.Fatal(err)
	}
	if u.srv.lastMissUnix.Load() != 0 {
		t.Fatal("sync fix counted as a miss immediately")
	}
	// webhook про ту саму тривогу приходить через кілька секунд
	b := hookBody("Activate", 7, "AIR", created, "Yellow", "", lvAt("Yellow", created))
	u.send(t, "POST", u.url, b, sign(u.key, time.Now().Unix(), b))
	u.srv.expirePending(time.Now().Add(missGrace))
	if u.srv.lastMissUnix.Load() != 0 || u.srv.misses.Load() != 0 {
		t.Fatal("webhook arrived, still counted as a miss")
	}
}

// Повільні й зловмисні клієнти на справжньому бінарнику: не тримають з'єднання вічно.
func TestHostileClients(t *testing.T) {
	h := newHarness(t)
	addr := strings.TrimPrefix(strings.Split(h.hookURL, "/hook/")[0], "http://")
	// slowloris: заголовки не дописуються — сервер закриває з'єднання (ReadHeaderTimeout 5 с)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("POST /hook/" + h.secret + " HTTP/1.1\\r\\nHost: x\\r\\n"))
	t0 := time.Now()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	io.ReadAll(c)
	c.Close()
	if d := time.Since(t0); d > 8*time.Second {
		t.Fatalf("slowloris held for %s", d)
	}
	// величезні заголовки — 431, а не читання без кінця
	req, _ := http.NewRequest("GET", strings.Split(h.hookURL, "/hook/")[0]+"/", nil)
	req.Header.Set("X-Big", strings.Repeat("a", 64<<10))
	resp, err := h.client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != 431 {
			t.Fatalf("64 KB header: %d", resp.StatusCode)
		}
	}
	// після всього цього сервіс жвавий
	b := hookBody("Activate", 14, "AIR", time.Now(), "Red", "", lv("Red", ""))
	if code, d := h.post(b, sign(h.key, time.Now().Unix(), b)); code != 200 || d > time.Second {
		t.Fatalf("after hostile clients: %d in %s", code, d)
	}
}

// БД відмовляє писати — webhook однаково отримують 200 швидко, стан у пам'яті актуальний,
// роздавальник (потік подій) отримує події; втрати видно в статистиці.
func TestDatabaseFailureKeepsServing(t *testing.T) {
	u := newUnitSrv(t, true)
	u.store.db.Exec(`CREATE TRIGGER deny BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'disk full'); END`)
	ch, _, _ := u.state.Subscribe(0, 0)
	for i := 0; i < 20; i++ {
		b := hookBody("Activate", 100+i, "AIR", time.Now(), "Red", "", lv("Red", ""))
		t0 := time.Now()
		code, _ := u.send(t, "POST", u.url, b, sign(u.key, time.Now().Unix(), b))
		if code != 200 || time.Since(t0) > 500*time.Millisecond {
			t.Fatalf("webhook %d during db failure: %d in %s", i, code, time.Since(t0))
		}
	}
	got := 0
	for got < 20 {
		select {
		case <-ch:
			got++
		case <-time.After(2 * time.Second):
			t.Fatalf("subscriber got %d of 20 events", got)
		}
	}
	if _, items := u.state.Snapshot(); len(items) != 20 {
		t.Fatalf("state: %d", len(items))
	}
	deadline := time.Now().Add(15 * time.Second)
	for u.store.dropped.Load() < 20 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if u.store.dropped.Load() != 20 || u.store.lastErr.Load().(string) == "" {
		t.Fatalf("dropped=%d lastErr=%v", u.store.dropped.Load(), u.store.lastErr.Load())
	}
}

// SITE_TITLE потрапляє у вкладку головної й сторінок помилок і завжди екранується.
func TestSiteTitle(t *testing.T) {
	defer SetSiteTitle("")
	page := func() string {
		rec := httptest.NewRecorder()
		errorPage(rec, httptest.NewRequest("GET", "/x", nil), http.StatusNotFound)
		return rec.Body.String()
	}
	if !strings.Contains(page(), "<title>Тут нічого немає.</title>") {
		t.Fatal("default title must be the neutral page heading")
	}
	SetSiteTitle(`<script>x</script>&"`)
	b := page()
	if strings.Contains(b, "<script>x") || !strings.Contains(b, "<title>&lt;script&gt;x&lt;/script&gt;&amp;&#34;</title>") {
		t.Fatalf("title not escaped: %s", b)
	}
	u := newUnitSrv(t, true)
	rec := httptest.NewRecorder()
	u.srv.HookHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rec.Body.String(), "<title>&lt;script&gt;") {
		t.Fatal("index page ignores SITE_TITLE")
	}
}

// hello першою подією; epoch — однаковий у /state, /stats і hello, зберігається між
// перезапусками тієї самої БД і відрізняється в новій БД.
func TestSSEHelloAndEpoch(t *testing.T) {
	dir := t.TempDir()
	open := func() *Store {
		st, err := OpenStore(filepath.Join(dir, "e.db"), 16)
		if err != nil {
			t.Fatal(err)
		}
		go st.Run()
		return st
	}
	st := open()
	e1 := st.Epoch()
	if len(e1) != 16 {
		t.Fatalf("epoch %q", e1)
	}
	st.Close()
	st = open()
	if st.Epoch() != e1 {
		t.Fatalf("epoch changed across restart: %s → %s", e1, st.Epoch())
	}
	st.Close()
	other, err := OpenStore(filepath.Join(t.TempDir(), "o.db"), 16)
	if err != nil {
		t.Fatal(err)
	}
	go other.Run()
	if other.Epoch() == e1 {
		t.Fatal("new db must get a new epoch")
	}
	other.Close()

	u := newUnitSrv(t, true)
	ls := httptest.NewServer(u.srv.LocalHandler())
	defer ls.Close()
	evs := readSSEx(t, ls.URL+"/events", nil, 1, 3*time.Second, true)
	want := fmt.Sprintf(`event: hello
data: {"api":1,"epoch":%q,"seq":`, u.srv.store.Epoch())
	if len(evs) != 1 || !strings.HasPrefix(evs[0], want) {
		t.Fatalf("hello: %v (want prefix %s)", evs, want)
	}
	resp, err := http.Get(ls.URL + "/state")
	if err != nil {
		t.Fatal(err)
	}
	var stv struct {
		API   int    `json:"api"`
		Epoch string `json:"epoch"`
	}
	json.NewDecoder(resp.Body).Decode(&stv)
	resp.Body.Close()
	if stv.API != 1 || stv.Epoch != u.srv.store.Epoch() {
		t.Fatalf("/state api/epoch: %+v", stv)
	}
}

// POLL_INTERVAL — частота опитування API; типово 61 с.
func TestPollIntervalConfig(t *testing.T) {
	t.Setenv("POLL_INTERVAL", "2m")
	if got := loadConfig().SyncInterval; got != 2*time.Minute {
		t.Fatalf("POLL_INTERVAL ignored: %s", got)
	}
	t.Setenv("POLL_INTERVAL", "")
	if got := loadConfig().SyncInterval; got != 61*time.Second {
		t.Fatalf("default: %s", got)
	}
}

// Пауза через ліміт і «щойно запустилась» — не помилки для check і /stats.
func TestRateLimitIsNotUpstreamError(t *testing.T) {
	u := newUnitSrv(t, true)
	u.srv.setUpstreamErr(&RateLimitError{Until: time.Now().Add(time.Second)})
	if e := u.srv.upstreamErr.Load(); e != "" {
		t.Fatalf("rate limit stored as error: %v", e)
	}
	u.srv.setUpstreamErr(errors.New("boom"))
	if e := u.srv.upstreamErr.Load(); e != "boom" {
		t.Fatalf("real error lost: %v", e)
	}
	var se *startingError
	if !errors.As(error(&startingError{wait: time.Second}), &se) {
		t.Fatal("startingError not detectable")
	}
}
