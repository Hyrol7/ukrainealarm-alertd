package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- спільне: сервер у процесі (без бінарника) ----------

type unitSrv struct {
	srv   *Server
	state *State
	store *Store
	key   *rsa.PrivateKey
	http  *httptest.Server
	url   string // …/hook/<secret>
}

func newUnitSrv(t testing.TB, withKey bool) *unitSrv {
	t.Helper()
	st, err := OpenStore(filepath.Join(t.TempDir(), "u.db"), 65536)
	if err != nil {
		t.Fatal(err)
	}
	go st.Run()
	state := NewState(st.Queue(), 1000)
	state.SetRegions(map[string]Region{"14": {ID: "14", Name: "Київська область", StateID: "14", Type: "State"}})
	state.SetHookTrust(2 * time.Minute)
	k := testKey(t)
	v := NewVerifier(nil, 5*time.Minute, nil)
	if withKey {
		v.SetKey(&k.PublicKey)
	}
	cfg := Config{HookSecret: "0123456789abcdef0123456789abcdef0123456789abcdef", SyncInterval: 90 * time.Second}
	srv := NewServer(cfg, state, st, v)
	hs := httptest.NewUnstartedServer(srv.HookHandler())
	hs.Config.ReadTimeout = 5 * time.Second // як у справжнього сервера: завислий клієнт не тримає обробник
	hs.Start()
	u := &unitSrv{srv: srv, state: state, store: st, key: k, http: hs, url: hs.URL + "/hook/" + cfg.HookSecret}
	t.Cleanup(func() { hs.Close(); state.Close(); st.Close() })
	return u
}

func (u *unitSrv) send(t testing.TB, method, url string, body []byte, hd http.Header) (int, string) {
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	for k, v := range hd {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// ---------- 1. Модель: випадковий порядок, дублікати, паралельність ----------

// Для кожного (регіон, тип) генеруємо хронологію знімків зі зростаючим createdAt,
// доставляємо їх перемішаними, з дублікатами й паралельно. Після доставки стан має
// дорівнювати останньому за часом знімку, а БД — стану (active_state і відкриті сесії).
func TestModelRandomDelivery(t *testing.T) {
	reasons := []string{"UAV activity", "Missile threat", "Ballistic missile threat", "Shelling", ""}
	for iter := 0; iter < 60; iter++ {
		rng := rand.New(rand.NewSource(int64(iter)))
		dir := t.TempDir()
		st, err := OpenStore(filepath.Join(dir, "m.db"), 65536)
		if err != nil {
			t.Fatal(err)
		}
		go st.Run()
		s := NewState(st.Queue(), 100)

		type snap struct {
			k   key
			at  time.Time
			lvl []Level
		}
		var all []snap
		want := map[key][]Level{}
		base := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
		for r := 1; r <= 6; r++ {
			for _, typ := range []string{"AIR", "ARTILLERY"} {
				k := key{strconv.Itoa(r), typ}
				n := 1 + rng.Intn(8)
				for i := 0; i < n; i++ {
					var lv []Level
					for j := 0; j < rng.Intn(3); j++ { // 0..2 рівні
						lvl := "Yellow"
						if rng.Intn(2) == 0 {
							lvl = "Red"
						}
						lv = append(lv, Level{Level: lvl, Reason: reasons[rng.Intn(len(reasons))]})
					}
					sn := snap{k, base.Add(time.Duration(r*1000+i*7) * time.Second), lv}
					all = append(all, sn)
					want[k] = canonLevels(lv)
				}
			}
		}
		// перемішати, додати дублікати
		rng.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
		for i := 0; i < len(all)/4; i++ {
			all = append(all, all[rng.Intn(len(all))])
		}
		var wg sync.WaitGroup
		ch := make(chan snap)
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for sn := range ch {
					s.Apply(Event{ReceivedAt: flexTime{time.Now()}, CreatedAt: flexTime{sn.at}, RegionID: sn.k.region,
						AlarmType: sn.k.typ, Status: "ACTIVATE", Active: sn.lvl, Source: "webhook"})
				}
			}()
		}
		for _, sn := range all {
			ch <- sn
		}
		close(ch)
		wg.Wait()

		_, items := s.Snapshot()
		got := map[key][]Level{}
		for _, it := range items {
			got[key{it.RegionID, it.AlarmType}] = it.Active
		}
		for k, w := range want {
			if len(w) == 0 {
				if _, ok := got[k]; ok {
					t.Fatalf("iter %d: %v should be inactive, got %v", iter, k, got[k])
				}
				continue
			}
			if !sameLevels(got[k], w) {
				t.Fatalf("iter %d: %v want %v got %v", iter, k, w, got[k])
			}
		}
		s.Close()
		st.Close()

		// БД узгоджена зі станом
		db, _ := OpenStore(filepath.Join(dir, "m.db"), 1)
		active := count(db.db, `SELECT COUNT(*) FROM active_state`)
		open := count(db.db, `SELECT COUNT(*) FROM sessions WHERE ended_ms IS NULL`)
		bad := count(db.db, `SELECT COUNT(*) FROM sessions WHERE ended_ms IS NOT NULL AND ended_ms < started_ms`)
		wantLvl := 0
		for _, it := range items {
			wantLvl += len(it.Levels)
		}
		openLvl := count(db.db, `SELECT COUNT(*) FROM level_sessions WHERE ended_ms IS NULL`)
		badLvl := count(db.db, `SELECT COUNT(*) FROM level_sessions WHERE ended_ms < started_ms`)
		if openLvl != wantLvl || badLvl != 0 {
			t.Fatalf("iter %d: open level sessions %d, want %d (bad %d)", iter, openLvl, wantLvl, badLvl)
		}
		if active != len(items) || open != len(items) || bad != 0 {
			t.Fatalf("iter %d: db active=%d open sessions=%d state=%d bad=%d", iter, active, open, len(items), bad)
		}
		db.db.Close()
	}
}

// Упорядкована доставка: тип зміни збігається з моделлю на кожному кроці.
func TestModelOrderedChanges(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	q := make(chan Event, 100000)
	s := NewState(q, 10)
	base := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	var prev []Level
	for i := 0; i < 2000; i++ {
		var lv []Level
		for j := 0; j < rng.Intn(3); j++ {
			lv = append(lv, Level{Level: []string{"Red", "Yellow"}[rng.Intn(2)], Reason: fmt.Sprint("r", rng.Intn(4))})
		}
		ev := s.Apply(Event{ReceivedAt: flexTime{base}, CreatedAt: flexTime{base.Add(time.Duration(i) * time.Second)},
			RegionID: "1", AlarmType: "AIR", Active: lv, Source: "webhook"})
		cur := canonLevels(lv)
		var want string
		switch {
		case len(prev) == 0 && len(cur) > 0:
			want = ChangeStart
		case len(prev) > 0 && len(cur) == 0:
			want = ChangeEnd
		case len(prev) > 0 && !sameLevels(prev, cur):
			want = ChangeUpdate
		default:
			want = ChangeNone
		}
		if ev.Change != want {
			t.Fatalf("step %d: want %s got %s (prev %v cur %v)", i, want, ev.Change, prev, cur)
		}
		prev = cur
	}
}

// ---------- 2. Фазинг розбору webhook ----------

func FuzzWebhookBody(f *testing.F) {
	for _, seed := range []string{
		`{"status":"Activate","regionId":14,"alarmType":"AIR","createdAt":"2026-09-07T12:05:00Z","alertLevel":"Red","reason":"x","activeAlertLevels":[{"alertLevel":"Red","reason":"x","createdAt":"2026-09-07T12:05:00Z"}]}`,
		`{"status":"DEACTIVATE","regionId":"14","alarmType":"AIR","createdAt":"2026-09-07T12:32:00","activeAlertLevels":[]}`,
		`{"regionId":1e3}`, `{"regionId":-1}`, `{"regionId":null}`, `[]`, `null`, `{"createdAt":"bad"}`,
	} {
		f.Add([]byte(seed))
	}
	q := make(chan Event, 1<<16)
	go func() {
		for range q {
		}
	}()
	s := NewState(q, 10)
	f.Fuzz(func(t *testing.T, body []byte) {
		var m webhookMsg
		if json.Unmarshal(body, &m) != nil || validate(&m) != nil {
			return
		}
		for _, c := range m.RegionID {
			if c < '0' || c > '9' {
				t.Fatalf("validate let through non-numeric id %q", m.RegionID)
			}
		}
		s.Apply(Event{ReceivedAt: flexTime{time.Now()}, CreatedAt: m.CreatedAt, RegionID: string(m.RegionID),
			AlarmType: normType(m.AlarmType), Status: normStatus(m.Status), Active: m.ActiveAlertLevels, Source: "webhook"})
	})
}

// ---------- 3. Матриця атак на публічну адресу ----------

func TestAttackMatrix(t *testing.T) {
	u := newUnitSrv(t, true)
	secret := u.srv.cfg.HookSecret
	base := strings.TrimSuffix(u.url, "/hook/"+secret)
	good := hookBody("Activate", 14, "AIR", time.Now(), "Red", "x", lv("Red", "x"))
	now := time.Now().Unix()

	// шляхи й методи — усе має бути однаковим 404
	for _, c := range []struct{ m, p string }{
		{"POST", "/hook/" + secret + "/"}, {"POST", "/hook//" + secret}, {"POST", "/HOOK/" + secret},
		{"POST", "/hook/" + strings.ToUpper(secret)}, {"POST", "/hook/" + secret[:len(secret)-1]},
		{"POST", "/hook/" + secret + "x"}, {"POST", "/hook/" + secret + "%00"}, {"POST", "//hook/" + secret},
		{"POST", "/hook/../hook/" + secret}, {"POST", "/hook/%2e%2e/" + secret}, {"POST", "/hook"}, {"POST", "/"},
		{"GET", "/hook/" + secret}, {"PUT", "/hook/" + secret}, {"DELETE", "/hook/" + secret},
		{"PATCH", "/hook/" + secret}, {"OPTIONS", "/hook/" + secret}, {"GET", "/stats"}, {"GET", "/events"},
		{"GET", "/state"}, {"GET", "/.env"}, {"GET", "/index.html"}, {"GET", "/favicon.ico"},
	} {
		code, body := u.send(t, c.m, base+c.p, good, sign(u.key, now, good))
		if code != 404 && !(code == 301 || code == 307 || code == 308) { // ServeMux-подібні редиректи теж прийнятні для «//»
			t.Errorf("%s %s: %d", c.m, c.p, code)
		}
		if code == 404 && !strings.Contains(body, `data-code="404"`) {
			t.Errorf("%s %s: not the 404 page", c.m, c.p)
		}
	}

	// підписи
	mut := func(f func(h http.Header)) http.Header { h := sign(u.key, now, good); f(h); return h }
	for name, hd := range map[string]http.Header{
		"no signature": mut(func(h http.Header) { h.Del("X-Webhook-Signature") }),
		"no timestamp": mut(func(h http.Header) { h.Del("X-Webhook-Timestamp") }),
		"bad base64":   mut(func(h http.Header) { h.Set("X-Webhook-Signature", "!!!") }),
		"wrong alg":    mut(func(h http.Header) { h.Set("X-Webhook-Signature-Alg", "none") }),
		"text ts":      mut(func(h http.Header) { h.Set("X-Webhook-Timestamp", "yesterday") }),
		"ts changed":   mut(func(h http.Header) { h.Set("X-Webhook-Timestamp", strconv.FormatInt(now+1, 10)) }),
		"future +10m":  sign(u.key, now+600, good),
		"past -10m":    sign(u.key, now-600, good),
		"foreign key":  sign(testKey(t), now, good),
		"empty sig":    mut(func(h http.Header) { h.Set("X-Webhook-Signature", "") }),
	} {
		if code, body := u.send(t, "POST", u.url, good, hd); code != 401 || !strings.Contains(body, `data-code="401"`) {
			t.Errorf("%s: %d", name, code)
		}
	}
	// підпис від іншого тіла
	other := hookBody("Activate", 15, "AIR", time.Now(), "Red", "x", lv("Red", "x"))
	if code, _ := u.send(t, "POST", u.url, good, sign(u.key, now, other)); code != 401 {
		t.Errorf("signature of other body: %d", code)
	}
	if u.srv.accepted.Load() != 0 {
		t.Fatalf("something was accepted: %d", u.srv.accepted.Load())
	}
	// правильний — 200; повтор того самого — 200, але не застосовується вдруге
	if code, b := u.send(t, "POST", u.url, good, sign(u.key, now, good)); code != 200 || b != "ok" {
		t.Fatalf("valid: %d %q", code, b)
	}
	if code, b := u.send(t, "POST", u.url, good, sign(u.key, now, good)); code != 200 || b != "dup" {
		t.Fatalf("replay: %d %q", code, b)
	}
	// той самий webhook із query-рядком — шлях той самий, теж дублікат (query не впливає)
	if code, b := u.send(t, "POST", u.url+"?x=1", good, sign(u.key, now, good)); code != 200 || b != "dup" {
		t.Fatalf("replay with query: %d %q", code, b)
	}
	if u.srv.accepted.Load() != 1 || u.srv.duplicates.Load() != 2 {
		t.Fatalf("accepted=%d duplicates=%d", u.srv.accepted.Load(), u.srv.duplicates.Load())
	}
	// валідно підписане, але некоректне — 200 ignored, стан не змінюється
	for _, b := range [][]byte{[]byte(`{"regionId":"abc"}`), []byte(`not json`), []byte(`{"regionId":1,"activeAlertLevels":` + strings.Repeat(`{},`, 70) + `{}]}`)} {
		if code, r := u.send(t, "POST", u.url, b, sign(u.key, now, b)); code != 200 || r != "ignored" {
			t.Errorf("invalid signed payload: %d %q", code, r)
		}
	}
	// розмір: рівно 256 КБ дозволено, більше — 413
	pad := append(append([]byte{}, good[:len(good)-1]...), []byte(`,"pad":"`+strings.Repeat("a", maxBody-len(good)-10)+`"}`)...)
	if len(pad) != maxBody-1 && len(pad) > maxBody {
		t.Fatalf("pad size %d", len(pad))
	}
	if code, _ := u.send(t, "POST", u.url, pad, sign(u.key, now, pad)); code != 200 {
		t.Errorf("max-size body: %d", code)
	}
	big := bytes.Repeat([]byte(" "), maxBody+1)
	if code, b := u.send(t, "POST", u.url, big, sign(u.key, now, big)); code != 413 || !strings.Contains(b, `data-code="413"`) {
		t.Errorf("oversize: %d", code)
	}
}

func TestNoKeyGives503(t *testing.T) {
	u := newUnitSrv(t, false)
	b := hookBody("Activate", 14, "AIR", time.Now(), "Red", "x", lv("Red", "x"))
	req, _ := http.NewRequest("POST", u.url, bytes.NewReader(b))
	for k, v := range sign(u.key, time.Now().Unix(), b) {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" || !strings.Contains(string(body), `data-code="503"`) {
		t.Fatalf("no key: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestPanicGives500(t *testing.T) {
	h := recoverPages(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), `data-code="500"`) {
		t.Fatalf("panic: %d", rec.Code)
	}
}

// ---------- 4. Сторінки й індикатор ----------

func TestErrorPagesAndHeaders(t *testing.T) {
	for code := range errorPages {
		rec := httptest.NewRecorder()
		errorPage(rec, httptest.NewRequest("GET", "/x", nil), code)
		h := rec.Header()
		if rec.Code != code || !strings.Contains(rec.Body.String(), fmt.Sprintf(`data-code="%d"`, code)) ||
			!strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") ||
			h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" ||
			h.Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
			t.Errorf("%d: bad page or headers %v", code, h)
		}
		if strings.Contains(rec.Body.String(), "<script") {
			t.Errorf("%d: page has a script", code)
		}
	}
}

func TestComputeHealth(t *testing.T) {
	now := time.Date(2026, 11, 8, 1, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	iv := 90 * time.Second
	for _, c := range []struct {
		name                     string
		hook, miss, sync         time.Time
		wantHook, wantSync, want string
	}{
		{"all good", ago(time.Hour), time.Time{}, ago(time.Minute), "ok", "ok", "ok"},
		{"night, no changes for hours", ago(10 * time.Hour), time.Time{}, ago(30 * time.Second), "ok", "ok", "ok"},
		{"webhooks never came", time.Time{}, time.Time{}, ago(time.Minute), "warn", "ok", "warn"},
		{"recent miss after last hook", ago(time.Hour), ago(5 * time.Minute), ago(time.Minute), "warn", "ok", "warn"},
		{"old miss forgiven", ago(time.Hour), ago(40 * time.Minute), ago(time.Minute), "ok", "ok", "ok"},
		{"hook after miss", ago(time.Minute), ago(5 * time.Minute), ago(time.Minute), "ok", "ok", "ok"},
		{"sync slow", ago(time.Hour), time.Time{}, ago(10 * time.Minute), "ok", "warn", "warn"},
		{"sync dead, hooks fine", ago(time.Minute), time.Time{}, ago(time.Hour), "ok", "bad", "warn"},
		{"everything dead", time.Time{}, time.Time{}, time.Time{}, "warn", "bad", "bad"},
	} {
		h := computeHealth(now, c.hook, c.miss, c.sync, iv)
		if h.Hook != c.wantHook || h.Sync != c.wantSync || h.Overall != c.want {
			t.Errorf("%s: got %+v", c.name, h)
		}
	}
}

// Головна нічого конкретного не каже: ні слів про сервіс, ні чисел, ні часу.
func TestIndexRevealsNothing(t *testing.T) {
	u := newUnitSrv(t, true)
	u.srv.lastSyncUnix.Store(time.Now().Unix())
	u.srv.lastHookUnix.Store(time.Now().Add(-time.Hour).Unix())
	base := strings.TrimSuffix(u.url, "/hook/"+u.srv.cfg.HookSecret)
	code, body := u.send(t, "GET", base+"/", nil, nil)
	if code != 200 || !strings.Contains(body, "online") || !strings.Contains(body, `class="pair"`) {
		t.Fatalf("index: %d", code)
	}
	main := body[strings.Index(body, "<main"):strings.Index(body, "</main>")]
	// скрипт: лише службовий код, без назв і адрес, крім /s
	script := body[strings.Index(body, "<script>")+8 : strings.Index(body, "</script>")]
	for _, w := range []string{"hook", "api", "ukrainealarm", "alert(", "example.com", "secret", "http"} {
		if strings.Contains(strings.ToLower(script), w) {
			t.Errorf("script mentions %q", w)
		}
	}
	for _, w := range []string{"webhook", "hook", "sync", "api", "ukrainealarm", "alert", "тривог", "звір", "example.com/", "secret"} {
		if strings.Contains(strings.ToLower(main), w) {
			t.Errorf("index body mentions %q", w)
		}
	}
	if regexp.MustCompile(`\d{2}:\d{2}|\d{4}-\d{2}-\d{2}`).MatchString(main) {
		t.Errorf("index shows a time or date")
	}
	// стани відображаються
	u.srv.lastSyncUnix.Store(0)
	u.srv.lastHookUnix.Store(0)
	if _, b := u.send(t, "GET", base+"/", nil, nil); !strings.Contains(b, "offline") {
		t.Errorf("offline state not shown")
	}
	// HEAD без тіла
	req, _ := http.NewRequest("HEAD", base+"/", nil)
	resp, _ := http.DefaultClient.Do(req)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(b) != 0 {
		t.Errorf("HEAD /: %d len %d", resp.StatusCode, len(b))
	}
}

// ---------- 5. Узгодження webhook і знімка (на реальних даних 08.11.2026) ----------

func lvAt(level string, t time.Time) Level { return Level{Level: level, CreatedAt: flexTime{t}} }

func ts(s string) time.Time { v, _ := parseFlexTime(s); return v }

// Районна тривога в /alerts повторюється в записах області, району й громад — це має бути
// ОДИН рівень, інакше кожна звірка давала б хибні update (реальні дані, Нікопольський район).
func TestSnapshotDeduplicatesRepeatedAlert(t *testing.T) {
	al := func(region string, created string) apiAlert {
		return apiAlert{RegionID: flexID(region), Type: "AIR", Levels: []Level{lvAt("Red", ts(created))}}
	}
	resp := []apiAlertRegion{
		{RegionID: "9", ActiveAlerts: []apiAlert{al("9100", "2026-11-08T01:17:30.515815Z")}},    // область
		{RegionID: "9100", ActiveAlerts: []apiAlert{al("9100", "2026-11-08T01:17:30.515815Z")}}, // район
		{RegionID: "9101", ActiveAlerts: []apiAlert{al("9100", "2026-11-08T01:17:30.515815Z")}}, // громади
		{RegionID: "9102", ActiveAlerts: []apiAlert{al("9100", "2026-11-08T01:17:30.515815Z")}},
		{RegionID: "9103", ActiveAlerts: []apiAlert{al("9100", "2026-11-08T01:17:30.5158156Z")}}, // 7 знаків — та сама мить
	}
	snap := parseAlerts(resp)
	if got := snap[key{"9100", "AIR"}]; len(got) != 1 {
		t.Fatalf("want 1 level, got %d: %+v", len(got), got)
	}
	// два різні рівні в одному регіоні лишаються обидва
	resp = append(resp, apiAlertRegion{RegionID: "9100", ActiveAlerts: []apiAlert{
		{RegionID: "9100", Type: "AIR", Levels: []Level{lvAt("Yellow", ts("2026-11-08T01:20:00Z"))}}}})
	if got := parseAlerts(resp)[key{"9100", "AIR"}]; len(got) != 2 {
		t.Fatalf("distinct levels merged: %+v", got)
	}
	if n := newestLevel(resp); !n.Equal(ts("2026-11-08T01:20:00Z")) {
		t.Fatalf("newest: %v", n)
	}
	// і жодного «пінг-понгу»: webhook дав 1 рівень, знімок із повторами — 0 виправлень
	q := make(chan Event, 100)
	s := NewState(q, 10)
	s.Apply(Event{ReceivedAt: flexTime{time.Now().Add(-5 * time.Minute)}, CreatedAt: flexTime{ts("2026-11-08T01:17:30.5158156Z")},
		RegionID: "9100", AlarmType: "AIR", Active: []Level{lvAt("Red", ts("2026-11-08T01:17:30.5158156Z"))}, Source: "webhook"})
	if fixes := s.Reconcile(parseAlerts(resp[:5]), newestLevel(resp[:5]), time.Now(), time.Second, "poll", false); len(fixes) != 0 {
		t.Fatalf("ping-pong: %+v", fixes)
	}
}

// Запорізький район, 22:47: звірка побачила тривогу раніше за webhook (рівень у знімку
// 22:47:34.492), а webhook про ту саму подію має createdAt 22:47:34.209. Це не stale, а повтор.
func TestLateWebhookAfterSnapshotIsNone(t *testing.T) {
	q := make(chan Event, 100)
	s := NewState(q, 10)
	snap := map[key][]Level{{"1", "AIR"}: {lvAt("Yellow", ts("2026-11-07T22:47:34.492862Z"))}}
	fixes := s.Reconcile(snap, ts("2026-11-07T22:47:34.492862Z"), time.Now(), time.Second, "poll", false)
	if len(fixes) != 1 || fixes[0].Change != ChangeStart {
		t.Fatalf("poll start: %+v", fixes)
	}
	ev := s.Apply(Event{ReceivedAt: flexTime{time.Now()}, CreatedAt: flexTime{ts("2026-11-07T22:47:34.209Z")},
		RegionID: "1", AlarmType: "AIR", Status: "ACTIVATE", Active: []Level{lvAt("Yellow", ts("2026-11-07T22:47:34.2093Z"))}, Source: "webhook"})
	if ev.Change != ChangeNone {
		t.Fatalf("late duplicate webhook: %s", ev.Change)
	}
	// справжній відбій пізніше — застосовується
	ev = s.Apply(Event{ReceivedAt: flexTime{time.Now()}, CreatedAt: flexTime{ts("2026-11-07T23:10:00Z")},
		RegionID: "1", AlarmType: "AIR", Status: "DEACTIVATE", Source: "webhook"})
	if ev.Change != ChangeEnd {
		t.Fatalf("end: %s", ev.Change)
	}
}

// Запізнілий webhook про стан, якого вже немає (знімок новіший), не «воскрешає» тривогу.
// Полтавський район: webhook прийшов через 56 с, коли звірка вже знала новіший стан.
func TestDelayedOldWebhookIsStale(t *testing.T) {
	q := make(chan Event, 100)
	s := NewState(q, 10)
	s.SetHookTrust(time.Minute)
	old := time.Now().Add(-10 * time.Minute)
	s.Apply(Event{ReceivedAt: flexTime{old}, CreatedAt: flexTime{ts("2026-11-07T23:30:00Z")}, RegionID: "5", AlarmType: "AIR",
		Active: []Level{lvAt("Yellow", ts("2026-11-07T23:30:00Z"))}, Source: "webhook"})
	// знімок без цієї тривоги; найсвіжіший рівень у знімку (інший регіон) — 23:41:40
	snap := map[key][]Level{{"6", "AIR"}: {lvAt("Red", ts("2026-11-07T23:41:40Z"))}}
	fixes := s.Reconcile(snap, ts("2026-11-07T23:41:40Z"), time.Now(), time.Second, "poll", false)
	ended := false
	for _, f := range fixes {
		if f.RegionID == "5" && f.Change == ChangeEnd {
			ended = true
		}
	}
	if !ended {
		t.Fatalf("poll did not end region 5: %+v", fixes)
	}
	// запізнілий webhook, створений 23:35 (до знімка) з тривогою — застарілий
	ev := s.Apply(Event{ReceivedAt: flexTime{time.Now()}, CreatedAt: flexTime{ts("2026-11-07T23:35:00Z")}, RegionID: "5", AlarmType: "AIR",
		Active: []Level{lvAt("Red", ts("2026-11-07T23:30:00Z"))}, Source: "webhook"})
	if ev.Change != ChangeStale {
		t.Fatalf("old webhook resurrected the alert: %s", ev.Change)
	}
	if _, items := s.Snapshot(); len(items) != 1 || items[0].RegionID != "6" {
		t.Fatalf("state: %+v", items)
	}
	// а webhook, створений після знімка, — це нова тривога
	ev = s.Apply(Event{ReceivedAt: flexTime{time.Now()}, CreatedAt: flexTime{ts("2026-11-07T23:45:00Z")}, RegionID: "5", AlarmType: "AIR",
		Active: []Level{lvAt("Red", ts("2026-11-07T23:45:00Z"))}, Source: "webhook"})
	if ev.Change != ChangeStart {
		t.Fatalf("new webhook after snapshot: %s", ev.Change)
	}
}

// Webhook, новіший за знімок, звірка не відкочує — але лише протягом hookTrust.
func TestWebhookNewerThanSnapshot(t *testing.T) {
	q := make(chan Event, 100)
	s := NewState(q, 10)
	s.SetHookTrust(2 * time.Minute)
	recv := time.Now().Add(-30 * time.Second)
	s.Apply(Event{ReceivedAt: flexTime{recv}, CreatedAt: flexTime{ts("2026-11-08T06:00:10Z")}, RegionID: "1", AlarmType: "AIR",
		Active: []Level{lvAt("Red", ts("2026-11-08T06:00:10Z"))}, Source: "webhook"})
	// знімок, найсвіжіший рівень якого старший за webhook — знімок міг ще не містити тривоги
	snap := map[key][]Level{{"2", "AIR"}: {lvAt("Red", ts("2026-11-08T05:59:00Z"))}}
	if fixes := s.Reconcile(snap, ts("2026-11-08T05:59:00Z"), time.Now(), time.Second, "poll", false); hasRegion(fixes, "1") {
		t.Fatalf("snapshot older than webhook rolled it back: %+v", fixes)
	}
	// знімок, який точно новіший (є рівень, створений після webhook) — звірка має рацію
	snap[key{"3", "AIR"}] = []Level{lvAt("Red", ts("2026-11-08T06:01:00Z"))}
	if fixes := s.Reconcile(snap, ts("2026-11-08T06:01:00Z"), time.Now(), time.Second, "poll", false); !hasRegion(fixes, "1") {
		t.Fatalf("newer snapshot did not correct: %+v", fixes)
	}
	// і без нових рівнів у знімку: після hookTrust звірка теж виправляє (губиться webhook відбою)
	s.Apply(Event{ReceivedAt: flexTime{time.Now().Add(-3 * time.Minute)}, CreatedAt: flexTime{ts("2026-11-08T06:30:00Z")}, RegionID: "4", AlarmType: "AIR",
		Active: []Level{lvAt("Red", ts("2026-11-08T06:30:00Z"))}, Source: "webhook"})
	if fixes := s.Reconcile(snap, ts("2026-11-08T06:01:00Z"), time.Now(), time.Second, "poll", false); !hasRegion(fixes, "4") {
		t.Fatalf("lost end webhook never corrected: %+v", fixes)
	}
}

func hasRegion(evs []Event, id string) bool {
	for _, e := range evs {
		if e.RegionID == id {
			return true
		}
	}
	return false
}

// ---------- 6. Збереження: ретенція ----------

func TestRetention(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "r.db"), 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	old := time.Now().Add(-200 * 24 * time.Hour)
	fresh := time.Now().Add(-time.Hour)
	var batch []Event
	for i, ts := range []time.Time{old, old, fresh} {
		batch = append(batch, Event{Seq: int64(i + 1), ReceivedAt: flexTime{ts}, CreatedAt: flexTime{ts}, RegionID: "1",
			AlarmType: "AIR", Status: "ACTIVATE", Change: ChangeNone, Source: "webhook", hash: fmt.Sprint("h", i)})
	}
	batch = append(batch, Event{Seq: 9, ReceivedAt: flexTime{old}, CreatedAt: flexTime{old}, RegionID: "2", AlarmType: "AIR",
		Status: "ACTIVATE", Active: []Level{lv("Red", "")}, Change: ChangeStart, Source: "webhook", SessionFrom: flexTime{old}, hash: "s"})
	if err := st.writeBatch(batch); err != nil {
		t.Fatal(err)
	}
	n, err := st.Prune(180 * 24 * time.Hour)
	if err != nil || n != 3 {
		t.Fatalf("pruned %d: %v", n, err)
	}
	if count(st.db, `SELECT COUNT(*) FROM events`) != 1 || count(st.db, `SELECT COUNT(*) FROM sessions`) != 1 {
		t.Fatal("retention removed the wrong rows")
	}
	if st.LastWebhook().Before(fresh.Add(-time.Second)) {
		t.Fatal("LastWebhook wrong")
	}
}

// ---------- 7. Наскрізні: перезапуск посеред тривоги, потік подій ----------

func TestRestartMidAlert(t *testing.T) {
	h := newHarness(t)
	db := h.db()
	h.waitFor("startup", func() bool { return count(db, `SELECT COUNT(*) FROM active_state`) == 2 })
	t0 := time.Now().UTC().Truncate(time.Second)
	b := hookBody("Activate", 14, "AIR", t0, "Red", "x", lv("Red", "x"))
	h.post(b, sign(h.key, time.Now().Unix(), b))
	// API теж знає про тривогу 14, тож стартова звірка після перезапуску її не закриє
	h.api.mu.Lock()
	h.api.alerts = append(h.api.alerts, apiAlertRegion{RegionID: "14", ActiveAlerts: []apiAlert{{RegionID: "14", Type: "AIR",
		Levels: []Level{{Level: "Red", Reason: "x", CreatedAt: flexTime{t0}}}}}})
	h.api.mu.Unlock()
	h.waitFor("session open", func() bool {
		return count(db, `SELECT COUNT(*) FROM sessions WHERE region_id='14' AND ended_ms IS NULL`) == 1
	})
	h.stop()
	h.start()
	time.Sleep(700 * time.Millisecond)
	// після перезапуску webhook відбою закриває ту саму сесію (спершу webhook, потім API)
	e := hookBody("DEACTIVATE", 14, "AIR", t0.Add(time.Minute), "Red", "x")
	if code, _ := h.post(e, sign(h.key, time.Now().Unix(), e)); code != 200 {
		t.Fatal("end webhook")
	}
	h.api.mu.Lock()
	h.api.alerts = h.api.alerts[:len(h.api.alerts)-1]
	h.api.mu.Unlock()
	h.waitFor("session closed", func() bool {
		return count(db, `SELECT COUNT(*) FROM sessions WHERE region_id='14' AND ended_ms IS NOT NULL`) == 1
	})
	if n := count(db, `SELECT COUNT(*) FROM sessions WHERE region_id='14'`); n != 1 {
		t.Fatalf("restart split the session: %d rows", n)
	}
	var started int64
	db.QueryRow(`SELECT started_ms FROM sessions WHERE region_id='14'`).Scan(&started)
	if started != t0.UnixMilli() {
		t.Fatalf("session start moved: %d vs %d", started, t0.UnixMilli())
	}
	if n := count(db, `SELECT COUNT(*) FROM events WHERE region_id='14' AND source != 'webhook'`); n != 0 {
		t.Fatalf("restart produced %d synthetic events for 14", n)
	}
}

// readSSE пропускає службову подію hello (її перевіряє TestSSEHelloAndEpoch).
func readSSE(t testing.TB, url string, header http.Header, n int, timeout time.Duration) []string {
	return readSSEx(t, url, header, n, timeout, false)
}

func readSSEx(t testing.TB, url string, header http.Header, n int, timeout time.Duration, keepHello bool) []string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []string
	sc := bufio.NewScanner(resp.Body)
	var cur []string
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if len(cur) > 0 && !strings.HasPrefix(cur[0], "retry") && (keepHello || cur[0] != "event: hello") {
				out = append(out, strings.Join(cur, "\n"))
				if len(out) >= n {
					return out
				}
			}
			cur = nil
			continue
		}
		cur = append(cur, line)
	}
	return out
}

func TestSSEResume(t *testing.T) {
	h := newHarness(t)
	db := h.db()
	h.waitFor("startup", func() bool { return count(db, `SELECT COUNT(*) FROM active_state`) == 2 })
	var seq0 int64
	db.QueryRow(`SELECT MAX(seq) FROM events`).Scan(&seq0)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		b := hookBody("Activate", 20+i, "AIR", now, "Red", "x", lv("Red", "x"))
		h.post(b, sign(h.key, time.Now().Unix(), b))
	}
	// Last-Event-ID = seq0 → рівно три пропущені події, по порядку
	evs := readSSE(t, h.localURL+"/events", http.Header{"Last-Event-Id": {strconv.FormatInt(seq0, 10)}}, 3, 3*time.Second)
	if len(evs) != 3 {
		t.Fatalf("backlog: %d events", len(evs))
	}
	for i, e := range evs {
		if !strings.Contains(e, fmt.Sprintf("id: %d", seq0+int64(i)+1)) {
			t.Fatalf("event %d out of order: %s", i, e)
		}
	}
	// клієнт «з майбутнього» — resync
	evs = readSSE(t, h.localURL+"/events?after=999999", nil, 1, 3*time.Second)
	if len(evs) != 1 || !strings.Contains(evs[0], "event: resync") {
		t.Fatalf("future id: %v", evs)
	}
}

// ---------- 8. Бенчмарки гарячого шляху ----------

func BenchmarkWebhookHandler(b *testing.B) {
	u := newUnitSrv(b, true)
	h := u.srv.HookHandler()
	bodies := make([][]byte, b.N)
	hds := make([]http.Header, b.N)
	now := time.Now()
	for i := range bodies {
		bodies[i] = hookBody("Activate", 1000+i%5000, "AIR", now.Add(time.Duration(i)*time.Millisecond), "Red", "x", lv("Red", "x"))
		hds[i] = sign(u.key, now.Unix(), bodies[i])
	}
	path := "/hook/" + u.srv.cfg.HookSecret
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", path, bytes.NewReader(bodies[i]))
		req.Header = hds[i]
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			b.Fatal(rec.Code)
		}
	}
}

func BenchmarkStateApply(b *testing.B) {
	q := make(chan Event, 1<<20)
	go func() {
		for range q {
		}
	}()
	s := NewState(q, 1000)
	now := time.Now()
	lvls := [][]Level{{lv("Red", "a")}, {lv("Red", "a"), lv("Yellow", "b")}, nil}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Apply(Event{ReceivedAt: flexTime{now}, CreatedAt: flexTime{now.Add(time.Duration(i))}, RegionID: strconv.Itoa(i % 1600),
			AlarmType: "AIR", Active: lvls[i%3], Source: "webhook"})
	}
}

func BenchmarkIndexPage(b *testing.B) {
	u := newUnitSrv(b, true)
	h := u.srv.HookHandler()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	}
}

// ---------- 9. Тривале навантаження (SOAK=1) ----------

func rssKB(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	m := regexp.MustCompile(`VmRSS:\s+(\d+)`).FindSubmatch(b)
	if m == nil {
		return -1
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

// 20 000 webhook (тривога по всій країні кілька разів), 128 паралельно, 16 підписників
// потоку подій, паралельно відкривають головну. Перевіряє: нічого не губиться, підписники
// отримують усе по порядку, пам'ять не тече.
func TestSoak(t *testing.T) {
	if os.Getenv("SOAK") == "" {
		t.Skip("SOAK not set")
	}
	h := newHarnessOpt(t, 0, func(h *harness) { h.extraEnv = []string{"GOMEMLIMIT=160MiB"} }) // як у systemd-юніті
	db := h.db()
	h.waitFor("startup", func() bool { return count(db, `SELECT COUNT(*) FROM active_state`) == 2 })
	pid := h.cmd.Process.Pid
	rss0 := rssKB(pid)
	var seq0 int64
	db.QueryRow(`SELECT MAX(seq) FROM events`).Scan(&seq0)

	const N = 20000
	type item struct {
		b  []byte
		hd http.Header
	}
	items := make([]item, N)
	base := time.Now().UTC()
	for i := range items {
		region := (i%25+1)*1000 + (i/25%4+1)*100 + (i/100)%10 + 1
		var bdy []byte
		if (i/1000)%2 == 0 {
			bdy = hookBody("Activate", region, "AIR", base.Add(time.Duration(i)*time.Millisecond), "Red", "m", lv("Red", "m"))
		} else {
			bdy = hookBody("DEACTIVATE", region, "AIR", base.Add(time.Duration(i)*time.Millisecond), "Red", "m")
		}
		items[i] = item{bdy, sign(h.key, time.Now().Unix(), bdy)}
	}
	// підписники
	var subWG sync.WaitGroup
	subCounts := make([]int, 16)
	subOrder := make([]bool, 16)
	ctx, cancel := context.WithCancel(context.Background())
	for sIdx := 0; sIdx < 16; sIdx++ {
		subWG.Add(1)
		go func(i int) {
			defer subWG.Done()
			req, _ := http.NewRequestWithContext(ctx, "GET", h.localURL+"/events?all=1", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			sc := bufio.NewScanner(resp.Body)
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			last, ok := int64(0), true
			for sc.Scan() {
				if l := sc.Text(); strings.HasPrefix(l, "id: ") {
					id, _ := strconv.ParseInt(l[4:], 10, 64)
					if last != 0 && id != last+1 {
						ok = false
					}
					last = id
					subCounts[i]++
				}
			}
			subOrder[i] = ok
		}(sIdx)
	}
	time.Sleep(300 * time.Millisecond)
	// головну відкривають паралельно
	stopIdx := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopIdx:
				return
			default:
				if r, err := h.client.Get(strings.TrimSuffix(h.hookURL, "/hook/"+h.secret) + "/"); err == nil {
					io.Copy(io.Discard, r.Body)
					r.Body.Close()
				}
			}
		}
	}()
	var next int64
	var mu sync.Mutex
	lat := make([]time.Duration, 0, N)
	var wg sync.WaitGroup
	t0 := time.Now()
	for w := 0; w < 128; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				i := next
				next++
				mu.Unlock()
				if i >= N {
					return
				}
				code, d := h.post(items[i].b, items[i].hd)
				if code != 200 {
					t.Errorf("item %d: %d", i, code)
				}
				mu.Lock()
				lat = append(lat, d)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	wall := time.Since(t0)
	close(stopIdx)
	h.waitFor("all soak events in db", func() bool {
		return count(db, `SELECT COUNT(*) FROM events WHERE source='webhook' AND seq > ?`, seq0) == N
	})
	time.Sleep(500 * time.Millisecond)
	cancel()
	subWG.Wait()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	rss1 := rssKB(pid)
	t.Logf("soak: %d webhooks in %s (%.0f req/s), round-trip p50 %s p99 %s; RSS %d → %d KB",
		N, wall.Round(time.Millisecond), float64(N)/wall.Seconds(), lat[N/2], lat[N*99/100], rss0, rss1)
	for i, c := range subCounts {
		if c < N || !subOrder[i] {
			t.Errorf("subscriber %d: got %d events, in order=%v", i, c, subOrder[i])
		}
	}
	if rss1 > 180*1024 {
		t.Errorf("RSS too high: %d KB", rss1)
	}
	// сесії узгоджені: відкриті = активні
	if a, o := count(db, `SELECT COUNT(*) FROM active_state`), count(db, `SELECT COUNT(*) FROM sessions WHERE ended_ms IS NULL`); a != o {
		t.Errorf("active_state %d vs open sessions %d", a, o)
	}
}

// Заявлене завелике тіло відхиляється до читання: сервер не чекає, поки клієнт його надішле.
func TestOversizeRejectedBeforeReading(t *testing.T) {
	u := newUnitSrv(t, true)
	pr, pw := io.Pipe()
	defer pw.Close()
	req, _ := http.NewRequest("POST", u.url, pr)
	req.ContentLength = 10 << 20
	go pw.Write([]byte("{"))                                                         // один байт, далі тиша
	time.AfterFunc(2*time.Second, func() { pw.CloseWithError(io.ErrUnexpectedEOF) }) // щоб тест не зависав, якщо сервер чекає
	c := &http.Client{Timeout: 3 * time.Second}
	t0 := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("server waited for the body instead of rejecting: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 || time.Since(t0) > time.Second {
		t.Fatalf("status %d after %s", resp.StatusCode, time.Since(t0))
	}
}

// /s — три слова; CSP головної дозволяє рівно наш скрипт (хеш збігається з текстом у сторінці).
func TestLiveStatusEndpointAndCSP(t *testing.T) {
	u := newUnitSrv(t, true)
	base := strings.TrimSuffix(u.url, "/hook/"+u.srv.cfg.HookSecret)
	u.srv.lastSyncUnix.Store(time.Now().Unix())
	u.srv.lastHookUnix.Store(time.Now().Unix())
	code, body := u.send(t, "GET", base+"/s", nil, nil)
	if code != 200 || body != "ok ok ok\n" {
		t.Fatalf("/s: %d %q", code, body)
	}
	u.srv.lastHookUnix.Store(0)
	if _, body := u.send(t, "GET", base+"/s", nil, nil); body != "warn warn ok\n" {
		t.Fatalf("/s degraded: %q", body)
	}
	for _, p := range []string{"/s/", "/S", "/s?x", "/status"} {
		code, _ := u.send(t, "GET", base+p, nil, nil)
		if p == "/s?x" {
			if code != 200 {
				t.Errorf("%s: %d", p, code)
			}
			continue
		}
		if code != 404 {
			t.Errorf("%s: %d", p, code)
		}
	}
	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	page := string(b)
	script := page[strings.Index(page, "<script>")+8 : strings.Index(page, "</script>")]
	sum := sha256.Sum256([]byte(script))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(csp, "script-src "+want) || !strings.Contains(csp, "connect-src 'self'") || !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("CSP does not pin the page script: %s", csp)
	}
	if strings.Count(page, "<script") != 1 {
		t.Fatal("more than one script")
	}
	// сторінки помилок без скриптів і без дозволу на скрипти
	rec := httptest.NewRecorder()
	errorPage(rec, httptest.NewRequest("GET", "/x", nil), 404)
	if strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src") || strings.Contains(rec.Body.String(), "<script") {
		t.Fatal("error page allows scripts")
	}
}

// Справжній браузер (CHROME=1): скрипт виконується при нашому CSP, перефарбовує крапки
// без перезавантаження, а коли сервіс не відповідає — показує offline.
func TestLiveIndicatorInChrome(t *testing.T) {
	if os.Getenv("CHROME") == "" {
		t.Skip("CHROME not set")
	}
	u := newUnitSrv(t, true)
	var down atomic.Bool
	h := u.srv.HookHandler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			// сторінка віддається у стані «offline», а одразу після цього стан стає «online»
			u.srv.lastSyncUnix.Store(0)
			u.srv.lastHookUnix.Store(0)
			h.ServeHTTP(w, r)
			u.srv.lastSyncUnix.Store(time.Now().Unix())
			u.srv.lastHookUnix.Store(time.Now().Unix())
			return
		}
		if down.Load() {
			errorPage(w, r, http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	dump := func() string {
		out, err := exec.Command("google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", "--no-proxy-server",
			"--virtual-time-budget=15000", "--dump-dom", srv.URL+"/").Output()
		if err != nil {
			t.Fatalf("chrome: %v", err)
		}
		return string(out)
	}
	dom := dump()
	if !strings.Contains(dom, `<span id="l0">online</span>`) || !strings.Contains(dom, `id="d1" class="dot ok"`) ||
		!strings.Contains(dom, `id="d0" class="dot ok pulse"`) {
		t.Fatalf("live update did not happen (CSP blocked the script?):\n%s", dom[strings.Index(dom, "<main"):strings.Index(dom, "</main>")])
	}
	down.Store(true)
	dom = dump()
	if !strings.Contains(dom, `<span id="l0">offline</span>`) || !strings.Contains(dom, `id="d0" class="dot bad"`) {
		t.Fatalf("outage not shown:\n%s", dom[strings.Index(dom, "<main"):strings.Index(dom, "</main>")])
	}
}

// ---------- 10. Загрози: Red — ракетна небезпека, Yellow — загроза БпЛА ----------

// Переходи рівнів і окремий облік кожної загрози в level_sessions.
func TestThreatTransitions(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "t.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	go st.Run()
	s := NewState(st.Queue(), 100)
	base := ts("2026-11-08T05:56:23Z")
	step := func(min int, active ...Level) Event {
		return s.Apply(Event{ReceivedAt: flexTime{base.Add(time.Duration(min) * time.Minute)},
			CreatedAt: flexTime{base.Add(time.Duration(min) * time.Minute)}, RegionID: "1", AlarmType: "AIR", Active: active, Source: "webhook"})
	}
	y, r := lvAt("Yellow", base), lvAt("Red", base)
	r2 := lvAt("red", base.Add(time.Minute)) // інший регістр — той самий рівень
	for i, c := range []struct {
		ev           Event
		change       string
		prev, levels string
	}{
		{step(0, y), ChangeStart, "", "Yellow"},
		{step(10, y, r), ChangeUpdate, "Yellow", "Red+Yellow"},
		{step(20, r, r2), ChangeUpdate, "Red+Yellow", "Red"},
		{step(30, y), ChangeUpdate, "Red", "Yellow"}, // як у Харківському: той самий рівень змінив колір
		{step(40), ChangeEnd, "Yellow", ""},
	} {
		if c.ev.Change != c.change || strings.Join(c.ev.PrevLevels, "+") != c.prev || strings.Join(c.ev.Levels, "+") != c.levels {
			t.Fatalf("step %d: %s [%v → %v]", i, c.ev.Change, c.ev.PrevLevels, c.ev.Levels)
		}
	}
	// JSON для роздавальника: порожні множини — [], не null
	if b, _ := json.Marshal(step(41)); !strings.Contains(string(b), `"levels":[]`) || !strings.Contains(string(b), `"prevLevels":[]`) {
		t.Fatalf("json: %s", b)
	}
	s.Close()
	st.Close()
	db, _ := sqlOpenRO(t, st)
	type row struct {
		level      string
		start, end int64
	}
	rows, err := db.Query(`SELECT level, (started_ms-?)/60000, COALESCE((ended_ms-?)/60000,-1) FROM level_sessions ORDER BY started_ms, level`,
		base.UnixMilli(), base.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var r row
		rows.Scan(&r.level, &r.start, &r.end)
		got = append(got, fmt.Sprintf("%s %d-%d", r.level, r.start, r.end))
	}
	rows.Close()
	// Yellow 0–20, Red 10–30, Yellow 30–40 (хвилини від початку)
	if strings.Join(got, "; ") != "Yellow 0-20; Red 10-30; Yellow 30-40" {
		t.Fatalf("level sessions: %v", got)
	}
	var threat string
	db.QueryRow(`SELECT threat FROM v_threats WHERE level='Red'`).Scan(&threat)
	if threat != "ракетна небезпека" {
		t.Fatalf("v_threats: %q", threat)
	}
	if n := count(db, `SELECT COUNT(*) FROM sessions`); n != 1 {
		t.Fatalf("whole alert must stay one session: %d", n)
	}
}

func sqlOpenRO(t testing.TB, st *Store) (*sql.DB, error) {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+st.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, nil
}

// Повний перебір: усі послідовності з 4 кроків над станами {немає, Yellow, Red, Red+Yellow}
// (none-yellow-red, red-none-yellow, yellow-red-none, …). Для кожної перевіряється тип зміни,
// prev/levels, найвищий рівень тривоги, кількість тривог (sessions) і відрізки кожної загрози.
func TestAllThreatSequences(t *testing.T) {
	states := [][]string{{}, {"Yellow"}, {"Red"}, {"Red", "Yellow"}}
	name := func(l []string) string {
		if len(l) == 0 {
			return "none"
		}
		return strings.Join(l, "+")
	}
	total := 0
	for seq := 0; seq < 4*4*4*4; seq++ {
		path := []int{seq % 4, seq / 4 % 4, seq / 16 % 4, seq / 64 % 4}
		st, err := OpenStore(filepath.Join(t.TempDir(), "s.db"), 100)
		if err != nil {
			t.Fatal(err)
		}
		go st.Run()
		s := NewState(st.Queue(), 10)
		base := ts("2026-11-08T08:00:00Z")
		prev := []string{}
		var label []string
		wantSessions, wantMax := 0, ""
		var maxes []string
		type iv struct {
			level      string
			start, end int
		}
		var want []iv
		open := map[string]int{}
		for i, si := range path {
			cur := states[si]
			label = append(label, name(cur))
			var active []Level
			for _, l := range cur {
				active = append(active, lvAt(l, base))
			}
			at := base.Add(time.Duration(i+1) * time.Minute)
			ev := s.Apply(Event{ReceivedAt: flexTime{at}, CreatedAt: flexTime{at}, RegionID: "1", AlarmType: "AIR", Active: active, Source: "webhook"})
			var wantChange string
			switch {
			case len(prev) == 0 && len(cur) > 0:
				wantChange = ChangeStart
				wantSessions++
				wantMax = ""
			case len(prev) > 0 && len(cur) == 0:
				wantChange = ChangeEnd
			case len(prev) > 0 && name(prev) != name(cur):
				wantChange = ChangeUpdate
			default:
				wantChange = ChangeNone
			}
			for _, l := range cur {
				if levelRank(l) > levelRank(wantMax) {
					wantMax = l
				}
			}
			if wantChange == ChangeEnd || (i == len(path)-1 && len(cur) > 0) {
				maxes = append(maxes, wantMax)
			}
			// відрізки загроз
			added, removed := diffLevels(prev, cur)
			for _, l := range added {
				open[l] = i + 1
				if wantChange == ChangeStart {
					open[l] = 0 // загрози, з якими тривога почалась, — з її початку (createdAt рівнів = base)
				}
			}
			for _, l := range removed {
				want = append(want, iv{l, open[l], i + 1})
				delete(open, l)
			}
			if ev.Change != wantChange || name(ev.PrevLevels) != name(prev) || name(ev.Levels) != name(cur) {
				t.Fatalf("%s step %d: got %s [%s → %s], want %s", strings.Join(label, "→"), i, ev.Change,
					name(ev.PrevLevels), name(ev.Levels), wantChange)
			}
			if len(cur) > 0 && ev.MaxLevel != wantMax {
				t.Fatalf("%s step %d: session max %q, want %q", strings.Join(label, "→"), i, ev.MaxLevel, wantMax)
			}
			prev = cur
		}
		for l, startMin := range open {
			want = append(want, iv{l, startMin, -1})
		}
		s.Close()
		st.Close()
		db, _ := sqlOpenRO(t, st)
		if n := count(db, `SELECT COUNT(*) FROM sessions`); n != wantSessions {
			t.Fatalf("%s: %d alert sessions, want %d", strings.Join(label, "→"), n, wantSessions)
		}
		var gotMax []string
		rows, _ := db.Query(`SELECT COALESCE(max_level,'') FROM sessions ORDER BY started_ms`)
		for rows.Next() {
			var m string
			rows.Scan(&m)
			gotMax = append(gotMax, m)
		}
		rows.Close()
		if strings.Join(gotMax, ",") != strings.Join(maxes, ",") {
			t.Fatalf("%s: session max levels %v, want %v", strings.Join(label, "→"), gotMax, maxes)
		}
		var got []string
		rows, _ = db.Query(`SELECT level, (started_ms-?)/60000, COALESCE((ended_ms-?)/60000,-1) FROM level_sessions ORDER BY level, started_ms`,
			base.UnixMilli(), base.UnixMilli())
		for rows.Next() {
			var x iv
			rows.Scan(&x.level, &x.start, &x.end)
			got = append(got, fmt.Sprintf("%s %d-%d", x.level, x.start, x.end))
		}
		rows.Close()
		var exp []string
		sort.Slice(want, func(i, j int) bool {
			if want[i].level != want[j].level {
				return want[i].level < want[j].level
			}
			return want[i].start < want[j].start
		})
		for _, x := range want {
			exp = append(exp, fmt.Sprintf("%s %d-%d", x.level, x.start, x.end))
		}
		if strings.Join(got, "; ") != strings.Join(exp, "; ") {
			t.Fatalf("%s: threat intervals %v, want %v", strings.Join(label, "→"), got, exp)
		}
		total++
	}
	t.Logf("checked %d threat sequences", total)
}
