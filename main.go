// alertd — збирач повітряних тривог з api.ukrainealarm.com.
//
// Приймає підписані webhook, тримає стан усієї країни в пам'яті, пише події,
// сесії тривог і поточний стан у SQLite, звіряється з API на випадок втрат
// і віддає локально (127.0.0.1) знімок стану та потік подій для роздавальника.
package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// version задається при збірці: -ldflags "-X main.version=1.0.0"
var version = "dev"

func logf(format string, a ...any) { log.Printf(format, a...) }

type Config struct {
	Token        string
	APIBase      string
	HookSecret   string
	PublicURL    string // https://alerts.example.com/hook/<секрет> — для subscribe і check
	HookListen   string
	LocalListen  string
	DBPath       string
	PubKeyFile   string
	SyncInterval time.Duration
	APIMinGap    time.Duration
	MaxSkew      time.Duration
	Retention    time.Duration
	LogEvents    bool
	SiteTitle    string // назва вкладки на публічних сторінках (порожня — нейтральний заголовок)
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	v := env(k, "")
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	log.Fatalf("bad duration %s=%q", k, v)
	return 0
}

// loadEnvFile читає KEY=VALUE (як EnvironmentFile у systemd) і задає лише ті змінні,
// яких ще немає в середовищі.
func loadEnvFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !envKeyRe.MatchString(k) {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
	return nil
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func loadConfig() Config {
	c := Config{
		Token:        env("UA_TOKEN", ""),
		APIBase:      env("UA_API_BASE", "https://api.ukrainealarm.com"),
		HookSecret:   env("HOOK_SECRET", ""),
		PublicURL:    env("PUBLIC_HOOK_URL", ""),
		HookListen:   env("HOOK_LISTEN", "127.0.0.1:8787"),
		LocalListen:  env("LOCAL_LISTEN", "127.0.0.1:8788"),
		DBPath:       env("DB_PATH", "/var/lib/alertd/alerts.db"),
		PubKeyFile:   env("PUBKEY_FILE", ""),
		SyncInterval: envDur("POLL_INTERVAL", 61*time.Second),
		APIMinGap:    envDur("API_MIN_GAP", 61*time.Second),
		MaxSkew:      envDur("MAX_SKEW", 5*time.Minute),
		Retention:    envDur("RETENTION", 180*24*time.Hour),
		LogEvents:    env("LOG_EVENTS", "1") != "0",
		SiteTitle:    env("SITE_TITLE", ""),
	}
	return c
}

func usage() {
	fmt.Fprintf(os.Stderr, `alertd %s — збирач повітряних тривог

  alertd run           запустити сервіс (типово)
  alertd subscribe     підписати PUBLIC_HOOK_URL на webhook ukrainealarm
  alertd update        змінити адресу webhook на PUBLIC_HOOK_URL
  alertd unsubscribe   відписатися
  alertd check         перевірити ключ, зв'язок з API (через службу, якщо вона працює) і публічну адресу
  alertd check --direct  те саме, але запитати API напряму (витрачає ліміт)
  alertd version

Налаштування — змінні середовища (див. alertd.env).
`, version)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd != "run" && cmd != "version" && os.Getenv("UA_TOKEN") == "" {
		// Для ручних команд: налаштування служби, щоб не вводити `set -a; . alertd.env`.
		if err := loadEnvFile(env("ENV_FILE", "/etc/alertd/alertd.env")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "попередження:", err)
		}
	}
	cfg := loadConfig()
	switch cmd {
	case "run":
		if err := run(cfg); err != nil {
			log.Fatal(err)
		}
	case "subscribe", "update", "unsubscribe":
		webhookCmd(cfg, cmd)
	case "check":
		checkCmd(cfg)
	case "version", "-v", "--version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func need(ok bool, msg string) {
	if !ok {
		fmt.Fprintln(os.Stderr, "помилка:", msg)
		os.Exit(1)
	}
}

func webhookCmd(cfg Config, cmd string) {
	need(cfg.Token != "", "не задано UA_TOKEN")
	need(strings.HasPrefix(cfg.PublicURL, "https://"), "PUBLIC_HOOK_URL має починатися з https://")
	need(cfg.HookSecret != "" && strings.HasSuffix(cfg.PublicURL, "/hook/"+cfg.HookSecret), "PUBLIC_HOOK_URL має закінчуватися на /hook/$HOOK_SECRET")
	method := map[string]string{"subscribe": "POST", "update": "PATCH", "unsubscribe": "DELETE"}[cmd]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	up := NewUpstream(cfg.APIBase, cfg.Token)
	var resp string
	var err error
	for attempt := 1; ; attempt++ {
		resp, err = up.Webhook(ctx, method, cfg.PublicURL)
		rl, limited := isRateLimited(err)
		if !limited || attempt >= 4 {
			break
		}
		fmt.Printf("ліміт запитів API, чекаю до %s і пробую ще раз…\n", rl.Until.Format("15:04:05"))
		if !sleepCtx(ctx, time.Until(rl.Until)) {
			break
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "помилка:", err)
		os.Exit(1)
	}
	fmt.Printf("%s: OK %s\n", cmd, strings.TrimSpace(resp))
}

// serviceStats читає /stats запущеної служби; nil, якщо служба не відповідає.
func serviceStats(cfg Config) map[string]any {
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Get("http://" + cfg.LocalListen + "/stats")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var m map[string]any
	if json.NewDecoder(resp.Body).Decode(&m) != nil {
		return nil
	}
	return m
}

func checkCmd(cfg Config) {
	need(cfg.Token != "", "не задано UA_TOKEN")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	up := NewUpstream(cfg.APIBase, cfg.Token)
	fail := false
	direct := len(os.Args) > 2 && os.Args[2] == "--direct"
	st := serviceStats(cfg)
	step := func(name string, f func() (string, error)) {
		t := time.Now()
		res, err := f()
		var se *startingError
		if errors.As(err, &se) {
			fmt.Printf("⚠ %-14s служба щойно запустилась, перша звірка з API — протягом ~%s\n", name, se.wait.Round(time.Second))
			return
		}
		if rl, ok := isRateLimited(err); ok {
			fmt.Printf("⚠ %-14s ліміт запитів API ukrainealarm, пауза до %s (служба продовжить сама)\n", name, rl.Until.Format("15:04:05"))
			return
		}
		if err != nil {
			fail = true
			fmt.Printf("✗ %-14s %v\n", name, err)
			return
		}
		fmt.Printf("✓ %-14s %s (%s)\n", name, res, time.Since(t).Round(time.Millisecond))
	}
	step("ключ підпису", func() (string, error) {
		k, _, err := loadKey(ctx, cfg, up)
		if err == nil {
			err = checkKey(k)
		}
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("RSA %d біт, sha256 %s", k.N.BitLen(), keyFingerprint(k)), nil
	})
	if st != nil && !direct {
		// Служба вже працює з API — не витрачаємо ліміт, а питаємо її.
		step("служба", func() (string, error) {
			return fmt.Sprintf("alertd %v працює %v, ключ: %v", st["version"], st["uptime"], st["signingKey"]), nil
		})
		step("API (зі служби)", func() (string, error) {
			if p, ok := st["apiPausedUntil"].(string); ok && p != "" {
				t, _ := time.Parse(time.RFC3339, p)
				return "", &RateLimitError{Until: t.Local()}
			}
			if e, _ := st["upstreamError"].(string); e != "" {
				return "", errors.New(e)
			}
			if st["lastSync"] == nil {
				up, _ := time.ParseDuration(fmt.Sprint(st["uptime"]))
				if up < cfg.SyncInterval+cfg.APIMinGap+time.Minute {
					return "", &startingError{wait: cfg.SyncInterval + cfg.APIMinGap - up}
				}
				return "", errors.New("ще не було вдалої звірки з API")
			}
			return fmt.Sprintf("остання звірка %v, регіонів %v, активних %v, запитів за хв %v",
				st["lastSync"], st["regionsKnown"], st["activeAlerts"], st["apiCalls1m"]), nil
		})
	} else {
		step("alerts", func() (string, error) {
			a, _, err := up.Alerts(ctx)
			return fmt.Sprintf("%d активних (регіон+тип)", len(a)), err
		})
	}
	if cfg.PublicURL != "" {
		// Непідписаний POST має пройти весь ланцюжок (CDN, reverse proxy) і отримати 401 саме від alertd.
		step("публічна адреса", func() (string, error) {
			req, _ := http.NewRequestWithContext(ctx, "POST", cfg.PublicURL, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "alertd-check/"+version)
			resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
			if err != nil {
				return "", err
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()
			switch {
			case resp.StatusCode == 401 && strings.Contains(string(body), `data-code="401"`):
				return "ланцюжок до alertd працює (непідписаний запит отримав 401 від alertd)", nil
			case resp.StatusCode == 403:
				return "", fmt.Errorf("HTTP 403: запит блокує CDN або фаєрвол перед alertd (напр. Cloudflare WAF / Bot Fight Mode)")
			case resp.StatusCode == 404 && strings.Contains(string(body), `data-code="404"`):
				return "", fmt.Errorf("HTTP 404 від alertd: HOOK_SECRET у PUBLIC_HOOK_URL не збігається")
			case resp.StatusCode == 404:
				return "", fmt.Errorf("HTTP 404: reverse proxy не передає цей шлях на alertd")
			case resp.StatusCode == 503 && strings.Contains(string(body), `data-code="503"`):
				return "", fmt.Errorf("HTTP 503: alertd ще не завантажив ключ підпису")
			case resp.StatusCode == 502 || resp.StatusCode == 503:
				return "", fmt.Errorf("HTTP %d: alertd не запущений або reverse proxy не бачить HOOK_LISTEN (%s)", resp.StatusCode, cfg.HookListen)
			}
			return "", fmt.Errorf("неочікувано: HTTP %d %s", resp.StatusCode, clean(string(body), 120))
		})
	}
	if fail {
		os.Exit(1)
	}
}

var secretRe = regexp.MustCompile(`^[A-Za-z0-9_-]{24,128}$`)

// validateConfig — налаштування, помилка в яких відкрила б щось назовні або зламала б прийом.
func validateConfig(cfg Config) error {
	if !secretRe.MatchString(cfg.HookSecret) {
		return errors.New("HOOK_SECRET: 24–128 символів [A-Za-z0-9_-] (openssl rand -hex 24)")
	}
	if !isLoopback(cfg.LocalListen) {
		return fmt.Errorf("LOCAL_LISTEN=%s: локальний API (стан, статистика) має слухати лише 127.0.0.1 або ::1", cfg.LocalListen)
	}
	u, err := url.Parse(cfg.APIBase)
	if err != nil || u.Host == "" {
		return fmt.Errorf("UA_API_BASE: некоректна адреса %q", cfg.APIBase)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Host)) {
		return fmt.Errorf("UA_API_BASE: лише https (токен не можна передавати відкрито)")
	}
	if cfg.SyncInterval < time.Second || cfg.APIMinGap < 0 {
		return errors.New("POLL_INTERVAL ≥ 1s, API_MIN_GAP ≥ 0")
	}
	if utf8.RuneCountInString(cfg.SiteTitle) > 64 || !utf8.ValidString(cfg.SiteTitle) ||
		strings.ContainsFunc(cfg.SiteTitle, unicode.IsControl) {
		return errors.New("SITE_TITLE: до 64 символів, без керівних")
	}
	return nil
}

func isLoopback(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loadKey(ctx context.Context, cfg Config, up *Upstream) (*rsa.PublicKey, string, error) {
	if cfg.PubKeyFile != "" {
		b, err := os.ReadFile(cfg.PubKeyFile)
		if err != nil {
			return nil, "", err
		}
		k, err := parsePublicKey(b)
		return k, "file", err
	}
	k, _, err := up.PublicKey(ctx)
	return k, "api", err
}

func run(cfg Config) error {
	if cfg.Token == "" {
		return errors.New("не задано UA_TOKEN")
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	SetSiteTitle(cfg.SiteTitle)
	if cfg.SyncInterval < cfg.APIMinGap {
		logf("POLL_INTERVAL=%s менший за API_MIN_GAP=%s: API опитуватиметься раз на %s", cfg.SyncInterval, cfg.APIMinGap, cfg.APIMinGap)
	}
	up := NewUpstream(cfg.APIBase, cfg.Token)
	up.SetMinGap(cfg.APIMinGap)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Ключ підпису вантажимо у фоні: поки його немає, webhook отримують 503 (Retry-After),
	// але стан, звірка з API і локальний API вже працюють.
	// Якщо підпис не сходиться (ротація ключа), пробуємо взяти новий ключ з API,
	// навіть коли основний ключ закріплено файлом (не частіше ніж раз на 5 хв).
	reload := func() (*rsa.PublicKey, error) {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		k, _, err := up.PublicKey(c)
		return k, err
	}
	verifier := NewVerifier(nil, cfg.MaxSkew, reload)
	go func() {
		for delay := 2 * time.Second; ; {
			kctx, c := context.WithTimeout(ctx, 20*time.Second)
			k, src, err := loadKey(kctx, cfg, up)
			c()
			if err == nil {
				err = verifier.SetKey(k)
			}
			if err == nil {
				logf("webhook public key loaded from %s: RSA %d bit, sha256 %s", src, k.N.BitLen(), keyFingerprint(k))
				return
			}
			logf("cannot load webhook public key: %v (retry in %s)", err, delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			if delay < time.Minute {
				delay *= 2
			}
		}
	}()

	store, err := OpenStore(cfg.DBPath, 65536)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	// Час останнього запиту до API переживає перезапуск: новий процес не порушить ліміт
	// ukrainealarm і не отримає 429 одразу після старту.
	if ms, err := strconv.ParseInt(store.GetMeta("api_last_call_ms"), 10, 64); err == nil {
		if last := time.UnixMilli(ms); !last.After(time.Now()) && time.Since(last) < cfg.APIMinGap {
			up.ResumeAfter(last)
			logf("previous API request %s ago: first request in %s", time.Since(last).Round(time.Second),
				(cfg.APIMinGap - time.Since(last)).Round(time.Second))
		}
	}
	up.SetOnCall(func(t time.Time) { store.SetMeta("api_last_call_ms", strconv.FormatInt(t.UnixMilli(), 10)) })
	state := NewState(store.Queue(), 10000) // буфер для перепідключень до /events
	state.seq = store.MaxSeq()
	if rs, err := store.LoadRegions(); err == nil && len(rs) > 0 {
		state.SetRegions(rs)
	}
	if n, err := store.LoadActive(state); err != nil {
		logf("restore active state: %v", err)
	} else {
		logf("restored %d active alerts from db, seq=%d", n, state.seq)
	}
	go store.Run()

	srv := NewServer(cfg, state, store, verifier)
	srv.up = up
	// Пам'ять дублікатів переживає перезапуск: інакше перехоплений webhook можна було б
	// повторити одразу після рестарту (підпис дійсний 5 хв).
	if hs, err := store.RecentHashes(time.Now().Add(-srv.dd.ttl)); err == nil {
		srv.dd.seed(hs, time.Now())
	} else {
		logf("dedup seed: %v", err)
	}
	state.SetHookTrust(cfg.SyncInterval + 30*time.Second)
	if t := store.LastWebhook(); !t.IsZero() { // індикатор пам'ятає webhook між перезапусками
		srv.lastHookUnix.Store(t.Unix())
	}
	if v, err := strconv.ParseInt(store.GetMeta("last_action_index"), 10, 64); err == nil {
		srv.lastActionIndex.Store(v)
	}

	hookLn, err := net.Listen("tcp", cfg.HookListen)
	if err != nil {
		return err
	}
	localLn, err := net.Listen("tcp", cfg.LocalListen)
	if err != nil {
		return err
	}
	hookSrv := &http.Server{Handler: srv.HookHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	localSrv := &http.Server{Handler: srv.LocalHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hookSrv.Serve(hookLn) }()
	go func() { _ = localSrv.Serve(localLn) }()
	logf("alertd %s: webhook on %s/hook/…, local api on %s, db %s", version, cfg.HookListen, cfg.LocalListen, cfg.DBPath)

	// Webhook приймаються одразу; паралельно — дерево регіонів і початкова звірка.
	go srv.syncLoop(ctx, up)
	sdNotify("READY=1")
	go runWatchdog(ctx, watchdogInterval(), func(c context.Context) bool {
		// живий, якщо стан і БД не заблоковані, а HTTP-сервер відповідає
		state.Snapshot()
		req, _ := http.NewRequestWithContext(c, "GET", "http://"+cfg.LocalListen+"/health", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true
	}, sdNotify)
	go srv.maintenanceLoop(ctx, up)

	<-ctx.Done()
	sdNotify("STOPPING=1")
	logf("shutting down")
	sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	_ = hookSrv.Shutdown(sctx)
	_ = localSrv.Close() // потоки /events тримаються довго — закриваємо одразу
	state.Close()        // після цього Apply нічого не пише в чергу БД
	store.Close()        // дописує все, що лишилось у черзі
	return nil
}

// startingError — служба щойно стартувала й чекає черги до API: це не збій.
type startingError struct{ wait time.Duration }

func (e *startingError) Error() string { return "перша звірка ще попереду" }

func (s *Server) setUpstreamErr(err error) {
	// Пауза через ліміт — не помилка: її видно в apiPausedUntil, і служба продовжить сама.
	if _, rl := isRateLimited(err); err == nil || rl {
		s.upstreamErr.Store("")
		return
	}
	s.upstreamErr.Store(err.Error())
}

func (s *Server) refreshRegions(ctx context.Context, up *Upstream) error {
	// Без тайм-ауту тут: очікування черги до API (API_MIN_GAP) може бути довшим за хвилину,
	// а сам HTTP-запит обмежує Upstream.
	rs, err := up.Regions(ctx)
	if err != nil {
		return err
	}
	s.state.SetRegions(rs)
	if err := s.store.SaveRegions(rs); err != nil {
		logf("save regions: %v", err)
	}
	logf("regions: %d loaded", len(rs))
	return nil
}

// fullSync бере знімок /alerts і виправляє розбіжності.
func (s *Server) fullSync(ctx context.Context, up *Upstream, source string, strict bool) error {
	fetchStart := time.Now()
	snap, newest, err := up.Alerts(ctx) // тайм-аут лише на сам HTTP-запит — у Upstream
	if err != nil {
		return err
	}
	fixes := s.state.Reconcile(snap, newest, fetchStart, time.Second, source, strict)
	if held, _ := s.state.MassEnd(); held {
		logf("%s sync: snapshot would end most alerts at once (%d active in it) — waiting for the next snapshot to confirm", source, len(snap))
	}
	if len(fixes) > 0 {
		s.reconcileFixes.Add(int64(len(fixes)))
		if source == "poll" {
			s.notePending(fixes, time.Now()) // пропуск — лише якщо webhook так і не прийде
		}
		var sample []string
		for i, ev := range fixes {
			if i == 5 {
				sample = append(sample, fmt.Sprintf("… ще %d", len(fixes)-5))
				break
			}
			name := ev.RegionName
			if name == "" {
				name = ev.RegionID
			}
			sample = append(sample, fmt.Sprintf("%s %s %s [%s → %s]", clean(name, 48), ev.AlarmType, ev.Change,
				strings.Join(ev.PrevLevels, "+"), strings.Join(ev.Levels, "+")))
		}
		logf("%s sync: %d corrections (snapshot has %d active): %s", source, len(fixes), len(snap), strings.Join(sample, "; "))
	}
	s.lastSyncUnix.Store(time.Now().Unix())
	if n := s.expirePending(time.Now()); n > 0 {
		logf("%d webhook(s) missed: the change was seen only by sync for over %s", n, missGrace)
	}
	return nil
}

// sleepCtx чекає d або скасування; false — якщо скасовано.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// noteUpstream записує стан зв'язку з API; про паузу через ліміт пише в журнал один раз.
func (s *Server) noteUpstream(what string, err error) {
	if err == nil {
		s.setUpstreamErr(nil)
		return
	}
	s.setUpstreamErr(err)
	if rl, ok := isRateLimited(err); ok {
		if last := s.lastPauseLogged.Load(); last != rl.Until.Unix() {
			s.lastPauseLogged.Store(rl.Until.Unix())
			logf("%s: %v", what, err)
		}
		return
	}
	logf("%s: %v", what, err)
}

// syncLoop — звірка з API в межах ліміту ukrainealarm (~1 запит на хвилину).
//
// Webhook — основне джерело. Звірка — це повний знімок /alerts раз на POLL_INTERVAL:
// один запит дає весь стан, тож окремий /alerts/status не потрібен. Дерево регіонів
// береться один раз (далі з БД) і оновлюється раз на добу. Між будь-якими запитами
// щонайменше API_MIN_GAP; після 429 — жодних запитів, доки сервер просить чекати.
func (s *Server) syncLoop(ctx context.Context, up *Upstream) {
	backoff := 5 * time.Second
	retryWait := func(err error) time.Duration {
		if rl, ok := isRateLimited(err); ok {
			return time.Until(rl.Until)
		}
		w := backoff
		if backoff < 5*time.Minute {
			backoff *= 2
		}
		return w
	}
	// 1. Дерево регіонів (лише якщо в БД його ще немає).
	for s.state.RegionCount() == 0 {
		err := s.refreshRegions(ctx, up)
		if err == nil {
			s.store.SetMeta("regions_ms", strconv.FormatInt(time.Now().UnixMilli(), 10))
			break
		}
		s.noteUpstream("regions", err)
		if !sleepCtx(ctx, retryWait(err)) {
			return
		}
	}
	// 2. Стартова звірка: виправляє все, що змінилося, поки служба не працювала.
	backoff = 5 * time.Second
	for {
		err := s.fullSync(ctx, up, "startup", true)
		if err == nil {
			s.noteUpstream("initial sync", nil)
			break
		}
		s.noteUpstream("initial sync", err)
		if !sleepCtx(ctx, retryWait(err)) {
			return
		}
	}
	// 3. Періодична звірка.
	for {
		if !sleepCtx(ctx, s.cfg.SyncInterval) {
			return
		}
		if p := up.PausedUntil(); time.Now().Before(p) && !sleepCtx(ctx, time.Until(p)) {
			return
		}
		if err := s.fullSync(ctx, up, "poll", false); err != nil {
			s.noteUpstream("sync", err)
			continue
		}
		s.noteUpstream("sync", nil)
	}
}

// maintenanceLoop: щодоби оновлює дерево регіонів і чистить старі події.
func (s *Server) maintenanceLoop(ctx context.Context, up *Upstream) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		last, _ := strconv.ParseInt(s.store.GetMeta("regions_ms"), 10, 64)
		if time.Since(time.UnixMilli(last)) > 24*time.Hour {
			if err := s.refreshRegions(ctx, up); err != nil {
				logf("regions refresh: %v", err)
			} else {
				s.store.SetMeta("regions_ms", strconv.FormatInt(time.Now().UnixMilli(), 10))
			}
		}
		if n, err := s.store.Prune(s.cfg.Retention); err != nil {
			logf("prune: %v", err)
		} else if n > 0 {
			logf("pruned %d old events", n)
		}
		s.state.Prune(48 * time.Hour)
		s.store.Optimize()
	}
}
