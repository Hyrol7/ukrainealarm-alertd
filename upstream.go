package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const requestTimeout = 30 * time.Second

// RateLimitError — API відповів 429; до Until жодних запитів не робимо.
type RateLimitError struct{ Until time.Time }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("API rate limit, paused until %s", e.Until.Format("15:04:05"))
}

func isRateLimited(err error) (*RateLimitError, bool) {
	var rl *RateLimitError
	ok := errors.As(err, &rl)
	return rl, ok
}

var waitRe = regexp.MustCompile(`(?i)wait\s+(\d+)\s+second`)

// Upstream — клієнт api.ukrainealarm.com.
type Upstream struct {
	base  string
	token string
	hc    *http.Client

	mu         sync.Mutex
	pauseUntil time.Time
	calls      []time.Time     // моменти запитів до API за останню хвилину
	minGap     time.Duration   // мінімальний проміжок між запитами до API
	onCall     func(time.Time) // викликається на кожен запит (щоб пам'ятати час між перезапусками)
	nextSlot   time.Time
}

// SetMinGap — рівномірний розподіл запитів: не частіше одного на gap.
// SetOnCall — що робити з часом кожного запиту до API (напр. зберегти в БД).
func (u *Upstream) SetOnCall(f func(time.Time)) {
	u.mu.Lock()
	u.onCall = f
	u.mu.Unlock()
}

// ResumeAfter — останній запит до API зробив попередній процес у момент last:
// перший запит цього процесу буде не раніше last+minGap (інакше після перезапуску — 429).
func (u *Upstream) ResumeAfter(last time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if next := last.Add(u.minGap); next.After(u.nextSlot) {
		u.nextSlot = next
	}
}

func (u *Upstream) SetMinGap(gap time.Duration) {
	u.mu.Lock()
	u.minGap = gap
	u.mu.Unlock()
}

// CallsLastMinute — скільки запитів до API зроблено за останні 60 с.
func (u *Upstream) CallsLastMinute() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.trimLocked(time.Now())
	return len(u.calls)
}

func (u *Upstream) PausedUntil() time.Time {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.pauseUntil
}

func (u *Upstream) trimLocked(now time.Time) {
	i := 0
	for i < len(u.calls) && now.Sub(u.calls[i]) > time.Minute {
		i++
	}
	u.calls = u.calls[i:]
}

// rateWait: скільки чекати після 429 — з тексту «wait N seconds», з Retry-After, інакше 60 с.
func rateWait(hdr http.Header, body []byte) time.Duration {
	if m := waitRe.FindSubmatch(body); m != nil {
		if n, err := strconv.Atoi(string(m[1])); err == nil && n >= 0 && n <= 3600 {
			return time.Duration(n)*time.Second + time.Second
		}
	}
	if n, err := strconv.Atoi(strings.TrimSpace(hdr.Get("Retry-After"))); err == nil && n >= 0 && n <= 3600 {
		return time.Duration(n)*time.Second + time.Second
	}
	return time.Minute
}

func NewUpstream(base, token string) *Upstream {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 4
	tr.IdleConnTimeout = 90 * time.Second
	return &Upstream{base: strings.TrimRight(base, "/"), token: token, hc: &http.Client{
		Transport: tr,
		// Жодних перенаправлень: токен іде лише на задану адресу API.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (u *Upstream) do(ctx context.Context, method, path string, body any, out any) error {
	_, err := u.doRaw(ctx, method, path, body, out)
	return err
}

func (u *Upstream) doRaw(ctx context.Context, method, path string, body any, out any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	u.mu.Lock()
	now := time.Now()
	if now.Before(u.pauseUntil) {
		until := u.pauseUntil
		u.mu.Unlock()
		return nil, &RateLimitError{Until: until}
	}
	// Черга з рівними проміжками: бронюємо наступний вільний слот і чекаємо його.
	slot := now
	if u.minGap > 0 && u.nextSlot.After(now) {
		slot = u.nextSlot
	}
	u.nextSlot = slot.Add(u.minGap)
	u.mu.Unlock()
	if d := time.Until(slot); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			// Звільняємо своє місце, якщо після нас ніхто не забронював — черга не «їде» вперед.
			u.mu.Lock()
			if u.nextSlot.Equal(slot.Add(u.minGap)) {
				u.nextSlot = slot
			}
			u.mu.Unlock()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	// Тайм-аут — лише на сам HTTP-запит, не на очікування черги.
	ctx, cancelReq := context.WithTimeout(ctx, requestTimeout)
	defer cancelReq()
	u.mu.Lock()
	if now := time.Now(); now.Before(u.pauseUntil) { // поки чекали, прийшов 429
		until := u.pauseUntil
		u.mu.Unlock()
		return nil, &RateLimitError{Until: until}
	}
	callAt := time.Now()
	u.trimLocked(callAt)
	u.calls = append(u.calls, callAt)
	onCall := u.onCall
	u.mu.Unlock()
	if onCall != nil {
		go onCall(callAt)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", u.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "alertd/"+version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := u.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		until := time.Now().Add(rateWait(resp.Header, data))
		u.mu.Lock()
		if until.After(u.pauseUntil) {
			u.pauseUntil = until
		}
		u.mu.Unlock()
		return data, &RateLimitError{Until: until}
	}
	if resp.StatusCode/100 != 2 {
		return data, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(trunc(data, 300))))
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return data, fmt.Errorf("%s %s: decode: %w", method, path, err)
		}
	}
	return data, nil
}

func trunc(b []byte, n int) []byte {
	if len(b) > n {
		return append(b[:n:n], "…"...)
	}
	return b
}

type apiRegion struct {
	ID       flexID      `json:"regionId"`
	Name     string      `json:"regionName"`
	Type     string      `json:"regionType"`
	Children []apiRegion `json:"regionChildIds"`
}

// Regions завантажує дерево і «розплющує» його з parent_id та state_id (ID області).
func (u *Upstream) Regions(ctx context.Context) (map[string]Region, error) {
	var resp struct {
		States []apiRegion `json:"states"`
	}
	if err := u.do(ctx, "GET", "/api/v3/regions", nil, &resp); err != nil {
		return nil, err
	}
	out := map[string]Region{}
	var walk func(r apiRegion, parent, state string, depth int)
	walk = func(r apiRegion, parent, state string, depth int) {
		id := string(r.ID)
		if id == "" {
			return
		}
		if depth == 0 {
			state = id
		}
		out[id] = Region{ID: id, Name: r.Name, Type: r.Type, ParentID: parent, StateID: state, Depth: depth}
		for _, c := range r.Children {
			walk(c, id, state, depth+1)
		}
	}
	for _, s := range resp.States {
		walk(s, "", "", 0)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("regions: empty tree")
	}
	return out, nil
}

type apiAlert struct {
	RegionID   flexID   `json:"regionId"`
	RegionType string   `json:"regionType"`
	Type       string   `json:"type"`
	LastUpdate flexTime `json:"lastUpdate"`
	Levels     []Level  `json:"activeAlertLevels"`
}

type apiAlertRegion struct {
	RegionID     flexID     `json:"regionId"`
	RegionType   string     `json:"regionType"`
	RegionName   string     `json:"regionName"`
	LastUpdate   flexTime   `json:"lastUpdate"`
	ActiveAlerts []apiAlert `json:"activeAlerts"`
}

// Alerts повертає повний знімок активних тривог: (регіон, тип) → рівні, а також найсвіжіший
// createdAt серед усіх рівнів (час за годинником ukrainealarm, до якого знімок точно актуальний).
//
// Та сама тривога в /alerts повторюється в записах області, району й кожної громади, тож рівні
// одного (регіон, тип) зводяться без повторів за (рівень, причина, createdAt).
// Якщо API не віддав рівнів (старий формат), підставляємо один рівень без причини.
func (u *Upstream) Alerts(ctx context.Context) (map[key][]Level, time.Time, error) {
	data, err := u.doRaw(ctx, "GET", "/api/v3/alerts", nil, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	// Лише справжній JSON-масив. Порожня відповідь чи null — збій API, а не «тривог немає»:
	// інакше один збій «скасував» би всі тривоги країни.
	if t := bytes.TrimSpace(data); len(t) == 0 || t[0] != '[' {
		return nil, time.Time{}, fmt.Errorf("GET /api/v3/alerts: not a JSON array: %q", trunc(t, 80))
	}
	var resp []apiAlertRegion
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, time.Time{}, fmt.Errorf("GET /api/v3/alerts: decode: %w", err)
	}
	return parseAlerts(resp), newestLevel(resp), nil
}

type levelID struct {
	level, reason string
	at            int64 // мікросекунди: webhook і API віддають різну кількість знаків
}

func parseAlerts(resp []apiAlertRegion) map[key][]Level {
	out := map[key][]Level{}
	seen := map[key]map[levelID]bool{}
	for _, r := range resp {
		for _, a := range r.ActiveAlerts {
			id := string(a.RegionID)
			if id == "" {
				id = string(r.RegionID)
			}
			k := key{id, normType(a.Type)}
			ls := a.Levels
			if len(ls) == 0 {
				t := a.LastUpdate
				if t.IsZero() {
					t = r.LastUpdate
				}
				ls = []Level{{Level: "Red", CreatedAt: t}}
			}
			if seen[k] == nil {
				seen[k] = map[levelID]bool{}
			}
			for _, l := range ls {
				lid := levelID{strings.ToLower(l.Level), l.Reason, l.CreatedAt.UnixMicro()}
				if seen[k][lid] {
					continue
				}
				seen[k][lid] = true
				out[k] = append(out[k], l)
			}
		}
	}
	return out
}

func newestLevel(resp []apiAlertRegion) time.Time {
	var t time.Time
	for _, r := range resp {
		for _, a := range r.ActiveAlerts {
			for _, l := range a.Levels {
				if l.CreatedAt.After(t) {
					t = l.CreatedAt.Time
				}
			}
		}
	}
	return t
}

func (u *Upstream) Status(ctx context.Context) (int64, error) {
	var resp struct {
		LastActionIndex int64 `json:"lastActionIndex"`
	}
	if err := u.do(ctx, "GET", "/api/v3/alerts/status", nil, &resp); err != nil {
		return 0, err
	}
	return resp.LastActionIndex, nil
}

func (u *Upstream) Webhook(ctx context.Context, method, url string) (string, error) {
	data, err := u.doRaw(ctx, method, "/api/v3/webhook", map[string]string{"webHookUrl": url}, nil)
	return string(data), err
}

func (u *Upstream) PublicKey(ctx context.Context) (*rsa.PublicKey, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.base+"/webhook-public.pem", nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "alertd/"+version)
	resp, err := u.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("public key: HTTP %d", resp.StatusCode)
	}
	k, err := parsePublicKey(data)
	return k, data, err
}
