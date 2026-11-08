package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// flexID приймає і число (webhook: regionId int), і рядок (REST API: regionId string).
type flexID string

func (f *flexID) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexID(strings.TrimSpace(s))
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("regionId: %w", err)
	}
	*f = flexID(n.String())
	return nil
}

// flexTime розбирає ISO 8601 з часовою зоною або без неї (.NET часто віддає без "Z").
// Час без зони вважаємо UTC, як і сказано в документації API.
type flexTime struct{ time.Time }

var timeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.9999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
}

func parseFlexTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time %q", s)
}

func (t *flexTime) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		t.Time = time.Time{}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := parseFlexTime(s)
	if err != nil {
		return err
	}
	t.Time = v
	return nil
}

func (t flexTime) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.UTC().Format(time.RFC3339Nano))
}

// Level — один активний рівень загрози з причиною.
type Level struct {
	Level     string   `json:"alertLevel"`
	Reason    string   `json:"reason"`
	CreatedAt flexTime `json:"createdAt"`
}

// canonLevels — копія з нормалізованими назвами рівнів (Red/Yellow; порожня назва — Unknown,
// щоб тривога з невідомим рівнем не зникала), без повністю порожніх записів, відсортована
// за (ранг ↓, назва, причина, createdAt).
func canonLevels(in []Level) []Level {
	out := make([]Level, 0, len(in))
	for _, l := range in {
		if strings.TrimSpace(l.Level) == "" && strings.TrimSpace(l.Reason) == "" {
			continue
		}
		l.Level = normLevel(l.Level)
		out = append(out, l)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := levelRank(a.Level), levelRank(b.Level); ra != rb {
			return ra > rb
		}
		if a.Level != b.Level {
			return a.Level < b.Level
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.CreatedAt.Before(b.CreatedAt.Time)
	})
	return out
}

// sameLevels — однакові множини (рівень, причина); повтори й createdAt не враховуються.
func sameLevels(a, b []Level) bool {
	type lr struct{ l, r string }
	set := func(x []Level) map[lr]bool {
		m := make(map[lr]bool, len(x))
		for _, v := range x {
			m[lr{normLevel(v.Level), v.Reason}] = true
		}
		return m
	}
	sa, sb := set(a), set(b)
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if !sb[k] {
			return false
		}
	}
	return true
}

func levelRank(l string) int {
	switch strings.ToLower(l) {
	case "red":
		return 2
	case "yellow":
		return 1
	}
	return 0
}

func normLevel(l string) string {
	switch t := strings.TrimSpace(l); strings.ToLower(t) {
	case "red":
		return "Red"
	case "yellow":
		return "Yellow"
	case "":
		return "Unknown"
	default:
		return t
	}
}

// levelSet — множина рівнів без повторів, Red першим; порожня множина — [] (не null) у JSON.
func levelSet(ls []Level) []string {
	out := []string{}
	for _, l := range ls {
		n := normLevel(l.Level)
		dup := false
		for _, x := range out {
			if x == n {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return levelRank(out[i]) > levelRank(out[j]) })
	return out
}

func diffLevels(a, b []string) (added, removed []string) {
	in := func(x string, set []string) bool {
		for _, y := range set {
			if y == x {
				return true
			}
		}
		return false
	}
	for _, x := range b {
		if !in(x, a) {
			added = append(added, x)
		}
	}
	for _, x := range a {
		if !in(x, b) {
			removed = append(removed, x)
		}
	}
	return
}

func maxLevel(ls []Level) string {
	best := ""
	for _, l := range ls {
		if levelRank(l.Level) > levelRank(best) {
			best = l.Level
		}
	}
	return best
}

// webhookMsg — тіло webhook (WebHookMessageModel).
type webhookMsg struct {
	Status            string   `json:"status"`
	RegionID          flexID   `json:"regionId"`
	AlarmType         string   `json:"alarmType"`
	CreatedAt         flexTime `json:"createdAt"`
	AlertLevel        string   `json:"alertLevel"`
	Reason            string   `json:"reason"`
	ActiveAlertLevels []Level  `json:"activeAlertLevels"`
}

// Зміни стану регіону після події.
const (
	ChangeStart  = "start"  // тривоги не було → з'явилась
	ChangeUpdate = "update" // тривога триває, змінився набір рівнів/причин
	ChangeEnd    = "end"    // відбій: активних рівнів не лишилось
	ChangeNone   = "none"   // повтор того самого стану
	ChangeStale  = "stale"  // подія старіша за вже застосовану, стан не змінено
)

// Event — нормалізована подія, яку бачать БД і локальні підписники.
type Event struct {
	Seq         int64    `json:"seq"`
	ReceivedAt  flexTime `json:"receivedAt"`
	CreatedAt   flexTime `json:"createdAt"`
	RegionID    string   `json:"regionId"`
	RegionName  string   `json:"regionName,omitempty"`
	RegionType  string   `json:"regionType,omitempty"`
	StateID     string   `json:"stateId,omitempty"`
	AlarmType   string   `json:"alarmType"`
	Status      string   `json:"status"`
	AlertLevel  string   `json:"alertLevel,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Active      []Level  `json:"activeAlertLevels"`
	Change      string   `json:"change"`
	Source      string   `json:"source"` // webhook | poll | startup
	SessionFrom flexTime `json:"sessionStartedAt"`
	MaxLevel    string   `json:"sessionMaxLevel,omitempty"`
	Reasons     []string `json:"sessionReasons,omitempty"`
	// Рівні загрози до й після події (без повторів, Red першим). Red — ракетна небезпека,
	// Yellow — загроза застосування БпЛА; можуть бути активні одночасно.
	Levels     []string `json:"levels"`
	PrevLevels []string `json:"prevLevels"`

	hash  string    // sha256 сирого тіла webhook (для дедуплікації в БД)
	wire  []byte    // JSON для підписників /events: серіалізується один раз на подію
	known time.Time // до якого моменту (годинник ukrainealarm) стан відомий — у БД як updated_ms
}

func normStatus(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ACTIVATE", "ACTIVE":
		return "ACTIVATE"
	case "DEACTIVATE", "INACTIVE":
		return "DEACTIVATE"
	case "":
		return "SYNC"
	}
	return strings.ToUpper(strings.TrimSpace(s))
}

func normType(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return "UNKNOWN"
	}
	return s
}

func i64(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v }

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}
