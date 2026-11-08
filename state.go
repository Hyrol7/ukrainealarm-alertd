package main

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// Region — вузол дерева «область → район → громада».
type Region struct {
	ID       string `json:"regionId"`
	Name     string `json:"regionName"`
	Type     string `json:"regionType"`
	ParentID string `json:"parentId,omitempty"`
	StateID  string `json:"stateId,omitempty"`
	Depth    int    `json:"depth"`
}

type key struct{ region, typ string }

type entry struct {
	Active    []Level   // поточний знімок activeAlertLevels (канонічно відсортований)
	Since     time.Time // початок поточної тривоги
	UpdatedAt time.Time // до якого моменту (годинник ukrainealarm) стан цього запису відомий
	SeenAt    time.Time // коли ми востаннє змінювали/підтверджували запис
	HookAt    time.Time // коли запис востаннє оновив саме webhook
	MaxLevel  string
	Reasons   []string
}

// State — стан усієї країни в пам'яті. Єдине джерело правди для гарячого шляху.
type State struct {
	mu      sync.Mutex
	regions map[string]Region
	m       map[key]*entry
	seq     int64

	ring    []Event // останні події для відновлення підписників (Last-Event-ID)
	ringPos int
	subs    map[chan Event]struct{}
	sink    chan<- Event // черга запису в БД
	closed  bool         // після Close події не пишуться в БД (зупинка сервісу)

	// hookTrust: скільки часу після отримання webhook його дані вважаються новішими за знімок,
	// якщо webhook створено пізніше за найсвіжіший рівень у знімку (див. Reconcile).
	hookTrust time.Duration

	// watermark — момент (годинник ukrainealarm), до якого всі зміни точно відображені в
	// останньому знімку: найсвіжіший createdAt рівня в знімку мінус 1 с. Webhook, створений
	// раніше, вже «врахований» знімком: якщо він не збігається зі станом — він застарілий.
	watermark time.Time

	// massEndHeld: попередній знімок хотів завершити більшість тривог одразу — чекаємо
	// підтвердження наступним знімком (захист від збою API, що віддав неповні дані).
	massEndHeld    bool
	massEndSkipped int64
}

// Запобіжник масового відбою: знімок, який завершує понад massEndMin тривог і понад половину
// активних, застосовується лише якщо наступний знімок це підтвердить.
const massEndMin = 10

// snapshotSlack — запас на те, що createdAt події у webhook трохи раніший (~0,3 с у реальних
// даних), ніж createdAt відповідного рівня в знімку.
const snapshotSlack = time.Second

// maxFutureSkew — наскільки час події від джерела може випереджати наш момент отримання.
const maxFutureSkew = 5 * time.Second

// MassEnd — чи відкладено масовий відбій і скільки разів таке було.
func (s *State) MassEnd() (held bool, skipped int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.massEndHeld, s.massEndSkipped
}

func (s *State) SetHookTrust(d time.Duration) {
	s.mu.Lock()
	s.hookTrust = d
	s.mu.Unlock()
}

// Close зупиняє запис у чергу БД і від'єднує підписників. Викликається перед закриттям черги.
func (s *State) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for ch := range s.subs {
		delete(s.subs, ch)
		close(ch)
	}
}

func NewState(sink chan<- Event, ringSize int) *State {
	return &State{
		regions: map[string]Region{},
		m:       map[key]*entry{},
		ring:    make([]Event, 0, ringSize),
		subs:    map[chan Event]struct{}{},
		sink:    sink,
	}
}

func (s *State) SetRegions(rs map[string]Region) {
	s.mu.Lock()
	s.regions = rs
	s.mu.Unlock()
}

func (s *State) RegionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.regions)
}

// Restore підвантажує стан із БД під час старту (без генерації подій).
func (s *State) Restore(region, typ string, active []Level, since, updated time.Time, maxLevel string, reasons []string) {
	s.mu.Lock()
	s.m[key{region, typ}] = &entry{Active: canonLevels(active), Since: since, UpdatedAt: updated, SeenAt: time.Time{}, MaxLevel: maxLevel, Reasons: reasons}
	s.mu.Unlock()
}

func addReasons(dst []string, ls []Level) []string {
	for _, l := range ls {
		if l.Reason == "" {
			continue
		}
		found := false
		for _, r := range dst {
			if r == l.Reason {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, l.Reason)
		}
	}
	return dst
}

// Apply застосовує подію до стану, нумерує її, кладе в чергу БД і розсилає підписникам.
// Усе під одним м'ютексом: порядок подій однаковий для БД і для підписників.
func (s *State) Apply(ev Event) Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyLocked(ev)
}

func (s *State) applyLocked(ev Event) Event {
	ev.Active = canonLevels(ev.Active)
	if r, ok := s.regions[ev.RegionID]; ok {
		ev.RegionName, ev.RegionType, ev.StateID = r.Name, r.Type, r.StateID
	}
	k := key{ev.RegionID, ev.AlarmType}
	e := s.m[k]
	was := e != nil && len(e.Active) > 0
	now := len(ev.Active) > 0
	ev.PrevLevels = []string{}
	if e != nil {
		ev.PrevLevels = levelSet(e.Active)
	}
	ev.Levels = levelSet(ev.Active)

	// Чи відомий нам стан цього запису на момент, новіший за подію (лише для подій із createdAt).
	known := s.watermark
	if e != nil && e.UpdatedAt.After(known) {
		known = e.UpdatedAt
	}
	older := !ev.CreatedAt.IsZero() && ev.CreatedAt.Before(known)
	same := was == now && (!now || sameLevels(e.Active, ev.Active))

	switch {
	case older && same:
		ev.Change = ChangeNone // запізнілий повтор того, що вже відомо (напр. звірка встигла раніше)
	case older:
		ev.Change = ChangeStale
	case !was && now:
		ev.Change = ChangeStart
	case was && !now:
		ev.Change = ChangeEnd
	case was && now && !sameLevels(e.Active, ev.Active):
		ev.Change = ChangeUpdate
	default:
		ev.Change = ChangeNone
	}

	if ev.Change != ChangeStale {
		// upd — до якого моменту (годинник ukrainealarm) стан запису тепер відомий.
		// Webhook: його createdAt. Звірка: найсвіжіший createdAt рівнів запису або watermark знімка.
		upd := ev.CreatedAt.Time
		if upd.IsZero() {
			upd = s.watermark
			for _, l := range ev.Active {
				if l.CreatedAt.After(upd) {
					upd = l.CreatedAt.Time
				}
			}
		}
		// час джерела з «майбутнього» не може заблокувати наступні події регіону
		if lim := ev.ReceivedAt.Add(maxFutureSkew); !ev.ReceivedAt.IsZero() && upd.After(lim) {
			upd = lim
		}
		if e != nil && e.UpdatedAt.After(upd) {
			upd = e.UpdatedAt // не відкочуємо назад
		}
		switch ev.Change {
		case ChangeStart:
			since := upd
			if since.IsZero() {
				since = ev.ReceivedAt.Time
			}
			for _, l := range ev.Active { // знімок може містити рівні, що почались раніше
				if !l.CreatedAt.IsZero() && l.CreatedAt.Before(since) {
					since = l.CreatedAt.Time
				}
			}
			e = &entry{Since: since, MaxLevel: maxLevel(ev.Active), Reasons: addReasons(nil, ev.Active)}
			s.m[k] = e
		case ChangeUpdate:
			if levelRank(maxLevel(ev.Active)) > levelRank(e.MaxLevel) {
				e.MaxLevel = maxLevel(ev.Active)
			}
			e.Reasons = addReasons(e.Reasons, ev.Active)
		case ChangeEnd:
			// після запису в БД запис видаляється з карти (нижче)
		case ChangeNone:
			if e == nil {
				e = &entry{}
				s.m[k] = e
			}
		}
		e.Active = ev.Active
		e.UpdatedAt = upd
		e.SeenAt = ev.ReceivedAt.Time
		ev.known = upd
		if ev.Source == "webhook" {
			e.HookAt = ev.ReceivedAt.Time
		}
		ev.SessionFrom = flexTime{e.Since}
		ev.MaxLevel = e.MaxLevel
		ev.Reasons = append([]string(nil), e.Reasons...)
		if ev.Change == ChangeEnd || len(e.Active) == 0 {
			// неактивні записи тримаємо лише як «маяк» часу, щоб відкидати застарілі події
			e.Since, e.MaxLevel, e.Reasons = time.Time{}, "", nil
		}
	} else {
		ev.Levels = ev.PrevLevels // stale нічого не змінює
		if e != nil {
			ev.SessionFrom = flexTime{e.Since}
		}
	}

	if s.closed {
		return ev
	}
	s.seq++
	ev.Seq = s.seq
	s.sink <- ev
	ev.wire, _ = json.Marshal(ev) // один раз для всіх підписників і буфера перепідключень
	s.publishLocked(ev)
	return ev
}

func (s *State) publishLocked(ev Event) {
	if cap(s.ring) > 0 {
		if len(s.ring) < cap(s.ring) {
			s.ring = append(s.ring, ev)
		} else {
			s.ring[s.ringPos] = ev
			s.ringPos = (s.ringPos + 1) % cap(s.ring)
		}
	}
	for ch := range s.subs {
		select {
		case ch <- ev:
		default: // повільний підписник: від'єднуємо, він перепідключиться з Last-Event-ID
			delete(s.subs, ch)
			close(ch)
		}
	}
}

// Subscribe повертає канал нових подій, усі буферизовані події з seq > after і поточний seq
// (усе атомарно). max — ліміт підписників; nil-канал, якщо ліміт вичерпано.
func (s *State) Subscribe(after int64, max int) (chan Event, []Event, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if max > 0 && len(s.subs) >= max {
		return nil, nil, s.seq
	}
	ch := make(chan Event, 4096)
	if s.closed {
		close(ch)
		return ch, nil, s.seq
	}
	s.subs[ch] = struct{}{}
	var backlog []Event
	if after > 0 {
		n := len(s.ring)
		start := 0
		if n == cap(s.ring) {
			start = s.ringPos
		}
		for i := 0; i < n; i++ {
			ev := s.ring[(start+i)%n]
			if ev.Seq > after {
				backlog = append(backlog, ev)
			}
		}
	}
	return ch, backlog, s.seq
}

func (s *State) Subscribers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.subs)
}

func (s *State) Unsubscribe(ch chan Event) {
	s.mu.Lock()
	if _, ok := s.subs[ch]; ok {
		delete(s.subs, ch)
		close(ch)
	}
	s.mu.Unlock()
}

// ActiveItem — рядок поточного стану для локального API.
type ActiveItem struct {
	RegionID   string   `json:"regionId"`
	RegionName string   `json:"regionName,omitempty"`
	RegionType string   `json:"regionType,omitempty"`
	StateID    string   `json:"stateId,omitempty"`
	AlarmType  string   `json:"alarmType"`
	Since      flexTime `json:"since"`
	MaxLevel   string   `json:"maxLevel,omitempty"`
	Levels     []string `json:"levels"` // Red — ракетна небезпека, Yellow — загроза БпЛА
	Active     []Level  `json:"activeAlertLevels"`
}

func (s *State) Snapshot() (int64, []ActiveItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ActiveItem, 0, len(s.m))
	for k, e := range s.m {
		if len(e.Active) == 0 {
			continue
		}
		r := s.regions[k.region]
		out = append(out, ActiveItem{
			RegionID: k.region, RegionName: r.Name, RegionType: r.Type, StateID: r.StateID,
			AlarmType: k.typ, Since: flexTime{e.Since}, MaxLevel: e.MaxLevel, Levels: levelSet(e.Active),
			Active: append([]Level(nil), e.Active...),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StateID != out[j].StateID {
			return out[i].StateID < out[j].StateID
		}
		if out[i].RegionID != out[j].RegionID {
			return out[i].RegionID < out[j].RegionID
		}
		return out[i].AlarmType < out[j].AlarmType
	})
	return s.seq, out
}

// Reconcile порівнює повний знімок з API зі станом у пам'яті та виправляє розбіжності.
// Записи, які webhook змінив після початку запиту знімка (fetchStart - slack), не чіпаємо:
// вони свіжіші за знімок. strict=true (старт сервісу) виправляє все.
func (s *State) Reconcile(snap map[key][]Level, newest, fetchStart time.Time, slack time.Duration, source string, strict bool) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	// Що знімок «бачив»: усі зміни, створені раніше за найсвіжіший рівень у ньому.
	if !newest.IsZero() {
		// Час із «майбутнього» (збій годинника джерела) не може зсунути водяний знак далі,
		// ніж момент, коли ми отримали знімок.
		if newest.After(now) {
			newest = now
		}
		if w := newest.Add(-snapshotSlack); w.After(s.watermark) {
			s.watermark = w
		}
	}
	var fixes []Event
	fix := func(k key, active []Level, status string) {
		ev := s.applyLocked(Event{
			ReceivedAt: flexTime{now}, RegionID: k.region, AlarmType: k.typ,
			Status: status, Active: active, Source: source,
		})
		fixes = append(fixes, ev)
	}
	// fresh: запис новіший за знімок — не чіпаємо.
	//  - webhook прийшов, поки знімок завантажувався;
	//  - або webhook створено пізніше за найсвіжіший рівень у знімку (знімок міг його ще не
	//    містити) — але лише недовго (hookTrust): якщо webhook про відбій загубиться, а знімок
	//    і далі не міститиме нових рівнів, наступні звірки все одно виправлять стан.
	// strict (старт сервісу): відновлені з БД записи виправляються завжди; але webhook,
	// отриманий уже під час завантаження знімка, свіжіший за знімок навіть на старті.
	fresh := func(e *entry) bool {
		if e == nil {
			return false
		}
		if e.SeenAt.After(fetchStart.Add(-slack)) {
			return true
		}
		return !strict && !e.HookAt.IsZero() && e.UpdatedAt.After(newest) && now.Sub(e.HookAt) < s.hookTrust
	}

	keys := make([]key, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].region+keys[i].typ < keys[j].region+keys[j].typ })
	for _, k := range keys {
		want := canonLevels(snap[k])
		e := s.m[k]
		if fresh(e) {
			continue
		}
		if e == nil || !sameLevels(e.Active, want) {
			fix(k, want, "SYNC")
		}
	}
	var ended []key
	activeN := 0
	for k, e := range s.m {
		if len(e.Active) == 0 {
			continue
		}
		activeN++
		if _, ok := snap[k]; ok || fresh(e) {
			continue
		}
		ended = append(ended, k)
	}
	if len(ended) > massEndMin && len(ended)*2 > activeN {
		if !s.massEndHeld {
			s.massEndHeld = true
			s.massEndSkipped++
			return fixes // нові тривоги зі знімка вже застосовано; відбої — після підтвердження
		}
	}
	s.massEndHeld = false
	sort.Slice(ended, func(i, j int) bool { return ended[i].region+ended[i].typ < ended[j].region+ended[j].typ })
	for _, k := range ended {
		fix(k, nil, "SYNC")
	}
	return fixes
}

// Prune прибирає неактивні «маяки», старші за maxAge, щоб карта не росла.
func (s *State) Prune(maxAge time.Duration) {
	s.mu.Lock()
	cut := time.Now().Add(-maxAge)
	for k, e := range s.m {
		if len(e.Active) == 0 && e.UpdatedAt.Before(cut) && e.SeenAt.Before(cut) {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}
