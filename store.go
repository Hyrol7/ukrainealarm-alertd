package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID;

-- Дерево регіонів: область (depth 0) → район (1) → громада (2) …
CREATE TABLE IF NOT EXISTS regions (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  type       TEXT,
  parent_id  TEXT,
  state_id   TEXT,
  depth      INTEGER,
  updated_ms INTEGER
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS regions_parent ON regions(parent_id);
CREATE INDEX IF NOT EXISTS regions_state  ON regions(state_id);

-- Журнал усіх подій у порядку надходження (seq) з часом джерела (created_ms).
CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY,
  seq         INTEGER NOT NULL,
  received_ms INTEGER NOT NULL,
  created_ms  INTEGER NOT NULL,
  region_id   TEXT NOT NULL,
  state_id    TEXT,
  alarm_type  TEXT NOT NULL,
  status      TEXT NOT NULL,
  alert_level TEXT,
  reason      TEXT,
  active      TEXT NOT NULL,
  active_cnt  INTEGER NOT NULL,
  change      TEXT NOT NULL,
  source      TEXT NOT NULL,
  body_hash   TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS events_created ON events(created_ms);
CREATE INDEX IF NOT EXISTS events_region  ON events(region_id, created_ms);
CREATE INDEX IF NOT EXISTS events_state   ON events(state_id, created_ms);
CREATE INDEX IF NOT EXISTS events_change  ON events(change, created_ms);

-- Поточні активні тривоги (одна стрічка на регіон + тип).
CREATE TABLE IF NOT EXISTS active_state (
  region_id  TEXT NOT NULL,
  alarm_type TEXT NOT NULL,
  state_id   TEXT,
  active     TEXT NOT NULL,
  max_level  TEXT,
  reasons    TEXT,
  since_ms   INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL,
  PRIMARY KEY (region_id, alarm_type)
) WITHOUT ROWID;

-- Сесії тривог: від початку до відбою, для аналізу тривалості й частоти.
CREATE TABLE IF NOT EXISTS sessions (
  id           INTEGER PRIMARY KEY,
  region_id    TEXT NOT NULL,
  state_id     TEXT,
  alarm_type   TEXT NOT NULL,
  started_ms   INTEGER NOT NULL,
  ended_ms     INTEGER,
  max_level    TEXT,
  reasons      TEXT,
  start_source TEXT,
  end_source   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS sessions_open ON sessions(region_id, alarm_type) WHERE ended_ms IS NULL;
CREATE INDEX IF NOT EXISTS sessions_region ON sessions(region_id, started_ms);
CREATE INDEX IF NOT EXISTS sessions_state  ON sessions(state_id, started_ms);
CREATE INDEX IF NOT EXISTS sessions_start  ON sessions(started_ms);

-- Окремо кожна загроза: Red — ракетна небезпека, Yellow — загроза БпЛА. Тривога (sessions)
-- може містити кілька таких відрізків, у тому числі одночасних.
CREATE TABLE IF NOT EXISTS level_sessions (
  id           INTEGER PRIMARY KEY,
  region_id    TEXT NOT NULL,
  state_id     TEXT,
  alarm_type   TEXT NOT NULL,
  level        TEXT NOT NULL,
  started_ms   INTEGER NOT NULL,
  ended_ms     INTEGER,
  start_source TEXT,
  end_source   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS level_sessions_open ON level_sessions(region_id, alarm_type, level) WHERE ended_ms IS NULL;
CREATE INDEX IF NOT EXISTS level_sessions_region ON level_sessions(region_id, started_ms);
CREATE INDEX IF NOT EXISTS level_sessions_start  ON level_sessions(started_ms);

-- Зручні представлення: локальний час Києва та назви регіонів.
CREATE VIEW IF NOT EXISTS v_active AS
SELECT a.region_id, r.name AS region, r.type AS region_type, s.name AS oblast, a.alarm_type,
       a.max_level, a.reasons,
       datetime(a.since_ms/1000, 'unixepoch', 'localtime') AS since_local,
       (strftime('%s','now')*1000 - a.since_ms)/60000 AS minutes,
       a.active
FROM active_state a
LEFT JOIN regions r ON r.id = a.region_id
LEFT JOIN regions s ON s.id = a.state_id
ORDER BY oblast, r.depth, region;

CREATE VIEW IF NOT EXISTS v_events AS
SELECT e.seq, datetime(e.created_ms/1000, 'unixepoch', 'localtime') AS created_local,
       (e.received_ms - e.created_ms) AS lag_ms,
       s.name AS oblast, r.name AS region, e.region_id, e.alarm_type, e.status, e.change,
       e.alert_level, e.reason, e.active_cnt, e.source
FROM events e
LEFT JOIN regions r ON r.id = e.region_id
LEFT JOIN regions s ON s.id = e.state_id
ORDER BY e.seq DESC;

CREATE VIEW IF NOT EXISTS v_threats AS
SELECT x.id, s.name AS oblast, r.name AS region, x.region_id, x.alarm_type, x.level,
       CASE x.level WHEN 'Red' THEN 'ракетна небезпека' WHEN 'Yellow' THEN 'загроза БпЛА' ELSE x.level END AS threat,
       datetime(x.started_ms/1000, 'unixepoch', 'localtime') AS started_local,
       datetime(x.ended_ms/1000, 'unixepoch', 'localtime')   AS ended_local,
       (COALESCE(x.ended_ms, strftime('%s','now')*1000) - x.started_ms)/60000 AS minutes
FROM level_sessions x
LEFT JOIN regions r ON r.id = x.region_id
LEFT JOIN regions s ON s.id = x.state_id
ORDER BY x.started_ms DESC;

CREATE VIEW IF NOT EXISTS v_sessions AS
SELECT x.id, s.name AS oblast, r.name AS region, x.region_id, x.alarm_type, x.max_level, x.reasons,
       datetime(x.started_ms/1000, 'unixepoch', 'localtime') AS started_local,
       datetime(x.ended_ms/1000, 'unixepoch', 'localtime')   AS ended_local,
       (COALESCE(x.ended_ms, strftime('%s','now')*1000) - x.started_ms)/60000 AS minutes
FROM sessions x
LEFT JOIN regions r ON r.id = x.region_id
LEFT JOIN regions s ON s.id = x.state_id
ORDER BY x.started_ms DESC;
`

type Store struct {
	path    string
	epoch   string
	db      *sql.DB
	queue   chan Event
	written atomic.Int64
	dropped atomic.Int64
	batches atomic.Int64
	lastErr atomic.Value // string
	done    chan struct{}
}

func OpenStore(path string, queueSize int) (*Store, error) {
	// SQLite перекладено в чистий Go (wasm2go): без JIT і без виконуваної пам'яті.
	// hard_heap_limit — жорстка межа пам'яті SQLite (64 МБ); trusted_schema(0) — схема БД
	// не може викликати функції з побічною дією, навіть якщо файл БД хтось підмінить.
	dsn := "file:" + path + "?_txlock=immediate" +
		"&_pragma=journal_mode(wal)&_pragma=synchronous(normal)" +
		"&_pragma=busy_timeout(5000)&_pragma=foreign_keys(0)&_pragma=temp_store(memory)" +
		"&_pragma=hard_heap_limit(67108864)&_pragma=trusted_schema(0)"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // один процес-записувач; читачі (sqlite3 CLI, роздавальник) відкривають власні з'єднання
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// epoch — випадковий ідентифікатор цієї БД. Нова БД = нова нумерація seq; клієнт
	// /events, що бачить інший epoch, мусить перечитати /state, а не довіряти своєму seq.
	var epoch string
	if err := db.QueryRow(`SELECT v FROM meta WHERE k='epoch'`).Scan(&epoch); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			db.Close()
			return nil, fmt.Errorf("read epoch: %w", err)
		}
		var b [8]byte
		_, _ = rand.Read(b[:])
		epoch = hex.EncodeToString(b[:])
		if _, err := db.Exec(`INSERT INTO meta(k,v) VALUES('epoch',?)`, epoch); err != nil {
			db.Close()
			return nil, fmt.Errorf("write epoch: %w", err)
		}
	}
	st := &Store{path: path, db: db, epoch: epoch, queue: make(chan Event, queueSize), done: make(chan struct{})}
	st.lastErr.Store("")
	return st, nil
}

func (st *Store) Queue() chan<- Event { return st.queue }

// Epoch — ідентифікатор БД (див. OpenStore).
func (st *Store) Epoch() string { return st.epoch }

// Run забирає події пачками: перша блокує, решта, що вже в черзі, йдуть у ту саму транзакцію.
func (st *Store) Run() {
	defer close(st.done)
	batch := make([]Event, 0, 1024)
	for ev := range st.queue {
		batch = append(batch[:0], ev)
	drain:
		for len(batch) < cap(batch) {
			select {
			case e, ok := <-st.queue:
				if !ok {
					break drain
				}
				batch = append(batch, e)
			default:
				break drain
			}
		}
		for attempt := 0; ; attempt++ {
			err := st.writeBatch(batch)
			if err == nil {
				st.written.Add(int64(len(batch)))
				st.batches.Add(1)
				break
			}
			st.lastErr.Store(err.Error())
			logf("db write failed (attempt %d, %d events): %v", attempt+1, len(batch), err)
			if attempt >= 2 && len(batch) > 1 {
				// Можливо, заважає одна подія: пишемо поштучно, губимо лише ті, що не пишуться.
				ok, lost := 0, 0
				for i := range batch {
					if err := st.writeBatch(batch[i : i+1]); err != nil {
						lost++
						logf("db: event #%d dropped: %v", batch[i].Seq, err)
					} else {
						ok++
					}
				}
				st.written.Add(int64(ok))
				st.dropped.Add(int64(lost))
				break
			}
			if attempt >= 5 {
				st.dropped.Add(int64(len(batch)))
				logf("dropping %d events after repeated db errors", len(batch))
				break
			}
			time.Sleep(time.Duration(200*(attempt+1)) * time.Millisecond)
		}
	}
}

func (st *Store) Close() {
	close(st.queue)
	<-st.done
	st.db.Close()
}

func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (st *Store) writeBatch(batch []Event) error {
	tx, err := st.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	insEv, err := tx.Prepare(`INSERT INTO events (seq, received_ms, created_ms, region_id, state_id, alarm_type, status,
		alert_level, reason, active, active_cnt, change, source, body_hash)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(body_hash) DO NOTHING`)
	if err != nil {
		return err
	}
	defer insEv.Close()
	upActive, err := tx.Prepare(`INSERT INTO active_state (region_id, alarm_type, state_id, active, max_level, reasons, since_ms, updated_ms)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(region_id, alarm_type) DO UPDATE SET state_id=excluded.state_id, active=excluded.active,
		max_level=excluded.max_level, reasons=excluded.reasons, since_ms=excluded.since_ms, updated_ms=excluded.updated_ms`)
	if err != nil {
		return err
	}
	defer upActive.Close()
	delActive, err := tx.Prepare(`DELETE FROM active_state WHERE region_id=? AND alarm_type=?`)
	if err != nil {
		return err
	}
	defer delActive.Close()
	openSess, err := tx.Prepare(`INSERT INTO sessions (region_id, state_id, alarm_type, started_ms, max_level, reasons, start_source)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(region_id, alarm_type) WHERE ended_ms IS NULL DO UPDATE SET max_level=excluded.max_level, reasons=excluded.reasons`)
	if err != nil {
		return err
	}
	defer openSess.Close()
	updSess, err := tx.Prepare(`UPDATE sessions SET max_level=?, reasons=? WHERE region_id=? AND alarm_type=? AND ended_ms IS NULL`)
	if err != nil {
		return err
	}
	defer updSess.Close()
	endSess, err := tx.Prepare(`UPDATE sessions SET ended_ms=?, end_source=? WHERE region_id=? AND alarm_type=? AND ended_ms IS NULL`)
	if err != nil {
		return err
	}
	defer endSess.Close()

	openLvl, err := tx.Prepare(`INSERT INTO level_sessions (region_id, state_id, alarm_type, level, started_ms, start_source)
		VALUES (?,?,?,?,?,?) ON CONFLICT(region_id, alarm_type, level) WHERE ended_ms IS NULL DO NOTHING`)
	if err != nil {
		return err
	}
	defer openLvl.Close()
	closeLvl, err := tx.Prepare(`UPDATE level_sessions SET ended_ms=?, end_source=?
		WHERE region_id=? AND alarm_type=? AND level=? AND ended_ms IS NULL`)
	if err != nil {
		return err
	}
	defer closeLvl.Close()

	for _, ev := range batch {
		var hash any
		if ev.hash != "" {
			hash = ev.hash
		}
		created := ms(ev.CreatedAt.Time)
		if created == 0 {
			created = ms(ev.ReceivedAt.Time)
		}
		if _, err := insEv.Exec(ev.Seq, ms(ev.ReceivedAt.Time), created, ev.RegionID, nullStr(ev.StateID), ev.AlarmType,
			ev.Status, nullStr(ev.AlertLevel), nullStr(ev.Reason), jsonStr(ev.Active), len(ev.Active), ev.Change, ev.Source, hash); err != nil {
			return err
		}
		if ev.Change == ChangeStart || ev.Change == ChangeUpdate || ev.Change == ChangeEnd {
			added, removed := diffLevels(ev.PrevLevels, ev.Levels)
			lvlStart := created
			if ev.Change == ChangeStart && !ev.SessionFrom.IsZero() {
				lvlStart = ms(ev.SessionFrom.Time) // загрози, з якими тривога почалась, — з її початку
			}
			for _, l := range added {
				if _, err := openLvl.Exec(ev.RegionID, nullStr(ev.StateID), ev.AlarmType, l, lvlStart, ev.Source); err != nil {
					return err
				}
			}
			for _, l := range removed {
				if _, err := closeLvl.Exec(created, ev.Source, ev.RegionID, ev.AlarmType, l); err != nil {
					return err
				}
			}
		}
		reasons := strings.Join(ev.Reasons, "; ")
		switch ev.Change {
		case ChangeStart, ChangeUpdate:
			upd := ms(ev.known)
			if upd == 0 {
				upd = created
			}
			if _, err := upActive.Exec(ev.RegionID, ev.AlarmType, nullStr(ev.StateID), jsonStr(ev.Active), ev.MaxLevel, reasons,
				ms(ev.SessionFrom.Time), upd); err != nil {
				return err
			}
			if ev.Change == ChangeStart {
				_, err = openSess.Exec(ev.RegionID, nullStr(ev.StateID), ev.AlarmType, ms(ev.SessionFrom.Time), ev.MaxLevel, reasons, ev.Source)
			} else {
				_, err = updSess.Exec(ev.MaxLevel, reasons, ev.RegionID, ev.AlarmType)
			}
			if err != nil {
				return err
			}
		case ChangeEnd:
			if _, err := delActive.Exec(ev.RegionID, ev.AlarmType); err != nil {
				return err
			}
			if _, err := endSess.Exec(created, ev.Source, ev.RegionID, ev.AlarmType); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (st *Store) SaveRegions(rs map[string]Region) error {
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO regions (id, name, type, parent_id, state_id, depth, updated_ms) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, type=excluded.type, parent_id=excluded.parent_id,
		state_id=excluded.state_id, depth=excluded.depth, updated_ms=excluded.updated_ms`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().UnixMilli()
	for _, r := range rs {
		if _, err := stmt.Exec(r.ID, r.Name, r.Type, nullStr(r.ParentID), nullStr(r.StateID), r.Depth, now); err != nil {
			return err
		}
	}
	// Події, що прийшли до завантаження дерева, отримують область заднім числом.
	for _, t := range []string{"events", "sessions", "active_state"} {
		if _, err := tx.Exec(`UPDATE ` + t + ` SET state_id = (SELECT r.state_id FROM regions r WHERE r.id = ` + t + `.region_id)
			WHERE state_id IS NULL AND region_id IN (SELECT id FROM regions)`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (st *Store) LoadRegions() (map[string]Region, error) {
	rows, err := st.db.Query(`SELECT id, name, COALESCE(type,''), COALESCE(parent_id,''), COALESCE(state_id,''), COALESCE(depth,0) FROM regions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Region{}
	for rows.Next() {
		var r Region
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.ParentID, &r.StateID, &r.Depth); err != nil {
			return nil, err
		}
		out[r.ID] = r
	}
	return out, rows.Err()
}

// LoadActive повертає збережений стан (для відновлення після перезапуску) і останній seq.
func (st *Store) LoadActive(s *State) (int, error) {
	rows, err := st.db.Query(`SELECT region_id, alarm_type, active, COALESCE(max_level,''), COALESCE(reasons,''), since_ms, updated_ms FROM active_state`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var region, typ, active, maxL, reasons string
		var since, upd int64
		if err := rows.Scan(&region, &typ, &active, &maxL, &reasons, &since, &upd); err != nil {
			return n, err
		}
		var ls []Level
		_ = json.Unmarshal([]byte(active), &ls)
		var rs []string
		if reasons != "" {
			rs = strings.Split(reasons, "; ")
		}
		s.Restore(region, typ, ls, time.UnixMilli(since).UTC(), time.UnixMilli(upd).UTC(), maxL, rs)
		n++
	}
	return n, rows.Err()
}

// LastWebhook — час останньої події, отриманої через webhook (для індикатора після перезапуску).
func (st *Store) LastWebhook() time.Time {
	var v sql.NullInt64
	_ = st.db.QueryRow(`SELECT MAX(received_ms) FROM events WHERE source = 'webhook'`).Scan(&v)
	if !v.Valid {
		return time.Time{}
	}
	return time.UnixMilli(v.Int64)
}

// RecentHashes — хеші тіл webhook, отриманих після since (для пам'яті дублікатів).
func (st *Store) RecentHashes(since time.Time) ([]string, error) {
	rows, err := st.db.Query(`SELECT body_hash FROM events WHERE body_hash IS NOT NULL AND received_ms >= ?`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if rows.Scan(&h) == nil {
			out = append(out, h)
		}
	}
	return out, rows.Err()
}

func (st *Store) MaxSeq() int64 {
	var v sql.NullInt64
	_ = st.db.QueryRow(`SELECT MAX(seq) FROM events`).Scan(&v)
	return v.Int64
}

func (st *Store) GetMeta(k string) string {
	var v string
	_ = st.db.QueryRow(`SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	return v
}

func (st *Store) SetMeta(k, v string) {
	_, _ = st.db.Exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
}

// Optimize — періодичне обслуговування: статистика для планувальника і скидання WAL.
func (st *Store) Optimize() {
	_, _ = st.db.Exec(`PRAGMA optimize`)
	_, _ = st.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
}

func (st *Store) Prune(retention time.Duration) (int64, error) {
	cut := time.Now().Add(-retention).UnixMilli()
	res, err := st.db.Exec(`DELETE FROM events WHERE created_ms < ?`, cut)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
