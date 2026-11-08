# База даних

`/var/lib/alertd/alerts.db` — SQLite у режимі WAL. Читати можна паралельно з роботою
сервісу (`sqlite3`, роздавальник, скрипти), писати — лише alertd.

Час у таблицях — UTC у мілісекундах; представлення `v_*` показують його в часовому
поясі сервера. Для київського часу: `sudo timedatectl set-timezone Europe/Kyiv`.

| Таблиця / представлення | Зміст |
|---|---|
| `meta` | службові значення, зокрема `epoch` — ідентифікатор цієї БД (див. [api.md](api.md)) |
| `regions` | дерево: область → район → громада (`parent_id`, `state_id` — ID області, `depth`) |
| `events` | кожна подія: `seq`, час джерела й отримання, регіон, область, тип, `status`, рівень, причина, знімок `active`, `change`, `source` (`webhook`/`poll`/`startup`) |
| `active_state` | поточні тривоги: регіон + тип → рівні, найвищий рівень, причини, початок |
| `sessions` | тривога від початку до відбою: тривалість, найвищий рівень (`Red` вище `Yellow`) |
| `level_sessions` | окремо кожна загроза: коли почалась і скінчилась ракетна небезпека / загроза БпЛА; в одній тривозі їх може бути кілька, зокрема одночасних |
| `v_active` | поточні тривоги з назвами й тривалістю в хвилинах |
| `v_events` | журнал із назвами й затримкою `lag_ms` |
| `v_sessions` | історія тривог із тривалістю |
| `v_threats` | історія загроз із назвою (`ракетна небезпека` / `загроза БпЛА`) і тривалістю |

Рівень, який є вже на початку тривоги, у `level_sessions` починається рівно з початком
тривоги; доданий пізніше — з моменту, коли його створено в ukrainealarm.

## Корисні запити

```sql
-- Активні тривоги в області
SELECT * FROM v_active WHERE oblast = 'Вінницька область';

-- Тривоги за тиждень по областях
SELECT oblast, COUNT(*) n, SUM(minutes) mins FROM v_sessions
WHERE started_local > datetime('now','-7 days','localtime') GROUP BY oblast ORDER BY mins DESC;

-- Години ракетної небезпеки / загрози БпЛА за тиждень по областях
SELECT oblast, threat, COUNT(*) n, round(SUM(minutes)/60.0,1) hours FROM v_threats
WHERE started_local > datetime('now','-7 days','localtime') GROUP BY 1,2 ORDER BY hours DESC;

-- Наскільки швидко доходять webhook
SELECT AVG(lag_ms), MAX(lag_ms) FROM v_events WHERE source = 'webhook';

-- Скільки змін першою побачила звірка, а не webhook
SELECT COUNT(*) FROM events WHERE source = 'poll';
```

## Зберігання

Події старші за `RETENTION` (типово 180 днів) видаляються раз на 6 годин, після чого
БД оптимізується. Сесії, загрози й поточний стан зберігаються завжди.

Резервна копія без зупинки сервісу:

```bash
sudo sqlite3 /var/lib/alertd/alerts.db ".backup '/root/alerts-$(date +%F).db'"
```

Якщо БД видалити, alertd створить нову (з новим `epoch`) і відновить поточний стан
першою ж звіркою з API; історія почнеться заново.
