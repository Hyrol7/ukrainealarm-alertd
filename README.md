# ukrainealarm-alertd — збирач повітряних тривог

Приймає підписані webhook від [api.ukrainealarm.com](https://api.ukrainealarm.com),
тримає стан тривог усієї України в пам'яті та складає його в SQLite: журнал подій,
сесії тривог (від початку до відбою), окремо кожну загрозу (ракетна небезпека,
загроза БпЛА) і поточні активні тривоги. Віддає зміни миттєво локальним потоком
подій для роздавальника, наприклад [ukrainealarm-alertcast](https://github.com/Hyrol7/ukrainealarm-alertcast).

```
ukrainealarm ──HTTPS POST, RSA-підпис──► [CDN] ──► reverse proxy (TLS) ──► alertd 127.0.0.1:8787
      ▲                                                                       │
      └──── раз на 61 с повний знімок /alerts (звірка) ───────────────────────┤
                                                                              ├─► SQLite /var/lib/alertd
                                                                              └─► 127.0.0.1:8788 /events, /state
                                                                                     │
                                                                          роздавальник (alertcast) → пристрої
```

- **Миттєво:** обробка webhook ~55 мкс, подія одразу йде підписникам `/events`; ~6 000 webhook/с на 2 ядрах.
- **Надійно:** пропущений webhook виправляє звірка з API (~1 хв); стан переживає перезапуск;
  захист від хибного «відбою по всій країні» через збій API; запис у БД пачками, без гальмування прийому.
- **Безпечно:** RSA-підпис кожного webhook, захист від повторів, секретний шлях, жорстка
  systemd-ізоляція (`systemd-analyze security`: 1.3), заборона виконуваної пам'яті, нічого
  не змінюється ззовні. Деталі — у [docs/security.md](docs/security.md).
- **Просто:** один статичний бінарник без залежностей (Linux amd64/arm64), SQLite вбудований.

## Що потрібно

- Linux із systemd (Ubuntu, Debian, Fedora, …), amd64 або arm64.
- Токен API ukrainealarm (видається на запит на api.ukrainealarm.com).
- Домен і HTTPS-доступ до сервера ззовні: ukrainealarm шле webhook лише на `https://`.
  TLS робить reverse proxy (Caddy, nginx тощо), за бажанням — CDN на кшталт Cloudflare.
  Готові конфігурації — у [docs/proxy.md](docs/proxy.md).

## Швидкий старт

```bash
V=1.0.0
cd "$(mktemp -d)"
curl -fLO https://github.com/Hyrol7/ukrainealarm-alertd/releases/download/v$V/alertd-$V.tar.gz
curl -fLO https://github.com/Hyrol7/ukrainealarm-alertd/releases/download/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar xzf alertd-$V.tar.gz && sudo ./alertd/alertd-install.sh    # після встановлення пакет видаляється

sudo nano /etc/alertd/alertd.env       # UA_TOKEN і домен у PUBLIC_HOOK_URL
# reverse proxy з HTTPS на 127.0.0.1:8787 — docs/proxy.md
sudo systemctl start alertd
sudo alertd check                      # усі рядки ✓
sudo alertd subscribe                  # підписатися на webhook ukrainealarm
```

Покроково, з поясненням кожного кроку — [docs/install.md](docs/install.md).
Оновлення, журнали, резервні копії, діагностика — [docs/maintenance.md](docs/maintenance.md).

**Публічна сторінка.** На `GET /` alertd показує нейтральну сторінку «Тут тихо.» з
непримітним індикатором: велика крапка — загальний стан (`online`/`degraded`/`offline`),
дві малі без підписів — webhook і звірка з API. Ні назв, ні чисел, ні часу. Будь-яка
інша адреса — однакова 404, тож ззовні не видно, що тут працює.

## Як це працює

**Один webhook — одна зміна в одному регіоні** (область, район або громада) по одному
типу тривоги. Підписка одна на всю країну; фільтрація за регіонами — справа роздавальника.

Webhook: перевірка розміру → підпис RSA і вік ≤ 5 хв → дублікат → поля → стан у пам'яті
→ `200`. Тієї ж миті подію отримують підписники `/events`, а в БД вона пишеться пачками.

**Стан визначає `activeAlertLevels`.** Порожній — відбій. Типи змін:

| `change` | Значення |
|---|---|
| `start` | тривоги не було → почалась |
| `update` | тривога триває, змінились рівні |
| `end` | відбій: не лишилось жодного рівня |
| `none` | повтор того самого стану (напр. webhook після звірки, що вже це застосувала) |
| `stale` | подія старша за вже відомий стан: записується, але стан не змінює |

**Рівні загрози:**

| Рівень | Загроза | Ранг |
|---|---|---|
| `Red` | ракетна небезпека | вищий |
| `Yellow` | загроза застосування БпЛА | нижчий |
| `Unknown` | рівень не вказано — тривога є, тип невідомий (вважається загрозою) | найнижчий |

Рівні можуть бути одночасно і змінюватись у будь-якому порядку. Кожна подія містить
`prevLevels` і `levels` (без повторів, `Red` першим): `["Yellow"] → ["Red"]` — загроза
посилилась, `["Red","Yellow"] → ["Yellow"]` — ракетну небезпеку знято, БпЛА лишається.

**Звірка в межах ліміту API.** ukrainealarm дозволяє ~1 запит на хвилину на токен,
тому звірка — це один повний знімок `/alerts` раз на `POLL_INTERVAL` (типово 61 с — найчастіше, що дозволяє ліміт), між запитами ≥ `API_MIN_GAP` (61 с), після
`429` — пауза, скільки просить сервер. Webhook ліміт не витрачають.

**Webhook і знімок узгоджуються за годинником ukrainealarm:** хто перший, той і подія;
запізнілий webhook не «воскресить» тривогу, що вже скінчилась; webhook, новіший за
знімок, звірка не відкочує (але не довше ~2 хв); масовий відбій приймається лише після
підтвердження наступним знімком.

## Документація

| Файл | Що |
|---|---|
| [docs/install.md](docs/install.md) | перше розгортання з нуля, крок за кроком |
| [docs/maintenance.md](docs/maintenance.md) | супровід: оновлення, моніторинг, резервні копії, діагностика, видалення |
| [docs/proxy.md](docs/proxy.md) | Caddy, nginx, Cloudflare: публікація webhook, приховування секрету в журналах |
| [docs/api.md](docs/api.md) | локальний API (`/state`, `/events`, …) — контракт для роздавальників |
| [docs/database.md](docs/database.md) | схема БД, представлення, корисні запити |
| [docs/security.md](docs/security.md) | модель загроз і захист на кожному рівні |
| [docs/configuration.md](docs/configuration.md) | усі змінні `alertd.env` |
| [docs/development.md](docs/development.md) | збірка, тести, релізи |
| [CHANGELOG.md](CHANGELOG.md) | зміни між версіями |

## Ліцензія

[MIT](LICENSE). Проєкт не пов'язаний з ukrainealarm.com; дані належать їхнім власникам,
користуйтеся API відповідно до його умов.
