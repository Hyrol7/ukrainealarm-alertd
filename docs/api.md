# Локальний API (контракт v1)

alertd віддає стан і зміни лише на loopback-адресі (`LOCAL_LISTEN`, типово
`127.0.0.1:8788`). Автентифікації немає: доступ має тільки цей сервер. Це інтерфейс
для роздавальників ([ukrainealarm-alertcast](https://github.com/Hyrol7/ukrainealarm-alertcast) чи власних).

**Сумісність.** Версія контракту — поле `api` (зараз `1`). У межах `api: 1` поля
лише додаються, нічого не перейменовується й не зникає. Клієнт має ігнорувати
невідомі поля й невідомі типи подій SSE.

| Запит | Відповідь |
|---|---|
| `GET /state` | усі активні тривоги (знімок) |
| `GET /state?state=<ID>` | лише в області з цим ID |
| `GET /events` | потік змін (Server-Sent Events) |
| `GET /events?after=<seq>` або заголовок `Last-Event-ID` | спершу пропущені події, далі живий потік |
| `GET /events?all=1` | також `none` і `stale` (для діагностики) |
| `GET /regions` | дерево регіонів |
| `GET /stats` | лічильники й діагностика (формат може розширюватись) |
| `GET /health` | `200` — звірка свіжа й ключ підпису завантажений, інакше `503` |

## Регіони

`GET /regions` → масив, відсортований за областю й глибиною:

```json
[{"regionId":"4","regionName":"Вінницька область","regionType":"State","stateId":"4","depth":0},
 {"regionId":"32","regionName":"Вінницький район","regionType":"District","parentId":"4","stateId":"4","depth":1},
 {"regionId":"1234","regionName":"Вінницька територіальна громада","regionType":"Community","parentId":"32","stateId":"4","depth":2}]
```

Тривога діє на свій регіон і всі вкладені: районна тривога стосується всіх громад
району. Щоб знати, чи «є тривога в громаді X», перевіряйте X і всіх її предків
(`parentId` до області). ukrainealarm здебільшого оголошує тривоги на рівні районів.

## Знімок стану

`GET /state` →

```json
{
  "api": 1,
  "epoch": "8f7137e2be0902e1",
  "seq": 4182,
  "active": [
    {"regionId":"32","regionName":"Вінницький район","regionType":"District","stateId":"4",
     "alarmType":"AIR","since":"2026-11-08T08:34:28Z","maxLevel":"Red",
     "levels":["Red","Yellow"],"activeAlertLevels":[…]}
  ]
}
```

- `seq` — номер останньої події, врахованої в знімку. Далі читайте `/events?after=<seq>`.
- `epoch` — ідентифікатор БД alertd (див. нижче).
- `levels` — множина рівнів: `Red` — ракетна небезпека, `Yellow` — загроза БпЛА,
  `Unknown` — рівень не вказано. `Red` завжди першим. Порожнього `levels` у знімку не буває.
- `alarmType` — тип з ukrainealarm (`AIR`, `ARTILLERY`, `URBAN_FIGHTS`, `CHEMICAL`,
  `NUCLEAR`, …). Один регіон може мати кілька записів різних типів.

## Потік подій

`GET /events` — `text/event-stream`. Типи подій:

| `event:` | Коли | `data` |
|---|---|---|
| `hello` | першою, одразу після підключення | `{"api":1,"epoch":"…","seq":N}` |
| `resync` | клієнт просив `after`, але пропущених подій уже немає в буфері (10 000 останніх) або номер невідомий | `{"seq":N}` |
| `alert` | зміна стану; `id:` = `seq` | подія (нижче) |

Також кожні 15 с надходить коментар `: ping`. Повільного клієнта alertd від'єднує
(він має перепідключитись з `Last-Event-ID`). Одночасно — до 64 підписників.

```json
{"seq":4183,"receivedAt":"2026-11-08T08:34:28.881Z","createdAt":"2026-11-08T08:34:24Z",
 "regionId":"32","regionName":"Вінницький район","regionType":"District","stateId":"4",
 "alarmType":"AIR","status":"ACTIVATE","alertLevel":"Red",
 "activeAlertLevels":[…],"levels":["Red"],"prevLevels":["Yellow"],
 "change":"update","source":"webhook",
 "sessionStartedAt":"2026-11-08T08:01:10Z","sessionMaxLevel":"Red"}
```

| Поле | Значення |
|---|---|
| `change` | `start` — тривога почалась; `update` — тривога триває, змінились рівні; `end` — відбій |
| `levels` / `prevLevels` | рівні після й до події. `["Yellow"]→["Red"]` — посилилась до ракетної; `["Red","Yellow"]→["Yellow"]` — ракетну знято; `end` має `levels: []` |
| `source` | `webhook` — від ukrainealarm; `poll` — звірка виправила пропущене; `startup` — звірка після старту |
| `createdAt` | час події за годинником ukrainealarm; `receivedAt` — коли отримав alertd |
| `sessionStartedAt`, `sessionMaxLevel` | початок поточної тривоги та найвищий рівень за неї |

Події одного регіону й типу приходять у правильному порядку, дублікати вже прибрано:
кожна `alert` — справжня зміна.

## Як правильно підписуватися

```
1. GET /state                → запам'ятати epoch, seq, active
2. GET /events?after=<seq>   → перша подія hello
   - hello.epoch ≠ збереженого → почати з п. 1 (БД alertd нова: старі seq нічого не значать)
3. alert                     → застосувати, запам'ятати seq (і epoch)
4. resync                    → почати з п. 1
5. обрив з'єднання           → перепідключитись з Last-Event-ID: <seq> (EventSource робить це сам)
```

Так клієнт не пропускає й не дублює жодної зміни навіть після перезапуску будь-якої зі
сторін. Між п. 1 і п. 2 нічого не губиться: `after=<seq>` віддасть усе, що сталося після
знімка.
