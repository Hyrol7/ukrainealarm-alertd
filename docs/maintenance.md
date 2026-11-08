# Супровід

## Стан

```bash
systemctl status alertd
sudo alertd check                      # ключ, служба, API, публічна адреса
curl -s localhost:8788/health          # 200 {"ok":true,…} — звірка свіжа, ключ є
curl -s localhost:8788/stats           # лічильники, затримки, стан БД
curl -s localhost:8788/state | head    # усі активні тривоги
```

| Поле `/stats` | Що показує | Норма |
|---|---|---|
| `webhooks.accepted` | прийняті webhook | зростає |
| `webhooks.rejected` | відхилені (невірний підпис чи без нього) | поодинокі — сканери; багато — див. «Діагностика» |
| `reconcileFixes` | зміни, які звірка застосувала раніше за webhook | зростає — знімок API часто випереджає webhook |
| `webhookMisses` | звірка знайшла зміну, а webhook про неї не прийшов і за 3 хв | 0 або поодинокі |
| `massEndHeld` | масовий «відбій» зі знімка відкладено до підтвердження | поодинокі |
| `db.dropped` | події, які не вдалося записати в БД | 0 |
| `apiCalls1m`, `apiPausedUntil` | запити до API за хвилину; пауза після `429` | 1; порожньо |
| `sourceLag` | затримка ukrainealarm → сервер | медіана — секунди |

Публічна сторінка `https://<домен>/` показує те саме коротко: зелена крапка `online` —
усе гаразд; жовта `degraded` — webhook давно не було або є пропуски; червона
`offline` — звірка з API давно не вдавалась.

Для зовнішнього моніторингу (UptimeRobot тощо) достатньо перевіряти, що
`https://<домен>/s` починається з `ok`.

## Журнал

```bash
journalctl -u alertd -f                          # наживо
journalctl -u alertd --since today | grep event  # зміни за сьогодні
journalctl -u alertd -p warning --since -1d      # лише попередження й помилки
```

`LOG_EVENTS=0` в налаштуваннях вимикає запис кожної зміни (лишаються старт, звірки й помилки).

## Оновлення

```bash
sudo alertd-update            # остання версія, якщо новіша за встановлену
sudo alertd-update 1.0.0      # конкретна версія (зокрема відкат)
```

Завантажує реліз з GitHub, перевіряє SHA256 (і походження, якщо на сервері є
авторизований `gh`), встановлює й перезапускає службу. Налаштування й БД не змінюються.
Перезапуск триває ~0,1 с; зміну, що прийде саме в цю мить, підбере наступна звірка.

Що змінилось у версіях — [CHANGELOG.md](../CHANGELOG.md).

## Налаштування

Після будь-якої зміни `/etc/alertd/alertd.env`:

```bash
sudo systemctl restart alertd
sudo alertd check
```

Як змінити секрет webhook — [configuration.md](configuration.md#зміна-секрету).

## Резервні копії

Без зупинки служби:

```bash
sudo sqlite3 /var/lib/alertd/alerts.db ".backup '/root/alerts-$(date +%F).db'"
sudo cp /etc/alertd/alertd.env /root/alertd.env.backup
```

Відновлення: зупинити службу, покласти файл на місце (власник `alertd`), запустити.
Навіть без резервної копії поточний стан тривог відновиться першою ж звіркою з API —
втрачається лише історія.

БД сама прибирає події старші за `RETENTION` (180 днів) і оптимізується. Розмір —
десятки мегабайт на рік.

## Діагностика

| Ознака | Що перевірити |
|---|---|
| `check`: `✗ публічна адреса` | текст помилки й таблиця в [proxy.md](proxy.md#перевірка) |
| webhook не приходять (`accepted` не росте, у журналі немає `event … webhook`) | `sudo alertd check`; підписка: `sudo alertd update`; правила CDN/фаєрвола для `/hook/` |
| багато `rejected` і в журналі `rejected webhook … bad signature` | годинник сервера (`timedatectl`); ключ підпису (рядок «ключ підпису» в `check`) |
| `apiPausedUntil` часто заповнене | інший процес користується тим самим токеном (напр. `check --direct` чи друга копія alertd) |
| служба не стартує | `journalctl -u alertd -n 30` — некоректні налаштування описані прямо в повідомленні |
| `db.dropped` > 0 | місце на диску (`df -h /var/lib/alertd`), журнал служби |

## Видалення

```bash
sudo alertd unsubscribe
sudo systemctl disable --now alertd
sudo rm -f /usr/local/bin/alertd /usr/local/sbin/alertd-update /etc/systemd/system/alertd.service
sudo systemctl daemon-reload
sudo rm -rf /etc/alertd                 # налаштування й секрет
sudo rm -rf /var/lib/alertd             # БД — за бажанням
sudo userdel alertd
```

І приберіть сайт із reverse proxy.
