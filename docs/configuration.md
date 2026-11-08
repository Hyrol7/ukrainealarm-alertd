# Налаштування

Файл `/etc/alertd/alertd.env` (права `600`, власник root). Після змін —
`sudo systemctl restart alertd`. Некоректні значення не дадуть сервісу стартувати:
причина буде в `journalctl -u alertd`.

| Змінна | Типово | Що |
|---|---|---|
| `UA_TOKEN` | — | токен API ukrainealarm (обов'язково) |
| `HOOK_SECRET` | генерує `alertd-install.sh` | секрет у шляху webhook: 24–128 символів `[A-Za-z0-9_-]` |
| `PUBLIC_HOOK_URL` | — | публічна адреса webhook, `https://<домен>/hook/<HOOK_SECRET>`; для `subscribe`, `update` і `check` |
| `HOOK_LISTEN` | `127.0.0.1:8787` | де приймати запити від reverse proxy |
| `LOCAL_LISTEN` | `127.0.0.1:8788` | локальний API; лише loopback (`127.x`, `::1`, `localhost`) |
| `DB_PATH` | `/var/lib/alertd/alerts.db` | БД |
| `POLL_INTERVAL` | `61s` (найменше можливе) | **частота опитування API**: як часто брати повний знімок `/alerts` і звіряти з ним стан (виправлення пропущених webhook). Менше за `API_MIN_GAP` не буває: тоді опитування раз на `API_MIN_GAP` |
| `API_MIN_GAP` | `61s` | мінімальний проміжок між будь-якими запитами до API (ліміт ~1/хв) |
| `MAX_SKEW` | `5m` | допустимий вік підпису webhook |
| `RETENTION` | `4320h` | скільки зберігати журнал подій (180 днів) |
| `LOG_EVENTS` | `1` | `1` — писати кожну зміну стану в журнал |
| `PUBKEY_FILE` | `/etc/alertd/webhook-public.pem` (у шаблоні) | закріплений ключ підпису; порожньо — брати ключ з API ukrainealarm |
| `SITE_TITLE` | порожньо | назва вкладки на публічних сторінках (≤ 64 символи); порожньо — нейтральний заголовок |
| `UA_API_BASE` | `https://api.ukrainealarm.com` | адреса API (лише https) |
| `ENV_FILE` | `/etc/alertd/alertd.env` | звідки ручні команди беруть налаштування |

Тривалості — у форматі Go (`90s`, `5m`, `4320h`) або числом секунд.

## Зміна секрету

```bash
NEW=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
sudo sed -i -e "s|^HOOK_SECRET=.*|HOOK_SECRET=$NEW|" \
            -e "s|/hook/[A-Za-z0-9_-]*$|/hook/$NEW|" /etc/alertd/alertd.env
sudo systemctl restart alertd
sudo alertd update      # повідомити ukrainealarm нову адресу
sudo alertd check
```

## Команди

| Команда | Що робить |
|---|---|
| `alertd run` | запустити сервіс (так його запускає systemd) |
| `alertd subscribe` | підписати `PUBLIC_HOOK_URL` на webhook ukrainealarm |
| `alertd update` | змінити адресу webhook на поточний `PUBLIC_HOOK_URL` |
| `alertd unsubscribe` | відписатися |
| `alertd check` | перевірити ключ, службу, API (через службу, без витрати ліміту) і публічну адресу |
| `alertd check --direct` | те саме, але запитати API напряму (витрачає ліміт) |
| `alertd version` | версія |
