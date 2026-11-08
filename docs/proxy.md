# Публікація webhook: reverse proxy і CDN

alertd слухає лише `127.0.0.1:8787` (`HOOK_LISTEN`) по HTTP. Назовні його публікує
reverse proxy з TLS. Передавайте на alertd **весь сайт**: alertd сам вирішує, що
віддати світу.

| Запит | Відповідь alertd |
|---|---|
| `GET`/`HEAD /` | нейтральна сторінка «Тут тихо.» з індикатором стану |
| `GET /s` | три слова для індикатора, напр. `ok ok ok` |
| `POST /hook/<HOOK_SECRET>` | webhook ukrainealarm (тіло ≤ 256 КБ) |
| будь-що інше | однакова 404 «Тут нічого немає.» — і для неправильного секрету чи методу |

Інші сторінки: 401 (невірний підпис), 413 (завелике тіло), 500 (внутрішня помилка,
подробиці — в журналі), 503 (ключ підпису ще не завантажений, з `Retry-After`).

Порт 8788 (локальний API) **ніколи** не публікуйте: alertd і не дасть його відкрити
не на loopback-адресі.

## Секрет у журналах

ukrainealarm дозволяє задати лише URL, тож секрет — у шляху, і reverse proxy зазвичай
пише його в журнал доступу. Секрет — додатковий шар: головний захист — RSA-підпис,
без приватного ключа ukrainealarm webhook не підробити навіть зі знанням секрету.
Але краще не писати його в журнали — приклади нижче це роблять. Якщо секрет
засвітився, змініть його: новий `HOOK_SECRET` і `PUBLIC_HOOK_URL`, `sudo systemctl
restart alertd`, `sudo alertd update`.

## Caddy

```caddy
alerts.example.com {
	encode zstd gzip
	reverse_proxy 127.0.0.1:8787

	log {
		output file /var/log/caddy/alerts-access.log
		format filter {
			wrap json
			fields {
				request>uri regexp ^/hook/.* /hook/…
			}
		}
	}
}
```

Caddy сам отримає сертифікат Let's Encrypt. Якщо журнал доступу не потрібен,
приберіть блок `log` — за замовчуванням Caddy журнал доступу не пише.

## nginx

```nginx
map $request_uri $alertd_log_uri {
    ~^/hook/   "/hook/…";
    default    $request_uri;
}
log_format alertd '$remote_addr [$time_local] "$request_method $alertd_log_uri" $status $body_bytes_sent';

server {
    listen 443 ssl;
    http2 on;
    server_name alerts.example.com;
    ssl_certificate     /etc/letsencrypt/live/alerts.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/alerts.example.com/privkey.pem;

    access_log /var/log/nginx/alertd.log alertd;
    client_max_body_size 256k;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 20s;
    }
}
```

## Cloudflare (необов'язково)

Cloudflare приховує IP сервера й відсікає сміття ще до нього. Для webhook треба
зняти перевірки, що ламають запити від серверів:

| Що | Значення |
|---|---|
| DNS | запис домену → IP сервера, **Proxied** |
| SSL/TLS | **Full (strict)** |
| Security → WAF → Custom rules → **Skip** | `(http.host eq "alerts.example.com" and starts_with(http.request.uri.path, "/hook/"))` → пропустити: remaining custom rules, rate limiting, managed rules, Super Bot Fight Mode; у *More components* — Browser Integrity Check, Security Level |
| Security → Settings | **Bot Fight Mode вимкнений** (на безкоштовному тарифі Skip його може не обходити) |

Додатково можна відсікти все зайве (правило **Block**, нижче за Skip):

```
(http.host eq "alerts.example.com" and not (
  (http.request.method eq "POST" and starts_with(http.request.uri.path, "/hook/")) or
  (http.request.method in {"GET" "HEAD"} and http.request.uri.path in {"/" "/s"})))
```

На сервері відкрийте 443 лише для [діапазонів Cloudflare](https://www.cloudflare.com/ips/),
щоб обійти Cloudflare напряму було неможливо. alertd у журналі показує адресу клієнта
з `CF-Connecting-IP`, якщо заголовок є.

## Перевірка

```bash
curl -s https://alerts.example.com/ | grep '<h1>'     # <h1>Тут тихо.</h1>
curl -s https://alerts.example.com/x | grep '<h1>'    # <h1>Тут нічого немає.</h1>
sudo alertd check                                      # рядок «публічна адреса» ✓
```

| Помилка в `check` | Причина |
|---|---|
| `403` | блокує CDN/фаєрвол (Cloudflare WAF, Bot Fight Mode) |
| `404 від alertd` | `HOOK_SECRET` у `PUBLIC_HOOK_URL` не збігається з `HOOK_SECRET` |
| `404` | reverse proxy не передає шлях на alertd |
| `503 … ключ підпису` | alertd працює, але ще не завантажив ключ |
| `502`/`503` | alertd не запущений або proxy не бачить `HOOK_LISTEN` |
