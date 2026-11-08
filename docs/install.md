# Перше розгортання

Від чистого сервера до першої тривоги в журналі — приблизно 15 хвилин.

## 0. Що підготувати

| Що | Навіщо |
|---|---|
| Сервер Linux із systemd (Ubuntu 22.04+, Debian 12+ тощо), amd64 або arm64, від 512 МБ RAM | alertd займає ~10–150 МБ пам'яті |
| Публічна IP-адреса й відкритий порт 443 | ukrainealarm надсилає webhook на ваш сервер |
| Домен (або піддомен), напр. `alerts.example.com` | webhook приймаються лише на `https://` |
| Токен API ukrainealarm | запит — на [api.ukrainealarm.com](https://api.ukrainealarm.com) |
| Reverse proxy з TLS — Caddy (найпростіше) або nginx | alertd сам TLS не робить і слухає лише `127.0.0.1` |

Перевірте час на сервері — підпис webhook дійсний лише ±5 хвилин:

```bash
timedatectl          # «System clock synchronized: yes»
```

## 1. DNS

Створіть запис `A` (і `AAAA` для IPv6) для вашого домену на IP сервера. Якщо
користуєтесь Cloudflare — див. розділ Cloudflare у [proxy.md](proxy.md).

## 2. Встановити alertd

Останню версію дивіться на сторінці [Releases](https://github.com/Hyrol7/ukrainealarm-alertd/releases).

```bash
V=1.0.0
cd "$(mktemp -d)"
curl -fLO https://github.com/Hyrol7/ukrainealarm-alertd/releases/download/v$V/alertd-$V.tar.gz
curl -fLO https://github.com/Hyrol7/ukrainealarm-alertd/releases/download/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS          # alertd-1.0.0.tar.gz: OK
tar xzf alertd-$V.tar.gz && sudo ./alertd/alertd-install.sh
```

Необов'язково, але надійніше — перевірити, що архів зібрано саме в цьому репозиторії
(потрібен [gh](https://cli.github.com/), до встановлення):

```bash
gh attestation verify alertd-$V.tar.gz --repo Hyrol7/ukrainealarm-alertd
```

`alertd-install.sh`:

- створює системного користувача `alertd` без входу в систему;
- ставить програму `/usr/local/bin/alertd` і команду оновлення `/usr/local/sbin/alertd-update`;
- ставить службу `/etc/systemd/system/alertd.service` з жорсткою ізоляцією;
- кладе ключ підпису ukrainealarm у `/etc/alertd/webhook-public.pem`;
- створює налаштування `/etc/alertd/alertd.env` (права `600`) з випадковим секретом `HOOK_SECRET`;
- після успіху видаляє розпакований пакет, архів і `SHA256SUMS` (`--keep` — залишити).

## 3. Налаштування

```bash
sudo nano /etc/alertd/alertd.env
```

Обов'язково заповнити лише два рядки:

```bash
UA_TOKEN=ваш-токен-ukrainealarm
PUBLIC_HOOK_URL=https://alerts.example.com/hook/<секрет — уже вписаний>
```

У `PUBLIC_HOOK_URL` замініть лише домен: секрет у кінці install-скрипт уже вписав, і він
має збігатися з `HOOK_SECRET`. Решта значень — розумні типові; усі описані в
[configuration.md](configuration.md).

## 4. Reverse proxy

Передайте весь сайт на `127.0.0.1:8787`. Для Caddy це три рядки:

```caddy
alerts.example.com {
	reverse_proxy 127.0.0.1:8787
}
```

```bash
sudo systemctl reload caddy
```

Конфігурації для nginx і Cloudflare, а також як не писати секрет у журнали — у
[proxy.md](proxy.md).

## 5. Запуск і перевірка

```bash
sudo systemctl start alertd
sudo alertd check
```

```
✓ ключ підпису   RSA 2048 біт, sha256 66161583d549264c6cf9a6febceacefd
✓ служба         alertd 1.0.0 працює 5s, ключ: true
✓ API (зі служби) остання звірка …, регіонів 1606, активних …
✓ публічна адреса ланцюжок до alertd працює (непідписаний запит отримав 401 від alertd)
```

`⚠` у рядку API одразу після старту — нормально: alertd дотримується ліміту ukrainealarm
(~1 запит на хвилину) і зробить першу звірку протягом хвилини. Якщо є `✗` — причину
підкаже текст поруч; таблиця помилок — у [proxy.md](proxy.md#перевірка).

## 6. Підписка на webhook

Тільки коли всі рядки `check` — `✓`:

```bash
sudo alertd subscribe
journalctl -u alertd -f
```

Підписка одна на всю Україну. З першою ж зміною будь-де з'являться рядки:

```
event #1 webhook 32 AIR ACTIVATE/Red → start [ → Red]
```

Готово. alertd запускається разом із сервером і перезапускається сам у разі збою.
Як підключити роздавальник — [api.md](api.md) і
[ukrainealarm-alertcast](https://github.com/Hyrol7/ukrainealarm-alertcast).
Подальший супровід — [maintenance.md](maintenance.md).
