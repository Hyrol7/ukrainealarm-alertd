#!/usr/bin/env bash
# Встановлення alertd (Linux із systemd) з розпакованого релізу: sudo ./alertd-install.sh
# Повторний запуск оновлює програму й не чіпає налаштувань і БД.
# Після успішного встановлення пакет (ця тека, архів і SHA256SUMS поруч) видаляється;
# --keep — залишити.
set -euo pipefail
cd "$(dirname "$0")"
PKG=$(pwd -P)
DOCS=https://github.com/Hyrol7/ukrainealarm-alertd/blob/main/docs

KEEP=0
[[ ${1:-} == --keep ]] && KEEP=1

[[ $EUID -eq 0 ]] || { echo "Запустіть через sudo"; exit 1; }
command -v systemctl >/dev/null || { echo "Потрібен systemd (systemctl не знайдено)"; exit 1; }

case "$(uname -m)" in
  x86_64)  BIN=alertd-linux-amd64 ;;
  aarch64) BIN=alertd-linux-arm64 ;;
  *) echo "Непідтримувана архітектура: $(uname -m)"; exit 1 ;;
esac

id alertd &>/dev/null || useradd --system --no-create-home --home-dir /var/lib/alertd --shell /usr/sbin/nologin alertd

install -m 0755 "$BIN" /usr/local/bin/alertd.new
mv -f /usr/local/bin/alertd.new /usr/local/bin/alertd
install -m 0755 alertd-update.sh /usr/local/sbin/alertd-update
install -m 0644 alertd.service /etc/systemd/system/alertd.service
install -d -m 0750 -o root -g alertd /etc/alertd   # alertd читає ключ підпису, але не alertd.env (600)
install -m 0640 -o root -g alertd webhook-public.pem /etc/alertd/webhook-public.pem

ENV=/etc/alertd/alertd.env
if [[ ! -f $ENV ]]; then
  SECRET=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')   # 48 hex-символів
  sed -e "s|^HOOK_SECRET=.*|HOOK_SECRET=$SECRET|" \
      -e "s|ВСТАВТЕ_HOOK_SECRET|$SECRET|" alertd.env.example > "$ENV"
  chmod 600 "$ENV"; chown root:root "$ENV"
  echo "Створено $ENV із новим HOOK_SECRET."
fi

systemctl daemon-reload
systemctl enable alertd >/dev/null

if grep -qE '^UA_TOKEN=.+' "$ENV"; then
  systemctl restart alertd
  sleep 2
  systemctl --no-pager --lines=8 status alertd || true
else
  echo
  echo "Далі:"
  echo "  1. Налаштування:  sudo nano $ENV"
  echo "                    UA_TOKEN=<токен ukrainealarm>"
  echo "                    PUBLIC_HOOK_URL=https://<ваш домен>/hook/… (секрет уже вписано)"
  echo "  2. Reverse proxy на $(grep -E '^HOOK_LISTEN=' "$ENV" | cut -d= -f2): $DOCS/proxy.md"
  echo "  3. Запуск:        sudo systemctl start alertd"
  echo "  4. Перевірка:     sudo alertd check"
  echo "  5. Підписка:      sudo alertd subscribe"
fi
VERSION=$(/usr/local/bin/alertd version)
echo
echo "alertd $VERSION встановлено. Оновлення: sudo alertd-update"

# Прибирання: лише якщо це справді розпакований реліз (а не, скажімо, тека з кодом).
if [[ $KEEP -eq 0 && $(basename "$PKG") == alertd && -f $PKG/alertd-linux-amd64 && ! -e $PKG/.git && $PKG != / ]]; then
  PARENT=$(dirname "$PKG")
  cd /
  rm -rf -- "$PKG"
  rm -f -- "$PARENT/alertd-$VERSION.tar.gz"
  if [[ -f $PARENT/SHA256SUMS ]] && grep -q "alertd-$VERSION\.tar\.gz" "$PARENT/SHA256SUMS"; then
    rm -f -- "$PARENT/SHA256SUMS"
  fi
  echo "Файли встановлення видалено ($PKG). Перейдіть в іншу теку: cd ~"
fi
