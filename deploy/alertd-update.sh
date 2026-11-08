#!/usr/bin/env bash
# Оновлення alertd з GitHub Releases: завантажує реліз, перевіряє SHA256 (і походження,
# якщо є gh), запускає alertd-install.sh. Налаштування й БД не змінюються.
#
#   sudo alertd-update            # остання версія (якщо новіша за встановлену)
#   sudo alertd-update 1.0.0      # конкретна версія (зокрема відкат)
#   sudo alertd-update --force    # перевстановити, навіть якщо версія та сама
set -euo pipefail

REPO=${ALERTD_REPO:-Hyrol7/ukrainealarm-alertd}
[[ $REPO =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "Некоректний ALERTD_REPO: $REPO"; exit 1; }

[[ $EUID -eq 0 ]] || { echo "Запустіть через sudo"; exit 1; }
for c in curl sha256sum tar; do
  command -v "$c" >/dev/null || { echo "Потрібна програма: $c"; exit 1; }
done

FORCE=0 WANT=
for a in "$@"; do
  case $a in
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) WANT=${a#v} ;;
  esac
done

if [[ -z $WANT ]]; then
  # Остання версія — з перенаправлення /releases/latest (без API GitHub і його лімітів).
  url=$(curl -fsSIL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")
  WANT=${url##*/tag/v}
fi
[[ $WANT =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Не вдалося визначити версію (отримано: ${WANT:-порожньо})"; exit 1; }

HAVE=$(/usr/local/bin/alertd version 2>/dev/null || echo "немає")
echo "Встановлено: $HAVE, реліз: $WANT"
if [[ $HAVE == "$WANT" && $FORCE -eq 0 ]]; then
  echo "Оновлення не потрібне (--force — перевстановити)."
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
BASE="https://github.com/$REPO/releases/download/v$WANT"
curl -fsSLO --proto '=https' --tlsv1.2 "$BASE/alertd-$WANT.tar.gz"
curl -fsSLO --proto '=https' --tlsv1.2 "$BASE/SHA256SUMS"
grep -E "  alertd-$WANT\.tar\.gz$" SHA256SUMS | sha256sum -c - \
  || { echo "Контрольна сума не збігається — оновлення скасовано."; exit 1; }

if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
  if gh attestation verify "alertd-$WANT.tar.gz" --repo "$REPO" >/dev/null 2>&1; then
    echo "Походження підтверджено: зібрано GitHub Actions у $REPO."
  else
    echo "Атестацію походження не підтверджено — оновлення скасовано."
    exit 1
  fi
else
  echo "Походження не перевірялося (немає авторизованого gh); перевірено лише SHA256."
fi

tar xzf "alertd-$WANT.tar.gz"
cd alertd
./alertd-install.sh --keep   # тимчасову теку прибере trap
