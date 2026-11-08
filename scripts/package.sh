#!/usr/bin/env bash
# Збирає реліз: dist/alertd-<версія>.tar.gz (бінарники amd64/arm64 + файли розгортання) і SHA256SUMS.
# Використання: scripts/package.sh [версія]   (типово — з git-тегу vX.Y.Z)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${1:-$(git describe --tags --exact-match 2>/dev/null | sed 's/^v//' || true)}
[[ -n $VERSION ]] || { echo "Вкажіть версію: scripts/package.sh 1.0.0"; exit 1; }
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || { echo "Некоректна версія: $VERSION"; exit 1; }

OUT=dist/alertd
rm -rf dist && mkdir -p "$OUT"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=$VERSION" -o "$OUT/alertd-linux-$arch" .
done
cp deploy/alertd-install.sh deploy/alertd-update.sh deploy/alertd.service deploy/alertd.env.example deploy/webhook-public.pem "$OUT/"
cp README.md LICENSE CHANGELOG.md SECURITY.md "$OUT/"
mkdir -p "$OUT/docs" && cp docs/*.md "$OUT/docs/"
chmod 755 "$OUT"/alertd-*.sh "$OUT"/alertd-linux-*

# Відтворювана архівація: фіксований час, власник і порядок файлів.
EPOCH=$(git log -1 --format=%ct 2>/dev/null || date +%s)
tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
    -C dist -czf "dist/alertd-$VERSION.tar.gz" alertd
(cd dist && sha256sum "alertd-$VERSION.tar.gz" alertd/alertd-linux-* > SHA256SUMS)
cat dist/SHA256SUMS
