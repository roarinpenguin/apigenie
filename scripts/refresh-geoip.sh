#!/usr/bin/env bash
# Download / refresh the MaxMind GeoLite2-City database used by the admin
# GeoMap tab. Pure curl + tar — no maxmind-specific tooling required.
#
# Usage:
#   ./scripts/refresh-geoip.sh [LICENSE_KEY]
#
#   * If LICENSE_KEY is omitted, the script reads MAXMIND_LICENSE_KEY from
#     ./.env (and exits cleanly with a hint if it isn't set).
#
# Idempotent and cron-safe. The MaxMind GeoLite2 EULA forbids public
# redistribution of the .mmdb, which is why we ship empty and let each
# deployer fetch their own copy.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

KEY="${1:-}"
if [ -z "$KEY" ] && [ -f .env ]; then
    KEY="$(awk -F= '/^MAXMIND_LICENSE_KEY=/ {print $2; exit}' .env || true)"
fi
# Strip whitespace, CR (Windows line endings), surrounding quotes — MaxMind
# keys are alnum+underscore so any of these characters is always wrong.
KEY="$(printf '%s' "$KEY" | tr -d '[:space:]\r' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
if [ -z "${KEY}" ]; then
    cat >&2 <<EOF
✗ No MaxMind license key supplied.
  Either pass it as an argument, or add this line to .env:
      MAXMIND_LICENSE_KEY=your_key_here
  Get a free key at https://www.maxmind.com/en/geolite2/signup .
  (Without an .mmdb, ApiGenie falls back to the ip-api.com public API —
   slower and rate-limited, but works out of the box.)
EOF
    exit 1
fi
echo "→ Using license key (${#KEY} chars)"

OUT_DIR="$ROOT/data/geoip"
mkdir -p "$OUT_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${KEY}&suffix=tar.gz"

echo "→ Downloading GeoLite2-City.mmdb …"
# Capture the final HTTP status so a failure prints something useful instead
# of curl's terse "(56) error: 401". MaxMind 302-redirects to a signed R2 URL,
# hence -L. -f makes curl exit non-zero on 4xx/5xx after redirects.
HTTP_OUT="$(curl -fsSL --retry 2 --retry-delay 2 \
    -w '\nFINAL_STATUS=%{http_code}\nFINAL_URL=%{url_effective}\n' \
    "$URL" -o "$TMP_DIR/geoip.tar.gz" 2>&1 || true)"
if [ ! -s "$TMP_DIR/geoip.tar.gz" ]; then
    echo "$HTTP_OUT" >&2
    cat >&2 <<EOF
✗ Download failed. Common causes:
  - Wrong / revoked key   → verify at https://www.maxmind.com/en/accounts/current/license-key
  - GeoLite2 EULA not accepted on the account → log in once and accept it
  - Outbound HTTPS blocked on this host
  - Clock skew > 15 min   → run 'date -u' and compare to https://time.is/
EOF
    exit 1
fi

echo "→ Extracting …"
tar -xzf "$TMP_DIR/geoip.tar.gz" -C "$TMP_DIR"

# Tarball contains GeoLite2-City_<date>/GeoLite2-City.mmdb — locate it.
MMDB="$(find "$TMP_DIR" -name 'GeoLite2-City.mmdb' -print -quit)"
if [ -z "$MMDB" ]; then
    echo "✗ GeoLite2-City.mmdb not found in archive" >&2
    exit 1
fi

# Atomic install: write to .new then rename so a reader never sees a half-written file.
cp "$MMDB" "$OUT_DIR/GeoLite2-City.mmdb.new"
mv "$OUT_DIR/GeoLite2-City.mmdb.new" "$OUT_DIR/GeoLite2-City.mmdb"
chmod 644 "$OUT_DIR/GeoLite2-City.mmdb"

echo "✓ Installed $OUT_DIR/GeoLite2-City.mmdb ($(du -h "$OUT_DIR/GeoLite2-City.mmdb" | cut -f1))"
echo "  Restart the apigenie container to pick up the new DB:"
echo "      docker compose restart apigenie"
