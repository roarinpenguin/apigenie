#!/usr/bin/env bash
# One-shot migration: import existing host-side Let's Encrypt certs into the
# repo-local ./certs/<domain>/ layout the new compose stack reads from.
#
# Use this when upgrading from a pre-portable apigenie deployment that mounted
# /etc/letsencrypt:ro into nginx. The imported cert lets nginx boot
# immediately. Once the stack is up, the in-stack `apigenie-certbot` service
# will re-issue the cert (HTTP-01 via the running nginx :80) and from then on
# owns the renewal lifecycle inside ./certs/. Your host-side certbot can then
# be removed.
#
# Usage:
#   ./scripts/migrate-certs.sh <domain>
#
# Idempotent: safe to re-run.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOMAIN="${1:?usage: $0 <domain>}"

LE_LIVE="/etc/letsencrypt/live/${DOMAIN}"
TARGET="${ROOT}/certs/${DOMAIN}"

if [ ! -d "${LE_LIVE}" ]; then
    echo "✗ ${LE_LIVE} not found." >&2
    echo "  No existing Let's Encrypt cert to migrate. Either:" >&2
    echo "    1. Use ./scripts/bootstrap.sh to start fresh, or" >&2
    echo "    2. Place fullchain.pem + privkey.pem manually in ${TARGET}/" >&2
    exit 1
fi

echo "→ Importing ${LE_LIVE} → ${TARGET}/"
mkdir -p "${TARGET}"

# /etc/letsencrypt is root-owned; privkey.pem is 0600 root.
SUDO=""
if [ ! -r "${LE_LIVE}/privkey.pem" ]; then
    SUDO="sudo"
    echo "  (using sudo to read root-owned ${LE_LIVE}/privkey.pem)"
fi

$SUDO cp -L "${LE_LIVE}/fullchain.pem" "${TARGET}/fullchain.pem"
$SUDO cp -L "${LE_LIVE}/privkey.pem"   "${TARGET}/privkey.pem"

# Hand ownership back to the invoking user so the in-stack certbot can later
# overwrite these files when it re-issues / renews.
$SUDO chown "$(id -u):$(id -g)" "${TARGET}/fullchain.pem" "${TARGET}/privkey.pem"
chmod 644 "${TARGET}/fullchain.pem"
chmod 600 "${TARGET}/privkey.pem"

echo "✓ Cert imported."
echo
echo "Next:"
echo "  1. Make sure .env has APIGENIE_TLS_MODE=letsencrypt and COMPOSE_PROFILES=letsencrypt"
echo "  2. docker compose up -d --build"
echo
echo "On first start the in-stack certbot will re-issue this cert (one-time"
echo "duplicate) and from then on handle all renewals automatically. After"
echo "you've confirmed it's working, you can remove the host-side certbot."
