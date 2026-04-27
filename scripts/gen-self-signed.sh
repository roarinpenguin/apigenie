#!/bin/sh
# Generate a self-signed TLS certificate for the given domain into
# ./certs/<domain>/{fullchain,privkey}.pem.
#
# Usage:  ./scripts/gen-self-signed.sh <domain>
#
# The cert is valid for 825 days (Apple's max-trust window) with a SAN list
# that includes the domain itself, *.<domain>, localhost, and 127.0.0.1 so
# that local development against the same stack just works.
set -eu

DOMAIN="${1:?usage: $0 <domain>}"
OUT_DIR="$(dirname "$0")/../certs/${DOMAIN}"
mkdir -p "$OUT_DIR"

# Build a SAN list with the domain, its wildcard subdomain, and loopback.
SAN="DNS:${DOMAIN},DNS:*.${DOMAIN},DNS:localhost,IP:127.0.0.1,IP:::1"

openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "${OUT_DIR}/privkey.pem" \
    -out    "${OUT_DIR}/fullchain.pem" \
    -subj "/CN=${DOMAIN}/O=API Genie/OU=Self-signed" \
    -addext "subjectAltName=${SAN}" \
    -addext "extendedKeyUsage=serverAuth"

chmod 600 "${OUT_DIR}/privkey.pem"
chmod 644 "${OUT_DIR}/fullchain.pem"

echo "Self-signed cert written to ${OUT_DIR}/"
echo "  Subject  : CN=${DOMAIN}"
echo "  SAN      : ${SAN}"
echo "  Validity : 825 days"
