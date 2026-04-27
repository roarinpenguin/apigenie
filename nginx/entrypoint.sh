#!/bin/sh
# Init step (placed in /docker-entrypoint.d/) — renders nginx.conf.template
# with envsubst before the default docker-entrypoint launches nginx.
#
# The default nginx image's auto-templating only handles
# /etc/nginx/templates/*.template -> /etc/nginx/conf.d/*. We need to template
# the full /etc/nginx/nginx.conf (worker_processes, http block, multiple
# server blocks across ports), which the built-in flow doesn't cover.
set -eu

: "${APIGENIE_DOMAIN:?APIGENIE_DOMAIN must be set in the environment}"

TEMPLATE=/etc/nginx/nginx.conf.template
TARGET=/etc/nginx/nginx.conf
CERT_DIR="/etc/nginx/certs/${APIGENIE_DOMAIN}"

# Sanity: make sure the cert files actually exist before nginx tries to load
# them, so we get a readable error message instead of nginx's cryptic
# "BIO_new_file() failed" line.
if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/privkey.pem" ]; then
    echo "[apigenie-nginx] FATAL: TLS certificate not found at $CERT_DIR" >&2
    echo "[apigenie-nginx]   Expected: $CERT_DIR/fullchain.pem and privkey.pem" >&2
    echo "[apigenie-nginx]   Run ./scripts/bootstrap.sh on the host to generate them," >&2
    echo "[apigenie-nginx]   or place your own certs there before starting nginx." >&2
    exit 1
fi

# Render. Listing the variables explicitly prevents envsubst from clobbering
# nginx's own \$variable references (host, scheme, request_uri, etc.).
envsubst '${APIGENIE_DOMAIN}' < "$TEMPLATE" > "$TARGET"

echo "[apigenie-nginx] Rendered $TARGET for domain ${APIGENIE_DOMAIN}"
