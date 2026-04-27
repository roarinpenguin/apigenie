#!/usr/bin/env bash
# API Genie — interactive first-time setup.
#
#   1. Asks for domain, admin creds, TLS mode.
#   2. Writes .env from .env.example with the answers substituted.
#   3. Populates ./certs/<domain>/ depending on the chosen TLS mode:
#        - self-signed : generates a 825-day local cert via openssl
#        - letsencrypt : runs the certbot compose profile (HTTP-01 on :80)
#        - provided    : verifies user-supplied certs are present
#   4. Prints next-step instructions.
#
# Re-run safely: existing .env is backed up to .env.bak before overwrite.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
DIM=$'\033[2m'
RESET=$'\033[0m'

say()  { printf "%s\n"  "$*"; }
ok()   { printf "${GREEN}✓${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}!${RESET} %s\n" "$*"; }
err()  { printf "${RED}✗${RESET} %s\n" "$*" >&2; }

ask() {
    # ask <prompt> <default> <varname>
    local prompt="$1" default="$2" __var="$3" reply
    read -r -p "$prompt [$default]: " reply || true
    printf -v "$__var" '%s' "${reply:-$default}"
}

ask_secret() {
    # ask_secret <prompt> <varname>
    local prompt="$1" __var="$2" reply confirm
    while :; do
        read -r -s -p "$prompt: " reply; echo
        read -r -s -p "Confirm: "    confirm; echo
        if [ -z "$reply" ]; then warn "Password cannot be empty."; continue; fi
        if [ "$reply" != "$confirm" ]; then warn "Passwords do not match."; continue; fi
        printf -v "$__var" '%s' "$reply"
        return 0
    done
}

require() {
    command -v "$1" >/dev/null 2>&1 || { err "Required tool '$1' not found in PATH."; exit 1; }
}

require openssl
require python3

# ─── 0. Load existing .env (if any) so prompts default to current values ──────
ENV_FILE="$ROOT/.env"
EXISTING_DOMAIN=""
EXISTING_KAFKA=""
EXISTING_ADMIN_USER=""
EXISTING_TLS_MODE=""
EXISTING_TLS_EMAIL=""
EXISTING_ADMIN_HASH=""
EXISTING_ADMIN_PASS=""
if [ -f "$ENV_FILE" ]; then
    # Source in a subshell to avoid polluting the namespace, then read each value
    # back via grep (avoids set -u tripping over quoting in the .env).
    EXISTING_DOMAIN=$(awk -F= '/^APIGENIE_DOMAIN=/ {print $2; exit}' "$ENV_FILE")
    EXISTING_KAFKA=$(awk -F= '/^APIGENIE_KAFKA_ADVERTISED_HOST=/ {print $2; exit}' "$ENV_FILE")
    EXISTING_ADMIN_USER=$(awk -F= '/^ADMIN_USERNAME=/ {print $2; exit}' "$ENV_FILE")
    EXISTING_TLS_MODE=$(awk -F= '/^APIGENIE_TLS_MODE=/ {print $2; exit}' "$ENV_FILE")
    EXISTING_TLS_EMAIL=$(awk -F= '/^APIGENIE_TLS_EMAIL=/ {print $2; exit}' "$ENV_FILE")
    EXISTING_ADMIN_HASH=$(awk -F= '/^ADMIN_PASSWORD_HASH=/ {print $2; exit}' "$ENV_FILE")
    # Un-escape '$$' -> '$' so the in-memory hash is canonical; we re-escape on write.
    EXISTING_ADMIN_HASH="${EXISTING_ADMIN_HASH//\$\$/\$}"
    EXISTING_ADMIN_PASS=$(awk -F= '/^ADMIN_PASSWORD=/ {print $2; exit}' "$ENV_FILE")
fi

say
say "${DIM}────────────────────────────────────────────────────────────${RESET}"
if [ -f "$ENV_FILE" ]; then
    say "  ${GREEN}API Genie${RESET} — reconfigure (existing .env detected)"
    say "  ${DIM}Press enter at any prompt to keep the existing value.${RESET}"
else
    say "  ${GREEN}API Genie${RESET} — first-time setup"
fi
say "${DIM}────────────────────────────────────────────────────────────${RESET}"
say

# ─── 1. Collect inputs ───────────────────────────────────────────────────────────
ask "Public DNS hostname"                 "${EXISTING_DOMAIN:-apigenie.example.com}" DOMAIN
ask "Kafka advertised hostname"           "${EXISTING_KAFKA:-$DOMAIN}"               KAFKA_HOST
ask "Admin username"                      "${EXISTING_ADMIN_USER:-admin}"            ADMIN_USER

# Admin password — if a hash is already set, offer to keep it.
if [ -n "$EXISTING_ADMIN_HASH" ]; then
    ask "Keep existing admin password? [Y/n]" "Y" KEEP_PWD
    case "$KEEP_PWD" in
        [nN]|[nN][oO]) ask_secret "New admin password" ADMIN_PASS_PLAIN; ADMIN_HASH="" ;;
        *)             ADMIN_HASH="$EXISTING_ADMIN_HASH"; ADMIN_PASS_PLAIN=""; ok "Keeping existing password hash." ;;
    esac
else
    ask_secret "Admin password" ADMIN_PASS_PLAIN
    ADMIN_HASH=""
fi

say
say "TLS mode:"
say "  1) self-signed  (lab — local cert, browsers warn)"
say "  2) letsencrypt  (public cert, requires DNS + port 80 reachable)"
say "  3) provided     (you'll place fullchain.pem + privkey.pem yourself)"
case "$EXISTING_TLS_MODE" in
    self-signed) TLS_DEFAULT=1 ;;
    letsencrypt) TLS_DEFAULT=2 ;;
    provided)    TLS_DEFAULT=3 ;;
    *)           TLS_DEFAULT=1 ;;
esac
ask "Choose 1, 2, or 3"                   "$TLS_DEFAULT"            TLS_CHOICE

case "$TLS_CHOICE" in
    1|self-signed)  TLS_MODE="self-signed"; TLS_EMAIL="" ;;
    2|letsencrypt)  TLS_MODE="letsencrypt"; ask "Email for Let's Encrypt notices" "${EXISTING_TLS_EMAIL:-admin@${DOMAIN#*.}}" TLS_EMAIL ;;
    3|provided)     TLS_MODE="provided";    TLS_EMAIL="" ;;
    *)              err "Unrecognised TLS choice: $TLS_CHOICE"; exit 1 ;;
esac

# ─── 2. Hash password (only if user supplied a new plaintext) ─────────────────
if [ -n "$ADMIN_PASS_PLAIN" ]; then
    say
    say "Hashing admin password (PBKDF2-SHA256)…"
    ADMIN_HASH="$(python3 "$ROOT/scripts/hash_password.py" --plain "$ADMIN_PASS_PLAIN")"
    ok "Hash generated."
fi

# ─── 3. Write .env ───────────────────────────────────────────────────────────
if [ -f "$ENV_FILE" ]; then
    cp "$ENV_FILE" "$ENV_FILE.bak"
    warn "Existing .env backed up to .env.bak"
fi

# If we kept the existing hash, reuse it; else use the freshly-generated one.
# ADMIN_PASSWORD is only kept as a plaintext fallback when no hash is set
# (first boot before user changes pwd in the UI).
ADMIN_PASS_FALLBACK=""
if [ -z "$ADMIN_HASH" ] && [ -n "$EXISTING_ADMIN_PASS" ]; then
    ADMIN_PASS_FALLBACK="$EXISTING_ADMIN_PASS"
fi

# Escape '$' as '$$' for docker-compose variable-substitution rules.
# The PBKDF2 hash format pbkdf2_sha256$<iters>$<salt>$<digest> contains
# three literal '$' that Compose would otherwise treat as ${iters} etc.
# and silently expand to empty strings, breaking login. See:
# https://docs.docker.com/compose/compose-file/12-interpolation/
ADMIN_HASH_ENV="${ADMIN_HASH//\$/\$\$}"

# COMPOSE_PROFILES drives which docker-compose profile-gated services start by
# default. For letsencrypt mode we want the in-stack certbot manager active.
if [ "$TLS_MODE" = "letsencrypt" ]; then
    COMPOSE_PROFILES_LINE="COMPOSE_PROFILES=letsencrypt"
else
    COMPOSE_PROFILES_LINE="# COMPOSE_PROFILES=  # set to 'letsencrypt' to enable the auto-renew sidecar"
fi

cat > "$ENV_FILE" <<EOF
# Generated by scripts/bootstrap.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# To regenerate, re-run ./scripts/bootstrap.sh — your old .env will be backed up.

# ── Public-facing identity ──
APIGENIE_DOMAIN=${DOMAIN}
APIGENIE_KAFKA_ADVERTISED_HOST=${KAFKA_HOST}

# ── TLS ──
APIGENIE_TLS_MODE=${TLS_MODE}
APIGENIE_TLS_EMAIL=${TLS_EMAIL}
${COMPOSE_PROFILES_LINE}

# ── Admin credentials ──
ADMIN_USERNAME=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASS_FALLBACK}
ADMIN_PASSWORD_HASH=${ADMIN_HASH_ENV}

# ── FastAPI server ──
LOG_LEVEL=INFO
PUBLISHERS_ENABLED=true

# ── GCP Pub/Sub emulator ──
PUBSUB_EMULATOR_HOST=pubsub-emulator:8085
GCP_PROJECT_ID=obs-test
PUBSUB_TOPIC_ID=audit-logs
PUBSUB_SUBSCRIPTION_ID=audit-logs-sub
PUBSUB_PUBLISH_INTERVAL=10
PUBSUB_BATCH_SIZE=5

# ── Kafka / Azure Event Hubs emulator ──
KAFKA_BOOTSTRAP_SERVERS=kafka:29092
KAFKA_TOPIC=azure-platform-logs
KAFKA_PUBLISH_INTERVAL=10
KAFKA_BATCH_SIZE=5

# Legacy compat
PUBLIC_HOSTNAME=${KAFKA_HOST}
EOF
chmod 600 "$ENV_FILE"
ok "Wrote $ENV_FILE"

# ─── 4. Provision certs ──────────────────────────────────────────────────────
CERT_DIR="$ROOT/certs/${DOMAIN}"
mkdir -p "$CERT_DIR"

have_certs() {
    [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ]
}

case "$TLS_MODE" in
    self-signed)
        if have_certs; then
            ask "Existing certs found at $CERT_DIR/. Regenerate? [y/N]" "N" REGEN
            case "$REGEN" in
                [yY]|[yY][eE][sS]) sh "$ROOT/scripts/gen-self-signed.sh" "$DOMAIN"; ok "Self-signed cert regenerated." ;;
                *)                  ok "Keeping existing certs at $CERT_DIR/." ;;
            esac
        else
            say "Generating self-signed certificate…"
            sh "$ROOT/scripts/gen-self-signed.sh" "$DOMAIN"
            ok "Self-signed cert installed."
        fi
        ;;
    letsencrypt)
        if have_certs; then
            ok "Existing certs at $CERT_DIR/ — leaving them in place."
            say "  ${DIM}The in-stack certbot manager will renew them automatically.${RESET}"
        elif [ -d "/etc/letsencrypt/live/${DOMAIN}" ]; then
            warn "Found existing host-side Let's Encrypt cert at /etc/letsencrypt/live/${DOMAIN}/"
            ask "Import it into the repo-local layout? [Y/n]" "Y" IMPORT
            case "$IMPORT" in
                [nN]|[nN][oO]) ok "Skipping import — the in-stack certbot will issue a fresh cert on first start." ;;
                *)             sh "$ROOT/scripts/migrate-certs.sh" "$DOMAIN"; ok "Existing host certs imported." ;;
            esac
        else
            say
            warn "letsencrypt mode picked. Pre-flight checklist:"
            say "  • DNS for ${DOMAIN} must already point at this host."
            say "  • Port 80 on this host must be reachable from the public internet."
            say
            sh "$ROOT/scripts/gen-self-signed.sh" "$DOMAIN"
            ok "Self-signed placeholder cert generated so nginx can boot."
            say "  ${DIM}The in-stack certbot manager will replace it with a real Let's Encrypt cert${RESET}"
            say "  ${DIM}within ~10 seconds of stack start, then renew automatically.${RESET}"
        fi
        ;;
    provided)
        if have_certs; then
            ok "Existing certs detected at $CERT_DIR/"
        else
            warn "TLS mode 'provided' selected but certs are missing:"
            warn "  Place fullchain.pem and privkey.pem in $CERT_DIR/"
            warn "  before running 'docker compose up -d'."
        fi
        ;;
esac

# ─── 5. Done ────────────────────────────────────────────────────────────────
say
say "${DIM}─────────────────────────────────────────────────────────${RESET}"
ok "Setup complete."
say
say "Next steps:"
say "  ${GREEN}docker compose up -d --build${RESET}"
say
say "Then visit:"
say "  ${GREEN}https://${DOMAIN}${RESET}                — landing page"
say "  ${GREEN}https://${DOMAIN}/admin/login${RESET}     — admin (user: ${ADMIN_USER})"
say
if [ "$TLS_MODE" = "letsencrypt" ]; then
    say "The in-stack certbot manager (apigenie-certbot) will:"
    say "  • issue a real cert ~10 s after first start (HTTP-01 via nginx :80)"
    say "  • wake up every 12 h and renew when within 30 days of expiry"
    say "  • SIGHUP nginx + restart kafka after each renewal (zero-downtime nginx)"
    say
    say "Watch it with:  ${GREEN}docker logs -f apigenie-certbot${RESET}"
    say
fi
