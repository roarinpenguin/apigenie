#!/usr/bin/env bash
# Seed the AGG aggregator with fake (X-Forwarded-For-spoofed) traffic so the
# Flows + GeoMap admin tabs have something to show without waiting for real
# collectors to call in.
#
# Usage:
#   ./scripts/seed-fake-traffic.sh              # hits https://localhost
#   ./scripts/seed-fake-traffic.sh https://apigenie.example.com
#   COUNT=300 ./scripts/seed-fake-traffic.sh    # bigger volume
#
# Requires curl. -k tolerates the self-signed cert in lab mode.
set -euo pipefail

BASE="${1:-https://localhost}"
COUNT="${COUNT:-120}"

# A geographically-diverse handful of public IPs — picked so the GeoMap looks
# interesting at first sight. None of these are sensitive; they are well-known
# anycast / DNS / CDN endpoints. Feel free to extend.
IPS=(
    "8.8.8.8"           # Google US
    "1.1.1.1"           # Cloudflare AU/global
    "9.9.9.9"           # Quad9 CH
    "208.67.222.222"    # OpenDNS US
    "151.101.1.69"      # Fastly US
    "185.199.108.153"   # GitHub US
    "104.18.32.7"       # Cloudflare global
    "203.0.113.42"      # TEST-NET-3 (RFC5737, geolocates as ?? — useful sanity case)
    "13.107.246.10"     # Microsoft
    "52.95.110.1"       # AWS
    "188.114.97.0"      # Cloudflare EU
    "200.221.11.101"    # Brazil
    "202.108.22.5"      # China (Baidu)
    "41.220.69.0"       # Africa
    "85.10.193.40"      # Hetzner DE
)

# (path, method, body) tuples — one per source we want to populate. Paths
# are matched by trace.py's _SOURCE_PATTERNS; status code doesn't matter.
PATHS=(
    "GET  /api/v1/logs/events"                                 # okta
    "GET  /api/v2/events/data/alert"                           # netskope
    "GET  /v1.0/auditLogs/directoryAudits"                     # entra_id
    "POST /v2.0/token"                                         # entra_id (oauth)
    "GET  /v1.0/security/alerts"                               # defender
    "GET  /admin/v1/logs/authentication"                       # cisco_duo
    "GET  /audit-log/v1/events"                                # tenable
    "GET  /v2/siem/all"                                        # proofpoint
    "GET  /modelbreaches"                                      # darktrace
)

echo "→ Seeding $BASE with $COUNT calls across ${#IPS[@]} IPs and ${#PATHS[@]} sources…"

for i in $(seq 1 "$COUNT"); do
    ip="${IPS[RANDOM % ${#IPS[@]}]}"
    spec="${PATHS[RANDOM % ${#PATHS[@]}]}"
    method="$(echo "$spec" | awk '{print $1}')"
    path="$(  echo "$spec" | awk '{print $2}')"
    # -s silent, -k self-signed-tolerant, -o /dev/null don't print body,
    # X-Forwarded-For spoof so the trace middleware picks up our fake origin.
    curl -sk -o /dev/null -X "$method" \
        -H "X-Forwarded-For: $ip" \
        -H "Authorization: Bearer apigenie-fake-seed-token" \
        "$BASE$path" || true
    # Lightly throttle so we don't pile up against a single-worker uvicorn.
    if (( i % 25 == 0 )); then printf "  %3d/%d\n" "$i" "$COUNT"; fi
done

echo "✓ Done. Open the admin Flows / GeoMap tabs."
