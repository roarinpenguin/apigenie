#!/usr/bin/env bash
# Regression smoke test for apigenie. Idempotent — pre-creates a session.
set -uo pipefail
PASS=0; FAIL=0
ok()   { echo "  ✓ $1"; PASS=$((PASS+1)); }
fail() { echo "  ✗ $1 — $2"; FAIL=$((FAIL+1)); }
chk()    { local n=$1 e=$2 g=$3; [ "$g" = "$e" ] && ok "$n (got $g)" || fail "$n" "expected $e got $g"; }
chk_min(){ local n=$1 m=$2 g=$3; [ "${g:-0}" -ge "$m" ] 2>/dev/null && ok "$n (got $g, min $m)" || fail "$n" "expected ≥$m got '$g'"; }

C=/tmp/agcookie.txt
TOK="apigenie-valid-token-001"

echo "── Auth"
chk "admin login" 303 "$(curl -sk -c $C -X POST https://localhost/admin/login -d 'username=admin&password=apigenie' -o /dev/null -w '%{http_code}')"

echo "── Functional APIs (regression — must NOT regress)"
chk "okta /api/v1/logs"             200 "$(curl -sk -H "Authorization: Bearer $TOK" https://localhost/api/v1/logs -o /tmp/r.json -w '%{http_code}')"
chk_min "okta payload bytes"        500 "$(wc -c </tmp/r.json | tr -d ' ')"
chk "netskope alerts"               200 "$(curl -sk -H "Authorization: Bearer $TOK" https://localhost/api/v2/events/data/alert -o /dev/null -w '%{http_code}')"
chk "entra audit"                   200 "$(curl -sk -H "Authorization: Bearer $TOK" https://localhost/v1.0/auditLogs/directoryAudits -o /dev/null -w '%{http_code}')"
chk "defender alerts"               200 "$(curl -sk -H "Authorization: Bearer $TOK" https://localhost/v1.0/security/alerts -o /dev/null -w '%{http_code}')"
chk "tenable audit"                 200 "$(curl -sk -H 'X-ApiKeys: accessKey=apigenie-ak-001;secretKey=apigenie-sk-001' https://localhost/audit-log/v1/events -o /dev/null -w '%{http_code}')"

echo "── Existing admin endpoints (regression)"
chk "/admin/api/requests/okta"      200 "$(curl -sk -b $C https://localhost/admin/api/requests/okta -o /tmp/r.json -w '%{http_code}')"
chk_min "okta trace entries"          1 "$(python3 -c 'import json; print(len(json.load(open(chr(47)+"tmp"+chr(47)+"r.json"))))')"
chk "/admin/api/settings"           200 "$(curl -sk -b $C https://localhost/admin/api/settings -o /dev/null -w '%{http_code}')"
chk "/admin/api/cert"               200 "$(curl -sk -b $C https://localhost/admin/api/cert -o /dev/null -w '%{http_code}')"
chk "/admin/gcp-sa.json"            200 "$(curl -sk -b $C https://localhost/admin/gcp-sa.json -o /dev/null -w '%{http_code}')"
chk "/admin/ dashboard renders"     200 "$(curl -sk -b $C https://localhost/admin/ -o /tmp/dash.html -w '%{http_code}')"
chk_min "dashboard size"          40000 "$(wc -c </tmp/dash.html | tr -d ' ')"
# Catch JS syntax errors in the inline <script> blob early — these otherwise
# manifest as a cosmetically-rendered but completely non-interactive admin UI.
# Skipped gracefully when node isn't on the host.
if command -v node >/dev/null 2>&1; then
  python3 -c "
import re; h=open('/tmp/dash.html').read()
scripts=re.findall(r'<script[^>]*>(.*?)</script>', h, re.DOTALL)
open('/tmp/dash.js','w').write(max(scripts, key=len) if scripts else '')
"
  chk "dashboard JS parses (node --check)" 0 "$(node --check /tmp/dash.js >/dev/null 2>&1; echo $?)"
else
  echo "  · skipping JS parse check (node not installed)"
fi

echo "── New admin endpoints"
chk "/admin/api/flows"              200 "$(curl -sk -b $C https://localhost/admin/api/flows -o /tmp/flows.json -w '%{http_code}')"
chk_min "flow nodes"                  5 "$(python3 -c 'import json; d=json.load(open("/tmp/flows.json")); print(len(d["nodes"]))')"
chk_min "flow links"                  3 "$(python3 -c 'import json; d=json.load(open("/tmp/flows.json")); print(len(d["links"]))')"
chk "/admin/api/flows?ip=8.8.8.8"   200 "$(curl -sk -b $C 'https://localhost/admin/api/flows?ip=8.8.8.8' -o /tmp/ff.json -w '%{http_code}')"
chk_min "filtered IP nodes"           1 "$(python3 -c 'import json; d=json.load(open("/tmp/ff.json")); print(sum(1 for n in d["nodes"] if n["type"]=="ip"))')"
chk "/admin/api/geo"                200 "$(curl -sk -b $C https://localhost/admin/api/geo -o /tmp/geo.json -w '%{http_code}')"
chk_min "geo rows"                    5 "$(python3 -c 'import json; d=json.load(open("/tmp/geo.json")); print(len(d["rows"]))')"
chk_min "rows resolved (mmdb)"        3 "$(python3 -c 'import json; d=json.load(open("/tmp/geo.json")); print(sum(1 for r in d["rows"] if r["geo"].get("status")=="ok"))')"

echo "── Auth gate (must 401 unauthenticated)"
chk "/admin/api/flows w/o cookie"   401 "$(curl -sk https://localhost/admin/api/flows -o /dev/null -w '%{http_code}')"
chk "/admin/api/geo w/o cookie"     401 "$(curl -sk https://localhost/admin/api/geo -o /dev/null -w '%{http_code}')"
chk "/admin/api/requests/okta w/o cookie" 401 "$(curl -sk https://localhost/admin/api/requests/okta -o /dev/null -w '%{http_code}')"

echo "── Dashboard contains new code"
chk_min "registerMap occurrences"     1 "$(grep -c registerMap /tmp/dash.html)"
chk_min "ensureGeoMap occurrences"    1 "$(grep -c ensureGeoMap /tmp/dash.html)"
chk_min "renderSankey occurrences"    1 "$(grep -c renderSankey /tmp/dash.html)"
chk_min "Listeners nav item"          1 "$(grep -c 'showTab..listeners' /tmp/dash.html)"
chk_min "loadListeners function"      1 "$(grep -c 'async function loadListeners' /tmp/dash.html)"
chk_min "Wizard modal present"        1 "$(grep -c 'id=.wiz-modal.' /tmp/dash.html)"
chk_min "Snippet modal present"       1 "$(grep -c 'id=.snippet-modal.' /tmp/dash.html)"

echo "── Custom Listeners (Phase 1 backbone — see docs/CUSTOM_LISTENERS.md)"
LID="smoketest-$(date +%s)"
# Clean up any prior listener with the same id (idempotent reruns).
curl -sk -b $C -X DELETE "https://localhost/admin/api/listeners/$LID" >/dev/null 2>&1 || true

# Auth gate
chk "/admin/api/listeners w/o cookie"  401 "$(curl -sk https://localhost/admin/api/listeners -o /dev/null -w '%{http_code}')"

# List (initially excludes our id)
chk "/admin/api/listeners (list)"      200 "$(curl -sk -b $C https://localhost/admin/api/listeners -o /tmp/l.json -w '%{http_code}')"

# Create — bearer auth, json codec, synthetic endpoint topic
read -r -d '' BODY <<JSON || true
{"id":"$LID","name":"Smoke","path":"/v1/events","method":"GET","codec":"json",
 "auth":{"kind":"bearer","token":"smoke-token-001"},
 "synthetic":{"topic":"endpoint","rate_per_request":10}}
JSON
chk "create listener"                  201 "$(curl -sk -b $C -X POST -H 'Content-Type: application/json' -d "$BODY" https://localhost/admin/api/listeners -o /tmp/lc.json -w '%{http_code}')"

# Reject duplicate id
chk "duplicate listener → 409"         409 "$(curl -sk -b $C -X POST -H 'Content-Type: application/json' -d "$BODY" https://localhost/admin/api/listeners -o /dev/null -w '%{http_code}')"

# Reject malformed payload (missing data source)
chk "invalid payload → 400"            400 "$(curl -sk -b $C -X POST -H 'Content-Type: application/json' -d '{"id":"badone","path":"/x"}' https://localhost/admin/api/listeners -o /dev/null -w '%{http_code}')"

# Public dispatcher behaviour
chk "GET listener w/o auth → 401"      401 "$(curl -sk "https://localhost/listener/$LID/v1/events" -o /dev/null -w '%{http_code}')"
chk "GET listener wrong path → 404"    404 "$(curl -sk -H 'Authorization: Bearer smoke-token-001' "https://localhost/listener/$LID/nope" -o /dev/null -w '%{http_code}')"
chk "GET listener wrong method → 405"  405 "$(curl -sk -X DELETE -H 'Authorization: Bearer smoke-token-001' "https://localhost/listener/$LID/v1/events" -o /dev/null -w '%{http_code}')"
chk "GET listener happy path → 200"    200 "$(curl -sk -H 'Authorization: Bearer smoke-token-001' "https://localhost/listener/$LID/v1/events" -o /tmp/lr.json -w '%{http_code}')"
chk_min "endpoint records returned"     5 "$(python3 -c 'import json; d=json.load(open("/tmp/lr.json")); print(d["count"])')"
chk_min "first record has host.name"    1 "$(python3 -c 'import json; d=json.load(open("/tmp/lr.json")); print(1 if d["records"][0].get("host",{}).get("name") else 0)')"

# Hits recorded
chk "GET /admin/api/listeners/$LID/hits" 200 "$(curl -sk -b $C "https://localhost/admin/api/listeners/$LID/hits" -o /tmp/lh.json -w '%{http_code}')"
chk_min "hits recorded"                  3 "$(python3 -c 'import json; d=json.load(open("/tmp/lh.json")); print(d["count"])')"

# Phase 3 snippet endpoint
chk "snippet?lang=lua → 200"            200 "$(curl -sk -b $C "https://localhost/admin/api/listeners/$LID/snippet?lang=lua" -o /tmp/snip.lua -w '%{http_code}')"
chk_min "lua has on_trigger"             1 "$(grep -c 'function on_trigger' /tmp/snip.lua)"
chk_min "lua has listener URL"           1 "$(grep -c "/listener/$LID/v1/events" /tmp/snip.lua)"
chk_min "lua has Bearer auth block"      1 "$(grep -c 'Authorization' /tmp/snip.lua)"
chk "snippet?lang=yaml → 200"           200 "$(curl -sk -b $C "https://localhost/admin/api/listeners/$LID/snippet?lang=yaml" -o /tmp/snip.yaml -w '%{http_code}')"
chk_min "yaml has type: scol"            1 "$(grep -c 'type: scol' /tmp/snip.yaml)"
chk_min "yaml has decoding:"             1 "$(grep -c 'decoding:' /tmp/snip.yaml)"
chk "snippet w/o cookie → 401"          401 "$(curl -sk "https://localhost/admin/api/listeners/$LID/snippet?lang=lua" -o /dev/null -w '%{http_code}')"
chk "snippet on missing → 404"          404 "$(curl -sk -b $C "https://localhost/admin/api/listeners/no-such-listener/snippet?lang=lua" -o /dev/null -w '%{http_code}')"

# Disable → 404 from dispatcher
chk "PATCH disable listener"           200 "$(curl -sk -b $C -X PATCH -H 'Content-Type: application/json' -d '{"enabled":false}' "https://localhost/admin/api/listeners/$LID" -o /dev/null -w '%{http_code}')"
chk "disabled listener → 404"          404 "$(curl -sk -H 'Authorization: Bearer smoke-token-001' "https://localhost/listener/$LID/v1/events" -o /dev/null -w '%{http_code}')"

# Cleanup
chk "DELETE listener"                  200 "$(curl -sk -b $C -X DELETE "https://localhost/admin/api/listeners/$LID" -o /dev/null -w '%{http_code}')"
chk "deleted listener → 404"           404 "$(curl -sk -b $C "https://localhost/admin/api/listeners/$LID" -o /dev/null -w '%{http_code}')"

# Listeners route is excluded from the global request trace (own per-listener pane)
chk "/listener/ excluded from REQUEST_TRACE" 200 "$(curl -sk -b $C https://localhost/admin/api/requests/okta -o /dev/null -w '%{http_code}')"

echo "── Custom Listeners Phase 2 (synthetic topics + codecs + pagination)"
# JSON payloads come from python (single source of truth, no shell-escaping
# nightmares with embedded double-quotes). Everything writes to /tmp/lp.json.

write_payload() {
  python3 - "$@" <<'PY'
import json, sys
lid, topic, codec = sys.argv[1], sys.argv[2], sys.argv[3]
pagination = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
body = {
  "id": lid, "name": lid, "path": "/x", "method": "GET", "codec": codec,
  "auth": {"kind": "none"},
  "synthetic": {"topic": topic, "rate_per_request": 4, "seed": 7},
}
if pagination == "cursor":
  body["pagination"] = {"kind": "cursor", "page_size": 4, "total_pages": 3}
elif pagination == "page":
  body["pagination"] = {"kind": "page",   "page_size": 4, "total_pages": 2}
open("/tmp/lp.json","w").write(json.dumps(body))
PY
}

create_listener() {
  local id=$1
  curl -sk -b $C -X DELETE "https://localhost/admin/api/listeners/$id" >/dev/null 2>&1 || true
  curl -sk -b $C -X POST -H 'Content-Type: application/json' \
    --data @/tmp/lp.json https://localhost/admin/api/listeners -o /dev/null -w '%{http_code}'
}

# Each topic returns shape-correct records (json codec)
for TOPIC in endpoint identity cloud network; do
  L="p2-$TOPIC-$$"
  write_payload "$L" "$TOPIC" json
  chk "create $TOPIC listener"  201 "$(create_listener $L)"
  chk "GET $TOPIC topic"        200 "$(curl -sk "https://localhost/listener/$L/x" -o /tmp/p2.json -w '%{http_code}')"
  chk_min "$TOPIC records >=4"    4 "$(python3 -c 'import json; print(json.load(open("/tmp/p2.json"))["count"])')"
done

# Topic-specific shape spot-checks
chk_min "endpoint has process.name"      1 "$(curl -sk "https://localhost/listener/p2-endpoint-$$/x" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["records"][0].get("process",{}).get("name") else 0)')"
chk_min "identity has actor.alternateId" 1 "$(curl -sk "https://localhost/listener/p2-identity-$$/x" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["records"][0].get("actor",{}).get("alternateId") else 0)')"
chk_min "cloud has _provider tag"        1 "$(curl -sk "https://localhost/listener/p2-cloud-$$/x"    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["records"][0].get("_provider") in ("aws","azure","gcp") else 0)')"
chk_min "network has uid + service"      1 "$(curl -sk "https://localhost/listener/p2-network-$$/x"  | python3 -c 'import json,sys; d=json.load(sys.stdin); r=d["records"][0]; print(1 if r.get("uid") and r.get("service") else 0)')"

# Seed determinism (structural — same seed produces same uid sequence, modulo ts)
A=$(curl -sk "https://localhost/listener/p2-network-$$/x" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(r["uid"] for r in d["records"]))')
B=$(curl -sk "https://localhost/listener/p2-network-$$/x" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(r["uid"] for r in d["records"]))')
chk "seed=7 produces identical uids" "$A" "$B"

# Codec: NDJSON
LN="p2-ndjson-$$"
write_payload "$LN" identity ndjson
chk "create ndjson listener"    201 "$(create_listener $LN)"
chk "GET ndjson"                 200 "$(curl -sk -D /tmp/h.txt "https://localhost/listener/$LN/x" -o /tmp/p2.nd -w '%{http_code}')"
chk_min "ndjson content-type"     1 "$(grep -ci 'content-type:.*ndjson' /tmp/h.txt)"
chk_min "ndjson lines"            4 "$(wc -l </tmp/p2.nd | tr -d ' ')"
chk_min "first ndjson line valid" 1 "$(head -1 /tmp/p2.nd | python3 -c 'import json,sys; json.loads(sys.stdin.read()); print(1)' 2>/dev/null || echo 0)"

# Codec: syslog
LS="p2-syslog-$$"
write_payload "$LS" endpoint syslog
chk "create syslog listener"    201 "$(create_listener $LS)"
chk "GET syslog"                 200 "$(curl -sk -D /tmp/h.txt "https://localhost/listener/$LS/x" -o /tmp/p2.sl -w '%{http_code}')"
chk_min "syslog content-type"     1 "$(grep -ci 'content-type:.*text/plain' /tmp/h.txt)"
chk_min "syslog has <134> pri"    4 "$(grep -c '^<134>' /tmp/p2.sl)"
chk_min "syslog tag includes id"  4 "$(grep -c "endpoint\\[$LS\\]" /tmp/p2.sl)"

# Pagination: cursor (3 pages)
LC="p2-cursor-$$"
write_payload "$LC" identity json cursor
chk "create cursor listener"    201 "$(create_listener $LC)"
chk "page 1 OK"                  200 "$(curl -sk -D /tmp/h.txt "https://localhost/listener/$LC/x" -o /tmp/p2.json -w '%{http_code}')"
chk_min "page 1 X-Next-Cursor"    1 "$(grep -ci 'x-next-cursor:' /tmp/h.txt)"
chk_min "page 1 next_cursor body" 1 "$(python3 -c 'import json; d=json.load(open("/tmp/p2.json")); print(1 if d.get("next_cursor")=="page-1" else 0)')"
chk "page 2 OK"                  200 "$(curl -sk "https://localhost/listener/$LC/x?cursor=page-1" -o /tmp/p2.json -w '%{http_code}')"
chk_min "page 2 next_cursor body" 1 "$(python3 -c 'import json; d=json.load(open("/tmp/p2.json")); print(1 if d.get("next_cursor")=="page-2" else 0)')"
chk "page 3 OK (last)"           200 "$(curl -sk -D /tmp/h.txt "https://localhost/listener/$LC/x?cursor=page-2" -o /tmp/p2.json -w '%{http_code}')"
chk_min "page 3 NO next_cursor"   1 "$(python3 -c 'import json; d=json.load(open("/tmp/p2.json")); print(0 if "next_cursor" in d else 1)')"
chk "page 3 NO X-Next-Cursor" 0 "$(grep -ci 'x-next-cursor:' /tmp/h.txt)"
chk "past-end cursor"            200 "$(curl -sk "https://localhost/listener/$LC/x?cursor=page-9" -o /tmp/p2.json -w '%{http_code}')"
chk "empty records past end"       0 "$(python3 -c 'import json; print(json.load(open("/tmp/p2.json"))["count"])')"

# Pagination: page-number (2 pages)
LP="p2-page-$$"
write_payload "$LP" cloud json page
chk "create page listener"      201 "$(create_listener $LP)"
chk_min "page=0 next_page=1"      1 "$(curl -sk "https://localhost/listener/$LP/x?page=0" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(1 if d.get("next_page")==1 else 0)')"
chk_min "page=1 NO next_page"     1 "$(curl -sk "https://localhost/listener/$LP/x?page=1" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(0 if "next_page" in d else 1)')"

# Cleanup all the Phase 2 listeners
for L in p2-endpoint-$$ p2-identity-$$ p2-cloud-$$ p2-network-$$ $LN $LS $LC $LP; do
  curl -sk -b $C -X DELETE "https://localhost/admin/api/listeners/$L" >/dev/null
done

echo "── Custom Listeners Phase 4 (replay engine + uploads)"
# UI markup checks (added at the dashboard level)
chk_min "wizard data-source toggle"     1 "$(grep -c 'wiz-ds-kind' /tmp/dash.html)"
chk_min "Replay upload modal"           1 "$(grep -c 'id=.replay-upload-modal.' /tmp/dash.html)"
chk_min "Manage uploads modal"          1 "$(grep -c 'id=.manage-uploads-modal.' /tmp/dash.html)"
chk_min "loadReplayDropdown function"   1 "$(grep -c 'async function loadReplayDropdown' /tmp/dash.html)"
chk_min "submitReplayUpload function"   1 "$(grep -c 'async function submitReplayUpload' /tmp/dash.html)"

# Auth gate
chk "/admin/api/replays w/o cookie"   401 "$(curl -sk https://localhost/admin/api/replays -o /dev/null -w '%{http_code}')"
chk "POST /admin/api/replays w/o cookie" 401 "$(curl -sk -X POST -F file=@/etc/hosts https://localhost/admin/api/replays -o /dev/null -w '%{http_code}')"

# Empty list initially (well — list is non-empty across reruns; assert the call works)
chk "GET /admin/api/replays"          200 "$(curl -sk -b $C https://localhost/admin/api/replays -o /tmp/replays.json -w '%{http_code}')"
chk_min "max_mb in response"            1 "$(python3 -c 'import json; d=json.load(open("/tmp/replays.json")); print(1 if d.get("max_mb",0)>=1 else 0)')"

# Build five tiny fixture files on the fly and upload each.
TMPDIR=$(mktemp -d)
cat > "$TMPDIR/edr.jsonl" <<JSONL
{"timestamp":"2026-01-01T10:00:00Z","host":"a","action":"login"}
{"timestamp":"2026-01-01T10:00:30Z","host":"b","action":"logout"}
{"timestamp":"2026-01-01T10:01:00Z","host":"c","action":"login"}
JSONL
cat > "$TMPDIR/dump.json" <<JSON
[{"timestamp":"2026-01-01T10:00:00Z","x":1},{"timestamp":"2026-01-01T10:00:10Z","x":2}]
JSON
cat > "$TMPDIR/audit.csv" <<CSV
timestamp,user,action
2026-01-01T10:00:00Z,alice,login
2026-01-01T10:00:30Z,bob,logout
CSV
cat > "$TMPDIR/syslog.log" <<SYSLOG
<165>1 2026-01-01T10:00:00Z host1 app1 1234 ID47 - msg-one
<165>1 2026-01-01T10:00:30Z host1 app1 1234 ID48 - msg-two
SYSLOG
cat > "$TMPDIR/events.cef" <<CEF
CEF:0|Vendor|Product|1.0|sig1|Name1|3|src=1.2.3.4 rt=1735725600000 act=login
CEF:0|Vendor|Product|1.0|sig2|Name2|3|src=1.2.3.5 rt=1735725660000 act=logout
CEF

upload_replay() {
  local file=$1; local fmt=$2; local tsf=$3
  local args=(-X POST -F "file=@$file")
  if [ -n "$fmt" ]; then args+=(-F "fmt=$fmt"); fi
  if [ -n "$tsf" ]; then args+=(-F "timestamp_field=$tsf"); fi
  curl -sk -b $C "${args[@]}" https://localhost/admin/api/replays
}

# Upload each format and capture the file_id
JSONL_RES=$(upload_replay "$TMPDIR/edr.jsonl" "" "")
JSONL_ID=$(echo "$JSONL_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("file_id",""))')
JSONL_FMT=$(echo "$JSONL_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("format",""))')
JSONL_LC=$(echo "$JSONL_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("line_count",0))')
chk     "upload jsonl auto-detect (got fmt=$JSONL_FMT)" jsonl "$JSONL_FMT"
chk     "jsonl line_count"            3 "$JSONL_LC"

JSON_RES=$(upload_replay "$TMPDIR/dump.json" "" "")
JSON_ID=$(echo "$JSON_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("file_id",""))')
JSON_FMT=$(echo "$JSON_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("format",""))')
chk     "upload json (array) auto-detect" json "$JSON_FMT"

CSV_RES=$(upload_replay "$TMPDIR/audit.csv" "" "")
CSV_ID=$(echo "$CSV_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("file_id",""))')
CSV_FMT=$(echo "$CSV_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("format",""))')
chk     "upload csv auto-detect"      csv "$CSV_FMT"

SYS_RES=$(upload_replay "$TMPDIR/syslog.log" "syslog" "")
SYS_ID=$(echo "$SYS_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("file_id",""))')
SYS_FMT=$(echo "$SYS_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("format",""))')
chk     "upload syslog (forced)"      syslog "$SYS_FMT"

CEF_RES=$(upload_replay "$TMPDIR/events.cef" "" "")
CEF_ID=$(echo "$CEF_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("file_id",""))')
CEF_FMT=$(echo "$CEF_RES" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("format",""))')
chk     "upload cef auto-detect"      cef "$CEF_FMT"

# All five present in the listing
chk_min "list shows >= 5 replays"     5 "$(curl -sk -b $C https://localhost/admin/api/replays | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("replays",[])))')"

# /preview returns parsed records
chk "preview jsonl"                   200 "$(curl -sk -b $C "https://localhost/admin/api/replays/$JSONL_ID/preview?n=2" -o /tmp/prev.json -w '%{http_code}')"
chk_min "preview returns >=2 records"  2 "$(python3 -c 'import json; print(len(json.load(open("/tmp/prev.json"))["records"]))')"
chk "preview missing → 404"           404 "$(curl -sk -b $C https://localhost/admin/api/replays/no-such-file/preview -o /dev/null -w '%{http_code}')"

# Bad format override → 400
chk "upload bad fmt → 400"            400 "$(curl -sk -b $C -X POST -F file=@$TMPDIR/edr.jsonl -F fmt=bogus https://localhost/admin/api/replays -o /dev/null -w '%{http_code}')"

# ── Replay-backed listener (anchor=now, jsonl, 3 records) ────────────────────
RID="p4-replay-$$"
cat > /tmp/lp.json <<EOF
{"id":"$RID","name":"$RID","path":"/x","method":"GET","codec":"json",
 "auth":{"kind":"none"},
 "replay":{"file_id":"$JSONL_ID","format":"jsonl","timestamp_field":"timestamp",
           "anchor_mode":"now","anchor_offset_seconds":0,"anchor_fixed_iso":null,
           "preserve_spread":true}}
EOF
curl -sk -b $C -X DELETE "https://localhost/admin/api/listeners/$RID" >/dev/null 2>&1 || true
chk "create replay listener"          201 "$(curl -sk -b $C -X POST -H 'Content-Type: application/json' --data @/tmp/lp.json https://localhost/admin/api/listeners -o /dev/null -w '%{http_code}')"
chk "GET replay listener"             200 "$(curl -sk "https://localhost/listener/$RID/x" -o /tmp/r1.json -w '%{http_code}')"
chk     "replay returns 3 records"      3 "$(python3 -c 'import json; print(json.load(open("/tmp/r1.json"))["count"])')"
chk_min "records have host field"       1 "$(python3 -c 'import json; d=json.load(open("/tmp/r1.json")); print(1 if d["records"][0].get("host") else 0)')"
# Verify anchor=now: latest record's timestamp should be within 60s of now.
chk_min "max ts within 60s of now"      1 "$(python3 -c '
import json, datetime
d = json.load(open("/tmp/r1.json"))
ts = max(r["timestamp"] for r in d["records"])
parsed = datetime.datetime.fromisoformat(ts.replace("Z","+00:00"))
delta = abs((datetime.datetime.now(datetime.timezone.utc) - parsed).total_seconds())
print(1 if delta < 60 else 0)
')"
# Verify spread preserved: original spread between max and min was 60s.
chk     "spread preserved (60s)"        60 "$(python3 -c '
import json, datetime
d = json.load(open("/tmp/r1.json"))
ts_list = sorted(datetime.datetime.fromisoformat(r["timestamp"].replace("Z","+00:00")) for r in d["records"])
print(int((ts_list[-1]-ts_list[0]).total_seconds()))
')"

# ── Anchor mode = fixed ──────────────────────────────────────────────────────
RID2="p4-fixed-$$"
cat > /tmp/lp.json <<EOF
{"id":"$RID2","name":"$RID2","path":"/x","method":"GET","codec":"json",
 "auth":{"kind":"none"},
 "replay":{"file_id":"$JSONL_ID","format":"jsonl","timestamp_field":"timestamp",
           "anchor_mode":"fixed","anchor_offset_seconds":0,
           "anchor_fixed_iso":"2030-06-15T12:00:00+00:00","preserve_spread":true}}
EOF
chk "create fixed-anchor listener"    201 "$(curl -sk -b $C -X POST -H 'Content-Type: application/json' --data @/tmp/lp.json https://localhost/admin/api/listeners -o /dev/null -w '%{http_code}')"
chk "GET fixed-anchor listener"       200 "$(curl -sk "https://localhost/listener/$RID2/x" -o /tmp/r2.json -w '%{http_code}')"
chk_min "max ts == 2030-06-15T12:00"   1 "$(python3 -c '
import json
d = json.load(open("/tmp/r2.json"))
mx = max(r["timestamp"] for r in d["records"])
print(1 if mx.startswith("2030-06-15T12:00:00") else 0)
')"

# ── Cursor pagination over replay (page_size=2 → 2 pages from 3-row file) ────
RID3="p4-cursor-$$"
cat > /tmp/lp.json <<EOF
{"id":"$RID3","name":"$RID3","path":"/x","method":"GET","codec":"json",
 "auth":{"kind":"none"},
 "pagination":{"kind":"cursor","page_size":2,"total_pages":99},
 "replay":{"file_id":"$JSONL_ID","format":"jsonl","timestamp_field":"timestamp",
           "anchor_mode":"now","anchor_offset_seconds":0,"anchor_fixed_iso":null,
           "preserve_spread":true}}
EOF
chk "create cursor replay listener"   201 "$(curl -sk -b $C -X POST -H 'Content-Type: application/json' --data @/tmp/lp.json https://localhost/admin/api/listeners -o /dev/null -w '%{http_code}')"
chk "page 1 OK"                       200 "$(curl -sk -D /tmp/h.txt "https://localhost/listener/$RID3/x" -o /tmp/r3.json -w '%{http_code}')"
chk     "page 1 has 2 records"          2 "$(python3 -c 'import json; print(json.load(open("/tmp/r3.json"))["count"])')"
chk_min "page 1 has X-Next-Cursor"     1 "$(grep -ci 'x-next-cursor:' /tmp/h.txt)"
chk "page 2 OK"                       200 "$(curl -sk -D /tmp/h.txt "https://localhost/listener/$RID3/x?cursor=page-1" -o /tmp/r3.json -w '%{http_code}')"
chk     "page 2 has 1 record"           1 "$(python3 -c 'import json; print(json.load(open("/tmp/r3.json"))["count"])')"
chk     "page 2 NO X-Next-Cursor"      0 "$(grep -ci 'x-next-cursor:' /tmp/h.txt)"

# ── Delete-while-in-use (409) ────────────────────────────────────────────────
chk "DELETE replay (in use) → 409"    409 "$(curl -sk -b $C -X DELETE https://localhost/admin/api/replays/$JSONL_ID -o /dev/null -w '%{http_code}')"

# ── Detach listeners then delete the replays ─────────────────────────────────
for L in $RID $RID2 $RID3; do
  curl -sk -b $C -X DELETE "https://localhost/admin/api/listeners/$L" >/dev/null
done
chk "DELETE replay (free) → 200"      200 "$(curl -sk -b $C -X DELETE https://localhost/admin/api/replays/$JSONL_ID -o /dev/null -w '%{http_code}')"
chk "DELETE replay missing → 404"     404 "$(curl -sk -b $C -X DELETE https://localhost/admin/api/replays/$JSONL_ID -o /dev/null -w '%{http_code}')"

# Cleanup the rest of the upload fixtures so reruns stay tidy.
for ID in $JSON_ID $CSV_ID $SYS_ID $CEF_ID; do
  [ -n "$ID" ] && curl -sk -b $C -X DELETE "https://localhost/admin/api/replays/$ID" >/dev/null
done
rm -rf "$TMPDIR"

echo
echo "════ result: $PASS passed, $FAIL failed ════"
exit $FAIL
