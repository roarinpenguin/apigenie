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

echo
echo "════ result: $PASS passed, $FAIL failed ════"
exit $FAIL
