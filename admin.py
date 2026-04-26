"""Admin UI — authentication, container logs, request inspector, source config guide."""

import asyncio
import json
import os
import secrets
import time
from typing import Any

from fastapi import APIRouter, Cookie, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse

from trace import REQUEST_TRACE

# ── Config ────────────────────────────────────────────────────────────────────
ADMIN_USER   = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASS   = os.environ.get("ADMIN_PASSWORD", "apigenie")
SESSION_TTL  = 86400  # 24 h
COOKIE       = "ag_session"

router = APIRouter(prefix="/admin", tags=["admin"])

_sessions: dict[str, float] = {}   # token → expires_at


def _new_session() -> str:
    tok = secrets.token_urlsafe(32)
    _sessions[tok] = time.time() + SESSION_TTL
    return tok


def _valid(token: str | None) -> bool:
    if not token:
        return False
    exp = _sessions.get(token)
    if not exp or time.time() > exp:
        _sessions.pop(token, None)
        return False
    return True


# ── Source config reference ───────────────────────────────────────────────────
BASE = "https://apigenie.roarinpenguin.com"

SOURCES: dict[str, dict[str, Any]] = {
    "okta": {
        "name": "Okta",
        "auth_type": "Bearer token",
        "credentials": {"token": "apigenie-valid-token-001"},
        "endpoints": [
            {"method": "GET",  "path": "/api/v1/logs",  "desc": "System event logs"},
        ],
        "curl": f'curl -s -H "Authorization: Bearer apigenie-valid-token-001" \\\n  "{BASE}/api/v1/logs?limit=5"',
    },
    "netskope": {
        "name": "Netskope",
        "auth_type": "Bearer token",
        "credentials": {"token": "apigenie-valid-token-001"},
        "endpoints": [
            {"method": "GET", "path": "/api/v2/events/data/alert", "desc": "Alert events"},
            {"method": "GET", "path": "/api/v2/events/data/audit", "desc": "Audit events"},
        ],
        "curl": f'curl -s -H "Authorization: Bearer apigenie-valid-token-001" \\\n  "{BASE}/api/v2/events/data/alert?limit=5"',
    },
    "entra_id": {
        "name": "Microsoft Entra ID",
        "auth_type": "OAuth2 Bearer (tenant token endpoint)",
        "credentials": {
            "token_url": f"{BASE}/oauth2/v2.0/token  (or /{'{tenant-id}'}/oauth2/v2.0/token)",
            "token": "apigenie-valid-token-001",
        },
        "endpoints": [
            {"method": "POST", "path": "/oauth2/v2.0/token",                  "desc": "Get access token"},
            {"method": "GET",  "path": "/v1.0/auditLogs/directoryAudits",      "desc": "Directory audit logs"},
            {"method": "GET",  "path": "/v1.0/auditLogs/signIns",              "desc": "Sign-in logs"},
        ],
        "curl": f'curl -s -H "Authorization: Bearer apigenie-valid-token-001" \\\n  "{BASE}/v1.0/auditLogs/directoryAudits?\\$top=5"',
    },
    "defender": {
        "name": "Microsoft Defender",
        "auth_type": "Bearer token",
        "credentials": {"token": "apigenie-valid-token-001"},
        "endpoints": [
            {"method": "GET", "path": "/subscriptions/{sub_id}/providers/Microsoft.Security/alerts",          "desc": "Security alerts"},
            {"method": "GET", "path": "/subscriptions/{sub_id}/providers/Microsoft.Security/recommendations", "desc": "Recommendations"},
        ],
        "curl": (
            f'curl -s -H "Authorization: Bearer apigenie-valid-token-001" \\\n'
            f'  "{BASE}/subscriptions/00000000-0000-0000-0000-000000000001'
            f'/providers/Microsoft.Security/alerts"'
        ),
    },
    "cisco_duo": {
        "name": "Cisco Duo",
        "auth_type": "HTTP Basic (HMAC-SHA1 — ikey as username, computed sig as password)",
        "credentials": {
            "ikey": "DIXXXXXXXXXXXXXXXXXX",
            "skey": "duo-mock-secret-key-for-testing",
            "shortcut": "pass ikey as username with empty password to skip HMAC check",
        },
        "endpoints": [
            {"method": "GET", "path": "/admin/v1/logs/authentication", "desc": "Auth logs (v1)"},
            {"method": "GET", "path": "/admin/v2/logs/authentication", "desc": "Auth logs (v2, ms timestamps)"},
            {"method": "GET", "path": "/admin/v1/logs/administrator",  "desc": "Admin action logs"},
            {"method": "GET", "path": "/admin/v1/info/summary",        "desc": "Account summary"},
        ],
        "curl": f'curl -s -u "DIXXXXXXXXXXXXXXXXXX:" \\\n  "{BASE}/admin/v1/logs/authentication?limit=5"',
    },
    "gcp_audit": {
        "name": "GCP Cloud Logging",
        "auth_type": "Bearer token",
        "credentials": {"token": "apigenie-valid-token-001"},
        "endpoints": [
            {"method": "POST", "path": "/v2/entries:list", "desc": "List log entries"},
        ],
        "curl": (
            f'curl -s -X POST \\\n'
            f'  -H "Authorization: Bearer apigenie-valid-token-001" \\\n'
            f'  -H "Content-Type: application/json" \\\n'
            f'  -d \'{{"pageSize":5}}\' \\\n'
            f'  "{BASE}/v2/entries:list"'
        ),
    },
    "tenable": {
        "name": "Tenable",
        "auth_type": "X-ApiKeys header (accessKey + secretKey)",
        "credentials": {
            "accessKey": "apigenie-ak-001",
            "secretKey": "apigenie-sk-001",
            "header": "X-ApiKeys: accessKey=apigenie-ak-001&secretKey=apigenie-sk-001",
        },
        "endpoints": [
            {"method": "POST", "path": "/vulns/export",                      "desc": "Start vuln export → returns export_uuid"},
            {"method": "GET",  "path": "/vulns/export/{uuid}/status",         "desc": "Poll export status"},
            {"method": "GET",  "path": "/vulns/export/{uuid}/chunks/{id}",    "desc": "Download chunk"},
            {"method": "POST", "path": "/assets/export",                      "desc": "Start asset export"},
            {"method": "GET",  "path": "/audit-log/v1/events",               "desc": "Audit log events"},
        ],
        "curl": (
            f'curl -s \\\n'
            f'  -H "X-ApiKeys: accessKey=apigenie-ak-001&secretKey=apigenie-sk-001" \\\n'
            f'  "{BASE}/audit-log/v1/events?limit=5"'
        ),
    },
    "proofpoint": {
        "name": "Proofpoint TAP",
        "auth_type": "HTTP Basic auth",
        "credentials": {
            "username": "apigenie-principal-001",
            "password": "apigenie-secret-001",
        },
        "endpoints": [
            {"method": "GET", "path": "/v2/siem/all",              "desc": "All SIEM events"},
            {"method": "GET", "path": "/v2/siem/messages/blocked", "desc": "Blocked messages"},
            {"method": "GET", "path": "/v2/siem/clicks/blocked",   "desc": "Blocked clicks"},
        ],
        "curl": f'curl -s -u "apigenie-principal-001:apigenie-secret-001" \\\n  "{BASE}/v2/siem/all?sinceSeconds=3600"',
    },
    "cloudtrail": {
        "name": "AWS CloudTrail",
        "auth_type": "Bearer token",
        "credentials": {"token": "apigenie-valid-token-001"},
        "endpoints": [
            {"method": "GET",  "path": "/v1/cloudtrail/events", "desc": "CloudTrail events (GET)"},
            {"method": "POST", "path": "/v1/cloudtrail/events", "desc": "CloudTrail events (POST)"},
        ],
        "curl": f'curl -s -H "Authorization: Bearer apigenie-valid-token-001" \\\n  "{BASE}/v1/cloudtrail/events"',
    },
    "waf": {
        "name": "AWS WAF",
        "auth_type": "Bearer token",
        "credentials": {"token": "apigenie-valid-token-001"},
        "endpoints": [
            {"method": "GET",  "path": "/v1/waf/logs", "desc": "WAF logs (GET)"},
            {"method": "POST", "path": "/v1/waf/logs", "desc": "WAF logs (POST)"},
        ],
        "curl": f'curl -s -H "Authorization: Bearer apigenie-valid-token-001" \\\n  "{BASE}/v1/waf/logs"',
    },
    "guardduty": {
        "name": "AWS GuardDuty",
        "auth_type": "Bearer token",
        "credentials": {"token": "apigenie-valid-token-001"},
        "endpoints": [
            {"method": "GET",  "path": "/v1/guardduty/findings",              "desc": "Findings (GET)"},
            {"method": "POST", "path": "/detector/{detector_id}/findings/get", "desc": "Findings (POST)"},
        ],
        "curl": f'curl -s -H "Authorization: Bearer apigenie-valid-token-001" \\\n  "{BASE}/v1/guardduty/findings"',
    },
    "wiz": {
        "name": "Wiz",
        "auth_type": "Bearer token + OAuth2",
        "credentials": {
            "token_url": f"{BASE}/oauth2/token",
            "token": "apigenie-valid-token-001",
        },
        "endpoints": [
            {"method": "POST", "path": "/oauth2/token", "desc": "Get access token"},
            {"method": "POST", "path": "/graphql",      "desc": "Issues via GraphQL"},
        ],
        "curl": (
            f'curl -s -X POST \\\n'
            f'  -H "Authorization: Bearer apigenie-valid-token-001" \\\n'
            f'  -H "Content-Type: application/json" \\\n'
            f'  -d \'{{"query":"{{ issues {{ id severity title }} }}","variables":{{"first":5}}}}\' \\\n'
            f'  "{BASE}/graphql"'
        ),
    },
    "snyk": {
        "name": "Snyk",
        "auth_type": "Bearer token",
        "credentials": {"token": "apigenie-valid-token-001"},
        "endpoints": [
            {"method": "GET", "path": "/v1/org/{org_id}/issues",   "desc": "Org issues"},
            {"method": "GET", "path": "/v1/org/{org_id}/projects",  "desc": "Org projects"},
            {"method": "GET", "path": "/v1/org/{org_id}/audit",     "desc": "Audit log"},
            {"method": "GET", "path": "/rest/orgs/{org_id}/issues", "desc": "Issues (REST API)"},
        ],
        "curl": (
            f'curl -s -H "Authorization: Bearer apigenie-valid-token-001" \\\n'
            f'  "{BASE}/v1/org/00000000-0000-0000-0000-000000000001/issues"'
        ),
    },
    "darktrace": {
        "name": "Darktrace",
        "auth_type": "HMAC-SHA1 (mock accepts any value)",
        "credentials": {"note": "Mock skips signature check — any Authorization header accepted"},
        "endpoints": [
            {"method": "GET", "path": "/modelbreaches",          "desc": "Model breaches"},
            {"method": "GET", "path": "/aianalyst/incident/log", "desc": "AI Analyst incidents"},
            {"method": "GET", "path": "/status",                 "desc": "System status"},
            {"method": "GET", "path": "/groups",                 "desc": "Device groups"},
        ],
        "curl": f'curl -s "{BASE}/modelbreaches?limit=5"',
    },
}

CONTAINERS = ["apigenie", "apigenie-nginx", "apigenie-kafka", "apigenie-zookeeper", "apigenie-pubsub"]

# ── HTML ──────────────────────────────────────────────────────────────────────

_LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ApiGenie · Admin Login</title>
<style>
:root{--deep:#10002b;--violet:#5a189a;--purple:#7b2cbf;--orchid:#9d4edd;--lilac:#c77dff;--mist:#e0aaff;--glow:rgba(199,125,255,.55)}
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(circle at 20% 20%,#3c096c,transparent 55%),radial-gradient(circle at 80% 80%,#7b2cbf,transparent 50%),#10002b;font-family:"Segoe UI",system-ui,sans-serif;color:var(--mist)}
.card{background:rgba(36,0,70,.7);border:1px solid rgba(199,125,255,.3);border-radius:20px;padding:40px 36px;width:100%;max-width:380px;backdrop-filter:blur(12px);box-shadow:0 20px 60px rgba(0,0,0,.5)}
h1{font-size:1.6rem;font-weight:700;text-align:center;margin-bottom:6px;background:linear-gradient(90deg,#e0aaff,#c77dff 40%,#9d4edd);-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{text-align:center;font-size:.85rem;color:rgba(224,170,255,.6);margin-bottom:28px}
label{display:block;font-size:.82rem;color:rgba(224,170,255,.7);margin-bottom:6px;margin-top:16px}
input{width:100%;background:rgba(90,24,154,.2);border:1px solid rgba(199,125,255,.35);border-radius:10px;padding:10px 14px;color:var(--mist);font-size:.95rem;outline:none;transition:border-color .2s}
input:focus{border-color:var(--lilac)}
button{width:100%;margin-top:24px;padding:12px;background:linear-gradient(135deg,#7b2cbf,#9d4edd);border:none;border-radius:12px;color:#fff;font-size:1rem;font-weight:600;cursor:pointer;box-shadow:0 0 20px var(--glow);transition:filter .2s}
button:hover{filter:brightness(1.15)}
.err{color:#ff7f7f;font-size:.85rem;text-align:center;margin-top:12px}
</style>
</head>
<body>
<div class="card">
  <h1>⚙ ApiGenie Admin</h1>
  <p class="sub">Restricted access</p>
  <form method="post" action="/admin/login">
    <label>Username</label>
    <input name="username" type="text" autocomplete="username" autofocus/>
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password"/>
    <button type="submit">Sign in</button>
    {error}
  </form>
</div>
</body>
</html>"""

_DASH_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ApiGenie · Admin</title>
<style>
:root{--deep:#10002b;--violet:#5a189a;--purple:#7b2cbf;--orchid:#9d4edd;--lilac:#c77dff;--mist:#e0aaff;--glow:rgba(199,125,255,.45);--sidebar:220px}
*{box-sizing:border-box;margin:0;padding:0}
body{display:flex;min-height:100vh;background:var(--deep);color:var(--mist);font-family:"Segoe UI",system-ui,sans-serif;font-size:.92rem}
/* Sidebar */
.sidebar{width:var(--sidebar);background:rgba(36,0,70,.8);border-right:1px solid rgba(199,125,255,.15);display:flex;flex-direction:column;padding:20px 0;flex-shrink:0;position:fixed;top:0;left:0;height:100vh;z-index:10}
.sidebar .brand{padding:0 20px 20px;font-size:1.1rem;font-weight:700;background:linear-gradient(90deg,#e0aaff,#c77dff);-webkit-background-clip:text;background-clip:text;color:transparent;border-bottom:1px solid rgba(199,125,255,.15)}
.nav-item{display:block;padding:11px 20px;color:rgba(224,170,255,.7);text-decoration:none;cursor:pointer;border-left:3px solid transparent;transition:all .15s}
.nav-item:hover,.nav-item.active{color:var(--mist);background:rgba(123,44,191,.2);border-left-color:var(--lilac)}
.nav-section{padding:16px 20px 6px;font-size:.72rem;color:rgba(224,170,255,.35);text-transform:uppercase;letter-spacing:.08em}
.sidebar .logout{margin-top:auto;padding:0 12px 12px}
.logout a{display:block;padding:9px 14px;text-align:center;border-radius:10px;background:rgba(90,24,154,.3);color:rgba(224,170,255,.6);text-decoration:none;font-size:.85rem;transition:all .15s}
.logout a:hover{background:rgba(123,44,191,.4);color:var(--mist)}
/* Main */
.main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;min-height:100vh}
.topbar{padding:16px 24px;border-bottom:1px solid rgba(199,125,255,.1);display:flex;align-items:center;gap:12px;background:rgba(16,0,43,.6);backdrop-filter:blur(8px)}
.topbar h2{font-size:1rem;font-weight:600;color:var(--mist)}
.content{padding:24px;flex:1}
/* Cards */
.card{background:rgba(36,0,70,.55);border:1px solid rgba(199,125,255,.2);border-radius:14px;padding:20px;margin-bottom:16px}
.card-title{font-size:.82rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--orchid);margin-bottom:14px}
/* Controls */
select{background:rgba(90,24,154,.25);border:1px solid rgba(199,125,255,.3);border-radius:8px;padding:7px 12px;color:var(--mist);font-size:.88rem;outline:none;cursor:pointer}
select:focus{border-color:var(--lilac)}
button,input[type=button]{background:linear-gradient(135deg,#7b2cbf,#9d4edd);border:none;border-radius:8px;padding:7px 16px;color:#fff;font-size:.85rem;font-weight:600;cursor:pointer;transition:filter .15s}
button:hover,input[type=button]:hover{filter:brightness(1.15)}
.btn-sm{padding:5px 12px;font-size:.8rem}
/* Requests table */
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 10px;font-size:.75rem;color:rgba(224,170,255,.5);text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid rgba(199,125,255,.12)}
td{padding:8px 10px;border-bottom:1px solid rgba(199,125,255,.07);vertical-align:top;word-break:break-all;max-width:240px}
tr:hover td{background:rgba(123,44,191,.1)}
.badge{display:inline-block;padding:2px 7px;border-radius:999px;font-size:.72rem;font-weight:600}
.b200{background:rgba(50,205,50,.15);color:#7fff7f}
.b4xx{background:rgba(255,140,0,.15);color:#ffb347}
.b5xx{background:rgba(255,50,50,.15);color:#ff7f7f}
.method{color:var(--lilac);font-weight:600;font-size:.78rem}
.ts{color:rgba(224,170,255,.45);font-size:.75rem}
.dur{color:rgba(224,170,255,.5);font-size:.75rem}
/* Detail expand */
details summary{cursor:pointer;color:var(--lilac);font-size:.78rem;padding:4px 0}
details pre{background:rgba(0,0,0,.3);border-radius:8px;padding:10px;font-size:.72rem;overflow-x:auto;margin-top:6px;max-height:220px;overflow-y:auto;color:rgba(224,170,255,.8)}
/* Log terminal */
.terminal{background:#000;border:1px solid rgba(199,125,255,.2);border-radius:10px;padding:14px;height:500px;overflow-y:auto;font-family:"JetBrains Mono","Fira Code",monospace;font-size:.75rem;line-height:1.6;color:#a8c0b0}
.terminal .err{color:#ff8080}
.terminal .warn{color:#ffd080}
/* Config */
.cfg-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px;margin-bottom:16px}
.cfg-item label{font-size:.72rem;color:rgba(224,170,255,.45);display:block;margin-bottom:3px}
.cfg-item code{font-family:monospace;font-size:.82rem;color:var(--mist);word-break:break-all}
.ep-list{list-style:none;margin-bottom:14px}
.ep-list li{display:flex;gap:10px;align-items:baseline;padding:5px 0;border-bottom:1px solid rgba(199,125,255,.08)}
.ep-method{min-width:42px;text-align:center;padding:1px 6px;border-radius:5px;font-size:.7rem;font-weight:700}
.GET{background:rgba(50,150,255,.2);color:#7fb5ff}
.POST{background:rgba(50,200,100,.2);color:#7fd6a0}
.ep-path{font-family:monospace;font-size:.8rem;color:var(--mist)}
.ep-desc{font-size:.75rem;color:rgba(224,170,255,.45);margin-left:auto}
.curl-block{position:relative}
.curl-block pre{background:rgba(0,0,0,.4);border:1px solid rgba(199,125,255,.2);border-radius:10px;padding:14px 14px 14px 14px;font-family:monospace;font-size:.78rem;color:#a8c0b0;overflow-x:auto;white-space:pre-wrap}
.copy-btn{position:absolute;top:8px;right:8px}
/* Tabs */
.tab-bar{display:flex;gap:4px;margin-bottom:20px}
.tab{padding:8px 18px;border-radius:8px;cursor:pointer;color:rgba(224,170,255,.55);font-size:.88rem;border:1px solid transparent;transition:all .15s}
.tab.active,.tab:hover{background:rgba(123,44,191,.3);color:var(--mist);border-color:rgba(199,125,255,.25)}
.tab.active{border-color:var(--lilac)}
.pane{display:none}.pane.active{display:block}
/* Misc */
.row{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.empty{color:rgba(224,170,255,.3);font-style:italic;padding:20px 0;text-align:center}
.source-chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.chip{padding:4px 12px;border-radius:999px;font-size:.75rem;border:1px solid rgba(199,125,255,.25);background:rgba(90,24,154,.2);color:rgba(224,170,255,.6);cursor:pointer;transition:all .15s}
.chip.active,.chip:hover{background:rgba(123,44,191,.4);color:var(--mist);border-color:var(--lilac)}
</style>
</head>
<body>

<nav class="sidebar">
  <div class="brand">⚙ ApiGenie Admin</div>
  <span class="nav-section">Monitor</span>
  <a class="nav-item active" onclick="showTab('requests', this)">📋 Requests</a>
  <a class="nav-item" onclick="showTab('logs', this)">📜 Container Logs</a>
  <span class="nav-section">Reference</span>
  <a class="nav-item" onclick="showTab('config', this)">🔧 Source Config</a>
  <div class="logout"><a href="/admin/logout">Sign out</a></div>
</nav>

<div class="main">
  <div class="topbar"><h2 id="page-title">Request Inspector</h2></div>
  <div class="content">

    <!-- REQUESTS TAB -->
    <div class="pane active" id="pane-requests">
      <div class="card">
        <div class="card-title">Source</div>
        <div class="source-chips" id="source-chips"></div>
      </div>
      <div class="card">
        <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
          Recent calls <button class="btn-sm" onclick="loadRequests()">↺ Refresh</button>
        </div>
        <div id="req-table-wrap"><p class="empty">Select a source above</p></div>
      </div>
    </div>

    <!-- LOGS TAB -->
    <div class="pane" id="pane-logs">
      <div class="card">
        <div class="row">
          <select id="log-container">
            {container_options}
          </select>
          <button onclick="startLogs()">▶ Start</button>
          <button onclick="stopLogs()" style="background:rgba(90,24,154,.4);border:1px solid rgba(199,125,255,.3)">■ Stop</button>
          <button onclick="clearLog()" class="btn-sm" style="background:rgba(36,0,70,.6);border:1px solid rgba(199,125,255,.2)">Clear</button>
        </div>
        <div class="terminal" id="terminal">
          <span style="color:rgba(224,170,255,.3)">Select a container and click Start…</span>
        </div>
      </div>
    </div>

    <!-- CONFIG TAB -->
    <div class="pane" id="pane-config">
      <div class="card">
        <div class="card-title">Source</div>
        <div class="source-chips" id="cfg-chips"></div>
      </div>
      <div id="cfg-detail"><p class="empty">Select a source above</p></div>
    </div>

  </div>
</div>

<script>
const SOURCES = {sources_json};
let activeSource = null;
let activeTab = 'requests';
let logES = null;

// ── Tab navigation ────────────────────────────────────────────────────────────
function showTab(tab, el) {
  document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('pane-' + tab).classList.add('active');
  if (el) el.classList.add('active');
  activeTab = tab;
  const titles = {requests:'Request Inspector', logs:'Container Logs', config:'Source Config'};
  document.getElementById('page-title').textContent = titles[tab];
}

// ── Source chips ──────────────────────────────────────────────────────────────
function buildChips(containerId, onClick) {
  const wrap = document.getElementById(containerId);
  wrap.innerHTML = '';
  Object.entries(SOURCES).forEach(([id, src]) => {
    const c = document.createElement('span');
    c.className = 'chip';
    c.textContent = src.name;
    c.dataset.id = id;
    c.onclick = () => {
      wrap.querySelectorAll('.chip').forEach(x => x.classList.remove('active'));
      c.classList.add('active');
      onClick(id);
    };
    wrap.appendChild(c);
  });
}

// ── Requests ──────────────────────────────────────────────────────────────────
function selectSource(id) {
  activeSource = id;
  // sync chips in both tabs if somehow both are rendered
  document.querySelectorAll('[data-id="' + id + '"]').forEach(c => c.classList.add('active'));
  loadRequests();
}

async function loadRequests() {
  if (!activeSource) return;
  const wrap = document.getElementById('req-table-wrap');
  wrap.innerHTML = '<p class="empty">Loading…</p>';
  try {
    const r = await fetch('/admin/api/requests/' + activeSource);
    if (!r.ok) { wrap.innerHTML = '<p class="empty">Error: ' + r.status + ' ' + r.statusText + ' — try signing in again.</p>'; return; }
    const data = await r.json();
    if (!data.length) { wrap.innerHTML = '<p class="empty">No requests recorded yet — wait for the collector to call in.</p>'; return; }
    let html = `<table><thead><tr>
      <th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>ms</th><th>Client</th><th>Detail</th>
    </tr></thead><tbody>`;
    data.forEach((e, i) => {
      const bc = e.status < 300 ? 'b200' : e.status < 500 ? 'b4xx' : 'b5xx';
      const q = e.query ? '?' + e.query : '';
      const hdr = JSON.stringify(e.req_headers, null, 2);
      const body = e.req_body || '';
      html += `<tr>
        <td class="ts">${e.ts.replace('T',' ')}</td>
        <td class="method">${e.method}</td>
        <td style="font-family:monospace;font-size:.78rem">${e.path}${q}</td>
        <td><span class="badge ${bc}">${e.status}</span></td>
        <td class="dur">${e.duration_ms}</td>
        <td class="ts">${e.client}</td>
        <td><details><summary>headers${body ? ' + body' : ''}</summary>
          <pre>${escHtml(hdr)}${body ? '\\n\\n--- Body ---\\n' + escHtml(body.substring(0,800)) : ''}</pre>
        </details></td>
      </tr>`;
    });
    html += '</tbody></table>';
    wrap.innerHTML = html;
  } catch(err) { wrap.innerHTML = '<p class="empty">Error: ' + err + '</p>'; }
}

// ── Logs ──────────────────────────────────────────────────────────────────────
function startLogs() {
  stopLogs();
  const container = document.getElementById('log-container').value;
  const term = document.getElementById('terminal');
  term.innerHTML = '<span style="color:var(--orchid)">Connecting to ' + container + '…</span>\\n';
  logES = new EventSource('/admin/api/logs/' + container);
  logES.onmessage = (e) => {
    const line = JSON.parse(e.data);
    const span = document.createElement('span');
    span.className = line.includes('ERROR') || line.includes('error') ? 'err'
                   : line.includes('WARN')  || line.includes('warn')  ? 'warn' : '';
    span.textContent = line + '\\n';
    term.appendChild(span);
    term.scrollTop = term.scrollHeight;
    // keep DOM lean
    while (term.childNodes.length > 600) term.removeChild(term.firstChild);
  };
  logES.onerror = () => { term.innerHTML += '<span class="err">Connection closed.\\n</span>'; stopLogs(); };
}

function stopLogs() { if (logES) { logES.close(); logES = null; } }
function clearLog() { document.getElementById('terminal').innerHTML = ''; }

// ── Config ────────────────────────────────────────────────────────────────────
function showConfig(id) {
  const src = SOURCES[id];
  const wrap = document.getElementById('cfg-detail');

  const creds = Object.entries(src.credentials || {}).map(([k,v]) =>
    `<div class="cfg-item"><label>${k}</label><code>${escHtml(v)}</code></div>`
  ).join('');

  const eps = (src.endpoints || []).map(ep =>
    `<li>
      <span class="ep-method ${ep.method}">${ep.method}</span>
      <span class="ep-path">${escHtml(ep.path)}</span>
      <span class="ep-desc">${ep.desc}</span>
    </li>`
  ).join('');

  const curl = src.curl || '';

  wrap.innerHTML = `
    <div class="card">
      <div class="card-title">${src.name}</div>
      <p style="font-size:.82rem;color:rgba(224,170,255,.55);margin-bottom:14px">Auth: ${src.auth_type}</p>
      <div class="card-title" style="font-size:.72rem">Credentials</div>
      <div class="cfg-grid">${creds}</div>
      <div class="card-title" style="font-size:.72rem">Endpoints</div>
      <ul class="ep-list">${eps}</ul>
      <div class="card-title" style="font-size:.72rem">Test with curl</div>
      <div class="curl-block">
        <pre id="curl-pre">${escHtml(curl)}</pre>
        <button class="btn-sm copy-btn" onclick="copyCurl()">Copy</button>
      </div>
    </div>`;
}

function copyCurl() {
  const text = document.getElementById('curl-pre').textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy', 2000);
  });
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Init ──────────────────────────────────────────────────────────────────────
buildChips('source-chips', selectSource);
buildChips('cfg-chips', showConfig);
// auto-select first source
document.querySelector('#source-chips .chip')?.click();
</script>
</body>
</html>"""


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(_LOGIN_HTML.replace("{error}", ""))


@router.post("/login")
async def login_submit(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        tok = _new_session()
        resp = RedirectResponse("/admin/", status_code=303)
        resp.set_cookie(COOKIE, tok, httponly=True, samesite="lax", max_age=SESSION_TTL)
        return resp
    html = _LOGIN_HTML.replace("{error}", '<p class="err">Invalid credentials.</p>')
    return HTMLResponse(html, status_code=401)


@router.get("/logout")
async def logout(ag_session: str | None = Cookie(None)):
    _sessions.pop(ag_session or "", None)
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie(COOKIE)
    return resp


@router.get("/", response_class=HTMLResponse)
@router.get("", response_class=HTMLResponse)
async def dashboard(ag_session: str | None = Cookie(None)):
    if not _valid(ag_session):
        return RedirectResponse("/admin/login", status_code=303)

    opts = "\n".join(f'<option value="{c}">{c}</option>' for c in CONTAINERS)
    sources_json = json.dumps({k: {
        "name": v["name"],
        "auth_type": v["auth_type"],
        "credentials": {str(ck): str(cv) for ck, cv in v.get("credentials", {}).items()},
        "endpoints": v.get("endpoints", []),
        "curl": v.get("curl", ""),
    } for k, v in SOURCES.items()})

    html = _DASH_HTML.replace("{container_options}", opts).replace("{sources_json}", sources_json)
    return HTMLResponse(html)


@router.get("/api/requests/{source}")
async def api_requests(source: str, ag_session: str | None = Cookie(None)):
    if not _valid(ag_session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = list(REQUEST_TRACE.get(source, []))
    return JSONResponse(data)


@router.get("/api/logs/{container}")
async def api_logs(container: str, ag_session: str | None = Cookie(None)):
    if not _valid(ag_session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    # Sanitise container name
    allowed = set(CONTAINERS)
    if container not in allowed:
        return JSONResponse({"error": "unknown container"}, status_code=400)

    async def generate():
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "logs", "--tail=200", "--follow", "--timestamps", container,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            assert proc.stdout
            while True:
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
                except asyncio.TimeoutError:
                    yield "data: \"[heartbeat]\"\n\n"
                    continue
                if not line:
                    break
                yield f"data: {json.dumps(line.decode('utf-8', errors='replace').rstrip())}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps('[error: ' + str(exc) + ']')}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
