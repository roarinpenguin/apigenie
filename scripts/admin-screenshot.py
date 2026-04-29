"""Drive the running apigenie admin via Chrome DevTools Protocol.

Login via curl (already have /tmp/agcookie.txt), then launch headless chrome
with the cookie pre-set, navigate to /admin/, click the GeoMap tab, capture
console messages + a screenshot.
"""
import json, os, ssl, subprocess, time, urllib.request, websocket

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
USERDIR = "/tmp/chrome-apigenie-test"
PORT = 9333

# 1. Read session cookie set by curl earlier.
cookie = None
for line in open("/tmp/agcookie.txt"):
    s = line.lstrip("#").strip()
    if "ag_session" in s:
        parts = s.split()
        cookie = parts[-1]
        break
print(f"cookie={cookie[:20]}…")
assert cookie

# 2. Launch chrome headless with remote debugging
subprocess.run(["pkill", "-f", "chrome-apigenie-test"], capture_output=True)
os.makedirs(USERDIR, exist_ok=True)
proc = subprocess.Popen([
    CHROME, "--headless=new", f"--remote-debugging-port={PORT}",
    f"--user-data-dir={USERDIR}", "--ignore-certificate-errors",
    "--disable-gpu", "--no-sandbox", "--window-size=1400,900",
    "--remote-allow-origins=*",
    "about:blank",
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)

# 3. Find the open tab's WebSocket URL
tabs = json.loads(urllib.request.urlopen(f"http://localhost:{PORT}/json").read())
ws_url = tabs[0]["webSocketDebuggerUrl"]
print(f"ws={ws_url[:60]}…")

ws = websocket.create_connection(ws_url, timeout=30)
msg_id = [0]
def send(method, params=None):
    msg_id[0] += 1
    ws.send(json.dumps({"id": msg_id[0], "method": method, "params": params or {}}))
    while True:
        m = json.loads(ws.recv())
        if m.get("id") == msg_id[0]:
            return m

console = []
def pump_until(method_pred, timeout=10):
    """Pump events until predicate or timeout."""
    end = time.time() + timeout
    while time.time() < end:
        ws.settimeout(max(0.1, end - time.time()))
        try:
            m = json.loads(ws.recv())
        except Exception:
            return None
        if "method" in m:
            if m["method"] in ("Runtime.consoleAPICalled", "Runtime.exceptionThrown",
                               "Log.entryAdded"):
                console.append(m)
            if method_pred(m):
                return m

send("Runtime.enable")
send("Network.enable")
send("Page.enable")
send("Log.enable")

# 4. Set the auth cookie BEFORE navigating
send("Network.setCookie", {
    "name": "ag_session", "value": cookie,
    "domain": "localhost", "path": "/", "secure": True,
})

# 5. Navigate to /admin/
send("Page.navigate", {"url": "https://localhost/admin/"})
pump_until(lambda m: m.get("method") == "Page.loadEventFired", timeout=15)
print("dashboard loaded")
time.sleep(1)

# 6. Click the GeoMap nav item — find by text content
res = send("Runtime.evaluate", {"expression": """
(function(){
  const items = [...document.querySelectorAll('.nav-item')];
  const geo = items.find(a => a.textContent.includes('GeoMap'));
  if (!geo) return 'NOT_FOUND';
  geo.click();
  return 'CLICKED';
})()
""", "returnByValue": True})
print("click result:", res.get("result", {}).get("result", {}).get("value"))

# 7. Wait for GeoMap loading and rendering — give async fetches time to complete
time.sleep(6)

# 8. Inspect the DOM state of #geomap
res = send("Runtime.evaluate", {"expression": """
(function(){
  const dom = document.getElementById('geomap');
  return JSON.stringify({
    geomap_html_len: dom ? dom.innerHTML.length : -1,
    geomap_html_first120: dom ? dom.innerHTML.slice(0,120) : null,
    geomap_w: dom ? dom.offsetWidth : -1,
    geomap_h: dom ? dom.offsetHeight : -1,
    has_canvas: dom ? !!dom.querySelector('canvas') : false,
    canvas_w: dom && dom.querySelector('canvas') ? dom.querySelector('canvas').width : -1,
    canvas_h: dom && dom.querySelector('canvas') ? dom.querySelector('canvas').height : -1,
    geomap_inited: !!window._geomap,
    map_registered: typeof echarts !== 'undefined' && !!echarts.getMap('world'),
    geo_meta: document.getElementById('geo-meta').textContent,
    sidebar_first_ip: document.querySelector('#geo-list .ip-row span')?.textContent || null,
  });
})()
""", "returnByValue": True})
print("\n=== DOM state ===")
print(res.get("result", {}).get("result", {}).get("value"))

# 9. Print captured console messages
print("\n=== console ===")
for m in console:
    method = m["method"]
    p = m["params"]
    if method == "Runtime.consoleAPICalled":
        text = " ".join(str(a.get("value", a.get("description", ""))) for a in p.get("args", []))
        print(f"[{p['type']}] {text}")
    elif method == "Runtime.exceptionThrown":
        print(f"[exception] {p.get('exceptionDetails',{}).get('text')} :: {p.get('exceptionDetails',{}).get('exception',{}).get('description','')}")
    elif method == "Log.entryAdded":
        e = p["entry"]
        if e["level"] in ("warning","error"):
            print(f"[log/{e['level']}] {e.get('text')}  src={e.get('url','')}:{e.get('lineNumber',0)}")

# 10. Screenshot
shot = send("Page.captureScreenshot", {"format": "png"})
import base64
open("/tmp/admin_geomap.png", "wb").write(base64.b64decode(shot["result"]["data"]))
print("\nscreenshot: /tmp/admin_geomap.png")

ws.close()
proc.terminate()
