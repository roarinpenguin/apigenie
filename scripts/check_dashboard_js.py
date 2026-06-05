#!/usr/bin/env python3
"""Render the user/admin dashboards and pipe the inline <script> body through
node's parser to catch JS syntax errors before they reach the browser.

Triggered by the long-standing rule: every admin.py edit that touches inline
JS MUST be node-compile-checked, because Python triple-quoted strings have
broken the live page three separate times.
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
import tempfile

# Redirect storage paths before importing admin.py so we don't write to /var.
_TMP = pathlib.Path(tempfile.mkdtemp(prefix="apigenie-jscheck-"))
for k in ("APIGENIE_DATA_DIR", "APIGENIE_DATA", "APIGENIE_DATA_ROOT"):
    os.environ.setdefault(k, str(_TMP))
os.environ.setdefault("APIGENIE_DB", str(_TMP / "apigenie.db"))
os.environ.setdefault("ADMIN_PASSWORD_FILE", str(_TMP / "admin_pass"))
os.environ.setdefault("USER_PASSWORD_FILE", str(_TMP / "user_pass"))

# Project root on path.
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import admin  # noqa: E402

NODE = os.environ.get("NODE_BIN", "/opt/homebrew/bin/node")

def _extract_scripts(html: str) -> list[str]:
    """All inline <script>…</script> bodies (skip src-only)."""
    out = []
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
        attrs, body = m.group(1), m.group(2)
        if "src=" in attrs.lower():
            continue
        if body.strip():
            out.append(body)
    return out


def _check(role: str) -> int:
    html = admin._render_dashboard(role)
    scripts = _extract_scripts(html)
    if not scripts:
        print(f"[{role}] no inline scripts found — suspicious")
        return 1
    bad = 0
    for i, src in enumerate(scripts):
        # node --check expects a file; --syntax-check only on input
        proc = subprocess.run(
            [NODE, "--check", "-e", src],
            capture_output=True, text=True
        )
        # node --check with -e isn't supported on every node version; fall back
        # to writing a temp file.
        if proc.returncode != 0 and "Unknown" in (proc.stderr or ""):
            tmp = _TMP / f"{role}_script_{i}.js"
            tmp.write_text(src, encoding="utf-8")
            proc = subprocess.run(
                [NODE, "--check", str(tmp)], capture_output=True, text=True)
        if proc.returncode != 0:
            bad += 1
            print(f"[{role}] script #{i} FAILED:")
            print((proc.stderr or proc.stdout or "")[:2000])
        else:
            print(f"[{role}] script #{i} OK ({len(src):,} bytes)")
    return bad


def _dump_only(out_dir: pathlib.Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    total = 0
    for role in ("user", "admin"):
        html = admin._render_dashboard(role)
        (out_dir / f"{role}_dashboard.html").write_text(html, encoding="utf-8")
        for i, src in enumerate(_extract_scripts(html)):
            (out_dir / f"{role}_script_{i}.js").write_text(src, encoding="utf-8")
            total += 1
    print(f"wrote {total} script files to {out_dir}")
    return 0


def main() -> int:
    # Dump-only mode (for environments without node, e.g. inside the container)
    if "--dump" in sys.argv:
        idx = sys.argv.index("--dump")
        out = pathlib.Path(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else _TMP
        return _dump_only(out)
    rc = 0
    for role in ("user", "admin"):
        rc += _check(role)
    if rc:
        print(f"\n❌ {rc} script(s) failed parse")
        return 1
    print("\n✅ all inline scripts parse cleanly under node")
    return 0


if __name__ == "__main__":
    sys.exit(main())
