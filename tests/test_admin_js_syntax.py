"""Smoke test: every <script> block on the rendered admin user-portal HTML
must parse cleanly under ``node --check``.

Background
----------
admin.py embeds JavaScript inside a Python triple-quoted HTML string. That
combination has bitten us repeatedly:

* Backtick template literals containing literal newlines silently become
  multi-line breaks in the rendered file, killing the parser.
* Escaped single quotes inside single-quoted JS strings produced by Python
  concatenation render as literal apostrophes and break the JS parser.

A static lint of admin.py can't catch these because the JS only exists in
its final, rendered form. So we render the page and shell out to Node.

The test self-skips if Node isn't on PATH (CI / minimal envs).
"""
from __future__ import annotations

import re
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def admin_html(make_user) -> str:
    """Render the authenticated user-portal HTML (which contains every JS
    block including the new Alert Push handlers)."""
    from app import app
    make_user("jschecker")
    c = TestClient(app)
    r = c.post("/portal/login",
               data={"username": "jschecker", "password": "testpassw0rd"},
               follow_redirects=False)
    assert r.status_code in (200, 303), r.text
    r = c.get("/portal/")
    assert r.status_code == 200, r.status_code
    return r.text


def test_every_script_block_parses(admin_html):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available; cannot validate embedded JS")

    blocks = re.findall(r"<script[^>]*>(.*?)</script>",
                        admin_html, flags=re.DOTALL)
    assert blocks, "expected at least one <script> block in the admin HTML"

    failures: list[tuple[int, str]] = []
    for idx, body in enumerate(blocks):
        if not body.strip():
            continue
        # Skip blocks that look like JSON or import maps — those aren't JS programs.
        attrs_at = admin_html.find(body)
        if attrs_at > 0:
            tag_open = admin_html.rfind("<script", 0, attrs_at)
            tag_attrs = admin_html[tag_open:attrs_at]
            if 'type="application/json"' in tag_attrs or 'type="importmap"' in tag_attrs:
                continue
        p = subprocess.run([node, "--check", "-"],
                           input=body, capture_output=True, text=True)
        if p.returncode != 0:
            failures.append((idx, p.stderr.strip()[:600]))

    if failures:
        msg = "Embedded JS failed node --check:\n" + "\n\n".join(
            f"  block #{i}: {err}" for i, err in failures
        )
        pytest.fail(msg)


def test_alert_push_ui_anchors_present(admin_html):
    """The Alert Push feature needs three coordinated pieces of UI to be wired
    end-to-end: a sidebar nav link, a tab pane, and the editor + custom-send
    modals. If any of them goes missing the feature becomes unreachable even
    though every backend test still passes (this is exactly what happened
    during the P4.3d UI port). Guard against that class of regression.
    """
    required = [
        # Sidebar nav link
        ("nav link", "showTab('alert-push', this); loadAlertProfiles()"),
        # Tab pane root
        ("tab pane", 'id="pane-alert-push"'),
        # Editor modal root
        ("editor modal", 'id="alert-modal"'),
        # Custom-alert send modal root
        ("custom modal", 'id="alert-custom-modal"'),
        # Template preview modal root
        ("template preview modal", 'id="alert-tpl-modal"'),
        # The 3 override sub-tabs the editor modal exposes
        ("identity override pane", 'data-ovr-pane="identity"'),
        ("resources override pane", 'data-ovr-pane="resources"'),
        ("custom override pane", 'data-ovr-pane="custom"'),
        # P4.6 XDR asset linkage checkbox
        ("link-xdr-assets checkbox", 'id="alert-link-xdr-assets"'),
    ]
    missing = [label for label, needle in required if needle not in admin_html]
    assert not missing, (
        "Alert Push UI is incomplete — these anchors are missing from the "
        f"rendered user portal HTML: {missing}"
    )
