"""Tests for the WEF per-binding authentication paths (v5.2).

Two mutually-exclusive auth methods on the binding config:

* ``client_cert`` — mTLS. ApiGenie presents a client cert + key from
  ``data/source_certs/wef/<binding_id>.pem.enc`` (decrypted on the fly).
  The httpx call must carry the ``cert=(certfile, keyfile)`` tuple.

* ``basic`` — TLS server-only + HTTP Basic. The Basic password is
  Fernet-encrypted (``basic_password_enc``) and decrypted only at
  request-build time. The httpx call carries the right
  ``Authorization: Basic <base64>`` header.

Switching ``auth_method`` clears the obsolete fields so we don't carry
stale secrets around.

Spec: docs/ROADMAP_2026-06-12.md §"Per-binding auth, selectable"
+ §"TDD plan" entry "test_wef_auth.py".
"""
from __future__ import annotations

import base64

import httpx
import pytest


# ── Helpers ────────────────────────────────────────────────────────────

def _capturing_client():
    captured: list[httpx.Request] = []
    sent_args: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(status_code=202)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return client, captured, sent_args


def _base_config() -> dict:
    return {
        "target_host": "wec.lab.example.com",
        "target_port": 5986,
        "target_path": "/wsman/SubscriptionManager/WEC",
        "tls_verify": True,
        "ca_bundle_path": None,
        "rate_per_min": 60,
        "batch_size": 1,
        "jitter_pct": 0,
        "channels_enabled": ["Security"],
    }


# ── Basic auth ─────────────────────────────────────────────────────────

def test_basic_auth_header_is_attached_correctly():
    from sources import windows_event_forwarding as wef
    from crypto import encrypt

    cfg = _base_config()
    cfg["auth_method"] = "basic"
    cfg["basic_username"] = "wec-svc"
    cfg["basic_password_enc"] = encrypt("s3cret!")

    client, captured, _ = _capturing_client()
    emitter = wef.WEFEmitter(cfg, http_client=client)
    emitter.push_batch(event_count=1)

    auth = captured[0].headers.get("authorization", "")
    assert auth.startswith("Basic "), f"Expected Basic auth header, got {auth!r}"
    decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
    assert decoded == "wec-svc:s3cret!", (
        f"Decoded credentials do not match: {decoded!r}"
    )


def test_basic_auth_with_missing_password_raises_configuration_error():
    from sources import windows_event_forwarding as wef

    cfg = _base_config()
    cfg["auth_method"] = "basic"
    cfg["basic_username"] = "wec-svc"
    cfg["basic_password_enc"] = None

    with pytest.raises(wef.BindingConfigError):
        wef.WEFEmitter(cfg)


# ── mTLS ───────────────────────────────────────────────────────────────

def test_mtls_attaches_cert_tuple(tmp_path, monkeypatch):
    """mTLS path resolves the per-binding cert + key paths from
    ``resolve_cert_files`` and passes them on the httpx request.

    We use ``monkeypatch`` to intercept ``resolve_cert_files`` so the
    test doesn't have to write real PEM material.
    """
    from sources import windows_event_forwarding as wef

    fake_cert = tmp_path / "client.crt"
    fake_key = tmp_path / "client.key"
    fake_cert.write_text("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n")
    fake_key.write_text("-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n")

    monkeypatch.setattr(
        wef, "resolve_cert_files",
        lambda binding_id, server_pem_fallback=None: (fake_cert, fake_key),
    )

    cfg = _base_config()
    cfg["auth_method"] = "client_cert"

    # Capture the kwargs the emitter passes to httpx so we can assert
    # the ``cert=`` tuple is correct without a real TLS handshake.
    seen_kwargs: dict = {}

    def fake_post(self, url, **kwargs):
        seen_kwargs["url"] = url
        seen_kwargs.update(kwargs)
        return httpx.Response(status_code=202, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.Client, "post", fake_post)

    emitter = wef.WEFEmitter(cfg, binding_id="b-001")
    emitter.push_batch(event_count=1)

    assert seen_kwargs.get("cert") == (str(fake_cert), str(fake_key)), (
        f"Expected cert tuple, got {seen_kwargs.get('cert')!r}"
    )
    # No Basic auth header when mTLS is the chosen method.
    headers = seen_kwargs.get("headers", {}) or {}
    assert "authorization" not in {k.lower() for k in headers}


def test_mtls_with_no_resolvable_cert_raises_configuration_error(monkeypatch):
    from sources import windows_event_forwarding as wef

    monkeypatch.setattr(
        wef, "resolve_cert_files",
        lambda binding_id, server_pem_fallback=None: None,
    )

    cfg = _base_config()
    cfg["auth_method"] = "client_cert"

    with pytest.raises(wef.BindingConfigError):
        # Either constructor or push_batch may raise; either is fine for
        # the contract. Use push_batch so the constructor can lazy-resolve.
        emitter = wef.WEFEmitter(cfg, binding_id="b-missing")
        emitter.push_batch(event_count=1)


# ── normalize_binding_config ──────────────────────────────────────────

def test_normalize_clears_basic_fields_when_method_is_client_cert():
    from sources import windows_event_forwarding as wef
    cfg = _base_config()
    cfg.update({
        "auth_method": "client_cert",
        "basic_username": "leftover",
        "basic_password_enc": "leftover-encrypted",
    })
    normalised = wef.normalize_binding_config(cfg)
    assert normalised["auth_method"] == "client_cert"
    assert normalised.get("basic_username") in (None, "")
    assert normalised.get("basic_password_enc") in (None, "")


def test_normalize_clears_cert_lookup_when_method_is_basic():
    """Switching from mTLS back to Basic must not carry forward a binding
    that still points at a cert bundle the operator just removed."""
    from sources import windows_event_forwarding as wef
    cfg = _base_config()
    cfg.update({
        "auth_method": "basic",
        "basic_username": "u",
        "basic_password_enc": "ciphertext",
        # legacy stale field a previous mTLS save left behind:
        "cert_uploaded": True,
    })
    normalised = wef.normalize_binding_config(cfg)
    assert normalised["auth_method"] == "basic"
    assert not normalised.get("cert_uploaded", False)


def test_validate_rejects_unknown_auth_method():
    from sources import windows_event_forwarding as wef
    cfg = _base_config()
    cfg["auth_method"] = "kerberos"  # explicitly out of scope per v5.2 spec
    errors = wef.validate_binding_config(cfg)
    assert errors, "Unknown auth_method must surface an error"
    assert any("auth_method" in err.lower() for err in errors)


def test_validate_rejects_basic_without_username():
    from sources import windows_event_forwarding as wef
    cfg = _base_config()
    cfg.update({
        "auth_method": "basic",
        "basic_username": "",
        "basic_password_enc": "x",
    })
    errors = wef.validate_binding_config(cfg)
    assert any("username" in e.lower() for e in errors)
