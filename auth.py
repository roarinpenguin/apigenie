"""Authentication middleware for all mock source endpoints."""

import hashlib
import hmac
import time
from base64 import b64decode
from email.utils import formatdate
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

VALID_TOKENS = frozenset(
    {
        "apigenie-valid-token-001",
        "apigenie-valid-token-002",
        "apigenie-valid-token-003",
        "imaas-valid-token-001",
        "imaas-valid-token-002",
        "imaas-valid-token-003",
        "imaas-valid-token-004",
        "imaas-valid-token-005",
    }
)

VALID_BASIC_AUTH = frozenset(
    {
        ("apigenie-principal-001", "apigenie-secret-001"),
        ("apigenie-principal-002", "apigenie-secret-002"),
        ("imaas-principal-001", "imaas-secret-001"),
        ("imaas-principal-002", "imaas-secret-002"),
        ("test-principal", "test-secret"),
    }
)

VALID_API_KEYS = frozenset(
    {
        "accessKey=VALIDACCESSKEY001&secretKey=VALIDSECRETKEY001",
        "accessKey=apigenie-ak-001&secretKey=apigenie-sk-001",
    }
)

# Duo HMAC signing key for mock (real Duo uses integration key + secret key)
DUO_IKEY = "DIXXXXXXXXXXXXXXXXXX"
DUO_SKEY = "duo-mock-secret-key-for-testing"

ERROR_RESPONSES: dict[str, tuple[int, dict]] = {
    "apigenie-error-401": (401, {"error": "unauthorized", "message": "Invalid or missing authentication token"}),
    "apigenie-error-403": (403, {"error": "forbidden", "message": "Access denied"}),
    "apigenie-error-404": (404, {"error": "not_found", "message": "Resource not found"}),
    "apigenie-error-429": (429, {"error": "rate_limited", "message": "Too many requests"}),
    "apigenie-error-500": (500, {"error": "internal_error", "message": "Internal server error"}),
}


def _extract_bearer(authorization: str | None) -> str | None:
    """Extract a bearer token, tolerating common collector quirks:
    - Standard "Bearer <token>" (RFC 6750)
    - Missing space: "Bearer<token>"
    - Case variants: "bearer", "BEARER", "sswsXXX"
    - Okta-style "SSWS <token>" / "token=<token>"
    - Bare token with no prefix at all
    Surrounding whitespace is trimmed.
    """
    if not authorization:
        return None
    auth = authorization.strip()
    lower = auth.lower()
    for prefix in ("bearer", "ssws"):
        if lower.startswith(prefix):
            rest = auth[len(prefix):].lstrip()  # tolerate missing or extra spaces
            return rest or None
    if lower.startswith("token="):
        return auth[len("token="):].strip() or None
    # Bare token (no scheme) — accept as-is so downstream validation can decide.
    return auth or None


def _check_error_token(token: str) -> None:
    for error_token, (status, body) in ERROR_RESPONSES.items():
        if token == error_token:
            raise HTTPException(status_code=status, detail=body)


async def require_bearer_auth(authorization: Annotated[str | None, Header()] = None) -> None:
    token = _extract_bearer(authorization)
    if not token:
        raise HTTPException(status_code=401, detail={"error": "unauthorized", "message": "Missing Bearer token"})
    _check_error_token(token)
    if token not in VALID_TOKENS:
        raise HTTPException(status_code=401, detail={"error": "unauthorized", "message": "Invalid token"})


async def require_basic_auth(authorization: Annotated[str | None, Header()] = None) -> None:
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(status_code=401, detail={"error": "unauthorized", "message": "Basic auth required"})
    try:
        decoded = b64decode(authorization[6:]).decode("utf-8")
        username, _, password = decoded.partition(":")
    except Exception:
        raise HTTPException(status_code=401, detail={"error": "unauthorized", "message": "Invalid Basic auth"})
    if (username, password) not in VALID_BASIC_AUTH:
        raise HTTPException(status_code=401, detail={"error": "unauthorized", "message": "Invalid credentials"})


async def require_x_api_keys(
    x_apikeys: Annotated[str | None, Header(alias="X-ApiKeys")] = None,
) -> None:
    if not x_apikeys:
        raise HTTPException(status_code=401, detail={"error": "unauthorized", "message": "X-ApiKeys header required"})
    _check_error_token(x_apikeys)
    if x_apikeys not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail={"error": "unauthorized", "message": "Invalid API keys"})


async def require_duo_auth(request: Request) -> None:
    """Mock Duo authentication.

    Real Duo uses HMAC-SHA1 signing of canonical request strings, but this is
    a mock service intended for collector integration testing. We accept any
    well-formed Basic auth header so collectors can use whatever ikey/skey pair
    they have configured in their secrets manager. The presence of *some*
    credential is required so we still exercise the auth code path.
    """
    authorization = request.headers.get("Authorization", "")
    if not authorization.lower().startswith("basic "):
        raise HTTPException(status_code=401, detail={"stat": "FAIL", "message": "Missing Basic auth"})

    try:
        decoded = b64decode(authorization[6:]).decode("utf-8")
        ikey, _, sig = decoded.partition(":")
    except Exception:
        raise HTTPException(status_code=401, detail={"stat": "FAIL", "message": "Invalid auth header"})

    if not ikey:
        raise HTTPException(status_code=401, detail={"stat": "FAIL", "message": "Empty integration key"})
    # Any non-empty ikey is accepted for the mock.
    return


BearerAuth = Annotated[None, Depends(require_bearer_auth)]
BasicAuth = Annotated[None, Depends(require_basic_auth)]
XApiKeysAuth = Annotated[None, Depends(require_x_api_keys)]
DuoAuth = Annotated[None, Depends(require_duo_auth)]
