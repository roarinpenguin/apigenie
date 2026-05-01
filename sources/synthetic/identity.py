"""Identity telemetry — auth / SSO / IAM events.

Loosely modelled on Okta System Log + Azure AD sign-ins. A Lua collector
parsing Okta's `/api/v1/logs` shape would feel right at home with this output.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

from sources.synthetic import seeded_uuid

_USERS = [
    "alice.smith@acme.com", "bob.jones@acme.com", "charlie.davis@acme.com",
    "diana.evans@acme.com", "evan.foster@acme.com", "frank.green@acme.com",
    "grace.hill@acme.com", "henry.ito@acme.com",
]
_APPS = [
    "Okta Dashboard", "Microsoft 365", "Salesforce", "GitHub Enterprise",
    "AWS Console", "Slack", "Zoom", "Workday", "ServiceNow", "Jira Cloud",
]
_FACTORS = ["push", "totp", "webauthn", "sms", "voice", "password_only"]
_OUTCOMES = [("SUCCESS", 0.85), ("FAILURE", 0.10), ("CHALLENGE", 0.05)]
_EVENTS = [
    ("user.session.start",        0.55),
    ("user.authentication.auth_via_mfa", 0.18),
    ("user.session.end",          0.10),
    ("user.account.lock",         0.04),
    ("user.account.unlock",       0.03),
    ("user.mfa.factor.activate",  0.03),
    ("group.user_membership.add", 0.03),
    ("application.user_membership.add", 0.02),
    ("policy.rule.update",        0.01),
    ("user.account.privilege.grant", 0.01),
]

_GEOS = [
    ("US", "United States", "California", "San Francisco", 37.77, -122.42),
    ("US", "United States", "New York",   "New York",      40.71, -74.00),
    ("GB", "United Kingdom","England",    "London",        51.50, -0.12),
    ("DE", "Germany",       "Berlin",     "Berlin",        52.52, 13.40),
    ("FR", "France",        "Île-de-France","Paris",       48.85, 2.35),
    ("JP", "Japan",         "Tokyo",      "Tokyo",         35.68, 139.69),
    ("AU", "Australia",     "NSW",        "Sydney",        -33.86,151.21),
    ("BR", "Brazil",        "São Paulo",  "São Paulo",     -23.55,-46.63),
    ("RU", "Russia",        "Moscow",     "Moscow",        55.75, 37.61),
    ("CN", "China",         "Beijing",    "Beijing",       39.90, 116.40),
]


def _weighted(rng: random.Random, items: list[tuple[str, float]]) -> str:
    r = rng.random()
    cum = 0.0
    for v, w in items:
        cum += w
        if r < cum:
            return v
    return items[-1][0]


def generate(n: int, seed: int | None = None) -> list[dict]:
    rng = random.Random(seed) if seed is not None else random.Random()
    now = datetime.now(timezone.utc)
    out: list[dict] = []
    for _ in range(max(0, n)):
        ts = now - timedelta(seconds=rng.randint(0, 1800))
        actor = rng.choice(_USERS)
        evt = _weighted(rng, _EVENTS)
        outcome = _weighted(rng, _OUTCOMES)
        country, country_name, region, city, lat, lon = rng.choice(_GEOS)
        ip = f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
        rec = {
            "uuid":      str(seeded_uuid(rng)),
            "published": ts.isoformat(timespec="milliseconds"),
            "eventType": evt,
            "displayMessage": evt.replace(".", " ").replace("_", " ").title(),
            "actor":     {"id": uuid.uuid5(uuid.NAMESPACE_DNS, actor).hex[:24],
                           "type": "User", "alternateId": actor, "displayName": actor.split("@")[0]},
            "outcome":   {"result": outcome, "reason": (
                "Verification succeeded" if outcome == "SUCCESS"
                else "Invalid credentials" if outcome == "FAILURE"
                else "MFA challenge issued"
            )},
            "authenticationContext": {
                "authenticationProvider": "FACTOR_PROVIDER",
                "credentialType":         "OTP" if rng.random() < 0.4 else "PASSWORD",
                "factor":                 rng.choice(_FACTORS),
            },
            "client": {
                "userAgent": {"rawUserAgent":
                    rng.choice([
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15",
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                        "okta-cli/2.5.0",
                    ])},
                "ipAddress": ip,
                "geographicalContext": {
                    "country": country_name, "country_code": country,
                    "state":   region, "city": city,
                    "geolocation": {"lat": lat, "lon": lon},
                },
            },
            "target": [{
                "id":          seeded_uuid(rng).hex[:24],
                "type":        "AppInstance",
                "displayName": rng.choice(_APPS),
            }],
        }
        out.append(rec)
    return out
