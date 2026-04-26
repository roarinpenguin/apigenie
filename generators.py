"""Common data generation utilities for all mock sources."""

import random
import secrets
import string
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any


def generate_uuid() -> str:
    return str(uuid.uuid4())


def generate_uuid_hex() -> str:
    return uuid.uuid4().hex


def generate_ip() -> str:
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_email(domain: str = "example.com") -> str:
    username = "".join(random.choices(string.ascii_lowercase, k=8))
    return f"{username}@{domain}"


def generate_hostname() -> str:
    prefix = random.choice(["web", "api", "app", "srv", "host", "node"])
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    domain = random.choice(["example.com", "test.local", "internal.net"])
    return f"{prefix}-{suffix}.{domain}"


def generate_country_code() -> str:
    return random.choice(["US", "GB", "DE", "FR", "JP", "AU", "CA", "IN", "BR", "CN", "RU", "KR"])


def random_timestamp_between(start_time: datetime, end_time: datetime) -> datetime:
    delta = end_time - start_time
    random_seconds = random.random() * delta.total_seconds()
    return start_time + timedelta(seconds=random_seconds)


def random_iso_timestamp(start_time: datetime, end_time: datetime) -> str:
    return random_timestamp_between(start_time, end_time).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def weighted_choice(items: dict[str, tuple[Any, float]]) -> Any:
    r = random.random()
    cumulative = 0.0
    for _key, (item, weight) in items.items():
        cumulative += weight
        if r < cumulative:
            return item
    return list(items.values())[-1][0]


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def now_minus_minutes_iso(minutes: int) -> str:
    dt = datetime.now(UTC) - timedelta(minutes=minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def now_epoch() -> int:
    return int(datetime.now(UTC).timestamp())


def now_minus_minutes_epoch(minutes: int) -> int:
    dt = datetime.now(UTC) - timedelta(minutes=minutes)
    return int(dt.timestamp())


def now_epoch_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def epoch_to_iso(ts: int | float) -> str:
    """Convert a Unix epoch (seconds, possibly fractional) to ISO 8601 with +00:00.

    Output shape matches what Cisco Duo, Okta and most real APIs return,
    e.g. '2026-04-26T13:34:05.123456+00:00'. This is what Observo's Lua
    `iso8601_to_epoch_ms` helper expects — passing a bare epoch int causes
    a nil-deref on the `.frac` field.
    """
    return datetime.fromtimestamp(float(ts), UTC).isoformat(timespec="microseconds")


def now_minus_minutes_epoch_ms(minutes: int) -> int:
    dt = datetime.now(UTC) - timedelta(minutes=minutes)
    return int(dt.timestamp() * 1000)


def generate_token(length: int = 32) -> str:
    return secrets.token_hex(length)


def get_time_range(
    start_time: int | str | None = None,
    end_time: int | str | None = None,
    default_range_minutes: int = 120,
) -> tuple[datetime, datetime]:
    now = datetime.now(UTC)

    if end_time is None:
        end_dt = now
    elif isinstance(end_time, int):
        end_dt = datetime.fromtimestamp(end_time, tz=UTC)
    else:
        end_dt = datetime.fromisoformat(str(end_time).replace("Z", "+00:00"))

    if start_time is None:
        start_dt = end_dt - timedelta(minutes=default_range_minutes)
    elif isinstance(start_time, int):
        start_dt = datetime.fromtimestamp(start_time, tz=UTC)
    else:
        start_dt = datetime.fromisoformat(str(start_time).replace("Z", "+00:00"))

    return start_dt, end_dt
