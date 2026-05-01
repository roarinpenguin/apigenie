"""Synthetic telemetry generators for the Custom Listeners feature.

Each topic module exposes a single function::

    generate(n: int, seed: int | None = None) -> list[dict]

The generators are pure: no global state, no FastAPI imports, and a fixed
``seed`` produces a deterministic record set so tests can assert exact
shapes. Used only by ``listeners.build_response``.

Topics
------
* endpoint  — EDR / process telemetry (host events)
* identity  — auth / SSO / IAM events
* cloud     — multi-cloud audit events (AWS / Azure / GCP)
* network   — Zeek-style flow + protocol events
"""

import random as _random
import uuid as _uuid


def seeded_uuid(rng: _random.Random) -> _uuid.UUID:
    """Return a v4-shaped UUID drawn from ``rng`` so the same seed produces the
    same UUID sequence. ``uuid.uuid4()`` reads ``os.urandom`` directly and
    therefore ignores the seeded RNG; this helper closes that gap."""
    return _uuid.UUID(int=rng.getrandbits(128), version=4)


from sources.synthetic import endpoint, identity, cloud, network

TOPICS = {
    "endpoint": endpoint.generate,
    "identity": identity.generate,
    "cloud":    cloud.generate,
    "network":  network.generate,
}

__all__ = ["TOPICS", "endpoint", "identity", "cloud", "network"]
