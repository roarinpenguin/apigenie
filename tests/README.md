# apigenie tests

Lightweight pytest suite. **All storage is redirected to a per-test tmp dir
by `conftest.py` before any project module is imported**, so tests never touch
the production `/var/lib/apigenie` volume.

## Running

The host Python is 3.9, the project targets 3.12, so the simplest is to run
inside the running container:

```bash
docker exec apigenie pip install --quiet pytest pytest-asyncio   # one-time
docker exec apigenie python -m pytest tests/ -v
```

To make pytest a permanent part of the image, add `pytest pytest-asyncio` to
the `Dockerfile` install step (currently only runtime deps are installed).

## Layout

- `conftest.py` — env redirection + `_isolated_state` autouse fixture (fresh
  SQLite DB and JSON tree per test) + `make_user` helper.
- `test_rbac_phase2.py` — backfill coverage for Phase 2.2 / 2.3 / 2.4:
  identifier registration & matching, reserved-credential guard, user-portal
  masking, identifier-kinds-per-source, `_session_identity` acting-as.
- `test_rbac_phase2_5_detection.py` — per-user detection-rule injection
  scoping (the rules a caller sees mirror `admin._can_see_obj`).

## Conventions

- New behaviour is added test-first when reasonable.
- Tests must not depend on each other; the autouse fixture wipes state.
- Avoid `time.sleep` and randomness assertions; prefer testing visibility/
  inclusion rather than exact counts where injection uses `random`.
