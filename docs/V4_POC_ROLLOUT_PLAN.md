# v4.0 POC Rollout Plan

**Status:** Active — POC validation by 5 testers required before production cutover.
**Production:** `https://apigenie.roarinpenguin.com` — must remain on v3.1.0 codebase.
**POC:** `https://apigenie-poc.roarinpenguin.com` (or similar) — new host, runs v4.0.

This document captures the git workflow that keeps the two lines isolated until the cutover is explicitly approved. It is the reference for the duration of the POC window and stays in the repo afterwards as institutional memory.

---

## The shape

```
origin (GitHub)
├── main                    ← v4.0 work eventually lands here (and POC tracks it)
├── release/v3.x            ← long-lived prod maintenance line, pinned at the pre-RBAC commit
├── feat/v4.0-multi-user    ← where v4.0 lives until the POC validates it
└── tags
    ├── v3.1.0              ← last pre-RBAC commit (the one prod runs today)
    └── v4.0.0              ← stamped only when POC validation passes
```

Two physical servers, two distinct domains, two distinct `./data` volumes, two distinct certs. **Never share a data volume between v3 and v4** — v4.0 mutates the schema (adds `apigenie.db` + `avatars/`).

---

## Step 1 — Snapshot today's prod, before any commit

```bash
# from your laptop, in the apigenie working tree
git status                                # confirm v4.0 work is still uncommitted
git tag -a v3.1.0 c8962d9 -m "Last pre-RBAC release (Mimecast 1.0)"
git branch release/v3.x c8962d9           # branch from current main HEAD
git push origin v3.1.0
git push origin release/v3.x
# Optional but recommended: protect both on GitHub so nobody force-pushes them.
```

That single `c8962d9` commit is now reachable two ways (`v3.1.0` tag + `release/v3.x` branch) — belt and braces.

---

## Step 2 — Move the v4.0 work onto its own branch

```bash
# still on your laptop, working tree dirty with the v4.0 changes
git checkout -b feat/v4.0-multi-user
git add -A
git commit -m "v4.0: Multi-User Edition — RBAC (Phases 1–3.5), per-user S1, self-service, Mimecast, AWS Terraform, 91 tests"
git push -u origin feat/v4.0-multi-user
```

After this push:
- `origin/main` still points at `c8962d9` — unchanged, prod-safe.
- `origin/feat/v4.0-multi-user` has the v4.0 work.

---

## Step 3 — Pin production explicitly to `release/v3.x` (one-time)

SSH to `apigenie.roarinpenguin.com`, in the apigenie checkout:

```bash
git fetch --tags origin
git checkout release/v3.x
git branch --set-upstream-to=origin/release/v3.x release/v3.x
git config --add branch.release/v3.x.mergeOptions --ff-only   # refuse rebases
git pull                                                       # no-op; sanity check
```

From now on, `git pull` on prod can **only** advance `release/v3.x`. There is no way it accidentally lands the v4.0 work — `main` could fast-forward to v4.0 tomorrow and prod wouldn't know.

---

## Step 4 — Stand up the POC site

On a **separate** host (sibling EC2 / VM):

```bash
git clone https://github.com/roarinpenguin/apigenie.git
cd apigenie
git checkout feat/v4.0-multi-user
./scripts/bootstrap.sh
#   ← Pick a NEW domain, e.g. apigenie-poc.roarinpenguin.com (DNS A record must
#     already point at this new host's IP). Pick "letsencrypt" mode so the POC
#     gets its own valid cert with no clash against prod.
#   ← Use a fresh ./data directory. The Compose file mounts it as a named
#     volume; nothing from prod ever touches this host.
docker compose up -d --build
```

The 5 testers each:

1. Log into `https://apigenie-poc.roarinpenguin.com/portal/set-password?token=…` using a link you mint via `POST /admin/api/rbac/users/{uid}/reset-link`.
2. Register their per-user source identifiers under **Source Identifiers**.
3. Point their collectors at the POC domain with their personal tokens.

Production keeps humming at `apigenie.roarinpenguin.com` on the v3.1.0 codebase.

---

## Step 5 — Hotfixes during the POC window

If something needs fixing on **prod** (say a Mimecast tweak), do it on `release/v3.x`:

```bash
git checkout release/v3.x
# … edit, commit …
git push origin release/v3.x
```

Then on the prod host: `git pull && docker compose up -d --build`.

Don't forget to **cherry-pick the same fix forward** so the POC stays current:

```bash
git checkout feat/v4.0-multi-user
git cherry-pick <hotfix-sha>
git push
```

Conversely, fixes you make to the v4.0 branch during POC validation **should not** flow back to `release/v3.x` automatically — only cherry-pick the bits that apply.

---

## Step 6 — When the POC wins (the cutover)

Once the 5 testers are happy:

```bash
# from your laptop
git checkout main
git merge --ff-only feat/v4.0-multi-user      # fast-forward only; refuses if main moved
git tag -a v4.0.0 -m "ApiGenie 4.0 — The Multi-User Edition"
git push origin main --follow-tags
```

Now opt prod in *deliberately* (no surprise pulls):

```bash
# on apigenie.roarinpenguin.com
docker compose down                            # graceful stop
tar czf /backup/apigenie-data-v3-$(date +%F).tgz /var/lib/docker/volumes/apigenie_data
git fetch --tags origin
git checkout main                              # leave release/v3.x — keep it as escape hatch
git pull
docker compose up -d --build
docker exec apigenie python -m pytest tests/ -v   # smoke
```

If anything goes wrong:

```bash
docker compose down
git checkout release/v3.x                      # or: git checkout v3.1.0 (detached, safest)
# restore the data tarball you took in the step above
docker compose up -d --build
```

`release/v3.x` lives forever — never delete it. You always have a one-command rollback to a pre-RBAC universe.

---

## Step 7 — After the cutover

- `feat/v4.0-multi-user` can be deleted (`git branch -d` locally, `git push origin --delete` on the remote) — its history is now in `main`.
- New work continues on `main`, normal flow.
- `release/v3.x` stays around for emergency rollback and any genuinely-needed long-tail v3 hotfixes (unlikely, but cheap to keep).

---

## Two things to *not* do

1. **Do not tag `v4.0.0` before the POC validation.** The version is currently bumped in `pyproject.toml` to `4.0.0` for the POC to identify itself; the git tag is only applied at Step 6 (cutover). If preferred, the `pyproject.toml` can be temporarily set to `4.0.0-rc1` during the POC window.
2. **Do not share `./data` between prod and POC.** v4.0 adds `apigenie.db`, `avatars/`, and per-user S1 settings; v3.x doesn't know about them. Use separate hosts (or at minimum separate Docker named volumes on the same host) to eliminate any chance of `docker compose down -v` hitting the wrong stack.

---

## Status checklist

Track progress here as steps are executed.

- [ ] Step 1 — `v3.1.0` tag + `release/v3.x` branch pushed to origin
- [ ] Step 2 — v4.0 work committed to `feat/v4.0-multi-user`, pushed to origin
- [ ] Step 3 — Production pinned to `release/v3.x` on `apigenie.roarinpenguin.com`
- [ ] Step 4 — POC host provisioned and bootstrapped on `apigenie-poc.roarinpenguin.com`
- [ ] Step 4 — 5 testers onboarded with handoff links
- [ ] **Step 5 — POC validation period (≥ 2 weeks of real usage)**
- [ ] Step 6 — v4.0 merged into `main`, `v4.0.0` tag stamped, prod cutover executed
- [ ] Step 7 — `feat/v4.0-multi-user` branch deleted; `release/v3.x` retained as rollback line
