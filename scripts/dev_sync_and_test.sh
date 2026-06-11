#!/usr/bin/env bash
# Dev-loop helper for the OTLP egress work.
#
# Copies the modified / new Python files into the running apigenie
# container, restarts it, and runs the full pytest suite. Lives in
# scripts/ so it's tracked, and exits non-zero on any failure so we can
# tell green from red at a glance.
#
# Usage:
#   bash scripts/dev_sync_and_test.sh                 # full regression
#   bash scripts/dev_sync_and_test.sh tests/test_otel_pusher.py
#                                                      # narrow run
#
# Designed to be runnable WITHOUT special-character escaping pitfalls.
# Plain single-line invocation, no multi-line continuations to mangle.

set -euo pipefail

C=apigenie

echo "[1/3] copying source files into the container..."
# OTLP work (v4.1)
docker cp admin.py                                 "$C":/app/admin.py
docker cp log_pusher.py                            "$C":/app/log_pusher.py
docker cp otlp_pusher.py                           "$C":/app/otlp_pusher.py
docker cp push_sources/__init__.py                 "$C":/app/push_sources/__init__.py
docker cp push_sources/synthetic_endpoint.py       "$C":/app/push_sources/synthetic_endpoint.py
docker cp push_sources/synthetic_identity.py       "$C":/app/push_sources/synthetic_identity.py
docker cp push_sources/synthetic_cloud.py          "$C":/app/push_sources/synthetic_cloud.py
docker cp push_sources/synthetic_network.py        "$C":/app/push_sources/synthetic_network.py
docker cp push_sources/replay_file.py              "$C":/app/push_sources/replay_file.py
docker cp tests/test_otel_pusher.py                "$C":/app/tests/test_otel_pusher.py
docker cp scripts/smoke_otlp_egress.py             "$C":/app/scripts/smoke_otlp_egress.py
# Webhooks (v5.0 Phase 6)
docker cp accounts.py                              "$C":/app/accounts.py
docker cp webhooks.py                              "$C":/app/webhooks.py
docker cp tests/conftest.py                        "$C":/app/tests/conftest.py
docker cp tests/test_webhooks.py                   "$C":/app/tests/test_webhooks.py
# Attack Scenarios Phase 2 + 3.1 + 3.2 — builder, import/export, events, cross-source search
docker cp attack_scenarios.py                      "$C":/app/attack_scenarios.py
docker cp attack_scenarios_library.py              "$C":/app/attack_scenarios_library.py
docker cp detection_rules.py                       "$C":/app/detection_rules.py
docker cp trace.py                                 "$C":/app/trace.py
docker cp tests/test_attack_scenarios.py           "$C":/app/tests/test_attack_scenarios.py
docker cp tests/test_phase32_attack_search.py      "$C":/app/tests/test_phase32_attack_search.py
docker cp tests/test_phase33_timeline.py           "$C":/app/tests/test_phase33_timeline.py
# Event Mix admin surface (v5.0 — completes v4.1 Phase 5)
docker cp event_mix.py                             "$C":/app/event_mix.py
docker cp sources/__init__.py                      "$C":/app/sources/__init__.py
docker cp tests/test_event_mix_admin.py            "$C":/app/tests/test_event_mix_admin.py
# Event Mix per-source rollout (v5.0)
docker cp sources/okta.py                          "$C":/app/sources/okta.py
docker cp sources/proofpoint.py                    "$C":/app/sources/proofpoint.py
docker cp sources/aws_cloudtrail.py                "$C":/app/sources/aws_cloudtrail.py
docker cp sources/aws_guardduty.py                 "$C":/app/sources/aws_guardduty.py
docker cp sources/aws_waf.py                       "$C":/app/sources/aws_waf.py
docker cp sources/azure_ad.py                      "$C":/app/sources/azure_ad.py
docker cp sources/microsoft_defender.py            "$C":/app/sources/microsoft_defender.py
docker cp tests/test_event_mix_sources.py          "$C":/app/tests/test_event_mix_sources.py

echo "[2/3] restarting container..."
docker restart "$C" > /dev/null
sleep 5

echo "[3/3] running pytest..."
if [[ $# -gt 0 ]]; then
  docker exec "$C" python -m pytest -q --no-header "$@"
else
  docker exec "$C" python -m pytest -q --no-header
fi
