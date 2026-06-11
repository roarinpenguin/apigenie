"""OTLP/gRPC push-sink server (port 4317).

The HTTP half of the push-sink listener kind lives in ``app.py``'s
``listener_dispatch``. This module hosts the **gRPC** half: a single
``grpc.aio.Server`` that listens on port ``4317`` inside the apigenie
container and implements the OTLP Logs / Metrics / Trace ``Export``
RPCs. nginx terminates TLS in front of us on ``4317`` (see
``nginx/nginx.conf.template``) — the server here speaks plaintext h2c on
the docker network only.

Design: docs/OTEL_LISTENER.md §5 (gRPC) + §10 (security).

Routing rule (matches multi-tenancy patterns used by Grafana
Loki/Mimir/Tempo, Datadog, Splunk OTel Collector):

  1. metadata ``x-apigenie-listener-id`` → that listener id, must have a
     push_sink with the matching ``signal``.
  2. metadata ``x-scope-orgid`` (Grafana convention) → same as above.
  3. metadata ``authorization`` with bearer token → unique push_sink
     listener whose ``auth.kind == "bearer"`` and ``auth.token`` matches.
  4. If exactly one push_sink listener exists for the signal → route there
     (development convenience; logged at WARN).
  5. Otherwise → ``grpc.StatusCode.NOT_FOUND`` / ``no_listener_matches``.

After resolution, ``check_auth()`` from ``listeners.py`` runs to enforce
the listener's declared auth requirement. The resulting ``identity`` is
recorded with the hit.
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time as _time
from datetime import datetime as _dt, timezone as _tz
from typing import Any

logger = logging.getLogger(__name__)

# ── Configuration ───────────────────────────────────────────────────────────
GRPC_PORT = int(os.environ.get("APIGENIE_OTLP_GRPC_PORT", "4317"))
GRPC_BIND = os.environ.get("APIGENIE_OTLP_GRPC_BIND", "0.0.0.0")
MAX_MSG_BYTES = int(os.environ.get("APIGENIE_OTLP_MAX_BODY_BYTES", str(4 * 1024 * 1024)))

# Module state — single asyncio Server instance, plus the thread that owns
# its event loop. We run the gRPC server in its **own thread + loop** so a
# slow OTLP export can't stall the FastAPI request loop, and so the lifespan
# context manager can shut us down cleanly without await contortions.
_LOCK = threading.Lock()
_SERVER: Any = None                   # grpc.aio.Server
_LOOP: asyncio.AbstractEventLoop | None = None
_THREAD: threading.Thread | None = None
_STARTED = False


# ── Public entry points ─────────────────────────────────────────────────────

def start(port: int | None = None) -> bool:
    """Start the gRPC server on its own thread. Returns True on success.

    Idempotent: a second call is a no-op. Any failure (missing deps,
    port-in-use, etc.) is logged and ``False`` is returned — apigenie keeps
    running with only the HTTP push-sink half operational.
    """
    global _SERVER, _LOOP, _THREAD, _STARTED
    with _LOCK:
        if _STARTED:
            return True
        try:
            import grpc  # noqa: F401 — probed for the side-effect of failing fast
            from opentelemetry.proto.collector.logs.v1 import logs_service_pb2_grpc      # noqa: F401
            from opentelemetry.proto.collector.metrics.v1 import metrics_service_pb2_grpc  # noqa: F401
            from opentelemetry.proto.collector.trace.v1 import trace_service_pb2_grpc      # noqa: F401
        except ImportError as exc:
            logger.warning(
                "OTLP gRPC server NOT started — missing dependency: %s. "
                "Install opentelemetry-proto and grpcio to enable.", exc,
            )
            return False

        bind_port = port if port is not None else GRPC_PORT

        ready = threading.Event()
        startup_error: list[BaseException] = []

        def _runner() -> None:
            global _SERVER, _LOOP
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            _LOOP = loop
            try:
                server = loop.run_until_complete(_build_and_start_server(bind_port))
                _SERVER = server
                ready.set()
                # Block on the server's termination. wait_for_termination()
                # is an awaitable on grpc.aio.Server.
                loop.run_until_complete(server.wait_for_termination())
            except BaseException as exc:  # noqa: BLE001
                startup_error.append(exc)
                ready.set()
            finally:
                try:
                    loop.run_until_complete(asyncio.sleep(0))  # drain
                except Exception:
                    pass
                loop.close()

        t = threading.Thread(target=_runner, name="otlp-grpc-server", daemon=True)
        t.start()
        _THREAD = t
        # Wait briefly for the server to come up so the caller gets a real
        # success/failure signal (matters in tests).
        if not ready.wait(timeout=5.0):
            logger.warning("OTLP gRPC server did not become ready within 5s")
            return False
        if startup_error:
            logger.warning(
                "OTLP gRPC server failed to start: %s", startup_error[0],
            )
            return False
        _STARTED = True
        logger.info("OTLP gRPC server listening on %s:%d", GRPC_BIND, bind_port)
        return True


def stop(grace: float = 1.0) -> None:
    """Stop the gRPC server. Idempotent; safe at any time."""
    global _SERVER, _LOOP, _THREAD, _STARTED
    with _LOCK:
        if not _STARTED or _SERVER is None or _LOOP is None:
            _STARTED = False
            return
        try:
            fut = asyncio.run_coroutine_threadsafe(_SERVER.stop(grace), _LOOP)
            fut.result(timeout=grace + 2.0)
        except Exception as exc:  # noqa: BLE001
            logger.warning("OTLP gRPC server stop raised: %s", exc)
        _SERVER = None
        if _THREAD is not None:
            _THREAD.join(timeout=grace + 2.0)
        _LOOP = None
        _THREAD = None
        _STARTED = False
        logger.info("OTLP gRPC server stopped")


def is_running() -> bool:
    return _STARTED and _SERVER is not None


# ── Server construction ─────────────────────────────────────────────────────

async def _build_and_start_server(port: int):
    import grpc
    from opentelemetry.proto.collector.logs.v1 import (
        logs_service_pb2 as logs_pb2,
        logs_service_pb2_grpc as logs_grpc,
    )
    from opentelemetry.proto.collector.metrics.v1 import (
        metrics_service_pb2 as metrics_pb2,
        metrics_service_pb2_grpc as metrics_grpc,
    )
    from opentelemetry.proto.collector.trace.v1 import (
        trace_service_pb2 as trace_pb2,
        trace_service_pb2_grpc as trace_grpc,
    )

    server = grpc.aio.server(
        options=[
            ("grpc.max_receive_message_length", MAX_MSG_BYTES),
            ("grpc.max_send_message_length",    MAX_MSG_BYTES),
        ],
    )
    logs_grpc.add_LogsServiceServicer_to_server(
        _LogsServicer(logs_pb2), server,
    )
    metrics_grpc.add_MetricsServiceServicer_to_server(
        _MetricsServicer(metrics_pb2), server,
    )
    trace_grpc.add_TraceServiceServicer_to_server(
        _TraceServicer(trace_pb2), server,
    )
    server.add_insecure_port(f"{GRPC_BIND}:{port}")
    await server.start()
    return server


# ── Servicers ───────────────────────────────────────────────────────────────

class _BaseServicer:
    """Shared routing + auth + hit-recording logic for all three signals.

    Each signal-specific subclass provides ``signal`` and the
    ``Export*ServiceResponse`` class to return on success.
    """
    signal: str = ""
    service_name: str = ""

    def __init__(self, response_module):
        self._response_module = response_module

    async def _handle(self, request, context):
        t0 = _time.monotonic()
        # Best-effort body size (for the hit pane). Falls back to 0 if we
        # can't serialise without paying full cost.
        try:
            body_size = request.ByteSize()
        except Exception:
            body_size = 0

        metadata = dict(context.invocation_metadata() or [])
        client = _client_ip(context)

        import listeners as L
        listener = _resolve_listener(metadata, self.signal)
        if listener is None:
            import grpc
            await context.abort(
                grpc.StatusCode.NOT_FOUND,
                "no push_sink listener matches this request "
                f"(signal={self.signal!r}; provide x-apigenie-listener-id "
                "or x-scope-orgid metadata, or a matching bearer token)",
            )
            return  # unreachable, but appeases the type checker

        # Auth re-use. We translate gRPC metadata into the HTTP-style header
        # dict that check_auth understands. authorization → Authorization
        # with optional "Bearer " prefix.
        synth_headers = _metadata_to_headers(metadata)
        ok, identity = L.check_auth(listener.auth, synth_headers)
        if not ok:
            await self._record(
                listener=listener,
                status_code=401,
                identity=identity,
                metadata=metadata,
                client=client,
                t0=t0,
                body_size=body_size,
                preview=None,
            )
            import grpc
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, f"unauthorized: {identity}")
            return

        # Rate-limit / chaos injection (shares state with the HTTP path so
        # an operator can stress-test using a mix of the two).
        injected = L.maybe_inject_status(listener)
        if injected is not None:
            await self._record(
                listener=listener,
                status_code=injected,
                identity=identity,
                metadata=metadata,
                client=client,
                t0=t0,
                body_size=body_size,
                preview=None,
            )
            import grpc
            await context.abort(
                grpc.StatusCode.UNAVAILABLE,
                f"injected_status={injected}",
            )
            return

        # Decode preview (best-effort) — only when the listener asked for it.
        preview: dict[str, Any] | None = None
        if listener.push_sink and listener.push_sink.decode_preview:
            # Serialise the incoming proto and run it through the same
            # decoder the HTTP path uses. Keeps the preview shape identical.
            import listeners_otlp
            try:
                body = request.SerializeToString()
            except Exception as exc:  # noqa: BLE001
                preview = {
                    "signal": self.signal, "codec": "otlp_proto",
                    "decode_error": f"serialize_failed: {exc}",
                }
            else:
                preview = listeners_otlp.decode_preview(
                    body=body,
                    codec="otlp_proto",
                    signal=self.signal,  # type: ignore[arg-type]
                    max_records=listener.push_sink.max_decode_records,
                )

        await self._record(
            listener=listener,
            status_code=200,
            identity=identity,
            metadata=metadata,
            client=client,
            t0=t0,
            body_size=body_size,
            preview=preview,
        )
        return self._build_ack()

    async def _record(self, *, listener, status_code, identity, metadata,
                      client, t0, body_size, preview):
        import listeners as L
        duration_ms = int((_time.monotonic() - t0) * 1000)
        # Mask sensitive metadata before sticking it into the hit.
        synth_headers = _metadata_to_headers(metadata)
        # We can't carry the raw protobuf bytes in the hit (would explode the
        # on-disk store), but we can record the size for the operator.
        body_str = f"<gRPC {self.signal} export · {body_size} bytes>"
        entry = L.make_hit(
            ts=_dt.now(_tz.utc).isoformat(timespec="seconds"),
            method="gRPC",
            path=f"/{self.service_name}/Export",
            query="",
            client=client,
            status=status_code,
            identity=identity,
            headers=synth_headers,
            body=body_str,
            duration_ms=duration_ms,
            resp_body="{}",                 # empty Export*ServiceResponse
            resp_size=2,
            otlp_preview=preview,
        )
        L.record_hit(listener.id, entry)

    def _build_ack(self):
        # Concrete subclasses override.
        raise NotImplementedError


class _LogsServicer(_BaseServicer):
    signal = "logs"
    service_name = "opentelemetry.proto.collector.logs.v1.LogsService"

    def _build_ack(self):
        return self._response_module.ExportLogsServiceResponse()

    async def Export(self, request, context):       # noqa: N802 — proto API
        result = await self._handle(request, context)
        return result if result is not None else self._build_ack()


class _MetricsServicer(_BaseServicer):
    signal = "metrics"
    service_name = "opentelemetry.proto.collector.metrics.v1.MetricsService"

    def _build_ack(self):
        return self._response_module.ExportMetricsServiceResponse()

    async def Export(self, request, context):       # noqa: N802 — proto API
        result = await self._handle(request, context)
        return result if result is not None else self._build_ack()


class _TraceServicer(_BaseServicer):
    signal = "traces"
    service_name = "opentelemetry.proto.collector.trace.v1.TraceService"

    def _build_ack(self):
        return self._response_module.ExportTraceServiceResponse()

    async def Export(self, request, context):       # noqa: N802 — proto API
        result = await self._handle(request, context)
        return result if result is not None else self._build_ack()


# ── Listener resolution ─────────────────────────────────────────────────────

def _resolve_listener(metadata: dict[str, str], signal: str):
    """Pick the push_sink listener for this RPC. See module docstring §1-5."""
    import listeners as L

    def _is_match(lst, *, require_bearer_token: str | None = None) -> bool:
        ps = getattr(lst, "push_sink", None)
        if ps is None:
            return False
        if ps.signal != signal:
            return False
        if not lst.enabled:
            return False
        if require_bearer_token is not None:
            if lst.auth.kind != "bearer":
                return False
            if (lst.auth.token or "") != require_bearer_token:
                return False
        return True

    # Step 1 — explicit listener id metadata.
    explicit_id = (metadata.get("x-apigenie-listener-id")
                   or metadata.get("x-scope-orgid"))
    if explicit_id:
        candidate = L.LISTENERS.get(explicit_id)
        if candidate is not None and _is_match(candidate):
            return candidate
        # Don't fall through — explicit id is a precise instruction.
        return None

    # Step 3 — bearer-token routing.
    authz = metadata.get("authorization", "")
    if authz:
        token = authz
        if token.lower().startswith("bearer "):
            token = token[7:]
        token = token.strip()
        if token:
            candidates = [
                lst for lst in L.LISTENERS.values()
                if _is_match(lst, require_bearer_token=token)
            ]
            if len(candidates) == 1:
                return candidates[0]
            # multiple matches → ambiguous; fall through to single-sink rule

    # Step 4 — exactly one push_sink for the signal.
    sole = [lst for lst in L.LISTENERS.values() if _is_match(lst)]
    if len(sole) == 1:
        logger.warning(
            "OTLP gRPC routed to sole %s push_sink %r — caller did not "
            "supply x-apigenie-listener-id; set the header explicitly to "
            "avoid ambiguity in multi-listener tenancies.",
            signal, sole[0].id,
        )
        return sole[0]

    return None


# ── Helpers ─────────────────────────────────────────────────────────────────

def _metadata_to_headers(metadata: dict[str, str]) -> dict[str, str]:
    """Map gRPC metadata into the header dict that check_auth() expects.

    Most check_auth code paths look at ``Authorization`` (with optional
    ``Bearer`` prefix), ``X-Api-Key``, and basic-auth headers. gRPC keys
    are always lowercase and never include a Bearer prefix by convention,
    but exporters frequently set the prefix anyway — so we leave the
    string intact.
    """
    out: dict[str, str] = {}
    for k, v in metadata.items():
        out[k] = v
        # Provide a Title-Case alias for the auth-header check.
        if "-" in k or k.islower():
            out[k.title()] = v
    return out


def _client_ip(context) -> str:
    """Best-effort peer IP extraction from a gRPC ServicerContext."""
    try:
        peer = context.peer()          # e.g. "ipv4:10.0.0.5:54321"
    except Exception:
        return "?"
    if not peer:
        return "?"
    # peer formats: "ipv4:ADDR:PORT", "ipv6:[ADDR]:PORT", "unix:PATH"
    if peer.startswith("ipv4:"):
        return peer[5:].rsplit(":", 1)[0]
    if peer.startswith("ipv6:"):
        addr = peer[5:]
        # Strip the trailing :PORT after the last "]:"
        if addr.endswith("]"):
            return addr[1:-1] if addr.startswith("[") else addr
        if "]:" in addr:
            host, _ = addr.rsplit("]:", 1)
            return host.lstrip("[")
        return addr
    return peer
