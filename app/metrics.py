from __future__ import annotations

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
except Exception:  # noqa: BLE001
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    Counter = None
    Histogram = None
    generate_latest = None


_REQ_COUNT = (
    Counter(
        "uptimemesh_http_requests_total",
        "Total HTTP requests",
        labelnames=("method", "path", "status"),
    )
    if Counter
    else None
)
_REQ_LATENCY = (
    Histogram(
        "uptimemesh_http_request_duration_seconds",
        "HTTP request latency seconds",
        labelnames=("method", "path"),
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.3, 0.5, 1.0, 2.5, 5.0, 10.0),
    )
    if Histogram
    else None
)
_ETCD_OPS = (
    Counter(
        "uptimemesh_etcd_operations_total",
        "Total etcd operations",
        labelnames=("action", "result"),
    )
    if Counter
    else None
)
_LXD_OPS = (
    Counter(
        "uptimemesh_lxd_operations_total",
        "Total LXD operations",
        labelnames=("action", "result"),
    )
    if Counter
    else None
)
_RUNTIME_LOOPS = (
    Counter(
        "uptimemesh_runtime_loops_total",
        "Runtime loop ticks",
        labelnames=("loop", "result"),
    )
    if Counter
    else None
)


def observe_http_request(*, method: str, path: str, status: int, duration_seconds: float) -> None:
    if _REQ_COUNT is not None:
        _REQ_COUNT.labels(method=method, path=path, status=str(status)).inc()
    if _REQ_LATENCY is not None:
        _REQ_LATENCY.labels(method=method, path=path).observe(duration_seconds)


def record_etcd_operation(*, action: str, ok: bool) -> None:
    if _ETCD_OPS is not None:
        _ETCD_OPS.labels(action=action, result="ok" if ok else "error").inc()


def record_lxd_operation(*, action: str, ok: bool) -> None:
    if _LXD_OPS is not None:
        _LXD_OPS.labels(action=action, result="ok" if ok else "error").inc()


def record_runtime_loop(*, loop: str, ok: bool) -> None:
    if _RUNTIME_LOOPS is not None:
        _RUNTIME_LOOPS.labels(loop=loop, result="ok" if ok else "error").inc()


def render_metrics() -> bytes:
    if generate_latest is None:
        return b""
    return generate_latest()


def metrics_content_type() -> str:
    return CONTENT_TYPE_LATEST


def is_enabled() -> bool:
    return generate_latest is not None
