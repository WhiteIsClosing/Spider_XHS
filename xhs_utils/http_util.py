"""HTTP client + behavior shaping for the XHS crawler.

This module is the single place that knows how requests are sent on the wire
and how they are paced. API code should ``from xhs_utils import http_util as
requests`` so swapping the underlying client (curl_cffi today, playwright in
phase B) stays transparent to call sites.

Backends, selected via ``XHS_HTTP_BACKEND``:

* ``curl_cffi`` (default) — impersonates a real Chrome's TLS+HTTP/2 fingerprint;
  the most consequential anti-bot defense on commercial WAFs that fingerprint
  clients (Akamai, Cloudflare-style). Override the impersonation profile via
  ``XHS_IMPERSONATE`` (default ``chrome120``).
* ``requests`` — vanilla python-requests. Use only as a baseline for A/B
  detection comparisons.

Pacing helpers draw inter-request gaps from a lognormal so the distribution
looks like a human reading rather than a uniform random draw. Long stops
appear naturally in the tail; no hand-coded "X% chance of long pause" branch.

``SessionBudgetExceeded`` caps a single run by request count and wall clock.
Real users don't grind for 8 hours. Pipeline catches it, flushes partial
results, exits cleanly.
"""
from __future__ import annotations

import math
import os
import random
import threading
import time
from typing import Any, Optional

from loguru import logger

REQUEST_TIMEOUT = 15

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

_BACKEND = os.getenv("XHS_HTTP_BACKEND", "curl_cffi").lower()
_IMPERSONATE = os.getenv("XHS_IMPERSONATE", "chrome120")


def _load_backend() -> tuple[Any, bool, str]:
    """Return (impl_module, use_impersonate, backend_name)."""
    if _BACKEND == "curl_cffi":
        try:
            from curl_cffi import requests as impl  # type: ignore[import-not-found]
            logger.info(f"[HTTP] backend=curl_cffi impersonate={_IMPERSONATE}")
            return impl, True, "curl_cffi"
        except ImportError:
            import requests as impl
            logger.warning(
                "[HTTP] curl_cffi not installed; falling back to python-requests "
                "(TLS fingerprint will look like Python — install curl_cffi for "
                "real protection)."
            )
            return impl, False, "requests-fallback"
    if _BACKEND == "requests":
        import requests as impl
        logger.info("[HTTP] backend=requests (no impersonation)")
        return impl, False, "requests"
    raise ValueError(f"Unknown XHS_HTTP_BACKEND={_BACKEND!r}")


_impl, _USE_IMPERSONATE, BACKEND_NAME = _load_backend()
_Session = _impl.Session


# Per-thread session: keeps cookies + connections warm within a worker, while
# distinct threads (if ever introduced) get their own state.
_thread_local = threading.local()


def _new_session() -> Any:
    if _USE_IMPERSONATE:
        return _Session(impersonate=_IMPERSONATE)
    return _Session()


def _session() -> Any:
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = _new_session()
        _thread_local.session = s
    return s


# ---------------------------------------------------------------------------
# Session budget
# ---------------------------------------------------------------------------


class SessionBudgetExceeded(Exception):
    """Raised when the per-run request count or wall-clock cap is hit."""


_budget_lock = threading.Lock()
_budget_state: dict[str, Any] = {
    "max_requests": None,
    "max_seconds": None,
    "started_at": None,
    "request_count": 0,
}


def configure_budget(
    max_requests: Optional[int] = None,
    max_minutes: Optional[float] = None,
) -> None:
    """Set per-run request and wall-clock caps. Call once at pipeline start.

    Pass ``None`` to either to disable that dimension.
    """
    with _budget_lock:
        _budget_state["max_requests"] = max_requests
        _budget_state["max_seconds"] = max_minutes * 60.0 if max_minutes else None
        _budget_state["started_at"] = time.time()
        _budget_state["request_count"] = 0
    logger.info(
        f"[Budget] configured max_requests={max_requests} max_minutes={max_minutes}"
    )


def _consume_budget() -> None:
    """Record one request; raise if it pushes us over either cap."""
    with _budget_lock:
        _budget_state["request_count"] += 1
        c = _budget_state["request_count"]
        max_r = _budget_state["max_requests"]
        max_s = _budget_state["max_seconds"]
        started = _budget_state["started_at"]
    if max_r is not None and c > max_r:
        raise SessionBudgetExceeded(
            f"request count {c} exceeded max_requests={max_r}"
        )
    if max_s is not None and started is not None:
        elapsed = time.time() - started
        if elapsed > max_s:
            raise SessionBudgetExceeded(
                f"wall clock {elapsed:.0f}s exceeded max_seconds={max_s:.0f}"
            )


# ---------------------------------------------------------------------------
# Drop-in replacements for ``requests.{get,post,put,Session}``
# ---------------------------------------------------------------------------


def get(url: str, **kwargs: Any) -> Any:
    _consume_budget()
    return _session().get(url, **kwargs)


def post(url: str, **kwargs: Any) -> Any:
    _consume_budget()
    return _session().post(url, **kwargs)


def put(url: str, **kwargs: Any) -> Any:
    _consume_budget()
    return _session().put(url, **kwargs)


def Session(*args: Any, **kwargs: Any) -> Any:
    """Create a fresh session honoring the configured backend / impersonation."""
    if _USE_IMPERSONATE and "impersonate" not in kwargs:
        kwargs["impersonate"] = _IMPERSONATE
    return _Session(*args, **kwargs)


# ---------------------------------------------------------------------------
# Pacing — lognormal delays + cooldowns
# ---------------------------------------------------------------------------


_request_counter = 0
_counter_lock = threading.Lock()


def _lognormal_seconds(median: float, sigma: float, cap: float) -> float:
    """Lognormal sample with the given median (seconds), capped at ``cap``.

    sigma=0.7 produces the long tail you want for a "skim a lot, occasionally
    pause to read a thread" pattern. The capped output makes accidental 5-minute
    sleeps impossible.
    """
    mu = math.log(max(median, 1e-3))
    return min(random.lognormvariate(mu, sigma), cap)


def random_delay(min_seconds: float = 2.0, max_seconds: float = 5.0) -> None:
    """Lognormal delay scaled to the [min, max] band (with floor + ~6x cap)."""
    median = math.sqrt(min_seconds * max_seconds)
    cap = max_seconds * 6.0
    delay = max(min_seconds * 0.4, _lognormal_seconds(median, 0.7, cap))
    time.sleep(delay)


def rate_limited_delay(
    min_seconds: float = 5.0,
    max_seconds: float = 15.0,
    cooldown_every: int = 10,
    cooldown_min: float = 60.0,
    cooldown_max: float = 120.0,
) -> None:
    """Inter-request pause with periodic cooldown.

    Distribution: lognormal centered at the geometric mean of [min, max] with
    sigma=0.7, capped at 6x ``max_seconds``. The heavy tail naturally produces
    the rare 60-90s "deep read" pause that real users do — no hand-coded
    probability branches needed.
    """
    global _request_counter
    with _counter_lock:
        _request_counter += 1
        count = _request_counter

    if count % cooldown_every == 0:
        delay = random.uniform(cooldown_min, cooldown_max)
        logger.info(f"[限速] 已发送 {count} 次请求，触发冷却 {delay:.0f}s")
        time.sleep(delay)
        return

    median = math.sqrt(min_seconds * max_seconds)
    cap = max_seconds * 6.0
    delay = max(min_seconds * 0.4, _lognormal_seconds(median, 0.7, cap))
    if delay > max_seconds * 1.5:
        logger.debug(f"[限速] 长尾停顿 {delay:.1f}s")
    time.sleep(delay)


def reset_request_counter() -> None:
    global _request_counter
    with _counter_lock:
        _request_counter = 0


def get_random_user_agent() -> str:
    return random.choice(_USER_AGENTS)
