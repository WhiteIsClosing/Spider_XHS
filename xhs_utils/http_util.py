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

This module also owns three single-identity defenses (see the sections below),
which matter most when there is no proxy/IP rotation to fall back on:

* a coherent, process-pinned client fingerprint (UA + Client Hints aligned to
  the TLS impersonation) so the identity never contradicts itself;
* a risk-control circuit breaker that backs off on soft-block signals and
  aborts the run before a soft block escalates to a hard ban;
* a rolling cookie store that feeds server Set-Cookie rotations back into
  outgoing requests and persists them, so the one cookie ages like a real one.
"""
from __future__ import annotations

import json
import math
import os
import random
import re
import threading
import time
from datetime import datetime
from typing import Any, Optional

from loguru import logger

REQUEST_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

_BACKEND = os.getenv("XHS_HTTP_BACKEND", "curl_cffi").lower()
_IMPERSONATE = os.getenv("XHS_IMPERSONATE", "chrome120")


# ---------------------------------------------------------------------------
# Client identity — ONE coherent fingerprint per process
# ---------------------------------------------------------------------------
#
# The single most common bot tell for a single-IP / single-cookie identity is
# an *internally inconsistent* fingerprint: a Safari User-Agent riding a Chrome
# TLS handshake, or sec-ch-ua headers that disagree with the UA. curl_cffi pins
# the TLS+HTTP/2 layer to ``_IMPERSONATE``; everything we declare in headers
# must match that, and must stay stable for the whole run (real browsers don't
# rotate their UA between requests within one session).
#
# We derive the UA + client hints from the impersonation target so the two can
# never drift apart. Override the visible UA with ``XHS_USER_AGENT`` only if you
# also align ``XHS_IMPERSONATE`` to the same browser/version.


def _build_client_profile(impersonate: str) -> dict[str, str]:
    """Map a curl_cffi impersonate token (e.g. ``chrome120``) to a coherent set
    of browser headers (UA + Client Hints) for a Windows desktop."""
    m = re.match(r"([a-zA-Z_]+?)(\d+)", impersonate or "")
    browser = (m.group(1).lower() if m else "chrome")
    major = (m.group(2) if m else "120")

    def _win_ua(token: str) -> str:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) {token} Safari/537.36"
        )

    if "edge" in browser:
        ua = _win_ua(f"Chrome/{major}.0.0.0") + f" Edg/{major}.0.0.0"
        brand = f'"Microsoft Edge";v="{major}", "Chromium";v="{major}", "Not?A_Brand";v="24"'
    elif "chrome" in browser:
        ua = _win_ua(f"Chrome/{major}.0.0.0")
        brand = f'"Google Chrome";v="{major}", "Chromium";v="{major}", "Not?A_Brand";v="24"'
    else:
        # Safari/Firefox/unknown: Chrome's client-hint headers wouldn't be sent
        # by those browsers, so falling back to a real Chrome profile keeps the
        # headers self-consistent rather than emitting a contradictory mix.
        major = "120"
        ua = _win_ua("Chrome/120.0.0.0")
        brand = '"Google Chrome";v="120", "Chromium";v="120", "Not?A_Brand";v="24"'

    return {
        "user_agent": os.getenv("XHS_USER_AGENT", ua),
        "sec_ch_ua": brand,
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
    }


CLIENT_PROFILE = _build_client_profile(_IMPERSONATE)


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


class RunAbort(BaseException):
    """Base for signals that must unwind the whole crawl.

    These subclass ``BaseException`` *on purpose*: every leaf API method wraps
    its request in a broad ``except Exception``, so an ``Exception`` raised from
    this HTTP layer would be silently turned into ``(False, msg)`` and the run
    would grind on. Mirroring why ``KeyboardInterrupt`` / ``SystemExit`` are
    ``BaseException``, "stop the whole run" must not be catchable as "this one
    request failed". The pipeline catches these explicitly to flush partials.
    """


class SessionBudgetExceeded(RunAbort):
    """Raised when the per-run request count or wall-clock cap is hit."""


class CircuitBreakerOpen(RunAbort):
    """Raised when consecutive risk-control signals trip the circuit breaker."""


_budget_lock = threading.Lock()
_budget_state: dict[str, Any] = {
    "max_requests": None,
    "max_seconds": None,
    "started_at": None,
    "request_count": 0,
    # Per-day quota that survives process restarts — a single IP/cookie should
    # not be able to bypass throttling just by relaunching the script.
    "max_daily": None,
    "daily_path": None,
    "daily_date": None,
    "daily_count": 0,
}


def _today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _read_daily_quota(path: str) -> tuple[Optional[str], int]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("date"), int(data.get("count", 0))
    except Exception:
        return None, 0


def _write_daily_quota(path: str, date: str, count: int) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"date": date, "count": count}, f)
    except Exception as e:
        logger.debug(f"[Budget] daily quota write failed: {e}")


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


def configure_daily_quota(max_daily: Optional[int], path: Optional[str]) -> None:
    """Set a per-calendar-day request cap that persists across runs.

    Loads today's running total from ``path`` so relaunching the script keeps
    counting toward the same daily budget instead of starting fresh.
    """
    with _budget_lock:
        _budget_state["max_daily"] = max_daily
        _budget_state["daily_path"] = path
        today = _today_str()
        if max_daily is not None and path:
            saved_date, saved_count = _read_daily_quota(path)
            _budget_state["daily_date"] = today
            _budget_state["daily_count"] = saved_count if saved_date == today else 0
            used = _budget_state["daily_count"]
        else:
            _budget_state["daily_date"] = today
            _budget_state["daily_count"] = 0
            used = 0
    logger.info(f"[Budget] daily quota max_daily={max_daily} (today used={used})")


def _consume_budget() -> None:
    """Record one request; raise if it pushes us over any cap."""
    daily_path = None
    daily_date = None
    daily_count = None
    max_daily = None
    with _budget_lock:
        _budget_state["request_count"] += 1
        c = _budget_state["request_count"]
        max_r = _budget_state["max_requests"]
        max_s = _budget_state["max_seconds"]
        started = _budget_state["started_at"]
        max_daily = _budget_state["max_daily"]
        if max_daily is not None:
            today = _today_str()
            if _budget_state["daily_date"] != today:  # rolled past midnight
                _budget_state["daily_date"] = today
                _budget_state["daily_count"] = 0
            _budget_state["daily_count"] += 1
            daily_count = _budget_state["daily_count"]
            daily_date = _budget_state["daily_date"]
            daily_path = _budget_state["daily_path"]

    if daily_path and daily_date is not None and daily_count is not None:
        _write_daily_quota(daily_path, daily_date, daily_count)

    if max_r is not None and c > max_r:
        raise SessionBudgetExceeded(
            f"request count {c} exceeded max_requests={max_r}"
        )
    if max_daily is not None and daily_count is not None and daily_count > max_daily:
        raise SessionBudgetExceeded(
            f"daily request count {daily_count} exceeded max_daily={max_daily}"
        )
    if max_s is not None and started is not None:
        elapsed = time.time() - started
        if elapsed > max_s:
            raise SessionBudgetExceeded(
                f"wall clock {elapsed:.0f}s exceeded max_seconds={max_s:.0f}"
            )


# ---------------------------------------------------------------------------
# Risk-control detection + backoff + circuit breaker
# ---------------------------------------------------------------------------
#
# With no proxy rotation, getting noticed is fatal: you cannot switch identity,
# so one aggressive request after a soft-block can escalate to a hard ban that
# burns the (manually supplied) cookie. The defense is a closed loop:
#
#   * inspect every response for risk signals (HTTP 429/461/47x, or a business
#     body that says 频繁/验证/风控/...);
#   * on a hit, back off with exponential delay so we *stop pushing*;
#   * after ``XHS_RISK_CIRCUIT_THRESHOLD`` consecutive hits, trip the breaker
#     and abort the run (raise CircuitBreakerOpen) instead of grinding on;
#   * a clean response resets the consecutive counter.

_RISK_HTTP_STATUS = {429, 461, 471, 472, 473}
_RISK_KEYWORDS = (
    "访问频繁", "操作频繁", "请求频繁", "频繁", "稍后再试", "稍后重试",
    "滑块", "验证码", "验证", "风控", "风险", "拦截", "异常访问", "访问异常",
    "当前访问人数", "操作异常",
)
_RISK_KEYWORDS_EN = ("rate limit", "too many", "blocked", "captcha", "verify")

_RISK_BACKOFF_BASE = float(os.getenv("XHS_RISK_BACKOFF_BASE", "30"))
_RISK_BACKOFF_CAP = float(os.getenv("XHS_RISK_BACKOFF_CAP", "300"))
_RISK_CIRCUIT_THRESHOLD = int(os.getenv("XHS_RISK_CIRCUIT_THRESHOLD", "3"))


def _risk_codes() -> set[int]:
    raw = os.getenv("XHS_RISK_CODES", "")
    codes: set[int] = set()
    for piece in raw.split(","):
        piece = piece.strip()
        if piece:
            try:
                codes.add(int(piece))
            except ValueError:
                continue
    return codes


_risk_lock = threading.Lock()
_risk_state: dict[str, Any] = {"consecutive": 0, "total": 0, "open": False}


def reset_risk_state() -> None:
    """Clear breaker state. Call once at pipeline start (per run)."""
    with _risk_lock:
        _risk_state["consecutive"] = 0
        _risk_state["total"] = 0
        _risk_state["open"] = False


def raise_if_circuit_open() -> None:
    """Raise CircuitBreakerOpen if the breaker has already tripped.

    Cheap guard callers can use to bail before issuing the next request.
    """
    with _risk_lock:
        if _risk_state["open"]:
            raise CircuitBreakerOpen("circuit breaker already open")


def is_risk_message(msg: Any) -> bool:
    """True if a business message reads like a risk-control / rate-limit reply.

    Lets callers that only have ``(success, msg)`` (e.g. the pipeline preflight)
    tell a风控 soft-block apart from a login failure or a stale signature.
    """
    s = str(msg or "")
    low = s.lower()
    return any(k in s for k in _RISK_KEYWORDS) or any(k in low for k in _RISK_KEYWORDS_EN)


def _classify_response(status: Optional[int], body: Any) -> tuple[str, Any, str]:
    """Return (kind, code, msg) where kind ∈ {"ok", "risk", "neutral"}."""
    code = None
    success = None
    msg = ""
    if isinstance(body, dict):
        code = body.get("code")
        success = body.get("success")
        msg = str(body.get("msg") or body.get("message") or "")

    if status in _RISK_HTTP_STATUS:
        return "risk", code, msg
    if code is not None and code in _risk_codes():
        return "risk", code, msg
    if msg:
        low = msg.lower()
        if any(k in msg for k in _RISK_KEYWORDS) or any(k in low for k in _RISK_KEYWORDS_EN):
            return "risk", code, msg
    if status == 200 and (success is True or code == 0):
        return "ok", code, msg
    return "neutral", code, msg


def _risk_backoff_seconds(n: int) -> float:
    raw = _RISK_BACKOFF_BASE * (2 ** (n - 1))
    return min(raw * random.uniform(0.8, 1.3), _RISK_BACKOFF_CAP)


def _observe_response(resp: Any) -> None:
    """Inspect a response, update breaker state, back off or trip as needed."""
    status = getattr(resp, "status_code", None)
    # Only parse the body when it's actually JSON. Crucially, this avoids
    # reading (and thus consuming) ``stream=True`` media downloads — calling
    # ``.json()`` on those would drain the stream before iter_content runs.
    body = None
    try:
        ctype = (resp.headers.get("content-type") or "").lower()
    except Exception:
        ctype = ""
    if "json" in ctype:
        try:
            body = resp.json()
        except Exception:
            body = None
    kind, code, msg = _classify_response(status, body)
    if kind == "neutral":
        return

    with _risk_lock:
        if kind == "ok":
            if _risk_state["consecutive"]:
                logger.info("[风控] 信号解除，连续计数清零")
            _risk_state["consecutive"] = 0
            return
        _risk_state["consecutive"] += 1
        _risk_state["total"] += 1
        n = _risk_state["consecutive"]

    detail = f"status={status} code={code} msg={msg[:60]!r}"
    if n >= _RISK_CIRCUIT_THRESHOLD:
        with _risk_lock:
            _risk_state["open"] = True
        logger.error(
            f"[风控] 连续 {n}/{_RISK_CIRCUIT_THRESHOLD} 次命中风控信号 → 熔断，停止本次运行 ({detail})"
        )
        raise CircuitBreakerOpen(f"risk signals x{n} ({detail})")

    delay = _risk_backoff_seconds(n)
    logger.warning(
        f"[风控] 命中风控信号 第 {n}/{_RISK_CIRCUIT_THRESHOLD} 次，退避 {delay:.0f}s ({detail})"
    )
    time.sleep(delay)


# ---------------------------------------------------------------------------
# Rolling cookie store — keep the one precious cookie fresh
# ---------------------------------------------------------------------------
#
# XHS rotates transport tokens (acw_tc, web_session, ...) via Set-Cookie. The
# API layer rebuilds the cookie dict from a static string on every call, so
# those rolled values were being dropped — the identity looked frozen. Here we:
#   * seed a live store from the supplied cookie,
#   * merge each response's Set-Cookie back in (rolled values win),
#   * inject the merged store into outgoing API requests,
#   * persist it so the next run resumes the aged identity.
# a1 (the device id, which the x-s signature is derived from) never rolls, so
# refreshing transport cookies does not invalidate signatures.

_cookie_lock = threading.Lock()
_live_cookies: dict[str, str] = {}


def seed_cookies(cookies_str: Optional[str]) -> None:
    if not cookies_str:
        return
    parsed: dict[str, str] = {}
    for piece in cookies_str.replace("; ", ";").split(";"):
        if "=" in piece:
            k, v = piece.split("=", 1)
            parsed[k.strip()] = v.strip()
    with _cookie_lock:
        _live_cookies.clear()
        _live_cookies.update(parsed)


def current_cookie_str() -> str:
    with _cookie_lock:
        return "; ".join(f"{k}={v}" for k, v in _live_cookies.items())


def _effective_cookies(passed: Any) -> Any:
    """Merge rolled/live cookies over what the caller passed.

    ``passed is None`` means the caller opted out of cookies (e.g. media
    downloads to a CDN) — don't inject anything there.
    """
    if passed is None:
        return None
    with _cookie_lock:
        if not _live_cookies:
            return passed
        if isinstance(passed, dict):
            merged = dict(passed)
            merged.update(_live_cookies)
            return merged
        return dict(_live_cookies)


def _merge_response_cookies(resp: Any) -> None:
    # Only absorb Set-Cookie from XHS itself. Media/CDN responses (xhscdn.com)
    # must not leak their cookies into the API jar or the persisted file.
    url = getattr(resp, "url", "") or ""
    if "xiaohongshu.com" not in str(url):
        return
    jar = getattr(resp, "cookies", None)
    if not jar:
        return
    try:
        items = list(jar.items())
    except Exception:
        try:
            items = list(jar.get_dict().items())
        except Exception:
            return
    if not items:
        return
    with _cookie_lock:
        for k, v in items:
            if k and v is not None:
                _live_cookies[k] = v


def persist_cookies(path: str) -> None:
    s = current_cookie_str()
    if not s:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(s)
        logger.debug(f"[Cookie] 已持久化滚动 cookie -> {path}")
    except Exception as e:
        logger.debug(f"[Cookie] 持久化失败: {e}")


def load_persisted_cookies(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip() or None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _apply_cookies(kwargs: dict[str, Any]) -> None:
    if "cookies" in kwargs and kwargs["cookies"] is not None:
        kwargs["cookies"] = _effective_cookies(kwargs["cookies"])


# ---------------------------------------------------------------------------
# Drop-in replacements for ``requests.{get,post,put,Session}``
# ---------------------------------------------------------------------------


def _dispatch(method: str, url: str, **kwargs: Any) -> Any:
    """Shared path for all verbs: budget → breaker guard → cookie merge →
    request → capture rolled cookies → risk inspection."""
    _consume_budget()
    raise_if_circuit_open()
    _apply_cookies(kwargs)
    resp = getattr(_session(), method)(url, **kwargs)
    _merge_response_cookies(resp)
    _observe_response(resp)
    return resp


def get(url: str, **kwargs: Any) -> Any:
    return _dispatch("get", url, **kwargs)


def post(url: str, **kwargs: Any) -> Any:
    return _dispatch("post", url, **kwargs)


def put(url: str, **kwargs: Any) -> Any:
    return _dispatch("put", url, **kwargs)


def Session(*args: Any, **kwargs: Any) -> Any:
    """Create a fresh session honoring the configured backend / impersonation."""
    if _USE_IMPERSONATE and "impersonate" not in kwargs:
        kwargs["impersonate"] = _IMPERSONATE
    return _Session(*args, **kwargs)


# ---------------------------------------------------------------------------
# Pacing — lognormal delays + cooldowns + circadian (昼夜节律)
# ---------------------------------------------------------------------------
#
# A real person doesn't browse at a constant rate around the clock — they skim
# during the day and barely touch the app at 3am. With a single identity, an
# evenly-paced 24/7 request stream is a tell. We scale all pauses by a
# time-of-day factor: ~1x in active hours, slower in the shoulders, much slower
# deep at night. Toggle with XHS_CIRCADIAN=0; tune the active window with
# XHS_ACTIVE_HOUR_START / XHS_ACTIVE_HOUR_END (local time, 24h).


_request_counter = 0
_counter_lock = threading.Lock()

_CIRCADIAN_ENABLED = os.getenv("XHS_CIRCADIAN", "1").lower() not in ("0", "false", "no", "")
_ACTIVE_HOUR_START = int(os.getenv("XHS_ACTIVE_HOUR_START", "9"))
_ACTIVE_HOUR_END = int(os.getenv("XHS_ACTIVE_HOUR_END", "23"))
_NIGHT_FACTOR = float(os.getenv("XHS_NIGHT_FACTOR", "4.0"))
_SHOULDER_FACTOR = float(os.getenv("XHS_SHOULDER_FACTOR", "2.0"))


def circadian_factor(now: Optional[datetime] = None) -> float:
    """Delay multiplier for the current local hour (1.0 = active baseline)."""
    if not _CIRCADIAN_ENABLED:
        return 1.0
    h = (now or datetime.now()).hour
    if 1 <= h < 7:  # deep night
        return _NIGHT_FACTOR
    if _ACTIVE_HOUR_START <= h < _ACTIVE_HOUR_END:
        return 1.0
    return _SHOULDER_FACTOR  # early morning / late night shoulders


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
    factor = circadian_factor()
    median = math.sqrt(min_seconds * max_seconds) * factor
    cap = max_seconds * 6.0 * factor
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
    probability branches needed. All pauses are scaled by ``circadian_factor``.
    """
    global _request_counter
    with _counter_lock:
        _request_counter += 1
        count = _request_counter

    factor = circadian_factor()

    if count % cooldown_every == 0:
        delay = random.uniform(cooldown_min, cooldown_max) * factor
        logger.info(f"[限速] 已发送 {count} 次请求，触发冷却 {delay:.0f}s (昼夜系数 {factor:g})")
        time.sleep(delay)
        return

    median = math.sqrt(min_seconds * max_seconds) * factor
    cap = max_seconds * 6.0 * factor
    delay = max(min_seconds * 0.4, _lognormal_seconds(median, 0.7, cap))
    if delay > max_seconds * 1.5:
        logger.debug(f"[限速] 长尾停顿 {delay:.1f}s (昼夜系数 {factor:g})")
    time.sleep(delay)


def reset_request_counter() -> None:
    global _request_counter
    with _counter_lock:
        _request_counter = 0


def get_user_agent() -> str:
    """The process-pinned User-Agent, consistent with the TLS impersonation."""
    return CLIENT_PROFILE["user_agent"]


def get_random_user_agent() -> str:
    """Back-compat shim. Returns the *pinned* UA, not a random one.

    Rotating the UA per request against a single cookie/IP is itself a tell and
    risks a UA/TLS mismatch, so callers now always get the one identity that
    matches the impersonation profile.
    """
    return CLIENT_PROFILE["user_agent"]


def get_client_hint_headers() -> dict[str, str]:
    """UA + Client-Hint headers as one coherent set. Use this when building
    request headers so the whole identity stays internally consistent."""
    return {
        "user-agent": CLIENT_PROFILE["user_agent"],
        "sec-ch-ua": CLIENT_PROFILE["sec_ch_ua"],
        "sec-ch-ua-mobile": CLIENT_PROFILE["sec_ch_ua_mobile"],
        "sec-ch-ua-platform": CLIENT_PROFILE["sec_ch_ua_platform"],
    }
