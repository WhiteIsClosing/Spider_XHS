"""Cookie source resolver chain.

Tries providers in order; the first one that yields a cookie passing structural
validation wins. Logs the winning provider name. The default chain is:

  1. ChromeLocalProvider       — read live cookies from local Chrome cookie DB
  2. PlaywrightProfileProvider — headless reuse of a persistent chromium profile
  3. EnvFileProvider           — fall back to .env COOKIES (manual)

Validation only checks structural completeness (required keys present); use the
pipeline's own session check (Data_Spider.check_session) for liveness.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Protocol

from loguru import logger

REQUIRED_COOKIE_KEYS: tuple[str, ...] = ("a1", "web_session", "webId")
XHS_DOMAIN_SUFFIX: str = "xiaohongshu.com"


class CookieProvider(Protocol):
    name: str

    def get(self) -> Optional[str]:
        """Return cookie string ('k=v; k=v; ...') or None if unavailable."""
        ...


def _domain_priority(domain: str) -> int:
    """Prefer edith.* (the API subdomain XHS uses) over www/root.

    The smoke-test docs warn that for cookies appearing on multiple subdomains
    (notably ``acw_tc``), the ``edith.xiaohongshu.com`` value is the one the
    API accepts.
    """
    d = (domain or "").lstrip(".")
    if d.startswith("edith."):
        return 0
    if d == XHS_DOMAIN_SUFFIX:
        return 1
    return 2


def _pairs_to_cookie_str(pairs: Iterable[tuple[str, str]]) -> str:
    seen: set[str] = set()
    parts: list[str] = []
    for k, v in pairs:
        if k in seen:
            continue
        seen.add(k)
        parts.append(f"{k}={v}")
    return "; ".join(parts)


def _has_required_keys(cookie_str: str) -> bool:
    found: set[str] = set()
    for piece in cookie_str.split(";"):
        if "=" in piece:
            found.add(piece.split("=", 1)[0].strip())
    return all(k in found for k in REQUIRED_COOKIE_KEYS)


@dataclass
class ChromeLocalProvider:
    """Read xhs cookies from Chrome's local cookie DB via browser-cookie3.

    On macOS this reads ~/Library/Application Support/Google/Chrome and uses
    Keychain to decrypt; the OS may prompt for the user's password the first
    time. Works whether or not Chrome is currently running.
    """

    name: str = "chrome-local"

    def get(self) -> Optional[str]:
        try:
            import browser_cookie3
        except ImportError:
            logger.debug(f"[Cookie:{self.name}] browser-cookie3 not installed")
            return None
        try:
            cj = browser_cookie3.chrome(domain_name=XHS_DOMAIN_SUFFIX)
        except Exception as e:
            logger.debug(f"[Cookie:{self.name}] read failed: {e}")
            return None
        candidates = [c for c in cj if XHS_DOMAIN_SUFFIX in (c.domain or "")]
        if not candidates:
            return None
        candidates.sort(key=lambda c: _domain_priority(c.domain or ""))
        return _pairs_to_cookie_str((c.name, c.value) for c in candidates)


@dataclass
class PlaywrightProfileProvider:
    """Headlessly load a persistent chromium profile and read its cookies.

    The profile is created by tools/login_playwright.py (one-time QR scan).
    Each ``get()`` launches headless chromium against the same profile, so
    rolling tokens (acw_tc, web_session) get refreshed by the browser before
    we read them out.
    """

    profile_dir: Path
    name: str = "playwright-profile"
    nav_timeout_ms: int = 15000

    def get(self) -> Optional[str]:
        if not self.profile_dir.exists():
            logger.debug(f"[Cookie:{self.name}] profile dir missing: {self.profile_dir}")
            return None
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            logger.debug(f"[Cookie:{self.name}] playwright not installed")
            return None
        cookies: list[dict] = []
        try:
            with sync_playwright() as p:
                ctx = p.chromium.launch_persistent_context(
                    user_data_dir=str(self.profile_dir),
                    headless=True,
                )
                try:
                    page = ctx.new_page()
                    page.goto(
                        f"https://www.{XHS_DOMAIN_SUFFIX}",
                        wait_until="domcontentloaded",
                        timeout=self.nav_timeout_ms,
                    )
                    cookies = ctx.cookies()
                finally:
                    ctx.close()
        except Exception as e:
            logger.debug(f"[Cookie:{self.name}] launch failed: {e}")
            return None
        candidates = [c for c in cookies if XHS_DOMAIN_SUFFIX in (c.get("domain") or "")]
        if not candidates:
            return None
        candidates.sort(key=lambda c: _domain_priority(c.get("domain") or ""))
        return _pairs_to_cookie_str((c["name"], c["value"]) for c in candidates)


@dataclass
class EnvFileProvider:
    """Fall back to the COOKIES variable in a .env file."""

    name: str = "env-file"

    def get(self) -> Optional[str]:
        from dotenv import load_dotenv

        load_dotenv()
        v = os.getenv("COOKIES")
        return v or None


def default_providers() -> list[CookieProvider]:
    repo_root = Path(__file__).resolve().parent.parent
    return [
        ChromeLocalProvider(),
        PlaywrightProfileProvider(profile_dir=repo_root / ".xhs_profile"),
        EnvFileProvider(),
    ]


def resolve(
    providers: Optional[list[CookieProvider]] = None,
) -> Optional[tuple[str, str]]:
    """Walk the chain. Return ``(cookie_str, provider_name)`` or ``None``."""
    chain = providers if providers is not None else default_providers()
    for p in chain:
        try:
            cookie = p.get()
        except Exception as e:
            logger.warning(f"[Cookie] provider={p.name} raised {e!r}")
            continue
        if not cookie:
            logger.debug(f"[Cookie] provider={p.name} -> empty")
            continue
        if not _has_required_keys(cookie):
            logger.warning(
                f"[Cookie] provider={p.name} -> missing required keys "
                f"{set(REQUIRED_COOKIE_KEYS)}, skipping"
            )
            continue
        logger.info(f"[Cookie] using provider={p.name}")
        return cookie, p.name
    logger.error("[Cookie] no provider produced a usable cookie")
    return None
