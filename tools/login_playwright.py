"""One-time QR-login that materializes a persistent playwright chromium profile.

Workflow:

  1. Run:  ``python tools/login_playwright.py``
  2. A real chromium window opens at xiaohongshu.com — scan the QR code and
     finish the login flow in the browser.
  3. Press Enter in the terminal once the page shows you logged in.
  4. The script verifies the profile by re-launching headless and counting
     persisted xhs cookies.

The profile lives at ``<repo>/.xhs_profile`` (gitignored). On every subsequent
crawler run, ``PlaywrightProfileProvider`` re-launches that profile headless
to read fresh cookies.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from xhs_utils.cookie_provider import XHS_DOMAIN_SUFFIX  # noqa: E402

PROFILE_DIR = REPO_ROOT / ".xhs_profile"


def _open_for_login() -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            headless=False,
            viewport={"width": 1280, "height": 800},
        )
        try:
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            page.goto(f"https://www.{XHS_DOMAIN_SUFFIX}")
            print("\n[login] browser is open. Scan the QR code and complete login.")
            input("[login] press Enter here once you are logged in (then the browser closes and the profile is saved)...\n")
        finally:
            ctx.close()


def _verify_profile() -> int:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            headless=True,
        )
        try:
            page = ctx.new_page()
            page.goto(
                f"https://www.{XHS_DOMAIN_SUFFIX}",
                wait_until="domcontentloaded",
                timeout=15000,
            )
            cookies = ctx.cookies()
        finally:
            ctx.close()
    return sum(1 for c in cookies if XHS_DOMAIN_SUFFIX in (c.get("domain") or ""))


def main() -> int:
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[login] profile dir: {PROFILE_DIR}")
    try:
        _open_for_login()
    except ImportError:
        print(
            "[login] playwright is not installed. Install with:\n"
            "    pip install playwright && python -m playwright install chromium",
            file=sys.stderr,
        )
        return 2

    try:
        n = _verify_profile()
    except Exception as e:
        print(f"[login] verification failed: {e}", file=sys.stderr)
        return 3

    if n == 0:
        print("[login] no xhs cookies persisted — login likely incomplete", file=sys.stderr)
        return 1
    print(f"[login] OK — {n} xhs cookies persisted in profile")
    return 0


if __name__ == "__main__":
    sys.exit(main())
