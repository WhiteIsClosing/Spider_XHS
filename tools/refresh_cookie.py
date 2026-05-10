"""Resolve cookies via the provider chain and write them back to ``.env``.

Use this when something downstream (test_phase1.py, third-party tools, ...)
expects cookies in ``.env`` rather than calling ``cookie_provider.resolve()``
directly. The crawler entry point uses the resolver natively, so for normal
runs you do **not** need to call this.

Run:  ``python tools/refresh_cookie.py``
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from xhs_utils.cookie_provider import resolve  # noqa: E402

ENV_PATH = REPO_ROOT / ".env"


def _write_cookie(env_path: Path, cookie_str: str) -> None:
    """Replace (or append) the COOKIES line; preserve other env vars."""
    kept: list[str] = []
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("COOKIES="):
                continue
            kept.append(line)
    kept.append(f"COOKIES='{cookie_str}'")
    env_path.write_text("\n".join(kept).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    result = resolve()
    if not result:
        print("[refresh] no provider produced a usable cookie", file=sys.stderr)
        return 1
    cookie_str, provider = result
    _write_cookie(ENV_PATH, cookie_str)
    print(f"[refresh] wrote cookie from provider={provider} -> {ENV_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
