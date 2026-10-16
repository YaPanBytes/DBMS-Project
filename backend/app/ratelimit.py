"""Throttle repeated failed password logins (per email and client address).

In-process and in-memory: enough for a single API worker. Behind several
workers or hosts, move the counters to a shared store (e.g. Redis).
"""

import time
from collections import deque
from threading import Lock

from fastapi import Request

from .config import get_settings
from .errors import AppError

_failures: dict[tuple[str, str], deque[float]] = {}
_lock = Lock()


def _key(request: Request, email: str) -> tuple[str, str]:
    return (email.strip().lower(), request.client.host if request.client else "-")


def _recent(key: tuple[str, str], now: float, window: int) -> deque[float]:
    times = _failures.setdefault(key, deque())
    while times and times[0] <= now - window:
        times.popleft()
    return times


def check_login_allowed(request: Request, email: str) -> None:
    """Raise 429 if this email/address has too many recent failures."""
    s = get_settings()
    now = time.monotonic()
    with _lock:
        times = _recent(_key(request, email), now, s.login_failure_window_seconds)
        if len(times) >= s.login_max_failures:
            retry = int(times[0] + s.login_failure_window_seconds - now) + 1
            raise AppError(
                429,
                "Too many failed sign-in attempts. Try again later.",
                details={"retry_after_seconds": retry},
                headers={"Retry-After": str(retry)},
            )


def record_login_failure(request: Request, email: str) -> None:
    s = get_settings()
    with _lock:
        _recent(_key(request, email), time.monotonic(), s.login_failure_window_seconds).append(
            time.monotonic()
        )
        if len(_failures) > 10_000:  # bound memory: drop keys with no recent failures
            for k in [k for k, v in _failures.items() if not v]:
                del _failures[k]


def record_login_success(request: Request, email: str) -> None:
    with _lock:
        _failures.pop(_key(request, email), None)


def reset() -> None:
    """Clear all counters (tests)."""
    with _lock:
        _failures.clear()
