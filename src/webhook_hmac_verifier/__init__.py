"""Verify HMAC-SHA256 webhook signatures of the form ``t=<unix>,v1=<hex>``.

The signed payload is ``<t>.<raw request body>``. A request is accepted only if
at least one ``v1`` signature matches and the timestamp lies inside the allowed
tolerance window. Standard library only.

This module checks authenticity and freshness. It does not detect replays
inside the tolerance window and does not make processing idempotent; see the
README for what that would take.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

__all__ = [
    "DEFAULT_TOLERANCE_SECONDS",
    "SignatureError",
    "MalformedHeader",
    "NoMatchingSignature",
    "TimestampOutOfTolerance",
    "Verified",
    "parse_header",
    "sign",
    "verify",
]

__version__ = "0.1.0"

DEFAULT_TOLERANCE_SECONDS = 300
_MAX_HEADER_LENGTH = 4096
_SCHEME = "v1"


class SignatureError(Exception):
    """Base class for every verification failure."""


class MalformedHeader(SignatureError):
    """The signature header cannot be parsed."""


class NoMatchingSignature(SignatureError):
    """No ``v1`` signature in the header matches the body and secret."""


class TimestampOutOfTolerance(SignatureError):
    """The signed timestamp is too old or too far in the future."""


@dataclass(frozen=True)
class Verified:
    """Result of a successful verification."""

    timestamp: int
    age_seconds: int


def parse_header(header: str) -> tuple[int, list[str]]:
    """Return ``(timestamp, [v1 signatures])`` from a signature header.

    Unknown schemes are ignored so that a sender can add new schemes later.
    Raises :class:`MalformedHeader` if there is no single valid timestamp or no
    ``v1`` signature.
    """
    if not isinstance(header, str) or not header.strip():
        raise MalformedHeader("empty signature header")
    if len(header) > _MAX_HEADER_LENGTH:
        raise MalformedHeader("signature header too long")

    timestamps: list[str] = []
    signatures: list[str] = []
    for part in header.split(","):
        key, sep, value = part.strip().partition("=")
        if not sep or not key or not value:
            raise MalformedHeader("signature header element is not key=value")
        if key == "t":
            timestamps.append(value)
        elif key == _SCHEME:
            signatures.append(value.lower())

    if len(timestamps) != 1:
        raise MalformedHeader("signature header must contain exactly one t=")
    if not (timestamps[0].isascii() and timestamps[0].isdigit()):
        raise MalformedHeader("timestamp is not a non-negative integer")
    if not signatures:
        raise MalformedHeader("signature header contains no v1 signature")
    for sig in signatures:
        if len(sig) != 64 or any(c not in "0123456789abcdef" for c in sig):
            raise MalformedHeader("v1 signature is not 64 hex characters")
    return int(timestamps[0]), signatures


def _expected(secret: bytes, timestamp: int, body: bytes) -> str:
    message = str(timestamp).encode("ascii") + b"." + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def sign(secret: bytes, body: bytes, timestamp: int | None = None) -> str:
    """Build a signature header for ``body``. Useful for tests and senders."""
    _check_types(secret, body)
    ts = int(time.time()) if timestamp is None else int(timestamp)
    if ts < 0:
        raise ValueError("timestamp must be non-negative")
    return f"t={ts},{_SCHEME}={_expected(secret, ts, body)}"


def verify(
    secret: bytes,
    body: bytes,
    header: str,
    *,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
) -> Verified:
    """Verify ``header`` against the raw ``body``.

    ``body`` must be the exact bytes received, before any JSON parsing or
    re-encoding. Raises a :class:`SignatureError` subclass on failure.
    The signature is checked before the timestamp, so a forged request never
    learns whether its timestamp would have been accepted.
    """
    _check_types(secret, body)
    if tolerance_seconds < 0:
        raise ValueError("tolerance_seconds must be non-negative")

    timestamp, signatures = parse_header(header)
    expected = _expected(secret, timestamp, body)
    matched = False
    for candidate in signatures:
        # Compare every candidate so timing does not reveal which one matched.
        if hmac.compare_digest(candidate, expected):
            matched = True
    if not matched:
        raise NoMatchingSignature("no v1 signature matches")

    current = int(time.time()) if now is None else int(now)
    age = current - timestamp
    if abs(age) > tolerance_seconds:
        raise TimestampOutOfTolerance(
            f"timestamp outside tolerance ({tolerance_seconds}s)"
        )
    return Verified(timestamp=timestamp, age_seconds=age)


def _check_types(secret: bytes, body: bytes) -> None:
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise TypeError("secret must be non-empty bytes")
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("body must be the raw request bytes")
