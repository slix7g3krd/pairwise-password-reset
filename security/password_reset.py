"""Password-reset primitives with secure defaults.

The previous implementation made account takeover practical: tokens were
``md5(email + timestamp)`` (guessable and not tied to the user), reusable,
long-lived, logged in clear text, and reset links were built from the
attacker-controlled ``Host`` header.  This module fixes all of those issues.

Design rules:

* Tokens are generated from the operating system CSPRNG and contain at least
  256 bits of entropy.  Only their SHA-256 digest is stored.
* A token is valid only while unused, unexpired, and while the account's
  password hash is unchanged.  Consumption is a single mutating operation.
* Issuing a new token invalidates every previous token for that account.
* Reset responses are identical whether or not the address exists, so the
  endpoint cannot be used to enumerate users.
* Reset URLs always use a configured origin; inbound ``Host`` headers are
  ignored.
* Logs never contain raw tokens (``redact_token``).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from typing import Any, Dict, Optional
from urllib.parse import quote

# A reset link should be usable quickly, not for a week.
TOKEN_TTL_SECONDS = 15 * 60

# 32 random bytes -> 43 URL-safe base64 characters (A-Z, a-z, 0-9, "-", "_").
TOKEN_BYTES = 32
TOKEN_MIN_LENGTH = 32

# Never derive this from the request; doing so lets an attacker who controls
# the Host header receive the victim's token.
RESET_URL_BASE = "https://app.example/reset"

# Identical copy for existing and non-existing accounts.
_RESET_RESPONSE = (
    "If an account exists for that email address, "
    "password reset instructions have been sent."
)

_SENSITIVE_KEY_VALUE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])"
    r"[A-Za-z0-9_.-]*(?:token|tok|secret|passw|pwd|key|auth|session|code|sig)"
    r"[A-Za-z0-9_.-]*"
    r"\s*[:=]\s*[\"']?[^&\s;,\"']+[\"']?"
)
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_LONG_OPAQUE_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])")

_TOKEN_HASH_RE = re.compile(r"[a-f0-9]{64}")


def _now(timestamp: Optional[float] = None) -> float:
    """Return a numeric timestamp, defaulting to the current time."""

    return time.time() if timestamp is None else timestamp


def hash_token(token: str) -> str:
    """Return the SHA-256 digest stored in place of a raw token."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token(nbytes: int = TOKEN_BYTES) -> str:
    """Return a fresh high-entropy token (>= 32 characters)."""

    if nbytes < TOKEN_BYTES:
        nbytes = TOKEN_BYTES
    return secrets.token_urlsafe(nbytes)


def _hash_matches(expected: Any, token: str) -> bool:
    """Constant-time comparison of a stored digest with a candidate token."""

    digest = hashlib.sha256(token.encode("utf-8"))
    if isinstance(expected, bytes):
        candidate: Any = digest.digest()
    elif isinstance(expected, str) and _TOKEN_HASH_RE.fullmatch(expected):
        candidate = digest.hexdigest()
    else:
        return False
    return hmac.compare_digest(expected, candidate)


def token_valid(
    record: Any,
    token: Any,
    now: Optional[float] = None,
    pw_hash: Optional[str] = None,
) -> bool:
    """Return whether *token* may still be used for *record*.

    A token is valid only when it hashes to the stored digest, has not been
    consumed, has not expired, and was issued against the account's current
    password hash.  Anything malformed fails closed.
    """

    if not isinstance(record, dict) or not record:
        return False
    if not isinstance(token, str) or not token:
        return False

    if record.get("used", False):
        return False

    expires = record.get("expires")
    if expires is None:
        return False
    try:
        if expires <= _now(now):
            return False
    except TypeError:
        return False

    # Bind the token to the password hash it was issued for.  After a
    # password change every outstanding link becomes invalid automatically.
    if not isinstance(pw_hash, str) or not pw_hash:
        return False
    bound_hash = record.get("pw_hash")
    if not isinstance(bound_hash, str) or not bound_hash:
        return False
    if not hmac.compare_digest(bound_hash, pw_hash):
        return False

    expected = record.get("token_hash")
    if expected is None:
        return False
    return _hash_matches(expected, token)


def consume_token(
    store: Any,
    token: Any,
    now: Optional[float] = None,
) -> bool:
    """Atomically validate and consume *token*.

    ``store`` may be keyed either by the raw token or by its SHA-256 digest.
    Returns ``True`` only for the first successful consumption.
    """

    if not isinstance(store, dict):
        return False
    if not isinstance(token, str) or not token:
        return False

    now = _now(now)
    for key in (token, hash_token(token)):
        record = store.get(key)
        if record is None:
            continue
        if not isinstance(record, dict):
            return False
        if record.get("used", False):
            return False
        expires = record.get("expires")
        if expires is None:
            return False
        try:
            if expires <= now:
                return False
        except TypeError:
            return False
        record["used"] = True
        record["used_at"] = now
        return True
    return False


def invalidate_user_tokens(
    store: Dict[str, Any],
    user_id: Any,
) -> int:
    """Mark every outstanding token for *user_id* as used.

    Called when a new reset is requested (so only the newest link works) and
    after a successful password change.  Returns the number invalidated.
    """

    if not isinstance(store, dict):
        return 0
    invalidated = 0
    for record in store.values():
        if not isinstance(record, dict):
            continue
        if record.get("user_id") != user_id or record.get("used", False):
            continue
        record["used"] = True
        invalidated += 1
    return invalidated


def issue_token(
    store: Dict[str, Any],
    user_id: Any,
    pw_hash: str,
    now: Optional[float] = None,
    ttl: int = TOKEN_TTL_SECONDS,
) -> str:
    """Create a token for *user_id* and revoke any previous ones.

    The raw token is returned for the email; only its digest is persisted.
    """

    if ttl <= 0 or ttl > TOKEN_TTL_SECONDS:
        raise ValueError("token TTL must be positive and short-lived")
    if not isinstance(pw_hash, str) or not pw_hash:
        raise ValueError("a current password hash is required")

    now = _now(now)
    invalidate_user_tokens(store, user_id)

    token = new_token()
    store[hash_token(token)] = {
        "token_hash": hash_token(token),
        "user_id": user_id,
        "pw_hash": pw_hash,
        "created": now,
        "expires": now + ttl,
        "used": False,
    }
    return token


def reset_response(email_exists: Optional[bool] = None) -> str:
    """Return the same message regardless of account existence."""

    return _RESET_RESPONSE


def build_reset_url(token: str, host: Optional[str] = None) -> str:
    """Build a reset URL from the configured origin.

    ``host`` is accepted for call-site compatibility but deliberately ignored:
    trusting it would let an attacker set ``Host: evil.example`` and receive a
    victim's token.
    """

    if not isinstance(token, str) or not token:
        raise ValueError("token is required")
    return "{base}?token={token}".format(base=RESET_URL_BASE, token=quote(token, safe=""))


def revoke_sessions(sessions: Dict[Any, Any], user_id: Any) -> int:
    """Drop all sessions for *user_id* and return how many were revoked."""

    if not isinstance(sessions, dict):
        return 0
    existing = sessions.get(user_id) or []
    try:
        count = len(existing)
    except TypeError:
        count = 0
    sessions[user_id] = []
    return count


def redact_token(text: Any) -> Any:
    """Remove raw tokens from a log line or URL.

    Handles ``token=...``/``token: ...`` pairs, ``Bearer`` credentials, and
    bare high-entropy tokens.  The key is removed along with its value so that
    even a short parameter name cannot collide with a secret.
    """

    if not isinstance(text, str):
        return text

    text = _SENSITIVE_KEY_VALUE.sub("[REDACTED]", text)
    text = _BEARER_TOKEN.sub("Bearer [REDACTED]", text)
    text = _LONG_OPAQUE_TOKEN.sub("[REDACTED]", text)
    return text


def normalize_email(email: Any) -> str:
    """Canonicalize an email for lookups and rate-limit keys."""

    if not isinstance(email, str):
        return ""
    return email.strip().casefold()


def new_csrf_token(nbytes: int = TOKEN_BYTES) -> str:
    """Return a random token suitable for a per-session CSRF secret."""

    return secrets.token_urlsafe(max(nbytes, TOKEN_BYTES))


def verify_csrf(session_token: Any, submitted_token: Any) -> bool:
    """Constant-time CSRF check for the password-reset POST."""

    if not isinstance(session_token, str) or not session_token:
        return False
    if not isinstance(submitted_token, str) or not submitted_token:
        return False
    return hmac.compare_digest(session_token, submitted_token)


def allow_request(
    buckets: Dict[str, list],
    key: str,
    now: Optional[float] = None,
    limit: int = 5,
    window: int = 15 * 60,
) -> bool:
    """Sliding-window rate limiter for reset requests.

    ``buckets`` is the caller-owned mutable state; *key* should normally be
    ``normalize_email(email)`` combined with the client IP.  Returns ``False``
    once *limit* requests have been made inside *window* seconds.
    """

    if not isinstance(buckets, dict) or not isinstance(key, str) or not key:
        return False
    if limit <= 0 or window <= 0:
        return False

    now = _now(now)
    cutoff = now - window
    recent = [stamp for stamp in buckets.get(key, []) if stamp > cutoff]

    if len(recent) >= limit:
        buckets[key] = recent
        return False

    recent.append(now)
    buckets[key] = recent
    return True
