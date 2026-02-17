from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Deque, Dict, Optional, Tuple

SESSION_COOKIE_NAME = "uptimemesh_session"
PASSWORD_HASH_ALGORITHM = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 120_000


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_password(password: str, *, iterations: int = PASSWORD_HASH_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{PASSWORD_HASH_ALGORITHM}${iterations}${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    parts = encoded_hash.split("$")
    if len(parts) != 4:
        return False
    algorithm, iteration_str, salt_hex, digest_hex = parts
    if algorithm != PASSWORD_HASH_ALGORITHM:
        return False
    try:
        iterations = int(iteration_str)
        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False

    computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(computed, expected_digest)


def create_session_token(
    username: str,
    secret_key: str,
    *,
    ttl_seconds: int,
    now: Optional[int] = None,
) -> str:
    issued_at = now if now is not None else int(time.time())
    payload = {
        "u": username,
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = _b64url_encode(payload_json)
    signature = hmac.new(
        secret_key.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{payload_b64}.{_b64url_encode(signature)}"


def decode_session_token(
    token: str, secret_key: str, *, now: Optional[int] = None
) -> Optional[str]:
    try:
        payload_b64, signature_b64 = token.split(".", 1)
    except ValueError:
        return None

    expected_signature = hmac.new(
        secret_key.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    try:
        actual_signature = _b64url_decode(signature_b64)
    except (ValueError, TypeError):
        return None

    if not hmac.compare_digest(actual_signature, expected_signature):
        return None

    try:
        payload = json.loads(_b64url_decode(payload_b64))
        username = payload["u"]
        expires_at = int(payload["exp"])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return None

    if not isinstance(username, str) or not username:
        return None

    current = now if now is not None else int(time.time())
    if expires_at < current:
        return None

    return username


def sanitize_next_path(next_path: Optional[str], *, fallback: str = "/ui") -> str:
    if not next_path:
        return fallback
    if not next_path.startswith("/"):
        return fallback
    if next_path.startswith("//"):
        return fallback
    return next_path


@dataclass
class _RateBucket:
    failures: Deque[float] = field(default_factory=deque)
    blocked_until: float = 0.0


class LoginRateLimiter:
    def __init__(
        self, *, max_failures: int = 5, window_seconds: int = 60, lockout_seconds: int = 300
    ) -> None:
        self._max_failures = max_failures
        self._window_seconds = window_seconds
        self._lockout_seconds = lockout_seconds
        self._buckets: Dict[str, _RateBucket] = {}
        self._lock = Lock()

    def check(self, key: str) -> Tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return True, 0
            self._prune(bucket, now)
            if bucket.blocked_until > now:
                return False, max(1, math.ceil(bucket.blocked_until - now))
            return True, 0

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.setdefault(key, _RateBucket())
            self._prune(bucket, now)
            bucket.failures.append(now)
            if len(bucket.failures) >= self._max_failures:
                bucket.blocked_until = now + self._lockout_seconds
                bucket.failures.clear()

    def record_success(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)

    def _prune(self, bucket: _RateBucket, now: float) -> None:
        threshold = now - self._window_seconds
        while bucket.failures and bucket.failures[0] < threshold:
            bucket.failures.popleft()
