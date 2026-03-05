from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional
import hmac
import re

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:  # pragma: no cover
    Fernet = None  # type: ignore[assignment]
    InvalidToken = Exception  # type: ignore[assignment]


DEFAULT_KEY_ENV = "APP_ENCRYPTION_KEY"


def generate_key() -> str:
    """Generate a new Fernet-compatible key."""
    if Fernet is None:
        raise ImportError("Missing dependency: cryptography")
    return Fernet.generate_key().decode("utf-8")


def _normalize_to_fernet_key(raw_key: str) -> bytes:
    """Accept a Fernet key or derive one deterministically from a plain secret."""
    key_bytes = raw_key.encode("utf-8")
    try:
        # Fast-path for already-valid Fernet keys.
        Fernet(key_bytes)
        return key_bytes
    except Exception:
        # Derive a 32-byte key from user-provided secret text.
        digest = hashlib.sha256(key_bytes).digest()
        return base64.urlsafe_b64encode(digest)


def _build_fernet(key: Optional[str] = None, *, key_env: str = DEFAULT_KEY_ENV) -> Fernet:
    if Fernet is None:
        raise ImportError("Missing dependency: cryptography")

    raw_key = key or os.getenv(key_env)
    if not raw_key:
        raise ValueError(
            f"Encryption key not provided. Pass `key=` or set environment variable {key_env}."
        )
    return Fernet(_normalize_to_fernet_key(raw_key))


def encrypt_text(plaintext: str, *, key: Optional[str] = None, key_env: str = DEFAULT_KEY_ENV) -> str:
    """Encrypt UTF-8 text and return a URL-safe token string."""
    f = _build_fernet(key=key, key_env=key_env)
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_text(
    ciphertext: str, *, key: Optional[str] = None, key_env: str = DEFAULT_KEY_ENV
) -> Optional[str]:
    """Decrypt a Fernet token and return UTF-8 plaintext, or None on failure."""
    f = _build_fernet(key=key, key_env=key_env)
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None




_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SALT_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{64}$")

DEFAULT_ITERATIONS = 260_000

def hash_sha256(value: str) -> str:
    """Return hex-encoded SHA-256 digest for text input."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def verify_sha256(value: str, expected_hex_digest: str) -> bool:
    """Constant-time verification for SHA-256 digest."""
    expected = expected_hex_digest.strip().lower()
    candidate = value.strip()
    if _SHA256_HEX_RE.fullmatch(candidate):
        actual = candidate.lower()
    else:
        actual = hash_sha256(candidate)
    return hmac.compare_digest(actual, expected)


def hash_with_salt(value: str, *, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Return a salted PBKDF2-HMAC-SHA256 digest as ``salt_hex:hash_hex``.
    A fresh 16-byte salt is generated for every call, so identical inputs
    produce different output strings — safe for password storage.
    """
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        salt,
        iterations,
    )
    return salt.hex() + ":" + dk.hex()


def verify_hash_with_salt(value: str, stored: str, *, iterations: int = DEFAULT_ITERATIONS) -> bool:
    """Constant-time verification for a salted PBKDF2-HMAC-SHA256 digest.
    ``stored`` must be a string previously returned by :func:`hash_with_salt`
    in the form ``salt_hex:hash_hex``.
    """
    stored = stored.strip()
    if not _SALT_HASH_RE.fullmatch(stored):
        raise ValueError(
            "Invalid stored hash format. Expected 'salt_hex:hash_hex' from hash_with_salt()."
        )
    salt_hex, hash_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(dk.hex(), hash_hex)