"""A small HSM-like cryptographic boundary for the Mini-TESLA challenge.

This class intentionally models *properties* of an HSM rather than claiming to be
one. Secret authentication keys remain private to the satellite-side instance and
are only returned by the explicit, policy-checked ``disclose_key`` operation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as stdlib_hmac
import json
import os
import secrets
from pathlib import Path
from typing import Final

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE: Final = 32
TAG_SIZE: Final = 32
NONCE_SIZE: Final = 12
FILE_MAGIC: Final = b"MINITESLA-HSM\x01"
DEFAULT_MASTER_KEY_ENV: Final = "MINITESLA_MASTER_KEY"


class HSMError(Exception):
    """Base class for HSM boundary errors."""


class EarlyDisclosureError(HSMError):
    """Raised when a key is requested before its disclosure interval."""


class InvalidKeyDisclosure(HSMError):
    """Raised when a disclosed key does not authenticate to the commitment."""


class PersistenceError(HSMError):
    """Raised when an encrypted HSM state cannot be exported or imported."""


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise PersistenceError("invalid base64 data in HSM state") from exc


def master_key_from_env(name: str = DEFAULT_MASTER_KEY_ENV) -> bytes:
    """Load a base64-encoded 32-byte AES-256 master key from an environment variable."""

    encoded = os.environ.get(name)
    if not encoded:
        raise PersistenceError(f"required environment variable {name!r} is not set")
    try:
        key = base64.b64decode(encoded.strip().encode("ascii"), validate=True)
    except Exception as exc:
        raise PersistenceError(f"{name!r} must contain valid base64") from exc
    if len(key) != KEY_SIZE:
        raise PersistenceError(f"{name!r} must decode to exactly 32 bytes")
    return key


class HSM:
    """HSM-like key store and cryptographic engine."""

    def __init__(
        self,
        *,
        role: str,
        commitment: bytes,
        chain_length: int,
        auth_keys: dict[int, bytes] | None = None,
        disclosed_keys: dict[int, bytes] | None = None,
    ) -> None:
        if role not in {"satellite", "receiver"}:
            raise ValueError("role must be 'satellite' or 'receiver'")
        if len(commitment) != KEY_SIZE:
            raise ValueError("commitment must be 32 bytes")
        if chain_length < 1:
            raise ValueError("chain_length must be at least 1")

        self._role = role
        self._commitment = bytes(commitment)
        self._chain_length = chain_length
        self._auth_keys = dict(auth_keys or {})
        self._disclosed_keys = dict(disclosed_keys or {})

    @classmethod
    def create_satellite(cls, chain_length: int) -> "HSM":
        """Generate a fresh SHA-256 one-way chain using CSPRNG key material."""

        if chain_length < 1:
            raise ValueError("chain_length must be at least 1")

        chain: list[bytes] = [b""] * (chain_length + 1)
        chain[chain_length] = secrets.token_bytes(KEY_SIZE)
        for index in range(chain_length, 0, -1):
            chain[index - 1] = _sha256(chain[index])

        return cls(
            role="satellite",
            commitment=chain[0],
            chain_length=chain_length,
            auth_keys={index: chain[index] for index in range(1, chain_length + 1)},
        )

    @classmethod
    def create_receiver(cls, commitment: bytes, chain_length: int) -> "HSM":
        return cls(role="receiver", commitment=commitment, chain_length=chain_length)

    @property
    def commitment(self) -> bytes:
        return self._commitment

    @property
    def chain_length(self) -> int:
        return self._chain_length

    @property
    def role(self) -> str:
        return self._role

    def _require_interval(self, interval: int) -> None:
        if not isinstance(interval, int) or isinstance(interval, bool):
            raise HSMError("interval must be an integer")
        if not 1 <= interval <= self._chain_length:
            raise HSMError("interval is outside the configured key chain")

    def generate_mac(self, interval: int, authenticated_data: bytes) -> bytes:
        """Generate HMAC-SHA256 without exposing the interval key."""

        if self._role != "satellite":
            raise HSMError("receiver HSM cannot generate satellite MACs")
        self._require_interval(interval)
        if not isinstance(authenticated_data, bytes):
            raise TypeError("authenticated_data must be bytes")

        key = self._auth_keys[interval]
        mac = hmac.HMAC(key, hashes.SHA256())
        mac.update(authenticated_data)
        return mac.finalize()

    def disclose_key(self, interval: int, *, current_interval: int, disclosure_delay: int) -> bytes:
        """Explicitly disclose a key only after the configured delay has passed."""

        if self._role != "satellite":
            raise HSMError("receiver HSM has no undisclosed satellite keys")
        self._require_interval(interval)
        if disclosure_delay < 1:
            raise HSMError("disclosure_delay must be at least 1")
        if current_interval < interval + disclosure_delay:
            raise EarlyDisclosureError(
                f"key for interval {interval} is not disclosable until interval "
                f"{interval + disclosure_delay}"
            )
        return bytes(self._auth_keys[interval])

    def validate_and_store_disclosed_key(self, interval: int, key: bytes) -> None:
        """Authenticate a disclosed chain key against the trusted commitment."""

        if self._role != "receiver":
            raise HSMError("satellite HSM does not import disclosed receiver keys")
        self._require_interval(interval)
        if not isinstance(key, bytes) or len(key) != KEY_SIZE:
            raise InvalidKeyDisclosure("disclosed key must be exactly 32 bytes")

        candidate = key
        for _ in range(interval):
            candidate = _sha256(candidate)
        if not stdlib_hmac.compare_digest(candidate, self._commitment):
            raise InvalidKeyDisclosure("disclosed key does not authenticate to the trusted commitment")

        previous = self._disclosed_keys.get(interval)
        if previous is not None and not stdlib_hmac.compare_digest(previous, key):
            raise InvalidKeyDisclosure("a different key was already validated for this interval")
        self._disclosed_keys[interval] = bytes(key)

    def has_disclosed_key(self, interval: int) -> bool:
        return interval in self._disclosed_keys

    def verify_mac(self, interval: int, authenticated_data: bytes, tag: bytes) -> bool:
        """Verify HMAC-SHA256 using a previously validated disclosed key."""

        if self._role != "receiver":
            raise HSMError("MAC verification with disclosed keys belongs to the receiver HSM")
        self._require_interval(interval)
        if interval not in self._disclosed_keys:
            raise HSMError("no validated disclosed key is available for this interval")
        if not isinstance(authenticated_data, bytes):
            raise TypeError("authenticated_data must be bytes")
        if not isinstance(tag, bytes) or len(tag) != TAG_SIZE:
            return False

        mac = hmac.HMAC(self._disclosed_keys[interval], hashes.SHA256())
        mac.update(authenticated_data)
        try:
            mac.verify(tag)
            return True
        except InvalidSignature:
            return False

    def export_encrypted(self, path: str | os.PathLike[str]) -> None:
        """Persist the HSM key store using the environment-provided AES-256 key."""

        master_key = master_key_from_env()

        state = {
            "version": 1,
            "role": self._role,
            "chain_length": self._chain_length,
            "commitment": _b64(self._commitment),
            "auth_keys": {str(i): _b64(k) for i, k in self._auth_keys.items()},
            "disclosed_keys": {str(i): _b64(k) for i, k in self._disclosed_keys.items()},
        }
        plaintext = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = AESGCM(master_key).encrypt(nonce, plaintext, FILE_MAGIC)

        output_path = Path(path)
        try:
            output_path.write_bytes(FILE_MAGIC + nonce + ciphertext)
            # Best-effort restrictive permissions on POSIX-like systems.
            os.chmod(output_path, 0o600)
        except OSError as exc:
            raise PersistenceError("unable to write encrypted HSM state") from exc

    @classmethod
    def import_encrypted(cls, path: str | os.PathLike[str]) -> "HSM":
        """Restore HSM state using the master key supplied through the environment."""

        master_key = master_key_from_env()

        try:
            blob = Path(path).read_bytes()
        except OSError as exc:
            raise PersistenceError("unable to read encrypted HSM state") from exc

        minimum = len(FILE_MAGIC) + NONCE_SIZE + 16
        if len(blob) < minimum or not blob.startswith(FILE_MAGIC):
            raise PersistenceError("invalid encrypted HSM file format")

        nonce_start = len(FILE_MAGIC)
        nonce = blob[nonce_start : nonce_start + NONCE_SIZE]
        ciphertext = blob[nonce_start + NONCE_SIZE :]
        try:
            plaintext = AESGCM(master_key).decrypt(nonce, ciphertext, FILE_MAGIC)
            state = json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PersistenceError("HSM file authentication/decryption failed") from exc

        try:
            if state.get("version") != 1:
                raise PersistenceError("unsupported HSM state version")
            role = state["role"]
            chain_length = int(state["chain_length"])
            commitment = _unb64(state["commitment"])
            auth_keys = {int(i): _unb64(k) for i, k in state.get("auth_keys", {}).items()}
            disclosed_keys = {
                int(i): _unb64(k) for i, k in state.get("disclosed_keys", {}).items()
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise PersistenceError("malformed HSM state") from exc

        if role == "receiver" and auth_keys:
            raise PersistenceError("receiver state must not contain undisclosed authentication keys")
        if role == "satellite" and set(auth_keys) != set(range(1, chain_length + 1)):
            raise PersistenceError("satellite state does not contain the complete key chain")
        if any(len(key) != KEY_SIZE for key in [*auth_keys.values(), *disclosed_keys.values()]):
            raise PersistenceError("persisted keys must be exactly 32 bytes")

        return cls(
            role=role,
            commitment=commitment,
            chain_length=chain_length,
            auth_keys=auth_keys,
            disclosed_keys=disclosed_keys,
        )

    def __repr__(self) -> str:
        return (
            f"HSM(role={self._role!r}, chain_length={self._chain_length}, "
            f"validated_disclosures={len(self._disclosed_keys)})"
        )
