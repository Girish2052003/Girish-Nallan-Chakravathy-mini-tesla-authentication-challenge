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
import tempfile
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
MAX_CHAIN_LENGTH: Final = 4096
MAX_STATE_FILE_SIZE: Final = 1_048_576


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


def _require_chain_length(value: int) -> None:
    if type(value) is not int or not 1 <= value <= MAX_CHAIN_LENGTH:
        raise ValueError(f"chain_length must be an integer in [1, {MAX_CHAIN_LENGTH}]")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value}")


def _decode_keys(value: object, chain_length: int) -> dict[int, bytes]:
    if type(value) is not dict:
        raise ValueError("key map must be an object")
    result = {}
    for index, key in value.items():
        if (type(index) is not str or not index.isascii() or not index.isdecimal()
                or index.startswith("0") or len(index) > len(str(MAX_CHAIN_LENGTH))):
            raise ValueError("key index must be a canonical positive decimal integer")
        number = int(index)
        if not 1 <= number <= chain_length:
            raise ValueError("key index is outside the configured chain")
        if type(key) is not str:
            raise ValueError("encoded key must be a string")
        result[number] = _unb64(key)
    return result


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
        if type(role) is not str or role not in {"satellite", "receiver"}:
            raise ValueError("role must be 'satellite' or 'receiver'")
        if type(commitment) is not bytes or len(commitment) != KEY_SIZE:
            raise ValueError("commitment must be 32 bytes")
        _require_chain_length(chain_length)

        auth_keys = {} if auth_keys is None else auth_keys
        disclosed_keys = {} if disclosed_keys is None else disclosed_keys
        for keys in (auth_keys, disclosed_keys):
            if type(keys) is not dict:
                raise ValueError("keys must be dictionaries")
            if any(type(i) is not int or not 1 <= i <= chain_length
                   or type(key) is not bytes or len(key) != KEY_SIZE for i, key in keys.items()):
                raise ValueError("invalid key index or length")
        if role == "receiver" and auth_keys:
            raise ValueError("receiver cannot contain undisclosed authentication keys")
        if role == "satellite":
            if set(auth_keys) != set(range(1, chain_length + 1)) or disclosed_keys:
                raise ValueError("satellite requires one complete chain and no receiver key cache")
            previous = commitment
            for index in range(1, chain_length + 1):
                if not stdlib_hmac.compare_digest(_sha256(auth_keys[index]), previous):
                    raise ValueError("authentication chain does not match commitment")
                previous = auth_keys[index]
        # Validate sparse cached keys against one another and finally K0 in O(N),
        # rather than independently hashing each key all the way to K0 in O(N²).
        previous_index = 0
        previous_key = commitment
        for index in sorted(disclosed_keys):
            candidate = disclosed_keys[index]
            for _ in range(index - previous_index):
                candidate = _sha256(candidate)
            if not stdlib_hmac.compare_digest(candidate, previous_key):
                raise ValueError("cached disclosure does not match commitment")
            previous_index, previous_key = index, disclosed_keys[index]

        self._role = role
        self._commitment = bytes(commitment)
        self._chain_length = chain_length
        self._auth_keys = dict(auth_keys)
        self._disclosed_keys = dict(disclosed_keys)

    @classmethod
    def create_satellite(cls, chain_length: int) -> "HSM":
        """Generate a fresh SHA-256 one-way chain using CSPRNG key material."""

        _require_chain_length(chain_length)

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
        if type(interval) is not int:
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
        if type(disclosure_delay) is not int or not 1 <= disclosure_delay <= 2**32 - 1:
            raise HSMError("disclosure_delay must be a positive uint32 integer")
        if type(current_interval) is not int or current_interval < 1:
            raise HSMError("current_interval must be a positive integer")
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
        if type(key) is not bytes or len(key) != KEY_SIZE:
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

        temporary = None
        try:
            output_path = Path(path)
            fd, temporary = tempfile.mkstemp(prefix=f".{output_path.name}.", suffix=".tmp",
                                              dir=output_path.parent)
            # mkstemp creates mode 0600 on POSIX before any bytes are written.
            with os.fdopen(fd, "wb") as stream:
                stream.write(FILE_MAGIC + nonce + ciphertext)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, output_path)
        except (OSError, TypeError, ValueError) as exc:
            raise PersistenceError("unable to write encrypted HSM state") from exc
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    @classmethod
    def import_encrypted(cls, path: str | os.PathLike[str]) -> "HSM":
        """Restore HSM state using the master key supplied through the environment."""

        master_key = master_key_from_env()

        try:
            with Path(path).open("rb") as stream:
                blob = stream.read(MAX_STATE_FILE_SIZE + 1)
        except (OSError, TypeError, ValueError) as exc:
            raise PersistenceError("unable to read encrypted HSM state") from exc

        if len(blob) > MAX_STATE_FILE_SIZE:
            raise PersistenceError("encrypted HSM state is too large")

        minimum = len(FILE_MAGIC) + NONCE_SIZE + 16
        if len(blob) < minimum or not blob.startswith(FILE_MAGIC):
            raise PersistenceError("invalid encrypted HSM file format")

        nonce_start = len(FILE_MAGIC)
        nonce = blob[nonce_start : nonce_start + NONCE_SIZE]
        ciphertext = blob[nonce_start + NONCE_SIZE :]
        try:
            plaintext = AESGCM(master_key).decrypt(nonce, ciphertext, FILE_MAGIC)
            state = json.loads(plaintext.decode("utf-8"), object_pairs_hook=_unique_object,
                               parse_constant=_reject_constant)
        except (InvalidTag, UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise PersistenceError("HSM file authentication/decryption failed") from exc

        try:
            expected = {"version", "role", "chain_length", "commitment", "auth_keys", "disclosed_keys"}
            if type(state) is not dict or set(state) != expected:
                raise ValueError("HSM state has missing or unexpected fields")
            if type(state["version"]) is not int or state["version"] != 1:
                raise ValueError("unsupported HSM state version")
            role = state["role"]
            chain_length = state["chain_length"]
            _require_chain_length(chain_length)
            if type(state["commitment"]) is not str:
                raise ValueError("commitment must be an encoded string")
            commitment = _unb64(state["commitment"])
            auth_keys = _decode_keys(state["auth_keys"], chain_length)
            disclosed_keys = _decode_keys(state["disclosed_keys"], chain_length)
            return cls(role=role, commitment=commitment, chain_length=chain_length,
                       auth_keys=auth_keys, disclosed_keys=disclosed_keys)
        except (KeyError, TypeError, ValueError) as exc:
            raise PersistenceError("malformed HSM state") from exc

    def __repr__(self) -> str:
        return (
            f"HSM(role={self._role!r}, chain_length={self._chain_length}, "
            f"validated_disclosures={len(self._disclosed_keys)})"
        )
