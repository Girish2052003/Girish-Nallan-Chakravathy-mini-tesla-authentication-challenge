"""Authenticated bootstrap for Mini-TESLA (independent of the TESLA key chain).

The receiver MUST already have an authentic, pinned Ed25519 public key.
A fresh receiver challenge binds every signed setup to one bootstrap attempt.
This module does not provide key provisioning or clock synchronization.
"""

from __future__ import annotations

import hmac
import re
import secrets
import struct
from dataclasses import dataclass, replace
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .hsm import KEY_SIZE, MAX_CHAIN_LENGTH
from .protocol import Receiver, Satellite

SETUP_DOMAIN: Final = b"MINI-TESLA-SATELLITE-SETUP-ED25519\x00"
SETUP_VERSION: Final = 1
CHALLENGE_SIZE: Final = 32
SIGNATURE_SIZE: Final = 64
MAX_ID_SIZE: Final = 64
MAX_UINT32: Final = 2**32 - 1
_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)


class SetupRejected(ValueError):
    """An untrusted TESLA bootstrap did not pass the required checks."""


def _encode_setup(
    satellite_id: str, challenge: bytes, commitment: bytes,
    chain_length: int, disclosure_delay: int, version: int,
) -> bytes:
    """Canonical, domain-separated and length-delimited signature input."""
    if type(version) is not int or version != SETUP_VERSION:
        raise SetupRejected("unsupported setup version")
    if type(satellite_id) is not str or _ID_PATTERN.fullmatch(satellite_id) is None:
        raise SetupRejected("satellite_id must be 1..64 safe ASCII characters")
    if type(challenge) is not bytes or len(challenge) != CHALLENGE_SIZE:
        raise SetupRejected("challenge must be 32 bytes")
    if type(commitment) is not bytes or len(commitment) != KEY_SIZE:
        raise SetupRejected("commitment must be 32 bytes")
    if type(chain_length) is not int or not 1 <= chain_length <= MAX_CHAIN_LENGTH:
        raise SetupRejected("invalid chain length")
    if type(disclosure_delay) is not int or not 1 <= disclosure_delay <= MAX_UINT32:
        raise SetupRejected("invalid disclosure delay")

    identity = satellite_id.encode("ascii")
    return (
        SETUP_DOMAIN
        + struct.pack(">BB", version, len(identity))
        + identity
        + challenge
        + commitment
        + struct.pack(">II", chain_length, disclosure_delay)
    )


@dataclass(frozen=True, slots=True)
class SignedSetup:
    """A public, signed configuration. Contains no signing private key."""

    satellite_id: str
    challenge: bytes
    commitment: bytes
    chain_length: int
    disclosure_delay: int
    signature: bytes
    version: int = SETUP_VERSION

    def signed_bytes(self) -> bytes:
        return _encode_setup(
            self.satellite_id, self.challenge, self.commitment,
            self.chain_length, self.disclosure_delay, self.version,
        )


def sign_satellite_setup(
    satellite: Satellite, *,
    signing_key: Ed25519PrivateKey,
    satellite_id: str,
    challenge: bytes,
) -> SignedSetup:
    """Sign a receiver's challenge and the exact satellite session parameters.

    The signing key is supplied by trusted sender configuration; NEVER accept
    an attacker-provided signing key as the claimed satellite identity.
    """
    if type(satellite) is not Satellite:
        raise TypeError("satellite must be a Satellite instance")
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise TypeError("signing_key must be an Ed25519 private key")

    # Do not sign a reused or partially disclosed chain for a different
    # receiver challenge. Old disclosed interval keys would otherwise
    # allow authenticated-looking forgeries in a restarted receiver.
    if satellite._bootstrap_signed or satellite.current_interval != 1 or satellite._next_sequence != 1:
        raise SetupRejected("signed setup requires a fresh, unused satellite chain")

    unsigned = SignedSetup(
        satellite_id=satellite_id,
        challenge=challenge,
        commitment=satellite.commitment,
        chain_length=satellite.chain_length,
        disclosure_delay=satellite.disclosure_delay,
        signature=b"",
    )
    signed = replace(unsigned, signature=signing_key.sign(unsigned.signed_bytes()))
    satellite._bootstrap_signed = True
    return signed


class ReceiverBootstrap:
    """Single-use receiver-side bootstrap with a pinned sender public key.

    Build this object from trusted local configuration. Transmit `challenge`
    over an untrusted channel. Only a correctly signed response to that exact
    challenge can establish a receiver session; verified success consumes it.
    """

    def __init__(self, *, trusted_public_key: Ed25519PublicKey,
                 expected_satellite_id: str) -> None:
        if not isinstance(trusted_public_key, Ed25519PublicKey):
            raise TypeError("trusted_public_key must be an Ed25519 public key")
        if type(expected_satellite_id) is not str or _ID_PATTERN.fullmatch(expected_satellite_id) is None:
            raise ValueError("invalid expected_satellite_id")
        self._trusted_public_key = trusted_public_key
        self._expected_satellite_id = expected_satellite_id
        self._challenge = secrets.token_bytes(CHALLENGE_SIZE)
        self._used = False

    @property
    def challenge(self) -> bytes:
        return self._challenge

    def establish(self, setup: SignedSetup, *, max_sender_ahead: int = 0,
                  max_buffered_packets: int = 1024,
                  max_buffered_bytes: int = 8_388_608,
                  max_packets_per_interval: int = 256,
                  max_candidates_per_identity: int = 4,
                  disclosure_grace: int = 8) -> Receiver:
        """Verify sender identity, challenge, signature, and session parameters.

        No Receiver is constructed from the untrusted commitment before the
        signature and freshness checks succeed.
        """
        if self._used:
            raise SetupRejected("bootstrap challenge has already been consumed")
        if type(setup) is not SignedSetup:
            raise SetupRejected("expected a SignedSetup")
        # Validate/encode all fields *before* trusting any attacker-controlled
        # configuration, and use constant-time comparison for the challenge.
        encoded = setup.signed_bytes()
        if setup.satellite_id != self._expected_satellite_id:
            raise SetupRejected("unexpected satellite identity")
        if not hmac.compare_digest(setup.challenge, self._challenge):
            raise SetupRejected("setup does not match the fresh receiver challenge")
        if type(setup.signature) is not bytes or len(setup.signature) != SIGNATURE_SIZE:
            raise SetupRejected("invalid setup signature length")
        try:
            self._trusted_public_key.verify(setup.signature, encoded)
        except InvalidSignature as exc:
            raise SetupRejected("setup signature verification failed") from exc

        # Caller-controlled limits are local receiver policy, NOT data supplied
        # by the untrusted sender; the signed disclosure delay is protocol state.
        receiver = Receiver(
            commitment=setup.commitment,
            chain_length=setup.chain_length,
            disclosure_delay=setup.disclosure_delay,
            max_sender_ahead=max_sender_ahead,
            max_buffered_packets=max_buffered_packets,
            max_buffered_bytes=max_buffered_bytes,
            max_packets_per_interval=max_packets_per_interval,
            max_candidates_per_identity=max_candidates_per_identity,
            disclosure_grace=disclosure_grace,
        )
        self._used = True
        return receiver
