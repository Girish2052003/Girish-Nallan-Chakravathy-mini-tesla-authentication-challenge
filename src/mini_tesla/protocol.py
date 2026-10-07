"""Mini-TESLA satellite and receiver protocol state machines."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Final

from .hsm import HSM, HSMError, InvalidKeyDisclosure, TAG_SIZE

PROTOCOL_VERSION: Final = 1
WIRE_DOMAIN: Final = b"MINI-TESLA-AUTH\\x00"
MAX_PAYLOAD_SIZE: Final = 1_048_576


class ProtocolError(Exception):
    """Base class for protocol-state errors."""


class PacketRejected(ProtocolError):
    """Raised when an incoming packet violates protocol or timing rules."""


class ReplayDetected(PacketRejected):
    """Raised when an already-seen logical message is received again."""


class DisclosureRejected(ProtocolError):
    """Raised when a key disclosure is early, malformed, or cryptographically invalid."""


@dataclass(frozen=True, slots=True)
class AuthPacket:
    """Authenticated message plus the metadata covered by its MAC."""

    interval: int
    sequence: int
    disclosure_delay: int
    payload: bytes
    tag: bytes
    version: int = PROTOCOL_VERSION

    def authenticated_bytes(self) -> bytes:
        """Return a deterministic, unambiguous byte representation for HMAC."""

        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be bytes")
        header = struct.pack(
            ">B I Q I I",
            self.version,
            self.interval,
            self.sequence,
            self.disclosure_delay,
            len(self.payload),
        )
        return WIRE_DOMAIN + header + self.payload

    @property
    def identity(self) -> tuple[int, int]:
        return (self.interval, self.sequence)

    @property
    def wire_fingerprint(self) -> bytes:
        return hashlib.sha256(self.authenticated_bytes() + self.tag).digest()


@dataclass(frozen=True, slots=True)
class VerificationResult:
    packet: AuthPacket
    accepted: bool
    reason: str


class Satellite:
    """Mini-TESLA sender using a private satellite-side HSM instance."""

    def __init__(self, *, chain_length: int = 32, disclosure_delay: int = 1) -> None:
        if disclosure_delay < 1:
            raise ValueError("disclosure_delay must be at least 1")
        self.hsm = HSM.create_satellite(chain_length)
        self.disclosure_delay = disclosure_delay
        self.current_interval = 1
        self._next_sequence = 1

    @property
    def commitment(self) -> bytes:
        return self.hsm.commitment

    @property
    def chain_length(self) -> int:
        return self.hsm.chain_length

    def authenticate(self, payload: bytes) -> AuthPacket:
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if len(payload) > MAX_PAYLOAD_SIZE:
            raise ValueError("payload exceeds maximum supported size")
        if self.current_interval > self.chain_length:
            raise ProtocolError("key chain is exhausted")

        unsigned = AuthPacket(
            interval=self.current_interval,
            sequence=self._next_sequence,
            disclosure_delay=self.disclosure_delay,
            payload=payload,
            tag=b"",
        )
        tag = self.hsm.generate_mac(unsigned.interval, unsigned.authenticated_bytes())
        packet = AuthPacket(
            interval=unsigned.interval,
            sequence=unsigned.sequence,
            disclosure_delay=unsigned.disclosure_delay,
            payload=unsigned.payload,
            tag=tag,
        )
        self._next_sequence += 1
        return packet

    def advance(self, steps: int = 1) -> int:
        if not isinstance(steps, int) or isinstance(steps, bool) or steps < 1:
            raise ValueError("steps must be a positive integer")
        self.current_interval += steps
        return self.current_interval

    def disclose(self, interval: int) -> bytes:
        return self.hsm.disclose_key(
            interval,
            current_interval=self.current_interval,
            disclosure_delay=self.disclosure_delay,
        )


class Receiver:
    """Mini-TESLA receiver that buffers first and authenticates after disclosure."""

    def __init__(
        self,
        *,
        commitment: bytes,
        chain_length: int,
        disclosure_delay: int = 1,
    ) -> None:
        if disclosure_delay < 1:
            raise ValueError("disclosure_delay must be at least 1")
        self.hsm = HSM.create_receiver(commitment, chain_length)
        self.disclosure_delay = disclosure_delay
        self.current_interval = 1
        self._buffer: dict[int, list[AuthPacket]] = {}
        self._reserved_ids: set[tuple[int, int]] = set()
        self._accepted_ids: set[tuple[int, int]] = set()

    def advance(self, steps: int = 1) -> int:
        if not isinstance(steps, int) or isinstance(steps, bool) or steps < 1:
            raise ValueError("steps must be a positive integer")
        self.current_interval += steps
        return self.current_interval

    def _validate_packet_shape(self, packet: AuthPacket) -> None:
        if not isinstance(packet, AuthPacket):
            raise PacketRejected("packet has an unexpected type")
        if packet.version != PROTOCOL_VERSION:
            raise PacketRejected("unsupported protocol version")
        if not 1 <= packet.interval <= self.hsm.chain_length:
            raise PacketRejected("packet interval is outside the configured key chain")
        if packet.interval > self.current_interval:
            raise PacketRejected("packet claims a future interval")
        if not isinstance(packet.sequence, int) or isinstance(packet.sequence, bool) or packet.sequence < 1:
            raise PacketRejected("sequence must be a positive integer")
        if packet.disclosure_delay != self.disclosure_delay:
            raise PacketRejected("packet disclosure delay does not match receiver policy")
        if not isinstance(packet.payload, bytes) or len(packet.payload) > MAX_PAYLOAD_SIZE:
            raise PacketRejected("payload is malformed or too large")
        if not isinstance(packet.tag, bytes) or len(packet.tag) != TAG_SIZE:
            raise PacketRejected("authentication tag must be exactly 32 bytes")

    def receive(self, packet: AuthPacket) -> str:
        """Apply the TESLA safety condition and buffer an unauthenticated packet."""

        self._validate_packet_shape(packet)

        if packet.identity in self._accepted_ids:
            raise ReplayDetected("message identity was already authenticated and accepted")
        if packet.identity in self._reserved_ids:
            raise ReplayDetected("duplicate message identity is already buffered")
        if self.hsm.has_disclosed_key(packet.interval):
            raise PacketRejected("authentication key for this interval is already disclosed")

        disclosure_interval = packet.interval + self.disclosure_delay
        if self.current_interval >= disclosure_interval:
            raise PacketRejected("packet arrived at or after its key-disclosure interval")

        self._buffer.setdefault(packet.interval, []).append(packet)
        self._reserved_ids.add(packet.identity)
        return "buffered"

    def process_disclosure(self, interval: int, key: bytes) -> list[VerificationResult]:
        """Validate a disclosed key, then authenticate all buffered packets for it."""

        if not isinstance(interval, int) or isinstance(interval, bool):
            raise DisclosureRejected("interval must be an integer")
        if self.current_interval < interval + self.disclosure_delay:
            raise DisclosureRejected("key disclosure arrived before the allowed interval")

        try:
            self.hsm.validate_and_store_disclosed_key(interval, key)
        except (InvalidKeyDisclosure, HSMError) as exc:
            raise DisclosureRejected(str(exc)) from exc

        packets = self._buffer.pop(interval, [])
        results: list[VerificationResult] = []
        for packet in packets:
            self._reserved_ids.discard(packet.identity)
            if packet.identity in self._accepted_ids:
                results.append(VerificationResult(packet, False, "replay"))
                continue

            if self.hsm.verify_mac(interval, packet.authenticated_bytes(), packet.tag):
                self._accepted_ids.add(packet.identity)
                results.append(VerificationResult(packet, True, "authenticated"))
            else:
                results.append(VerificationResult(packet, False, "invalid authentication tag"))
        return results

    @property
    def buffered_count(self) -> int:
        return sum(len(items) for items in self._buffer.values())
