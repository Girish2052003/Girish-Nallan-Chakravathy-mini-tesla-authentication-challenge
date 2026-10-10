"""Mini-TESLA satellite and receiver protocol state machines.

Clocks are trusted, monotonic logical clocks. Receiver admission uses a trusted
upper bound on sender time; this simulation does not synchronize clocks.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from typing import Final

from .hsm import HSM, HSMError, TAG_SIZE

PROTOCOL_VERSION: Final = 1
WIRE_DOMAIN: Final = b"MINI-TESLA-AUTH\x00"
MAX_PAYLOAD_SIZE: Final = 1_048_576
UINT32_MAX: Final = 2**32 - 1
UINT64_MAX: Final = 2**64 - 1


class ProtocolError(Exception):
    """Base class for protocol-state errors."""


class PacketRejected(ProtocolError):
    """An incoming packet violates protocol, timing, or resource policy."""


class ReplayDetected(PacketRejected):
    """An exact candidate or a message for a closed interval was received again."""


class DisclosureRejected(ProtocolError):
    """A key disclosure is early, malformed, or cryptographically invalid."""


def _integer(value: object, minimum: int, maximum: int, name: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")


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
        """Encode only valid wire-domain values; never coerce bools or floats."""
        _integer(self.version, 0, 255, "version")
        _integer(self.interval, 1, UINT32_MAX, "interval")
        _integer(self.sequence, 1, UINT64_MAX, "sequence")
        _integer(self.disclosure_delay, 1, UINT32_MAX, "disclosure_delay")
        if type(self.payload) is not bytes or len(self.payload) > MAX_PAYLOAD_SIZE:
            raise ValueError("payload must be bytes within the maximum supported size")
        header = struct.pack(
            ">B I Q I I", self.version, self.interval, self.sequence,
            self.disclosure_delay, len(self.payload),
        )
        return WIRE_DOMAIN + header + self.payload

    @property
    def identity(self) -> tuple[int, int]:
        return (self.interval, self.sequence)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    packet: AuthPacket
    accepted: bool
    reason: str


class _Clock:
    @property
    def current_interval(self) -> int:
        return self._current_interval

    @property
    def disclosure_delay(self) -> int:
        return self._disclosure_delay

    def advance(self, steps: int = 1) -> int:
        if type(steps) is not int or steps < 1:
            raise ValueError("steps must be a positive integer")
        self._current_interval += steps
        return self._current_interval


class Satellite(_Clock):
    """Mini-TESLA sender using a private satellite-side HSM instance."""

    def __init__(self, *, chain_length: int = 32, disclosure_delay: int = 1) -> None:
        _integer(disclosure_delay, 1, UINT32_MAX, "disclosure_delay")
        self.hsm = HSM.create_satellite(chain_length)
        self._disclosure_delay = disclosure_delay
        self._current_interval = 1
        self._next_sequence = 1
        # A key chain must only be signed for one authenticated session.
        self._bootstrap_signed = False

    @property
    def commitment(self) -> bytes:
        return self.hsm.commitment

    @property
    def chain_length(self) -> int:
        return self.hsm.chain_length

    def authenticate(self, payload: bytes) -> AuthPacket:
        if type(payload) is not bytes:
            raise TypeError("payload must be bytes")
        if len(payload) > MAX_PAYLOAD_SIZE:
            raise ValueError("payload exceeds maximum supported size")
        if self.current_interval > self.chain_length:
            raise ProtocolError("key chain is exhausted")
        if self._next_sequence > UINT64_MAX:
            raise ProtocolError("sequence number space is exhausted")
        unsigned = AuthPacket(self.current_interval, self._next_sequence,
                              self.disclosure_delay, payload, b"")
        tag = self.hsm.generate_mac(unsigned.interval, unsigned.authenticated_bytes())
        self._next_sequence += 1
        return replace(unsigned, tag=tag)

    def disclose(self, interval: int) -> bytes:
        return self.hsm.disclose_key(interval, current_interval=self.current_interval,
                                     disclosure_delay=self.disclosure_delay)


class Receiver(_Clock):
    """Bounded, single-threaded receiver with delayed authentication.

    ``max_sender_ahead`` must bound sender_time - receiver_time at every receive.
    Zero assumes synchronized logical intervals. Limits include all unauthenticated
    candidates; flooding can exhaust them and cause legitimate traffic to be lost.
    Buffered packets expire at interval + delay + disclosure_grace (local time).
    """

    def __init__(self, *, commitment: bytes, chain_length: int, disclosure_delay: int = 1,
                 max_sender_ahead: int = 0, max_buffered_packets: int = 1024,
                 max_buffered_bytes: int = 8_388_608, max_packets_per_interval: int = 256,
                 max_candidates_per_identity: int = 4, disclosure_grace: int = 8) -> None:
        for name, value in (("disclosure_delay", disclosure_delay),
                            ("max_buffered_packets", max_buffered_packets),
                            ("max_buffered_bytes", max_buffered_bytes),
                            ("max_packets_per_interval", max_packets_per_interval),
                            ("max_candidates_per_identity", max_candidates_per_identity),
                            ("disclosure_grace", disclosure_grace)):
            _integer(value, 1, UINT32_MAX, name)
        _integer(max_sender_ahead, 0, UINT32_MAX, "max_sender_ahead")
        self.hsm = HSM.create_receiver(commitment, chain_length)
        self._disclosure_delay = disclosure_delay
        self._current_interval = 1
        self._max_sender_ahead = max_sender_ahead
        self._max_buffered_packets = max_buffered_packets
        self._max_buffered_bytes = max_buffered_bytes
        self._max_packets_per_interval = max_packets_per_interval
        self._max_candidates_per_identity = max_candidates_per_identity
        self._disclosure_grace = disclosure_grace
        # Snapshot plus canonical bytes: no caller-owned objects or later encoding.
        self._buffer: dict[int, list[tuple[AuthPacket, bytes]]] = {}
        self._buffered_count = 0
        self._buffered_bytes = 0

    def _take_interval(self, interval: int) -> list[tuple[AuthPacket, bytes]]:
        entries = self._buffer.pop(interval, [])
        self._buffered_count -= len(entries)
        self._buffered_bytes -= sum(len(data) + TAG_SIZE for _, data in entries)
        return entries

    def advance(self, steps: int = 1) -> int:
        super().advance(steps)
        for interval in list(self._buffer):
            if self.current_interval >= interval + self.disclosure_delay + self._disclosure_grace:
                self._take_interval(interval)
        return self.current_interval

    def _validate_packet_shape(self, packet: AuthPacket) -> bytes:
        if type(packet) is not AuthPacket:
            raise PacketRejected("packet has an unexpected type")
        try:
            data = packet.authenticated_bytes()
        except (TypeError, ValueError, struct.error) as exc:
            raise PacketRejected(str(exc)) from exc
        if packet.version != PROTOCOL_VERSION:
            raise PacketRejected("unsupported protocol version")
        if packet.interval > self.hsm.chain_length:
            raise PacketRejected("packet interval is outside the configured key chain")
        if packet.interval > self.current_interval:
            raise PacketRejected("packet claims a future interval")
        if packet.disclosure_delay != self.disclosure_delay:
            raise PacketRejected("packet disclosure delay does not match receiver policy")
        if type(packet.tag) is not bytes or len(packet.tag) != TAG_SIZE:
            raise PacketRejected("authentication tag must be exactly 32 bytes")
        return data

    def receive(self, packet: AuthPacket) -> str:
        """Apply the safety condition and reserve bounded candidate storage."""
        data = self._validate_packet_shape(packet)
        if self.hsm.has_disclosed_key(packet.interval):
            raise ReplayDetected("authentication key for this interval is already disclosed")
        if self.current_interval + self._max_sender_ahead >= packet.interval + self.disclosure_delay:
            raise PacketRejected("packet arrived at or after its possible key-disclosure interval")

        entries = self._buffer.get(packet.interval, [])
        candidates = [p for p, _ in entries if p.identity == packet.identity]
        if packet in candidates:
            raise ReplayDetected("exact duplicate candidate is already buffered")
        if len(candidates) >= self._max_candidates_per_identity:
            raise PacketRejected("candidate limit for this identity reached")
        if len(entries) >= self._max_packets_per_interval:
            raise PacketRejected("per-interval packet limit reached")
        if self._buffered_count >= self._max_buffered_packets:
            raise PacketRejected("total buffered packet limit reached")
        size = len(data) + TAG_SIZE
        if self._buffered_bytes + size > self._max_buffered_bytes:
            raise PacketRejected("total buffered byte limit reached")
        self._buffer.setdefault(packet.interval, []).append((replace(packet), data))
        self._buffered_count += 1
        self._buffered_bytes += size
        return "buffered"

    def process_disclosure(self, interval: int, key: bytes) -> list[VerificationResult]:
        """Authenticate a key before removing or processing its candidate batch."""
        if type(interval) is not int or not 1 <= interval <= self.hsm.chain_length:
            raise DisclosureRejected("interval must be an integer within the key chain")
        if self.current_interval < interval + self.disclosure_delay:
            raise DisclosureRejected("key disclosure arrived before the allowed interval")
        try:
            self.hsm.validate_and_store_disclosed_key(interval, key)
        except HSMError as exc:
            raise DisclosureRejected(str(exc)) from exc

        results: list[VerificationResult] = []
        accepted_ids: set[tuple[int, int]] = set()
        for packet, data in self._take_interval(interval):
            if packet.identity in accepted_ids:
                results.append(VerificationResult(packet, False, "replay"))
            elif self.hsm.verify_mac(interval, data, packet.tag):
                accepted_ids.add(packet.identity)
                results.append(VerificationResult(packet, True, "authenticated"))
            else:
                results.append(VerificationResult(packet, False, "invalid authentication tag"))
        # No unbounded message replay set: validated-key and deadline guards close
        # the interval permanently, and acceptance identities live only in this batch.
        return results

    @property
    def buffered_count(self) -> int:
        return self._buffered_count

    @property
    def buffered_bytes(self) -> int:
        """Bytes of buffered canonical messages plus tags (not Python overhead)."""
        return self._buffered_bytes
