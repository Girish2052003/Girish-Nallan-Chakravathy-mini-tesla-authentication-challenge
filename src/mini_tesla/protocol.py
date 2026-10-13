"""Mini-TESLA satellite and receiver protocol state machines.

Clocks are trusted, monotonic logical clocks. Receiver admission uses a trusted
upper bound on sender time; this simulation does not synchronize clocks.
"""
# This module describes the sender and receiver's changing state: their clocks,
# the sender's next message number, and the receiver's waiting messages.
# TESLA delays proof of authenticity: the sender first sends a message with a
# MAC (a short check value made with a secret key), then reveals that key later.
# Once a key is public, anyone can make a matching MAC. The receiver therefore
# must remember that it received the message BEFORE that key could be public.
# A "logical interval" is a numbered time slot, such as 1, 2, or 3; it is not
# automatically a second or a reading of the computer's wall clock.
# Type annotations such as `: int` and `-> bytes` describe intended inputs and
# outputs. They help readers and checking tools but do not validate values by
# themselves. This future import postpones evaluating those annotations.
from __future__ import annotations

# `struct` converts numbers to an exact, agreed sequence of bytes for the MAC.
import struct
# `dataclass` builds ordinary record methods, including initialization and
# equality. `replace` copies a dataclass record while optionally changing fields.
from dataclasses import dataclass, replace
# `Callable` describes a function-like input. `Final` marks a name that should
# not be reassigned; this is a checking-tool convention, not a runtime lock.
from typing import Callable, Final

# The leading dot means "from this same package". HSM is the simulated key
# store/cryptography boundary, HSMError is its common error type, and TAG_SIZE
# is the required MAC length in bytes (32 for HMAC-SHA256 in this project).
from .hsm import HSM, HSMError, TAG_SIZE

# These capitalized names are shared settings. `=` gives each name its value.
# Version 1 identifies the packet format this implementation understands.
PROTOCOL_VERSION: Final = 1
# `b"..."` is bytes rather than text, and `\x00` is one zero byte. This fixed
# prefix says "these bytes belong to Mini-TESLA message authentication" so the
# same bytes from another purpose are not accidentally treated as this format.
# Such a prefix is called domain separation; it does not encrypt the message.
WIRE_DOMAIN: Final = b"MINI-TESLA-AUTH\x00"
# Reject payloads larger than 1 MiB. Underscores make this integer easy to read;
# 1_048_576 means exactly the same number as 1048576.
MAX_PAYLOAD_SIZE: Final = 1_048_576
# `**` means "raised to the power". An unsigned 32-bit number has 2**32
# possible values, from zero through 2**32 - 1 (4,294,967,295).
UINT32_MAX: Final = 2**32 - 1
# The sequence field gets 64 bits, so its largest value is 2**64 - 1.
UINT64_MAX: Final = 2**64 - 1


# A class defines a kind of object. Here it defines an error kind, inheriting
# normal exception behavior from Python's Exception. `raise` will report such
# an error and stop the current operation unless a caller catches it.
class ProtocolError(Exception):
    """Base class for protocol-state errors."""


# Inheriting from ProtocolError lets a caller catch either this specific packet
# error or all protocol errors with a single handler for the parent class.
class PacketRejected(ProtocolError):
    """An incoming packet violates protocol, timing, or resource policy."""


# A replay is another copy of a candidate already held, or a message for an
# interval whose key is already known. It is a particular PacketRejected error.
class ReplayDetected(PacketRejected):
    """An exact candidate or a message for a closed interval was received again."""


# Key-disclosure failures have their own error kind, separate from packet
# admission failures, while still belonging to the ProtocolError family.
class DisclosureRejected(ProtocolError):
    """A key disclosure is early, malformed, or cryptographically invalid."""


# `def` defines a reusable function. These parameters are the value to check,
# its inclusive lower/upper limits, and the field name used in an error.
# `object` permits any incoming Python value; `-> None` means there is no useful
# return value. Success means returning normally; failure means raising an error.
def _integer(value: object, minimum: int, maximum: int, name: str) -> None:
    # Require exactly Python's int type. In Python, True and False also behave
    # like integers in many contexts, but `type(True) is int` is false, so this
    # rejects booleans as well as floats such as 1.0. `or` rejects if either the
    # type is wrong or the value is outside the inclusive chained comparison.
    if type(value) is not int or not minimum <= value <= maximum:
        # An f-string inserts the named values inside `{...}` into the message.
        # The exception tells the caller both the bad field and its valid range.
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")


# An `@` decorator applies extra behavior to the following class. This one
# generates record methods. `frozen=True` prevents normal field reassignment;
# `slots=True` reserves the declared fields instead of a general attribute map.
# These options help keep records stable and small; they are not a boundary
# against hostile Python code running inside the same process.
@dataclass(frozen=True, slots=True)
class AuthPacket:
    """Authenticated message plus the metadata covered by its MAC."""

    # The time slot in which the sender made this message; it chooses a key.
    interval: int
    # A sender-assigned message number; together with interval it identifies a
    # message. A number alone does not prove who sent the packet.
    sequence: int
    # How many intervals the sender waits before publishing this interval's key.
    disclosure_delay: int
    # The actual message as immutable bytes. Authentication does not hide it.
    payload: bytes
    # The MAC to check later, after the receiver has authenticated a disclosed key.
    tag: bytes
    # A caller may omit this final field and receive the supported version, 1.
    version: int = PROTOCOL_VERSION

    # A method is a function attached to a class. `self` is the particular packet
    # being used. This method returns the bytes protected by its MAC; the MAC
    # itself is deliberately absent, because a MAC cannot include itself.
    def authenticated_bytes(self) -> bytes:
        """Encode only valid wire-domain values; never coerce bools or floats."""
        # The version occupies one byte, which can store integers 0 through 255.
        # Format support is checked separately by the receiver after encoding.
        _integer(self.version, 0, 255, "version")
        # Interval zero is reserved for the chain commitment, not a message key.
        _integer(self.interval, 1, UINT32_MAX, "interval")
        # Message numbering starts at 1 and must fit the eight-byte sequence field.
        _integer(self.sequence, 1, UINT64_MAX, "sequence")
        # A positive delay preserves a gap between sending and releasing the key.
        _integer(self.disclosure_delay, 1, UINT32_MAX, "disclosure_delay")
        # `len` counts bytes here. Require actual bytes and cap their size before
        # constructing an encoded message, to avoid accepting oversized content.
        if type(self.payload) is not bytes or len(self.payload) > MAX_PAYLOAD_SIZE:
            # Stop encoding if the message type or size does not match the format.
            raise ValueError("payload must be bytes within the maximum supported size")
        # A header is the fixed-size metadata placed before the payload.
        # `struct.pack` returns binary bytes; the parentheses let this call span
        # several lines. `>` chooses big-endian (largest place value first).
        # B = one-byte unsigned integer, I = four-byte unsigned integer, and
        # Q = eight-byte unsigned integer. Spaces in this format are ignored.
        # In this standard format there is no alignment padding: 21 header bytes.
        header = struct.pack(
            # These first three values fill B, I, Q: version, interval, sequence.
            ">B I Q I I", self.version, self.interval, self.sequence,
            # The remaining two I fields hold delay and payload byte length.
            # An explicit length gives the payload an unambiguous boundary;
            # changing length or any other header field changes the MAC input.
            self.disclosure_delay, len(self.payload),
        )
        # `+` joins byte sequences in order. Domain + fixed header + known-length
        # payload forms one canonical representation (one agreed encoding).
        # For example, b"AB" gives length 2 and two payload bytes, not a text
        # number "2". This framing avoids ambiguous field concatenations.
        return WIRE_DOMAIN + header + self.payload

    # `@property` lets callers read `packet.identity` without writing `()`.
    @property
    # `tuple[int, int]` describes a fixed pair of integer values.
    def identity(self) -> tuple[int, int]:
        # Parentheses and a comma form a tuple. Different candidate packets may
        # claim this same pair until the disclosed key shows which MAC is valid.
        return (self.interval, self.sequence)


# Store a verification decision as another fixed record, using the same
# generated initialization/equality and ordinary immutability as AuthPacket.
@dataclass(frozen=True, slots=True)
class VerificationResult:
    # Keep the exact candidate to which this result belongs.
    packet: AuthPacket
    # A boolean: True means accepted as authentic; False means rejected.
    accepted: bool
    # Human-readable explanation, such as "authenticated" or "replay".
    reason: str


# This shared base class supplies clock behavior to Satellite and Receiver.
# A leading underscore marks an implementation detail by convention; it does
# not make the class or its attributes inaccessible from other Python code.
class _Clock:
    # Expose the stored interval through an attribute-like, read-only interface.
    @property
    def current_interval(self) -> int:
        # A subclass's initializer creates this internal counter.
        return self._current_interval

    # Expose the configured key-release delay in the same attribute-like way.
    @property
    def disclosure_delay(self) -> int:
        # Return a setting; reading it does not advance time.
        return self._disclosure_delay

    # Advance the manual logical clock by `steps`, defaulting to one time slot,
    # and return its new integer reading. This does not sleep or measure seconds.
    def advance(self, steps: int = 1) -> int:
        # Only positive actual integers may move this clock, so it cannot stay
        # still or move backward through this method; booleans are also rejected.
        if type(steps) is not int or steps < 1:
            # Tell the caller the requested clock movement is invalid.
            raise ValueError("steps must be a positive integer")
        # `+=` adds to the existing stored value and writes the new value back.
        self._current_interval += steps
        # Let the caller use the new interval immediately.
        return self._current_interval


# `( _Clock )` in the class declaration (without spaces here) means Satellite
# inherits the base class's interval, delay, and manual advance interface.
class Satellite(_Clock):
    """Mini-TESLA sender using a private satellite-side HSM instance."""

    # Python calls __init__ when making a Satellite. `self` is the new object.
    # `*` makes the following options keyword-only, for example
    # Satellite(chain_length=32, disclosure_delay=2). Defaults are 32 keys and
    # a one-interval delay. Initialization returns None, not the created object.
    def __init__(self, *, chain_length: int = 32, disclosure_delay: int = 1) -> None:
        # Enforce a positive delay representable by the four-byte packet field.
        _integer(disclosure_delay, 1, UINT32_MAX, "disclosure_delay")
        # Create a fresh random one-way key chain inside a sender-role HSM.
        # That factory also checks the chain length. This project simulates HSM
        # behavior in Python; this attribute is not physical tamper-proof hardware.
        self.hsm = HSM.create_satellite(chain_length)
        # Keep the chosen release policy for both packet headers and disclosures.
        self._disclosure_delay = disclosure_delay
        # Begin at the first message interval; K[0] is the public commitment.
        self._current_interval = 1
        # Give the first message sequence number 1, then increase it per message.
        self._next_sequence = 1
        # A key chain must only be signed for one authenticated session.
        # setup.py changes this flag after signing the initial configuration.
        # False means this new chain has not yet been used for a signed bootstrap.
        self._bootstrap_signed = False

    # Expose a public chain anchor with property syntax: satellite.commitment.
    @property
    def commitment(self) -> bytes:
        # The commitment is K[0], a hash-chain anchor used to check later keys.
        # It is safe to share; it is not an undisclosed message-authentication key.
        return self.hsm.commitment

    # Expose the number of usable message-key intervals in this chain.
    @property
    def chain_length(self) -> int:
        # Read the HSM's configured length rather than duplicating that setting.
        return self.hsm.chain_length

    # Turn one bytes payload into an AuthPacket for the current sender interval.
    # The result includes a MAC, but a receiver must still apply the arrival-time
    # rule and later authenticate it using the disclosed key.
    def authenticate(self, payload: bytes) -> AuthPacket:
        # Reject text, mutable bytearrays, and other values instead of silently
        # converting them and risking disagreement about which bytes were sent.
        if type(payload) is not bytes:
            # Wrong data kind is a TypeError; no packet is created.
            raise TypeError("payload must be bytes")
        # Reject messages beyond the supported payload bound before computing a MAC.
        if len(payload) > MAX_PAYLOAD_SIZE:
            # The payload has the right type but an invalid size.
            raise ValueError("payload exceeds maximum supported size")
        # Every sending interval needs its own chain key; there is no key after
        # chain_length. Starting a fresh session is outside this method.
        if self.current_interval > self.chain_length:
            # Stop rather than reuse a key or index beyond the available chain.
            raise ProtocolError("key chain is exhausted")
        # The sequence must fit its unsigned 64-bit field; do not wrap it to 1.
        if self._next_sequence > UINT64_MAX:
            # Reusing sequence numbers would undermine unique message identities.
            raise ProtocolError("sequence number space is exhausted")
        # Build a temporary record with interval and sequence as its first fields.
        unsigned = AuthPacket(self.current_interval, self._next_sequence,
                              # Add the release delay, caller's payload, and an
                              # empty tag placeholder; version takes its default.
                              self.disclosure_delay, payload, b"")
        # Ask the HSM to MAC this record's exact canonical bytes using the secret
        # key for its interval. The method returns the tag, not the secret key.
        tag = self.hsm.generate_mac(unsigned.interval, unsigned.authenticated_bytes())
        # Reserve a fresh sequence for the next successful call, even if the
        # sender remains in this same interval and sends several messages.
        self._next_sequence += 1
        # `replace` makes a new frozen record with all existing fields and the
        # computed tag. It does not alter the temporary `unsigned` record.
        return replace(unsigned, tag=tag)

    # Request the key for one past interval. Return its bytes only if the HSM's
    # release-time checks pass; invalid or early requests raise an HSM error.
    def disclose(self, interval: int) -> bytes:
        # Supply the requested key index and this sender's current logical time.
        return self.hsm.disclose_key(interval, current_interval=self.current_interval,
                                     # Pass the configured waiting period by name:
                                     # interval 3, delay 2 permits release at 5.
                                     disclosure_delay=self.disclosure_delay)


# The receiver inherits the clock interface but adds packet buffering and later
# verification. It cannot authenticate a new packet immediately: it must first
# receive that interval's key and check the key against the trusted commitment.
class Receiver(_Clock):
    """Bounded, single-threaded receiver with delayed authentication.

    ``max_sender_ahead`` must bound sender_time - receiver_time at every receive.
    Zero assumes synchronized logical intervals. Limits include all unauthenticated
    candidates; flooding can exhaust them and cause legitimate traffic to be lost.
    Buffered packets expire at interval + delay + disclosure_grace (local time).
    """

    # Create a receiver from a TRUSTED chain commitment and agreed chain settings.
    # The constructor itself does not check a satellite signature; setup.py's
    # ReceiverBootstrap is the higher-level path that authenticates these inputs.
    # Options after `*` must be named. `commitment` anchors the chain, chain_length
    # counts its usable keys, and disclosure_delay says when a key becomes public.
    def __init__(self, *, commitment: bytes, chain_length: int, disclosure_delay: int = 1,
                 # max_sender_ahead is a trusted bound on how many intervals the
                 # sender can be ahead; max_buffered_packets limits waiting records.
                 max_sender_ahead: int = 0, max_buffered_packets: int = 1024,
                 # Limit encoded bytes across all waiting packets, then the count
                 # of waiting candidates that may claim any one interval.
                 max_buffered_bytes: int = 8_388_608, max_packets_per_interval: int = 256,
                 # Allow a few competing versions of one (interval, sequence),
                 # and retain waiting packets for this many extra release intervals.
                 max_candidates_per_identity: int = 4, disclosure_grace: int = 8,
                 # Start the receiver's logical clock at this positive interval.
                 initial_interval: int = 1,
                 # `Callable[[], int]` means "can be called with no arguments and
                 # returns an integer". `| None` also permits no source, which
                 # selects manual clock mode for simulations or trusted callers.
                 trusted_interval_source: Callable[[], int] | None = None) -> None:
        # Iterate through pairs (field name, supplied value). `for name, value`
        # unpacks each pair into two variables, reusing the same bounds check.
        # All fields in this group must be positive, unlike max_sender_ahead.
        for name, value in (("disclosure_delay", disclosure_delay),
                            # Maximum total number of unauthenticated candidates.
                            ("max_buffered_packets", max_buffered_packets),
                            # Maximum accounted bytes held for those candidates.
                            ("max_buffered_bytes", max_buffered_bytes),
                            # Maximum candidates in one interval's batch.
                            ("max_packets_per_interval", max_packets_per_interval),
                            # Maximum conflicting candidates claiming one identity.
                            ("max_candidates_per_identity", max_candidates_per_identity),
                            # Extra local intervals to wait after scheduled release.
                            ("disclosure_grace", disclosure_grace)):
            # Use each pair's own name in an informative range/type error.
            _integer(value, 1, UINT32_MAX, name)
        # A zero lead is allowed, but assumes the sender is never ahead of this
        # receiver clock. This number is an external trust assumption, not a bound
        # the receiver can learn by reading potentially forged incoming packets.
        _integer(max_sender_ahead, 0, UINT32_MAX, "max_sender_ahead")
        # Receiver interval zero has no corresponding message-key time slot.
        _integer(initial_interval, 1, UINT32_MAX, "initial_interval")
        # `is not None` checks whether a source was supplied. `callable` checks
        # that it can be invoked, but cannot prove that its time reading is honest.
        if trusted_interval_source is not None and not callable(trusted_interval_source):
            # Fail early if a supplied clock is a value rather than a function.
            raise TypeError("trusted_interval_source must be callable")
        # Make a receiver-role HSM holding the public commitment and chain length,
        # with no sender secret keys. The HSM validates their shapes and bounds.
        self.hsm = HSM.create_receiver(commitment, chain_length)
        # Store the release delay expected in every packet in this session.
        self._disclosure_delay = disclosure_delay
        # Save the initial reading; a live source will be checked against it.
        self._current_interval = initial_interval
        # Keep the callback itself, not just one reading, so later traffic triggers
        # a fresh reading. None explicitly keeps this receiver in manual mode.
        self._trusted_interval_source = trusted_interval_source
        # Save the sender-lead bound used in the safe-arrival inequality.
        self._max_sender_ahead = max_sender_ahead
        # Store the limit across all waiting candidates, not only valid messages.
        self._max_buffered_packets = max_buffered_packets
        # Store the total canonical-message-plus-tag byte budget.
        self._max_buffered_bytes = max_buffered_bytes
        # Store the per-interval count budget so one interval cannot grow forever.
        self._max_packets_per_interval = max_packets_per_interval
        # Store the limit for alternative packets sharing the same claimed ID.
        self._max_candidates_per_identity = max_candidates_per_identity
        # Store how long to allow a late key before forgetting its waiting batch.
        self._disclosure_grace = disclosure_grace
        # Snapshot plus canonical bytes: no caller-owned objects or later encoding.
        # `{}` creates an empty dictionary. Each integer interval maps to a list;
        # each list item is a tuple (copied AuthPacket, its encoded bytes).
        # A "candidate" is a packet that might be authentic but is not verified yet.
        self._buffer: dict[int, list[tuple[AuthPacket, bytes]]] = {}
        # Maintain a total candidate count for quick checks without scanning lists.
        self._buffered_count = 0
        # Track serialized message bytes plus tags, not Python object memory costs.
        self._buffered_bytes = 0

    # Remove and return one interval's waiting batch while updating both budgets.
    # The underscore marks this as a helper for receiver methods, by convention.
    def _take_interval(self, interval: int) -> list[tuple[AuthPacket, bytes]]:
        # `pop` removes this dictionary entry and returns its list. If it does not
        # exist, the supplied default `[]` (an empty list) avoids a lookup error.
        entries = self._buffer.pop(interval, [])
        # `-=` subtracts the number of removed candidates from the running count.
        self._buffered_count -= len(entries)
        # Count each stored encoding plus its fixed-length tag, then subtract the
        # total. `for _, data in entries` unpacks each pair; `_` marks the packet
        # value as intentionally unused. `sum(...)` adds all those sizes, or zero
        # for an empty batch, without first building a separate list of sizes.
        self._buffered_bytes -= sum(len(data) + TAG_SIZE for _, data in entries)
        # The caller may now verify these entries or simply discard them.
        return entries

    # Free storage for packets that have waited too long for a key. This helper
    # changes state and has no useful return value (`-> None`).
    def _expire_buffers(self) -> None:
        # Make a list snapshot of dictionary keys before looping because removing
        # entries while directly iterating a dictionary would be invalid.
        for interval in list(self._buffer):
            # Expire at the deadline itself or later. For interval 3, delay 2,
            # grace 8, expiration starts at local interval 13 (= 3 + 2 + 8).
            # Grace allows key-delivery lateness; it never relaxes packet admission.
            if self._current_interval >= interval + self.disclosure_delay + self._disclosure_grace:
                # Remove the whole expired batch and release its counted budget.
                # Its return value is ignored because expired packets are dropped.
                self._take_interval(interval)

    # Read the live trusted clock, if configured, and require a valid reading that
    # does not go backward. Equal readings are allowed within the same interval.
    def _refresh_trusted_interval(self) -> None:
        """Fail closed if host time becomes invalid or moves backward."""
        # Keep a local reference to the configured callback for this operation.
        source = self._trusted_interval_source
        # None means the caller is responsible for moving the manual clock safely.
        if source is None:
            # A bare return exits early and returns None; no live reading exists.
            return
        # `try` marks a block whose ordinary errors will be handled below.
        try:
            # Parentheses call the source now. Saving only its setup-time value
            # would let an old reading incorrectly admit traffic after key release.
            observed = source()
        # Catch ordinary callback failures and keep the original error as `exc`.
        except Exception as exc:
            # "Fail closed" means reject when time cannot be established rather
            # than guess that a possibly late packet is safe. `from exc` preserves
            # the original failure as the cause for debugging.
            raise ProtocolError("trusted interval source failed") from exc
        # Reject booleans, fractions, zero, negatives, and numbers beyond uint32.
        if type(observed) is not int or not 1 <= observed <= UINT32_MAX:
            # Do not change stored time when the reading is malformed.
            raise ProtocolError("trusted interval source returned an invalid interval")
        # A smaller reading would reopen old arrival windows after key disclosure.
        if observed < self._current_interval:
            # A backward clock is an error, not permission to reconsider old packets.
            raise ProtocolError("trusted interval source moved backward")
        # Keep the validated live reading as the latest known receiver interval.
        self._current_interval = observed
        # Time may have jumped forward; remove batches whose waiting window ended.
        self._expire_buffers()

    # Override the base property so even reading receiver.current_interval obtains
    # a new trusted reading when live-clock mode is enabled.
    @property
    def current_interval(self) -> int:
        # The source is consulted every time, so it must be trusted and usable
        # throughout the session, not only during bootstrap.
        self._refresh_trusted_interval()
        # Return the reading only after validation and expiration have succeeded.
        return self._current_interval

    # Move a manual receiver clock by a positive number of intervals and return
    # its new reading. Live-clock receivers take time only from their source.
    def advance(self, steps: int = 1) -> int:
        # Mixing manual advancement with an external clock could produce
        # inconsistent safety decisions, so refuse that combination.
        if self._trusted_interval_source is not None:
            # Tell the caller to let the configured trusted source provide time.
            raise ProtocolError("trusted-clock receiver cannot be advanced manually")
        # `super()` selects inherited behavior: _Clock.advance checks steps and
        # updates the counter. This receiver adds expiration after that operation.
        super().advance(steps)
        # Remove old candidates immediately after a manual time change as well.
        self._expire_buffers()
        # Report the updated interval after both actions are complete.
        return self._current_interval

    # Check a packet's shape and session settings, returning its canonical MAC
    # input. Passing these checks does not yet prove its sender or its tag.
    def _validate_packet_shape(self, packet: AuthPacket) -> bytes:
        # Require the exact record class, not a lookalike or a subclass that could
        # override how authenticated_bytes works.
        if type(packet) is not AuthPacket:
            # Reject before calling methods on an unexpected packet object.
            raise PacketRejected("packet has an unexpected type")
        # Encoding performs the shared strict integer and payload checks.
        try:
            # Save the validated encoding once, both for byte accounting and for
            # eventual verification of exactly the bytes admitted now.
            data = packet.authenticated_bytes()
        # Several errors can mean malformed fields. The parenthesized tuple says
        # to handle any one of these exception types with the same handler.
        except (TypeError, ValueError, struct.error) as exc:
            # Convert the underlying error to the receiver's packet-error type;
            # str(exc) retains its explanation and `from` preserves its cause.
            raise PacketRejected(str(exc)) from exc
        # A one-byte version can be encodable yet still unsupported by this receiver.
        if packet.version != PROTOCOL_VERSION:
            # `!=` means "not equal"; do not interpret another version's format.
            raise PacketRejected("unsupported protocol version")
        # Reject a key index for which this configured chain has no usable key.
        if packet.interval > self.hsm.chain_length:
            # The packet cannot select keys beyond this session's authenticated chain.
            raise PacketRejected("packet interval is outside the configured key chain")
        # This receiver policy rejects packet intervals ahead of its local reading.
        # Accessing current_interval also rechecks the live clock if one is present.
        if packet.interval > self.current_interval:
            # Future-claiming packets do not reserve buffer space.
            raise PacketRejected("packet claims a future interval")
        # A sender-supplied delay cannot extend this receiver's agreed safety window.
        if packet.disclosure_delay != self.disclosure_delay:
            # Keep the receiver's session policy authoritative over packet claims.
            raise PacketRejected("packet disclosure delay does not match receiver policy")
        # Require exactly 32 immutable bytes for the HMAC-SHA256 tag.
        if type(packet.tag) is not bytes or len(packet.tag) != TAG_SIZE:
            # Correct tag size is only a format check, not a successful MAC check.
            raise PacketRejected("authentication tag must be exactly 32 bytes")
        # All shape/policy checks passed; return the bytes to the admission method.
        return data

    # Consider one untrusted packet for temporary storage. The returned string
    # "buffered" means only that it can wait for its key, never "authenticated".
    # Failed admission raises a PacketRejected/ReplayDetected or clock error.
    def receive(self, packet: AuthPacket) -> str:
        """Apply the safety condition and reserve bounded candidate storage."""
        # Update trusted time first and release storage belonging to expired batches.
        self._refresh_trusted_interval()
        # Reject malformed fields and obtain the exact bytes that a future MAC
        # verification must cover, including interval, sequence, delay, and length.
        data = self._validate_packet_shape(packet)
        # Once this key is validated and stored, its interval is closed to new
        # packets: anyone who knows a public key can compute its matching MAC.
        if self.hsm.has_disclosed_key(packet.interval):
            # Reject even if this specific sequence number has not been seen before.
            raise ReplayDetected("authentication key for this interval is already disclosed")
        # Let R = receiver time, B = maximum sender lead, i = packet interval,
        # and d = release delay. Trusted configuration promises sender time <= R+B.
        # We need R+B < i+d so the key CANNOT yet be public at the sender.
        # Equality is already too late. Example: i=5, d=2, R=5, B=1 gives
        # 6 < 7 and passes; B=2 gives 7 >= 7 and rejects. A forged MAC made
        # after release could otherwise look as good as an original sender MAC.
        # This test relies on the real bound and clock source being trustworthy;
        # the arithmetic cannot verify those external assumptions by itself.
        if self.current_interval + self._max_sender_ahead >= packet.interval + self.disclosure_delay:
            # The key might already be available to an attacker, so do not buffer.
            raise PacketRejected("packet arrived at or after its possible key-disclosure interval")

        # Look up this interval's candidates without adding a dictionary entry yet.
        # If the interval is new, work with a temporary empty list (`[]`).
        entries = self._buffer.get(packet.interval, [])
        # A list comprehension builds a new list: unpack each (packet, bytes) pair
        # as p and _, keep p only when its (interval, sequence) equals the new ID.
        # Alternative payloads/tags may share an ID, so a first forged candidate
        # does not automatically prevent a later authentic version from being tried.
        candidates = [p for p, _ in entries if p.identity == packet.identity]
        # Dataclass equality compares all fields, so this finds an exact duplicate,
        # including payload and tag, rather than only a reused identity pair.
        if packet in candidates:
            # Do not spend more storage on the same candidate twice.
            raise ReplayDetected("exact duplicate candidate is already buffered")
        # Competing candidates help tolerate a forged first arrival, but must be
        # limited. With the default 4, a fifth version of one claimed ID is refused.
        if len(candidates) >= self._max_candidates_per_identity:
            # A malicious sender can still fill those slots; this bound limits
            # storage use, not all denial-of-service attacks or delivery loss.
            raise PacketRejected("candidate limit for this identity reached")
        # Count all candidates in this interval, including different versions of
        # the same identity. Equality to the limit means there is no free slot.
        if len(entries) >= self._max_packets_per_interval:
            # Enforce this interval's budget before modifying any counters.
            raise PacketRejected("per-interval packet limit reached")
        # Also enforce the count limit across every currently buffered interval.
        if self._buffered_count >= self._max_buffered_packets:
            # A receiver with all its candidate slots occupied refuses new work.
            raise PacketRejected("total buffered packet limit reached")
        # Account for the entire canonical MAC input plus the separate 32-byte tag.
        # This count does not include Python list/dictionary/object memory overhead.
        size = len(data) + TAG_SIZE
        # Check the prospective total before storing. Exactly the allowed byte
        # total is permitted; only exceeding it (`>`) is rejected here.
        if self._buffered_bytes + size > self._max_buffered_bytes:
            # The count budget alone would not stop a few very large payloads.
            raise PacketRejected("total buffered byte limit reached")
        # `setdefault` finds the list or creates it only now that checks passed.
        # `append` adds one pair. `replace(packet)` copies the record, and `data`
        # preserves its canonical encoding, so later work uses the admitted
        # snapshot. Payload/tag/encoding are bytes, which are ordinarily immutable.
        self._buffer.setdefault(packet.interval, []).append((replace(packet), data))
        # Reserve one candidate slot in the global running count.
        self._buffered_count += 1
        # Reserve the corresponding number of accounted bytes.
        self._buffered_bytes += size
        # A successful return promises only delayed verification, not authenticity.
        return "buffered"

    # Accept a claimed key disclosure for an interval and return one result per
    # surviving candidate in that interval. A list can be empty if no candidates
    # were admitted or if their waiting deadline already expired.
    def process_disclosure(self, interval: int, key: bytes) -> list[VerificationResult]:
        """Authenticate a key before removing or processing its candidate batch."""
        # Recheck live time on disclosures too; this may expire overdue batches.
        self._refresh_trusted_interval()
        # Require an actual integer key index within this receiver's finite chain.
        if type(interval) is not int or not 1 <= interval <= self.hsm.chain_length:
            # Reject booleans, out-of-range indexes, and other malformed indexes.
            raise DisclosureRejected("interval must be an integer within the key chain")
        # This local-time policy waits until interval + delay before accepting a
        # key. For interval 3 and delay 2, local time must have reached at least 5.
        if self.current_interval < interval + self.disclosure_delay:
            # An early key is not imported into the HSM or used for authentication.
            raise DisclosureRejected("key disclosure arrived before the allowed interval")
        # Validate the claimed key before taking its batch out of storage. An
        # attacker should not be able to erase a still-live batch with a fake key.
        try:
            # The HSM checks key type/size and repeatedly hashes it to the trusted
            # commitment. Only a key that matches the chain is cached for MAC checks.
            self.hsm.validate_and_store_disclosed_key(interval, key)
        # Handle the HSM family's validation errors at this protocol boundary.
        except HSMError as exc:
            # Present a disclosure-specific error while retaining the original cause.
            raise DisclosureRejected(str(exc)) from exc

        # Start the ordered list of per-candidate decisions; `[]` is empty.
        results: list[VerificationResult] = []
        # A set keeps unique values and supports membership checks. Here it holds
        # only IDs successfully accepted in THIS batch, not a growing lifetime log.
        accepted_ids: set[tuple[int, int]] = set()
        # Remove this batch and free its counters, then unpack each stored pair
        # into the packet record and the bytes saved when that packet arrived.
        for packet, data in self._take_interval(interval):
            # Deliver at most one authentic candidate for each claimed identity.
            if packet.identity in accepted_ids:
                # This ID already succeeded earlier in the batch; report a replay
                # without checking another candidate's tag. False means rejected.
                results.append(VerificationResult(packet, False, "replay"))
            # `elif` means "otherwise, if". Use the authenticated disclosed key
            # to check the tag against the exact bytes that passed arrival checks.
            elif self.hsm.verify_mac(interval, data, packet.tag):
                # Remember this accepted ID so later candidates cannot duplicate
                # application delivery. Failed candidates never claim this ID.
                accepted_ids.add(packet.identity)
                # True marks success: both the earlier safe-arrival rule and this
                # cryptographic verification were satisfied for the candidate.
                results.append(VerificationResult(packet, True, "authenticated"))
            # `else` handles a tag that did not match, with no earlier accepted ID.
            else:
                # Record the failure and continue to other candidates. A bad first
                # version does not prevent a later valid version of the same ID.
                results.append(VerificationResult(packet, False, "invalid authentication tag"))
        # No unbounded message replay set: validated-key and deadline guards close
        # the interval permanently, and acceptance identities live only in this batch.
        # The HSM's disclosed-key cache is bounded by the configured chain length.
        # For example, a forged candidate followed by the real message can yield
        # [invalid tag, authenticated]; a later arrival for that interval is refused
        # by receive because its key is now disclosed, even with a new sequence.
        return results

    # Provide a read-only property for inspecting current waiting-candidate count.
    @property
    def buffered_count(self) -> int:
        # This reads the counter; it does not itself refresh the clock or expire
        # old entries. Receive, disclosure, and clock operations do that work.
        return self._buffered_count

    # Provide the corresponding accounted-byte total for monitoring and tests.
    @property
    def buffered_bytes(self) -> int:
        """Bytes of buffered canonical messages plus tags (not Python overhead)."""
        # Return the current bookkeeping value without recomputing all encodings.
        return self._buffered_bytes
