"""Authenticated bootstrap for Mini-TESLA (independent of the TESLA key chain).

The receiver MUST already have an authentic, pinned Ed25519 public key.
A fresh receiver challenge binds every signed setup to one bootstrap attempt.
This module does not provide key provisioning or clock synchronization.
"""

# "Bootstrap" means establishing the trusted starting settings for a session.
# The receiver already knows an authentic sender public key from some trusted
# provisioning process outside this module. That is the "pinned" key: incoming
# setup data must not be allowed to choose its own supposedly trusted verifier.
# Ed25519 is a digital-signature scheme: a private key creates a signature, and
# its matching public key checks it without revealing the signing secret.
# This is separate from TESLA's message MACs, whose secret keys are released later.
# Type hints describe intended values for readers/checkers, rather than enforcing
# them at runtime; this import postpones evaluating those annotations.
from __future__ import annotations

# Here Python's hmac module supplies a comparison routine designed not to stop
# early based on matching contents; it is not used to sign the setup message.
import hmac
# Regular expressions describe a text pattern; re checks satellite ID characters.
import re
# `secrets` provides randomness suitable for security-sensitive challenges.
import secrets
# `struct` turns numeric fields into precisely sized, ordered binary bytes.
import struct
# `dataclass` generates record methods; `replace` makes a copy with chosen changes.
from dataclasses import dataclass, replace
# `Callable` describes a function-like value, and `Final` tells type checkers a
# named constant should not be reassigned. Neither proves that a value is trusted.
from typing import Callable, Final

# The cryptography library raises this error when a signature does not verify.
from cryptography.exceptions import InvalidSignature
# Parentheses allow a multi-line import of the two Ed25519 key interfaces.
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    # Only the sender-side signing operation should receive this secret-key type.
    Ed25519PrivateKey,
    # Receiver bootstrap uses this public-key type to check the sender's signature.
    Ed25519PublicKey,
)

# A leading dot imports from this package. KEY_SIZE is 32 bytes and the HSM's
# MAX_CHAIN_LENGTH limits how many message-key intervals a session may contain.
from .hsm import KEY_SIZE, MAX_CHAIN_LENGTH
# These classes hold the sender's existing chain and the receiver session that
# will be constructed only after setup authentication succeeds.
from .protocol import Receiver, Satellite

# Domain separation: this fixed byte prefix identifies signatures as Mini-TESLA
# satellite setup signatures, rather than signatures for some other purpose.
# `b"..."` is bytes, `\x00` is a zero byte, and `: Final` marks a constant hint.
SETUP_DOMAIN: Final = b"MINI-TESLA-SATELLITE-SETUP-ED25519\x00"
# Only setup format version 1 is accepted by this implementation.
SETUP_VERSION: Final = 1
# Each receiver-generated challenge has 32 random bytes (256 bits). A challenge
# is public, not a password; its unpredictability binds a reply to this attempt.
CHALLENGE_SIZE: Final = 32
# Ed25519 signatures are exactly 64 bytes; reject wrong-sized inputs before verify.
SIGNATURE_SIZE: Final = 64
# Declare the intended maximum ID length; the pattern below enforces 64 characters.
MAX_ID_SIZE: Final = 64
# `**` means exponentiation. An unsigned 32-bit field ranges from 0 to 2**32-1.
MAX_UINT32: Final = 2**32 - 1
# Compile the ID rule once for reuse. The first character must be an ASCII letter
# or digit; the next 0..63 may also include dot, underscore, or hyphen. Thus a
# complete ID has 1..64 characters. `[ ... ]` lists allowed characters, `{0,63}`
# counts repetitions, and `\Z` anchors the end. The `r` string prefix keeps the
# backslash for the regex engine; re.ASCII requests ASCII matching conventions.
_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)


# Define a setup-specific exception (an error object). Inheriting from ValueError
# also lets callers handle this together with other invalid-value failures.
class SetupRejected(ValueError):
    """An untrusted TESLA bootstrap did not pass the required checks."""


# Convert setup fields into the one agreed byte representation that will be
# signed or verified. The leading underscore marks a module helper by convention.
# `-> bytes` describes the returned immutable binary data; errors raise instead.
def _encode_setup(
    # Text sender ID, receiver's random challenge, and public chain anchor K[0].
    satellite_id: str, challenge: bytes, commitment: bytes,
    # Number of usable interval keys, key-release waiting period, and format version.
    chain_length: int, disclosure_delay: int, version: int,
) -> bytes:
    """Canonical, domain-separated and length-delimited signature input."""
    # `type(...) is int` requires an actual integer, excluding bools such as True,
    # even though Python often lets them act like 1. `or` also rejects another
    # version number. Type hints alone would not perform either validation.
    if type(version) is not int or version != SETUP_VERSION:
        # `raise` stops this operation with an error unless a caller catches it.
        raise SetupRejected("unsupported setup version")
    # Require actual text and a full ID-pattern match. `fullmatch` returns None
    # when the entire string does not fit. `or` stops after a wrong type so the
    # pattern is not asked to match a non-string value.
    if type(satellite_id) is not str or _ID_PATTERN.fullmatch(satellite_id) is None:
        # ASCII and length restrictions give IDs a small, predictable representation.
        raise SetupRejected("satellite_id must be 1..64 safe ASCII characters")
    # Only an immutable bytes challenge of exactly the agreed length is encodable.
    if type(challenge) is not bytes or len(challenge) != CHALLENGE_SIZE:
        # `len` counts the number of bytes, not the number of displayed hex digits.
        raise SetupRejected("challenge must be 32 bytes")
    # The public chain anchor must have the same 32-byte size as the hash-chain keys.
    if type(commitment) is not bytes or len(commitment) != KEY_SIZE:
        # This checks shape only; the sender's signature will establish its origin.
        raise SetupRejected("commitment must be 32 bytes")
    # The chain must contain at least one key and stay within the HSM's resource
    # limit. `1 <= value <= limit` is an inclusive chained comparison.
    if type(chain_length) is not int or not 1 <= chain_length <= MAX_CHAIN_LENGTH:
        # Reject zero, negative, excessive, boolean, and non-integer lengths.
        raise SetupRejected("invalid chain length")
    # Require a positive delay that fits the unsigned four-byte encoding.
    if type(disclosure_delay) is not int or not 1 <= disclosure_delay <= MAX_UINT32:
        # A zero delay would remove the time gap needed for delayed authentication.
        raise SetupRejected("invalid disclosure delay")

    # Turn the validated ASCII text into bytes. Every allowed character occupies
    # exactly one byte, so the ID's byte length is within 1..64 as well.
    identity = satellite_id.encode("ascii")
    # Parentheses group a multi-line expression. Each `+` joins another byte
    # sequence in order; the complete result is the signature's message input.
    # Canonical means that these fields have one agreed encoding, not several
    # spellings that different participants could interpret differently.
    return (
        # Begin with the purpose-specific fixed prefix, including its zero byte.
        SETUP_DOMAIN
        # `>` chooses big-endian order; each B is a one-byte unsigned integer.
        # Write the version and the ID's length before writing the ID itself.
        # An ID "SAT-1" has length 5, so a verifier knows to read exactly 5 bytes.
        + struct.pack(">BB", version, len(identity))
        # Append those ID bytes; the preceding length determines their boundary.
        + identity
        # This field is always 32 bytes, so it needs no separate length prefix.
        + challenge
        # Append the 32-byte public anchor that all later disclosed keys must match.
        + commitment
        # Each I is a four-byte unsigned integer: first chain length, then delay.
        # Explicit field sizes and byte order prevent ambiguous concatenation or
        # platform-dependent layouts. No private signing key is included here.
        + struct.pack(">II", chain_length, disclosure_delay)
    )


# `@dataclass` supplies the record initializer and equality behavior. frozen=True
# prevents normal field reassignment; slots=True limits ordinary attributes to
# declared fields. These are useful record properties, not protection against
# hostile code with control of this Python process.
@dataclass(frozen=True, slots=True)
class SignedSetup:
    """A public, signed configuration. Contains no signing private key."""

    # The claimed sender name, which must match the receiver's trusted expectation.
    satellite_id: str
    # The receiver's challenge echoed back so the signature covers this attempt.
    challenge: bytes
    # The public hash-chain anchor for this particular sender session.
    commitment: bytes
    # How many interval keys belong to this chain.
    chain_length: int
    # How many logical intervals to wait before each key's scheduled disclosure.
    disclosure_delay: int
    # The Ed25519 signature bytes; anyone with the pinned public key can check them.
    signature: bytes
    # Default the optional version field to the supported setup format, version 1.
    version: int = SETUP_VERSION

    # `self` is this record. Return exactly the fields protected by the signature;
    # the signature field itself is excluded to avoid trying to sign itself.
    def signed_bytes(self) -> bytes:
        # Reuse the same validation and encoding for signing and verification.
        return _encode_setup(
            # Supply this record's identity, one-attempt challenge, and chain anchor.
            self.satellite_id, self.challenge, self.commitment,
            # Supply its chain length, disclosure policy, and format version.
            self.chain_length, self.disclosure_delay, self.version,
        )


# Make a signed public setup record for an existing, unused Satellite instance.
# The key is trusted sender configuration; this function does not provision keys,
# synchronize clocks, transmit messages, or hide any public setup field.
def sign_satellite_setup(
    # The Satellite can be positional. `*` requires all following inputs by name.
    satellite: Satellite, *,
    # Sender's Ed25519 private key; knowledge of it permits issuing setup signatures.
    signing_key: Ed25519PrivateKey,
    # Name that the receiver expects for this sender.
    satellite_id: str,
    # Fresh random bytes received from the particular receiver bootstrap attempt.
    challenge: bytes,
    # The return annotation describes the public SignedSetup record produced.
) -> SignedSetup:
    """Sign a receiver's challenge and the exact satellite session parameters.

    The signing key is supplied by trusted sender configuration; NEVER accept
    an attacker-provided signing key as the claimed satellite identity.
    """
    # Require the actual Satellite class because this operation depends on its
    # precise session state, not just an object with similarly named attributes.
    if type(satellite) is not Satellite:
        # Reject an unexpected object before consulting its key-chain state.
        raise TypeError("satellite must be a Satellite instance")
    # `isinstance` permits the library's implementations of this key interface.
    # It checks key kind, not whether a human obtained the key from a trusted place.
    if not isinstance(signing_key, Ed25519PrivateKey):
        # A public key, arbitrary bytes, or another key algorithm cannot sign here.
        raise TypeError("signing_key must be an Ed25519 private key")

    # Do not sign a reused or partially disclosed chain for a different
    # receiver challenge. Old disclosed interval keys would otherwise
    # allow authenticated-looking forgeries in a restarted receiver.
    # All three freshness conditions must hold: never signed before, still at
    # interval 1, and no message sequence consumed. `or` rejects if any condition
    # fails. These underscore attributes are internal state shared with protocol.py.
    if satellite._bootstrap_signed or satellite.current_interval != 1 or satellite._next_sequence != 1:
        # A new challenge needs a new unused chain, not a signature over old keys.
        raise SetupRejected("signed setup requires a fresh, unused satellite chain")

    # Build an intermediate public record. Named arguments explicitly identify
    # each field, avoiding accidental confusion among several bytes-valued inputs.
    unsigned = SignedSetup(
        # Bind the claimed sender ID into the signature input.
        satellite_id=satellite_id,
        # Bind the receiver's exact unpredictable challenge, not a sender-chosen one.
        challenge=challenge,
        # Read the real anchor from the Satellite's HSM-backed chain.
        commitment=satellite.commitment,
        # Sign the actual number of available interval keys for that same chain.
        chain_length=satellite.chain_length,
        # Sign the sender's actual release delay so tampering is detectable.
        disclosure_delay=satellite.disclosure_delay,
        # The signature is not known yet; an empty byte string is its placeholder.
        # signed_bytes excludes this field, and version uses the record's default.
        signature=b"",
    )
    # First validate/encode the unsigned record, then sign those exact bytes.
    # `replace` returns a new record with the resulting 64-byte signature, leaving
    # the frozen intermediate record untouched. The private key stays outside it.
    signed = replace(unsigned, signature=signing_key.sign(unsigned.signed_bytes()))
    # Mark the chain as consumed for bootstrap only AFTER signing succeeds.
    # This prevents this same Satellite from issuing another challenged session.
    satellite._bootstrap_signed = True
    # Give the caller the signed configuration to deliver to the receiver.
    return signed


# Keep the receiver's trusted inputs and one pending challenge together. An
# instance can establish one session successfully; it cannot be reused afterward.
class ReceiverBootstrap:
    """Single-use receiver-side bootstrap with a pinned sender public key.

    Build this object from trusted local configuration. Transmit `challenge`
    over an untrusted channel. Only a correctly signed response to that exact
    challenge can establish a receiver session; verified success consumes it.
    """

    # Python calls __init__ to initialize a new object; `self` means that object.
    # `*` requires named arguments, and `-> None` means initialization returns no
    # useful value. The public key MUST already be authentic local configuration.
    def __init__(self, *, trusted_public_key: Ed25519PublicKey,
                 # Name of the sender this local receiver intends to communicate with.
                 expected_satellite_id: str,
                 # A zero-argument callable returning the live logical interval
                 # for THIS sender session, not an unrelated timestamp or old value.
                 trusted_interval_source: Callable[[], int]) -> None:
        # Accept the cryptography library's public-key implementations. A valid
        # type does not prove the key's owner; trusted provisioning must do that.
        if not isinstance(trusted_public_key, Ed25519PublicKey):
            # A private-key object, raw byte string, or other key type is invalid here.
            raise TypeError("trusted_public_key must be an Ed25519 public key")
        # Apply the same full ASCII ID rule used in signature encoding to the
        # local expected identity. `or` avoids matching when its type is wrong.
        if type(expected_satellite_id) is not str or _ID_PATTERN.fullmatch(expected_satellite_id) is None:
            # Reject invalid local configuration before issuing a challenge.
            raise ValueError("invalid expected_satellite_id")
        # This must be something that can be called, because time is consulted
        # during establishment and again during later receiver operations.
        if not callable(trusted_interval_source):
            # An integer snapshot is not a live clock callback.
            raise TypeError("trusted_interval_source must be callable")
        # Save the callable itself; do not turn it into a frozen reading here.
        self._trusted_interval_source = trusted_interval_source
        # Pin the trusted verification key for all responses to this challenge.
        self._trusted_public_key = trusted_public_key
        # Keep the expected sender ID separately from all untrusted setup fields.
        self._expected_satellite_id = expected_satellite_id
        # Generate a new, unpredictable 32-byte challenge with a secure random
        # generator. Replaying an old setup normally carries another challenge
        # and therefore cannot satisfy this new attempt's comparison.
        self._challenge = secrets.token_bytes(CHALLENGE_SIZE)
        # False means this object's challenge has not established a session yet.
        self._used = False

    # Expose the public challenge as `bootstrap.challenge`, without call parentheses.
    @property
    def challenge(self) -> bytes:
        # The caller can transmit these bytes over an untrusted network: secrecy
        # is not needed, but the sender's response must sign their exact value.
        return self._challenge

    # Verify a received setup and return a usable Receiver if every check passes.
    # `setup` is untrusted input; all following keyword-only options are trusted
    # local policy. max_sender_ahead bounds how far the sender's clock may lead.
    def establish(self, setup: SignedSetup, *, max_sender_ahead: int = 0,
                  # Cap the total number of waiting, unauthenticated candidates.
                  max_buffered_packets: int = 1024,
                  # Cap their encoded-message-plus-tag bytes (8 MiB by default).
                  max_buffered_bytes: int = 8_388_608,
                  # Cap all candidates claiming any one sending interval.
                  max_packets_per_interval: int = 256,
                  # Permit a bounded number of conflicting versions of one ID.
                  max_candidates_per_identity: int = 4,
                  # Wait this many extra local intervals for late key disclosures.
                  disclosure_grace: int = 8) -> Receiver:
        """Verify sender identity, challenge, signature, and session parameters.

        No Receiver is constructed from the untrusted commitment before the
        signature and freshness checks succeed.
        """
        # Each bootstrap object can produce only one receiver session successfully.
        if self._used:
            # Reusing a signed response must not reset receiver replay/timing state.
            raise SetupRejected("bootstrap challenge has already been consumed")
        # Require the exact record class, excluding a subclass that could replace
        # signed_bytes with behavior unrelated to these public fields.
        if type(setup) is not SignedSetup:
            # Reject before invoking a method on an unexpected object.
            raise SetupRejected("expected a SignedSetup")
        # Validate/encode all fields *before* trusting any attacker-controlled
        # configuration, and use constant-time comparison for the challenge.
        # This runs _encode_setup's strict checks and creates the exact signature
        # input. It establishes a valid format, but has not established trust yet.
        encoded = setup.signed_bytes()
        # A correctly formed response must name the specific locally expected sender.
        if setup.satellite_id != self._expected_satellite_id:
            # A signed configuration for a different expected identity is not usable.
            raise SetupRejected("unexpected satellite identity")
        # Compare the received and locally generated byte strings with a routine
        # designed to avoid content-dependent early exits. This is a freshness
        # check, not signature verification; the challenge is public information.
        if not hmac.compare_digest(setup.challenge, self._challenge):
            # For example, a valid response to yesterday's random challenge cannot
            # answer today's newly generated challenge simply by being replayed.
            raise SetupRejected("setup does not match the fresh receiver challenge")
        # Ed25519 requires exactly 64 signature bytes; enforce both type and length.
        if type(setup.signature) is not bytes or len(setup.signature) != SIGNATURE_SIZE:
            # Refuse malformed input before entering signature verification.
            raise SetupRejected("invalid setup signature length")
        # `try` lets the following handler translate the library's signature error.
        try:
            # Use ONLY the pinned local key, never a key carried by the response.
            # verify returns normally on success and raises on a mismatch; it does
            # not return True/False. It authenticates the whole encoded setup,
            # including challenge, identity, commitment, length, delay, and version.
            self._trusted_public_key.verify(setup.signature, encoded)
        # Bind the library error to `exc` so it can be retained as the cause.
        except InvalidSignature as exc:
            # Report a setup-specific failure; `from exc` preserves the original
            # diagnostic chain. Do not construct a receiver after this failure.
            raise SetupRejected("setup signature verification failed") from exc

        # The caller's trusted clock is expressed in THIS sender session's
        # logical intervals; S <= R + B must hold throughout the session.
        # A challenged signature alone does not prove that K[1] is still secret.
        # Here S means real sender interval, R the trusted receiver reading, and
        # B the configured sender-lead bound. Clock synchronization and proving
        # that bound are the caller's responsibility, outside this implementation.
        # An attacker may delay a freshly signed response until after key release;
        # its signature/challenge would still verify, so live time is also essential.
        try:
            # Read the source NOW, after signature verification. A function that
            # always returns its old setup-time reading would violate the trust
            # requirement even if its values remain valid positive integers.
            current = self._trusted_interval_source()
        # Treat an ordinary clock-source exception as an inability to establish
        # that first-key secrecy still holds, rather than guessing a safe time.
        except Exception as exc:
            # Wrap the source failure and keep its original cause for diagnostics.
            raise SetupRejected("trusted interval source failed") from exc
        # Accept an actual positive uint32 integer, excluding True, floats, and
        # readings outside the session's representable logical-time range.
        if type(current) is not int or not 1 <= current <= MAX_UINT32:
            # Invalid clock output prevents establishing a receiver.
            raise SetupRejected("trusted interval source returned an invalid interval")
        # The lead bound is a nonnegative uint32 integer. Zero is permitted only
        # when the sender is never ahead of the supplied trusted receiver reading.
        if type(max_sender_ahead) is not int or not 0 <= max_sender_ahead <= MAX_UINT32:
            # Never silently round a bound or accept booleans as timing policy.
            raise SetupRejected("max_sender_ahead must be a nonnegative uint32 integer")
        # The first message key K[1] can be public at sender interval 1 + delay.
        # Require the conservative upper bound current + lead to stay strictly
        # before that deadline; equality is unsafe. Example: delay 3 means a
        # deadline of 4. current=2 with lead=1 passes (3 < 4); current=3 with
        # lead=1 fails (4 >= 4), even when the signature and challenge are valid.
        if current + max_sender_ahead >= 1 + setup.disclosure_delay:
            # Reject late setup instead of creating a session around potentially
            # public keys that an attacker could already use to forge message MACs.
            raise SetupRejected("signed setup arrived after the safe first-key admission deadline")

        # Receiver policy is local; no untrusted setup field can override it.
        # The live source is checked again for every packet and disclosure.
        # Only now create a receiver: signature, identity, challenge, and live
        # first-key timing have passed. The constructor also validates the local
        # storage limits. Named arguments make the source of each setting explicit.
        receiver = Receiver(
            # Use the public chain anchor that the pinned sender key just authenticated.
            commitment=setup.commitment,
            # Use the number of chain keys protected by that same signature.
            chain_length=setup.chain_length,
            # Use the signed sender delay so receiver and sender share one policy.
            disclosure_delay=setup.disclosure_delay,
            # Use the caller's trusted lead bound, not a claim from incoming data.
            max_sender_ahead=max_sender_ahead,
            # Apply the receiver's local overall candidate-count limit.
            max_buffered_packets=max_buffered_packets,
            # Apply the receiver's local total serialized byte budget.
            max_buffered_bytes=max_buffered_bytes,
            # Apply the local per-interval candidate limit.
            max_packets_per_interval=max_packets_per_interval,
            # Apply the local cap on competing candidates for one (interval, sequence).
            max_candidates_per_identity=max_candidates_per_identity,
            # Apply the local wait time for a late disclosure, not a longer
            # arrival-time window for new packets.
            disclosure_grace=disclosure_grace,
            # Start from the just-validated live reading, not automatically from 1.
            initial_interval=current,
            # Pass the callable, not `current`: future receive/disclosure operations
            # must obtain fresh readings and reject time that becomes invalid or
            # moves backward. This is what keeps the initial timing check live.
            trusted_interval_source=self._trusted_interval_source,
        )
        # Consume the challenge only after every check AND construction succeeded.
        # A failed attempt does not turn this flag on; a successful one cannot be
        # replayed through this bootstrap object to obtain another fresh receiver.
        self._used = True
        # Return the initialized receiver to the application that called establish.
        return receiver
