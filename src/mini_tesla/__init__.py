"""Mini-TESLA authentication challenge implementation."""

# __init__.py is the package's front door: it lets other files write
# "from mini_tesla import Satellite" instead of naming the internal file.
# A leading dot in an import means "look inside this same package".
# Importing a name makes it available here; it does not create a sender or key.

# Bring in the key-management class, its error types, and its key-loading helper.
from .hsm import (
    # HSM keeps key operations in one software object (not hardware isolation).
    HSM,
    # This error means a caller asked to release a key before its allowed interval.
    EarlyDisclosureError,
    # This is the shared parent error type for HSM-related failures.
    HSMError,
    # This error means a proposed public key disclosure failed validation.
    InvalidKeyDisclosure,
    # This error reports a problem saving or loading encrypted HSM state.
    PersistenceError,
    # This helper reads and validates the encryption master key from the environment.
    master_key_from_env,
)
# Bring in the message records, sender/receiver objects, and protocol errors.
from .protocol import (
    # AuthPacket holds a message, its timing/sequence fields, and its HMAC tag.
    AuthPacket,
    # This error reports a disclosure the receiver cannot use safely.
    DisclosureRejected,
    # This error reports a message the receiver will not buffer.
    PacketRejected,
    # ProtocolError is the parent type that groups protocol failures together.
    ProtocolError,
    # Receiver buffers timely packets and checks them after key disclosure.
    Receiver,
    # This error reports an already-seen packet or message identity where checked.
    ReplayDetected,
    # Satellite creates authenticated packets and releases interval keys later.
    Satellite,
    # VerificationResult pairs a checked packet with its decision and reason.
    VerificationResult,
)

# ReceiverBootstrap verifies initial trust; SetupRejected reports failed setup;
# SignedSetup stores the signed setup data; sign_satellite_setup creates it.
from .setup import ReceiverBootstrap, SetupRejected, SignedSetup, sign_satellite_setup

# __all__ lists the public names exported by "from mini_tesla import *".
# Quotes make each item a name string, not a function call. This is a public
# interface list, not an access-control barrier that hides internal Python data.
__all__ = [
    # The message record passed from sender to receiver.
    "AuthPacket",
    # The receiver's rejected-key-disclosure error.
    "DisclosureRejected",
    # The HSM's too-early-key-release error.
    "EarlyDisclosureError",
    # The software key-management object and its common error type.
    "HSM",
    "HSMError",
    # The HSM's invalid-disclosed-key error.
    "InvalidKeyDisclosure",
    # The receiver's rejected-message error and the common protocol error.
    "PacketRejected",
    "ProtocolError",
    # The save/load failure error.
    "PersistenceError",
    # The message receiver and the helper that establishes it from a signed setup.
    "Receiver",
    "ReceiverBootstrap",
    # The duplicate/replay error.
    "ReplayDetected",
    # The message sender.
    "Satellite",
    # The failed-setup error and the signed-setup data record.
    "SetupRejected",
    "SignedSetup",
    # The result record returned when a buffered packet is checked.
    "VerificationResult",
    # The environment key reader and the setup-signing function.
    "master_key_from_env",
    "sign_satellite_setup",
]
