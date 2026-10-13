# Lines beginning with # are explanatory comments; Python does not execute them.
# The triple-quoted paragraph below is a docstring: documentation stored on this
# module. Functions and classes may also begin with a docstring describing them.
"""A small HSM-like cryptographic boundary for the Mini-TESLA challenge.

This class intentionally models *properties* of an HSM rather than claiming to be
one. Secret authentication keys remain private to the satellite-side instance and
are only returned by the explicit, policy-checked ``disclose_key`` operation.
"""

# This module is one Python file. It provides the cryptographic operations used
# by a satellite (the sender) and a receiver (the checker of received messages).
# Python runs a function only when it is called, such as _sha256(data). Values in
# parentheses are arguments passed to that call. A colon after def, class, if,
# for, or try starts a block; the indented lines below belong to that block.
# A single = assigns a value to a name; == asks whether two values are equal.
# HSM means "hardware security module", a device intended to protect secret
# keys. This class is a SOFTWARE model: its checks describe that boundary, but
# Python code with access to the object or process can still inspect its memory.
# An underscore in a name, such as _auth_keys, means "internal use by convention";
# it does not give the hardware or operating-system isolation of a real HSM.
#
# A key is a sequence of bytes (numbers from 0 to 255), not ordinary text.
# For example, b"A" is one byte with value 65. Hexadecimal writes that byte as
# "41"; base64 writes it as "QQ==". Those are representations, not encryption.
# A Python str is text; bytes is the immutable binary form cryptography uses.
#
# TESLA authenticates messages with keys that become public after a delay.
# Before disclosure, only the sender should know the relevant key. Afterward,
# receivers can check earlier messages, but must already have checked WHEN those
# messages arrived. A valid MAC alone does not prove timely arrival or freshness.

# Postpone evaluation of type annotations (the hints after : and ->). This lets
# annotations describe classes without needing those classes to exist yet.
from __future__ import annotations

# Base64 converts binary keys to printable text for JSON and back again.
import base64
# hashlib supplies SHA-256, a one-way function that produces a 32-byte digest.
import hashlib
# Rename Python's hmac module locally so it cannot be confused with the separate
# cryptography.hmac import below. We use this version's secure comparison helper.
import hmac as stdlib_hmac
# JSON is a text format for saving dictionaries, strings, numbers, and lists.
import json
# os supplies environment variables and low-level file operations.
import os
# secrets supplies randomness suitable for secret keys and cryptographic nonces.
import secrets
# tempfile safely creates a fresh temporary file without guessing an unused name.
import tempfile
# "from ... import ..." brings one named feature into this module. Path offers
# convenient methods for file names, parent directories, and opening files.
from pathlib import Path
# Final marks constants for type-checking tools; Python does not enforce that
# promise at runtime, so assigning a new value would still be technically possible.
from typing import Final

# These exceptions are raised when cryptography rejects an HMAC or an AES-GCM
# authentication tag. An exception interrupts normal execution unless caught.
from cryptography.exceptions import InvalidSignature, InvalidTag
# hashes selects SHA-256; this hmac module constructs keyed message authenticators.
from cryptography.hazmat.primitives import hashes, hmac
# AESGCM provides encryption AND integrity checks using AES in GCM mode.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Uppercase names conventionally mean constants. A byte contains 8 bits, so a
# 32-byte key has 256 bits. Both chain keys and the AES master key use this size.
KEY_SIZE: Final = 32
# An HMAC-SHA256 tag is the complete 32-byte authentication result, not a key.
TAG_SIZE: Final = 32
# AES-GCM uses a 12-byte (96-bit) nonce here. A nonce distinguishes encryptions
# under one key; it is public, but reusing it with that key would be dangerous.
NONCE_SIZE: Final = 12
# b"..." creates bytes. This recognizable file header includes a version byte:
# \x01 means the byte with numeric value 1, not four literal text characters.
FILE_MAGIC: Final = b"MINITESLA-HSM\x01"
# This is the NAME of the environment variable, never the secret key itself.
DEFAULT_MASTER_KEY_ENV: Final = "MINITESLA_MASTER_KEY"
# Bound how many message intervals one chain can cover and how much validation
# work a caller can request. An interval is a numbered time slot starting at 1.
MAX_CHAIN_LENGTH: Final = 4096
# Underscores make this integer easier to read: it is 1,048,576 bytes (1 MiB).
# Importing a saved state rejects anything larger than this bound.
MAX_STATE_FILE_SIZE: Final = 1_048_576


# "class Child(Parent)" defines a new type that inherits the parent's behavior.
# Our common parent lets callers catch all boundary-specific errors as HSMError.
class HSMError(Exception):
    """Base class for HSM boundary errors."""


# A distinct error tells callers that the requested key is still secret by policy.
class EarlyDisclosureError(HSMError):
    """Raised when a key is requested before its disclosure interval."""


# This subtype distinguishes an invalid received key from an ordinary input error.
class InvalidKeyDisclosure(HSMError):
    """Raised when a disclosed key does not authenticate to the commitment."""


# "Persistence" means saving information so it can survive this process ending.
# Use this subtype for problems reading, decrypting, or writing saved HSM state.
class PersistenceError(HSMError):
    """Raised when an encrypted HSM state cannot be exported or imported."""


# "def" defines a function. data is its input parameter; : bytes and -> bytes
# document the expected input and returned value, without enforcing their types.
# SHA-256 is deterministic: the same bytes always produce the same digest. It is
# designed to make recovering an input from its digest computationally infeasible.
def _sha256(data: bytes) -> bytes:
    # Hash the input, then request its binary digest. return passes that digest
    # to the caller and immediately finishes this function; it is not hex text.
    return hashlib.sha256(data).digest()


# Convert arbitrary binary bytes to a text string suitable for a JSON field.
def _b64(data: bytes) -> str:
    # b64encode returns ASCII bytes; decode converts those bytes into text.
    # Example: the one-byte input b"A" becomes the four-character string "QQ==".
    return base64.b64encode(data).decode("ascii")


# Reverse _b64: take base64 text and return the binary data it represents.
def _unb64(value: str) -> bytes:
    # try starts a block whose failures can be handled by the following except.
    try:
        # encode turns text into ASCII bytes. validate=True rejects characters
        # outside the base64 format instead of silently ignoring them.
        return base64.b64decode(value.encode("ascii"), validate=True)
    # "as exc" gives the original exception a name for the error chain below.
    except Exception as exc:
        # Raise a domain-specific error; "from exc" preserves the original cause
        # so a developer can see why decoding failed when inspecting a traceback.
        raise PersistenceError("invalid base64 data in HSM state") from exc


# A validation helper returns no useful value (-> None). Successful completion
# means the input passed; invalid input interrupts the caller with an exception.
def _require_chain_length(value: int) -> None:
    # type(value) is int requires an exact integer: it also rejects True/False,
    # which Python otherwise treats as integer-like. "or" means either defect
    # is enough to reject it; "not 1 <= value <= limit" rejects values outside
    # the inclusive range. The type check runs first, avoiding an invalid comparison.
    if type(value) is not int or not 1 <= value <= MAX_CHAIN_LENGTH:
        # An f-string inserts expressions inside {...} into a readable message.
        raise ValueError(f"chain_length must be an integer in [1, {MAX_CHAIN_LENGTH}]")


# JSON calls this helper with a list of (field name, field value) pairs for each
# object it reads. tuple[str, object] describes one two-part pair; object allows
# any value type. Reject duplicate names instead of silently choosing one value.
def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    # {} creates an empty dictionary: a mapping from unique names to values.
    result = {}
    # The loop visits each pair; name, value unpacks its two parts into variables.
    for name, value in pairs:
        # "in" tests whether this field name has already been added to the map.
        if name in result:
            # Duplicate fields could make different readers interpret a file
            # differently, so stop rather than accept ambiguous saved state.
            raise ValueError("duplicate JSON field")
        # Square brackets choose the dictionary entry for name and store its value.
        result[name] = value
    # Only a complete, duplicate-free object reaches this return statement.
    return result


# Python's JSON reader can accept NaN and Infinity, although strict JSON cannot.
# Installing this callback below makes encountering either spelling an error.
def _reject_constant(value: str) -> None:
    # value is the text of the unsupported constant, included in the explanation.
    raise ValueError(f"non-JSON numeric constant {value}")


# Rebuild a key map from saved JSON: {"1": "base64..."} becomes {1: b"..."}.
# value starts as object because decrypted JSON still needs type checking.
# chain_length limits allowed indexes; the return maps integer indexes to bytes.
def _decode_keys(value: object, chain_length: int) -> dict[int, bytes]:
    # Require an actual dictionary, which is how json.loads represents an object.
    if type(value) is not dict:
        # A list, string, or other JSON value cannot stand in for this key map.
        raise ValueError("key map must be an object")
    # Build a separate output map rather than mutating the decoded JSON input.
    result = {}
    # .items() yields both each textual index and its associated encoded key.
    for index, key in value.items():
        # Only plain ASCII decimal text is accepted: "1" is valid; "01", "0",
        # "+1", and non-ASCII digit spellings are rejected. startswith("0")
        # rejects zero and leading zeros; len bounds text size before int parsing.
        # Parentheses let this condition continue onto the next source line.
        if (type(index) is not str or not index.isascii() or not index.isdecimal()
                or index.startswith("0") or len(index) > len(str(MAX_CHAIN_LENGTH))):
            # "Canonical" means there is just one accepted spelling per index.
            raise ValueError("key index must be a canonical positive decimal integer")
        # Turn the checked decimal string, for example "12", into integer 12.
        number = int(index)
        # A syntactically valid index must also refer to a slot in this chain.
        if not 1 <= number <= chain_length:
            # Do not allow keys with indexes the configured chain cannot contain.
            raise ValueError("key index is outside the configured chain")
        # Keys in JSON must be base64 strings, not arrays of numbers or null.
        if type(key) is not str:
            # Reject the wrong shape before passing it to the base64 decoder.
            raise ValueError("encoded key must be a string")
        # Decode the key and store it under the integer index. The HSM constructor
        # later checks each decoded key's byte length and relationship to the chain.
        result[number] = _unb64(key)
    # Return the fully decoded map; an empty input map produces an empty map.
    return result


# This public helper optionally accepts a different environment variable name.
# "= DEFAULT_MASTER_KEY_ENV" supplies the argument when the caller omits it.
def master_key_from_env(name: str = DEFAULT_MASTER_KEY_ENV) -> bytes:
    """Load a base64-encoded 32-byte AES-256 master key from an environment variable."""

    # Read text from the current process's environment. .get returns None if the
    # name is absent. The deployment must arrange to supply and protect this key.
    encoded = os.environ.get(name)
    # Both None (missing) and "" (empty text) count as false in this condition.
    if not encoded:
        # !r displays the name with quotes for clarity; the secret is not printed.
        raise PersistenceError(f"required environment variable {name!r} is not set")
    # Handle formatting failures separately from the later key-size check.
    try:
        # Ignore surrounding whitespace, convert remaining text to ASCII, and
        # strictly decode base64. Base64 is how the secret is represented, not how
        # it is protected: anyone who reads this variable can recover its bytes.
        key = base64.b64decode(encoded.strip().encode("ascii"), validate=True)
    # Convert any encoding/decoding exception into the module's persistence error.
    except Exception as exc:
        # Preserve the failure cause without inserting the key into our message.
        raise PersistenceError(f"{name!r} must contain valid base64") from exc
    # len counts bytes here. AES-256 requires 32 decoded bytes, not 32 characters
    # of base64 text; other AES key lengths are deliberately rejected by this API.
    if len(key) != KEY_SIZE:
        # "!=" means "is not equal to". Reject an incorrectly sized master key.
        raise PersistenceError(f"{name!r} must decode to exactly 32 bytes")
    # Return binary key material to the encryption/decryption operation.
    return key


# An HSM instance groups its state (attributes) and operations (methods).
# Satellite instances keep the complete secret chain; receiver instances start
# with a trusted public commitment and cache only validated disclosed keys.
class HSM:
    """HSM-like key store and cryptographic engine."""

    # Python calls __init__ when HSM(...) creates an instance. self is that new
    # instance; methods use it to read or store state belonging to this instance.
    # The lone * makes all following arguments keyword-only, so callers must
    # write role="satellite", for example, instead of relying on argument order.
    # role selects sender or receiver; commitment is the trusted 32-byte K0;
    # chain_length is the number of usable interval keys K1 through KN.
    # auth_keys holds a satellite's secret keys; disclosed_keys holds a receiver's
    # accepted public keys. dict[int, bytes] describes index-to-key mappings.
    # "| None" means a mapping OR no supplied mapping; None is the default here.
    def __init__(
        self,
        *,
        role: str,
        commitment: bytes,
        chain_length: int,
        auth_keys: dict[int, bytes] | None = None,
        disclosed_keys: dict[int, bytes] | None = None,
    ) -> None:
        # Require exact text and one supported role. {...} with values only is a
        # set; "not in" tests that role is absent from both allowed alternatives.
        if type(role) is not str or role not in {"satellite", "receiver"}:
            # Stop construction before storing any inconsistent state.
            raise ValueError("role must be 'satellite' or 'receiver'")
        # The commitment must be raw bytes of the SHA-256 digest length. Checking
        # type first also keeps len from being called on an incompatible object.
        if type(commitment) is not bytes or len(commitment) != KEY_SIZE:
            # A textual hex/base64 representation must be decoded before this call.
            raise ValueError("commitment must be 32 bytes")
        # Reuse the shared exact-integer and size bounds for every new instance.
        _require_chain_length(chain_length)

        # These conditional expressions choose {} only when an argument is None.
        # Creating empty maps here avoids a mutable default dictionary shared by
        # multiple instances. A supplied nonempty or empty map is kept for checking.
        auth_keys = {} if auth_keys is None else auth_keys
        # The receiver cache likewise starts empty when no mapping was supplied.
        disclosed_keys = {} if disclosed_keys is None else disclosed_keys
        # The tuple (...) groups the two maps so the same checks apply to each.
        for keys in (auth_keys, disclosed_keys):
            # Do not accept a list or another object pretending to be a key map.
            if type(keys) is not dict:
                # Raise before iterating, so .items() below is safe to call.
                raise ValueError("keys must be dictionaries")
            # any(...) is true as soon as ONE entry is bad. The condition before
            # "for i, key in keys.items()" is evaluated for each index/key pair:
            # indexes must be exact integers within 1..N, keys exact 32-byte bytes.
            # This generator checks entries without first building another list.
            if any(type(i) is not int or not 1 <= i <= chain_length
                   or type(key) is not bytes or len(key) != KEY_SIZE for i, key in keys.items()):
                # One invalid index, value type, or key size rejects the whole map.
                raise ValueError("invalid key index or length")
        # A nonempty dictionary is truthy; "and" requires BOTH conditions. A
        # receiver is not allowed to be initialized with sender-only secret keys.
        if role == "receiver" and auth_keys:
            # Enforce the intended separation between sender and receiver state.
            raise ValueError("receiver cannot contain undisclosed authentication keys")
        # Satellite instances have stricter completeness requirements.
        if role == "satellite":
            # set(auth_keys) collects map indexes. range(1, N + 1) visits 1..N
            # because its upper endpoint is excluded. Require exactly those keys,
            # and reject any receiver cache, even if all cached entries look valid.
            if set(auth_keys) != set(range(1, chain_length + 1)) or disclosed_keys:
                # Missing/extra keys or mixed roles cannot form a valid satellite.
                raise ValueError("satellite requires one complete chain and no receiver key cache")
            # Chain rule: SHA256(K1) = K0, SHA256(K2) = K1, and so on.
            # Start at public K0, then verify every adjacent secret-key relationship.
            previous = commitment
            # Check key indexes in increasing order: 1, 2, ..., chain_length.
            for index in range(1, chain_length + 1):
                # Hash the current key and compare with its expected predecessor.
                # compare_digest avoids ordinary equality's content-dependent
                # early exit; it helps reduce timing information about secret bytes.
                if not stdlib_hmac.compare_digest(_sha256(auth_keys[index]), previous):
                    # Any broken link means these keys do not form the stated chain.
                    raise ValueError("authentication chain does not match commitment")
                # The current key becomes the expected predecessor for the next one.
                previous = auth_keys[index]
        # Validate sparse cached keys against K0, then one another, using O(N)
        # hashes, rather than independently hashing each key to K0 in O(N²) hashes.
        # "Sparse" means only some indexes may be present. The total hashing work
        # is at most N (linear, written O(N)), instead of potentially proportional
        # to N squared if every key were separately hashed all the way back to K0.
        # First compare the earliest cached key to K0; then compare each later
        # key to the already validated earlier key. Empty caches need no work.
        previous_index = 0
        # Index 0 is the public commitment, our initial trusted reference point.
        previous_key = commitment
        # sorted(...) returns cached indexes from smallest to largest, so index
        # gaps below are positive and earlier reference keys are checked first.
        for index in sorted(disclosed_keys):
            # Work with a temporary candidate; keep the original cached key intact.
            candidate = disclosed_keys[index]
            # If indexes 2 and 5 are cached, hash K5 three times to obtain K2.
            # range(gap) repeats gap times. _ is an intentionally unused loop value.
            for _ in range(index - previous_index):
                # Each hash takes one step toward the LOWER numbered chain key.
                candidate = _sha256(candidate)
            # The result must match the previously trusted point in the chain.
            if not stdlib_hmac.compare_digest(candidate, previous_key):
                # Reject even a well-sized key if it does not belong to this chain.
                raise ValueError("cached disclosure does not match commitment")
            # Tuple assignment updates both reference values together for the next
            # cache entry; use the original key, not its repeatedly hashed candidate.
            previous_index, previous_key = index, disclosed_keys[index]

        # Construction has passed every check. Save the role on this instance;
        # a dot such as self._role accesses an attribute belonging to the object.
        self._role = role
        # Store the public commitment as bytes. bytes(...) may reuse an existing
        # bytes object; that is safe because bytes cannot be modified in place.
        self._commitment = bytes(commitment)
        # Remember the maximum valid interval for later operations.
        self._chain_length = chain_length
        # dict(...) copies the map, so editing the caller's dictionary afterward
        # cannot add/remove this instance's keys. The immutable byte values may
        # be shared; this is not a guarantee of secret-memory erasure or isolation.
        self._auth_keys = dict(auth_keys)
        # Give the receiver cache its own dictionary for the same reason.
        self._disclosed_keys = dict(disclosed_keys)

    # @classmethod changes the first argument from an instance (self) to the
    # class (cls). It lets HSM.create_satellite(N) construct a new HSM directly.
    @classmethod
    # chain_length chooses the number of keys. -> "HSM" describes the new object
    # returned; quotes allow referring to this class while its body is defined.
    def create_satellite(cls, chain_length: int) -> "HSM":
        """Generate a fresh SHA-256 one-way chain using CSPRNG key material."""

        # Reject invalid or excessive lengths before allocating storage or hashing.
        _require_chain_length(chain_length)

        # Allocate N + 1 list slots: public K0 plus keys K1..KN. [b""] is a list
        # containing empty bytes; * repeats that placeholder. It is safe to repeat
        # this placeholder because bytes are immutable and slots get replaced.
        chain: list[bytes] = [b""] * (chain_length + 1)
        # Choose the LAST key randomly with a cryptographically secure random
        # number generator (CSPRNG). The other keys are hashes derived from it.
        chain[chain_length] = secrets.token_bytes(KEY_SIZE)
        # range(N, 0, -1) counts N, N-1, ..., 1: -1 is the step, and 0 is excluded.
        # Build backward because hashing is easy, while reversing a hash is hard.
        for index in range(chain_length, 0, -1):
            # Example with N=3: choose random K3, hash it to K2, hash K2 to K1,
            # then hash K1 to public K0. Knowing K1 does not feasibly reveal K2;
            # knowing K2 does reveal K1 by hashing. Disclosure therefore moves
            # forward in index order while hash computation moves backward.
            chain[index - 1] = _sha256(chain[index])

        # Call the class constructor with named arguments; it validates the chain
        # above and returns a fully initialized satellite instance to the caller.
        return cls(
            # The sender role grants MAC generation and policy-checked disclosure.
            role="satellite",
            # K0 is the public value receivers must obtain through a trusted route.
            commitment=chain[0],
            # Record how many numbered intervals have an authentication key.
            chain_length=chain_length,
            # A dictionary comprehension builds {1: K1, 2: K2, ..., N: KN}.
            # It deliberately excludes K0, which is a commitment, not an interval key.
            auth_keys={index: chain[index] for index in range(1, chain_length + 1)},
        )

    # This factory also belongs to the class and does not require an existing HSM.
    @classmethod
    # The caller supplies trusted K0 and the agreed chain length; returns a receiver.
    def create_receiver(cls, commitment: bytes, chain_length: int) -> "HSM":
        # Omitted key-map arguments default to empty maps in __init__. This receiver
        # cannot check message MACs until it validates a disclosed interval key.
        return cls(role="receiver", commitment=commitment, chain_length=chain_length)

    # @property exposes this method as an attribute: read hsm.commitment without
    # parentheses. There is no setter here, so normal assignment to it is blocked.
    @property
    # This getter returns the public commitment as bytes, with no secret disclosure.
    def commitment(self) -> bytes:
        # Bytes are immutable, so a caller cannot edit this value in place.
        return self._commitment

    # A second read-only property exposes the configured number of usable keys.
    @property
    def chain_length(self) -> int:
        # Return the integer stored after constructor validation.
        return self._chain_length

    # Expose whether this object is a satellite or receiver through a property.
    @property
    def role(self) -> str:
        # Return the role text; this does not expose either key dictionary.
        return self._role

    # Internal guard shared by operations that use a numbered interval. Success
    # returns None implicitly; invalid indexes raise before key-map lookup.
    def _require_interval(self, interval: int) -> None:
        # Check exact int to exclude booleans, fractional numbers, and text like "1".
        if type(interval) is not int:
            # Tell callers this is an invalid HSM operation argument.
            raise HSMError("interval must be an integer")
        # A chain of length N supplies interval keys only for indexes 1 through N.
        if not 1 <= interval <= self._chain_length:
            # This avoids looking up index 0 (the commitment) or an absent key.
            raise HSMError("interval is outside the configured key chain")

    # Produce a message authentication code (MAC) for exact message bytes in one
    # interval. HMAC means hash-based message authentication code. It combines a
    # secret key with hashing and detects changed data for a checker who knows
    # that key, but does not hide the message's contents.
    # authenticated_data is already serialized by the caller; returns tag bytes.
    def generate_mac(self, interval: int, authenticated_data: bytes) -> bytes:
        """Generate HMAC-SHA256 without exposing the interval key."""

        # Only the satellite role has secret interval keys for creating these tags.
        if self._role != "satellite":
            # A receiver must not be offered a sender operation through this API.
            raise HSMError("receiver HSM cannot generate satellite MACs")
        # Verify the index exists within this instance's configured chain.
        self._require_interval(interval)
        # isinstance accepts bytes and its subclasses. Encoding text to bytes is
        # the caller's responsibility; silently choosing an encoding could change
        # the exact sequence sender and receiver authenticate.
        if not isinstance(authenticated_data, bytes):
            # TypeError specifically reports that the argument's type is unsuitable.
            raise TypeError("authenticated_data must be bytes")

        # Select the internal secret key assigned to this numbered time slot.
        key = self._auth_keys[interval]
        # Create a fresh HMAC computation using that key and the SHA-256 algorithm.
        # hashes.SHA256() selects the hash; hmac.HMAC(...) owns the running computation.
        mac = hmac.HMAC(key, hashes.SHA256())
        # Feed in the exact bytes to authenticate. No text/base64 transformation
        # happens here; even one changed byte would normally produce a different tag.
        mac.update(authenticated_data)
        # Finish the computation and return its 32-byte tag. The key itself is not
        # returned, and this completed HMAC object is not reused for another message.
        return mac.finalize()

    # Return an interval's actual key once its waiting period has elapsed. The *
    # requires explicitly named current_interval= and disclosure_delay= arguments.
    # Both interval and delay are counts of time slots, not seconds or timestamps.
    # This object has no clock: it trusts the supplied current_interval and delay.
    # The caller must get them from a trusted clock and agreed protocol policy;
    # a dishonest caller can defeat the timing rule by supplying a future interval.
    def disclose_key(self, interval: int, *, current_interval: int, disclosure_delay: int) -> bytes:
        """Explicitly disclose a key only after the configured delay has passed."""

        # A receiver has a disclosed-key cache, not the satellite's secret chain.
        if self._role != "satellite":
            # Refuse this method when the role cannot supply undisclosed keys.
            raise HSMError("receiver HSM has no undisclosed satellite keys")
        # The requested key must be one of K1..KN, regardless of current time.
        self._require_interval(interval)
        # ** means exponentiation. An unsigned 32-bit integer (uint32) can range
        # from 0 to 2**32 - 1; this policy excludes 0 so disclosure is delayed.
        # Exact int rejects True even though Python often treats it like number 1.
        if type(disclosure_delay) is not int or not 1 <= disclosure_delay <= 2**32 - 1:
            # Reject a zero, negative, oversized, or non-integer waiting period.
            raise HSMError("disclosure_delay must be a positive uint32 integer")
        # Current time must be represented by a positive integer slot. It may
        # exceed chain_length so that the final chain key can eventually be disclosed.
        if type(current_interval) is not int or current_interval < 1:
            # Reject unusable time input before doing the disclosure arithmetic.
            raise HSMError("current_interval must be a positive integer")
        # Example: key K3 with delay 2 first becomes disclosable in interval 5.
        # Using < means equality with that release interval is allowed.
        if current_interval < interval + disclosure_delay:
            # A distinct exception lets callers distinguish "wait longer" from
            # malformed input. No key is returned through this error branch.
            raise EarlyDisclosureError(
                # Adjacent f-strings are joined into one message by Python; the
                # first inserts the requested interval, the second its release slot.
                f"key for interval {interval} is not disclosable until interval "
                f"{interval + disclosure_delay}"
            )
        # Explicitly release immutable key bytes after every check. This does not
        # delete or mark the key; later authorized requests can return it again.
        return bytes(self._auth_keys[interval])

    # A receiver accepts a claimed Ki only after checking it belongs to trusted K0.
    # interval identifies i; key must be the raw key bytes. Returns None on success
    # and stores the key for future MAC checks. This checks chain membership, not
    # when a packet arrived or whether the key's disclosure happened on schedule.
    def validate_and_store_disclosed_key(self, interval: int, key: bytes) -> None:
        """Authenticate a disclosed chain key against the trusted commitment."""

        # Importing public disclosed keys is specifically a receiver operation.
        if self._role != "receiver":
            # Keep satellite state from accumulating a receiver-specific cache.
            raise HSMError("satellite HSM does not import disclosed receiver keys")
        # Reject invalid indexes before allowing them to control a hashing loop.
        self._require_interval(interval)
        # Only an exact 32-byte binary key has the expected chain format.
        if type(key) is not bytes or len(key) != KEY_SIZE:
            # Report this as a bad received disclosure rather than accepting it.
            raise InvalidKeyDisclosure("disclosed key must be exactly 32 bytes")

        # Preserve key for storage and hash a separate variable toward K0 instead.
        candidate = key
        # Starting from Ki requires exactly i hashes to reach K0. For example,
        # a claimed K2 must satisfy SHA256(SHA256(K2)) == the trusted commitment.
        for _ in range(interval):
            # Replace the candidate with the preceding key's hash-chain value.
            candidate = _sha256(candidate)
        # Compare against the commitment with the timing-conscious helper. This
        # establishes membership only if K0 itself was obtained through trust.
        if not stdlib_hmac.compare_digest(candidate, self._commitment):
            # A mismatch means this claimed key cannot authenticate to our chain.
            raise InvalidKeyDisclosure("disclosed key does not authenticate to the trusted commitment")

        # .get returns the already accepted key, or None if this slot is uncached.
        previous = self._disclosed_keys.get(interval)
        # Repeating the same disclosure is allowed; replacing an existing key with
        # different bytes is not, even after the commitment check above passes.
        if previous is not None and not stdlib_hmac.compare_digest(previous, key):
            # Preserve the earlier accepted key instead of changing receiver state.
            raise InvalidKeyDisclosure("a different key was already validated for this interval")
        # Cache only a key that passed all checks, using its interval as the map key.
        # bytes(...) preserves the immutable binary form; there is no explicit
        # return statement, so Python returns None when the method reaches its end.
        self._disclosed_keys[interval] = bytes(key)

    # A simple cache query: returns True when this interval has an accepted key,
    # False otherwise. It does not perform the role/index validation of other methods.
    def has_disclosed_key(self, interval: int) -> bool:
        # "in" checks dictionary keys, so no key bytes are exposed to the caller.
        return interval in self._disclosed_keys

    # Recompute/check a MAC for authenticated_data with a cached public interval key.
    # tag is the claimed 32-byte MAC; the result is a boolean (True or False).
    # Incorrect role, unavailable keys, or invalid argument types may still raise.
    # Once a key is public, anyone can make matching tags, so receiver protocol
    # code must also enforce that accepted messages arrived safely before disclosure.
    def verify_mac(self, interval: int, authenticated_data: bytes, tag: bytes) -> bool:
        """Verify HMAC-SHA256 using a previously validated disclosed key."""

        # This method belongs to receivers, which validate using disclosed keys.
        if self._role != "receiver":
            # Refuse to use a satellite's private store for this receiver operation.
            raise HSMError("MAC verification with disclosed keys belongs to the receiver HSM")
        # Validate the slot before trying to find a key for it.
        self._require_interval(interval)
        # Membership here means validate_and_store_disclosed_key (or constructor
        # validation during import) has already authenticated this cached key.
        if interval not in self._disclosed_keys:
            # No key means verification cannot be attempted, not merely a bad tag.
            raise HSMError("no validated disclosed key is available for this interval")
        # Data must have the same binary form used by the sender's HMAC operation.
        if not isinstance(authenticated_data, bytes):
            # Do not invent an encoding for an unexpected text or other object.
            raise TypeError("authenticated_data must be bytes")
        # A non-binary or wrong-length tag cannot be a complete HMAC-SHA256 result.
        # "or" skips len(tag) if the first check already rejects the type.
        if not isinstance(tag, bytes) or len(tag) != TAG_SIZE:
            # Malformed tags are treated as a failed verification, not an exception.
            return False

        # Start the same HMAC-SHA256 algorithm with the now-validated interval key.
        mac = hmac.HMAC(self._disclosed_keys[interval], hashes.SHA256())
        # Feed exactly the bytes whose integrity the receiver is checking.
        mac.update(authenticated_data)
        # cryptography reports a wrong tag by raising InvalidSignature; translate
        # that particular failure into this method's simple boolean result.
        try:
            # Finish and securely compare with the supplied tag. Successful verify
            # returns normally; it does not return a True/False result itself.
            mac.verify(tag)
            # Reaching this line means the library accepted the tag.
            return True
        # Catch only a mismatch exception, so unrelated failures are not disguised.
        except InvalidSignature:
            # The tag does not authenticate this exact data under this interval key.
            return False

    # Save this instance's state to an encrypted file. path may be a filename
    # string or a path-like object such as Path; the | in this type hint means
    # either type is accepted. Success returns None; file failures raise an error.
    # A satellite's saved state contains its WHOLE secret chain, so confidentiality
    # depends on protecting the master key separately from this encrypted file.
    def export_encrypted(self, path: str | os.PathLike[str]) -> None:
        """Persist the HSM key store using the environment-provided AES-256 key."""

        # Load the separate AES-256 storage key from the environment. It is not
        # an interval authentication key and will not be included in the saved JSON.
        master_key = master_key_from_env()

        # Build a plain dictionary that JSON can serialize. Quoted names on the
        # left are file-format field names; values on the right come from this HSM.
        state = {
            # This version describes the decrypted state's expected structure.
            "version": 1,
            # Preserve whether this state belongs to a satellite or a receiver.
            "role": self._role,
            # Preserve the agreed number of usable key intervals.
            "chain_length": self._chain_length,
            # JSON cannot directly represent bytes, so encode public K0 as base64.
            "commitment": _b64(self._commitment),
            # Turn integer indexes into string field names and binary secret keys
            # into base64 values. For a receiver this dictionary should be empty.
            # "for i, k in ...items()" builds one entry for each index/key pair.
            "auth_keys": {str(i): _b64(k) for i, k in self._auth_keys.items()},
            # Save accepted receiver keys the same way. For a satellite this map
            # should be empty; role and map consistency are checked when restoring.
            "disclosed_keys": {str(i): _b64(k) for i, k in self._disclosed_keys.items()},
        }
        # dumps converts the dictionary to JSON text. Sort field names for stable
        # ordering and use comma/colon separators without extra spaces, then encode
        # the text as UTF-8 bytes for AES-GCM. This variable still contains secrets
        # in process memory; base64/JSON alone provides no confidentiality.
        plaintext = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # Generate a fresh random 12-byte nonce. Randomness makes collisions
        # unlikely, but does NOT guarantee uniqueness across repeated exports.
        # GCM requires avoiding nonce reuse under the same master key; this code
        # does not keep a used-nonce registry or coordinate multiple processes.
        nonce = secrets.token_bytes(NONCE_SIZE)
        # Encrypt the JSON and append GCM's 16-byte authentication tag to the result.
        # FILE_MAGIC is additional authenticated data (AAD): visible bytes whose
        # integrity is checked without encrypting them. Like a visible envelope
        # label covered by a seal, the header must match when decrypting the file.
        # This binds the ciphertext to this exact format marker/version; it does
        # not make the file name or all filesystem metadata authenticated.
        ciphertext = AESGCM(master_key).encrypt(nonce, plaintext, FILE_MAGIC)

        # None means no temporary filename has been obtained yet. The finally
        # block can use this sentinel to decide whether there is anything to clean up.
        temporary = None
        # Wrap filesystem operations so expected operating-system/input failures
        # are reported consistently as PersistenceError.
        try:
            # Normalize either accepted path representation into a Path object.
            output_path = Path(path)
            # mkstemp creates AND opens a new temporary file, returning two values:
            # fd is its integer file descriptor; temporary is its filename.
            # Prefix with the target name and suffix .tmp; place it in the same
            # directory so the later replace operation can happen on one filesystem.
            # The leading dot conventionally hides the temporary filename on Unix.
            fd, temporary = tempfile.mkstemp(prefix=f".{output_path.name}.", suffix=".tmp",
                                              dir=output_path.parent)
            # mkstemp creates mode 0600 on POSIX before any bytes are written.
            # 0600 means only the owner receives read/write permissions. fdopen
            # wraps the already-open descriptor as a Python file object; "wb"
            # means write binary bytes. "with ... as stream" closes it when this
            # block ends, including when an operation in the block raises an error.
            with os.fdopen(fd, "wb") as stream:
                # + concatenates byte sequences in this order:
                # [public header][12-byte public nonce][ciphertext plus GCM tag].
                # The nonce need not be hidden; the master key is never written here.
                stream.write(FILE_MAGIC + nonce + ciphertext)
                # Push Python's buffered output to the operating system first.
                stream.flush()
                # Ask the operating system to synchronize this file's data to
                # storage; fileno() gives fsync the underlying file descriptor.
                os.fsync(stream.fileno())
            # Publish the complete temporary file at the requested destination,
            # replacing an existing destination if present. Same-filesystem
            # replacement is atomic on POSIX: readers see an old or new file,
            # rather than a partially rewritten one. No directory fsync occurs
            # here, so this is not a promise of surviving every possible crash.
            os.replace(temporary, output_path)
        # A tuple of exception classes catches any of these expected failure kinds.
        except (OSError, TypeError, ValueError) as exc:
            # Keep the original filesystem/input error as the cause for debugging.
            raise PersistenceError("unable to write encrypted HSM state") from exc
        # finally always runs after the try/except, whether the save worked or not.
        finally:
            # Only attempt deletion after a temporary filename was assigned.
            if temporary is not None:
                # Cleanup is best-effort and must not replace the main save error.
                try:
                    # Remove a leftover temporary file after failure. After a
                    # successful replace, its old filename is normally already gone.
                    os.unlink(temporary)
                # A missing file or other OS cleanup failure is intentionally ignored.
                except OSError:
                    # pass is Python's explicit "do nothing" statement for this block.
                    pass

    # This class method constructs a new instance from a saved file; no existing
    # satellite or receiver object is required to perform the import.
    @classmethod
    # path accepts the same string/path-like forms as export; returns a validated
    # HSM instance or raises PersistenceError for unsupported or damaged state.
    # Authentication detects modification but does not detect replay of an older
    # valid state file; this format does not contain an external freshness check.
    def import_encrypted(cls, path: str | os.PathLike[str]) -> "HSM":
        """Restore HSM state using the master key supplied through the environment."""

        # The same master-key bytes used for export must be supplied separately.
        # A missing/malformed environment key already raises PersistenceError here.
        master_key = master_key_from_env()

        # Separate file reading errors from format and decryption errors below.
        try:
            # "rb" means read binary, preserving file bytes without text decoding.
            # The with block ensures the file closes after reading or on failure.
            with Path(path).open("rb") as stream:
                # Read at most the maximum plus one byte. That extra byte lets us
                # recognize oversized files without loading their entire contents.
                blob = stream.read(MAX_STATE_FILE_SIZE + 1)
        # Catch inaccessible paths and unsuitable path arguments.
        except (OSError, TypeError, ValueError) as exc:
            # Report a read failure while retaining its original cause.
            raise PersistenceError("unable to read encrypted HSM state") from exc

        # The bounded read returns that extra byte only if the file exceeds our cap.
        if len(blob) > MAX_STATE_FILE_SIZE:
            # Reject before decrypting/parsing to bound memory and processing work.
            raise PersistenceError("encrypted HSM state is too large")

        # Even empty encrypted plaintext requires a header, a nonce, and GCM's
        # 16-byte authentication tag. This is only a structural minimum; a valid
        # JSON state requires more data and is checked after decryption.
        minimum = len(FILE_MAGIC) + NONCE_SIZE + 16
        # Require sufficient bytes AND the expected exact header at the start.
        # startswith checks this public marker before costly cryptographic work;
        # it is not itself an authenticity check (the GCM check comes later).
        if len(blob) < minimum or not blob.startswith(FILE_MAGIC):
            # Reject truncated files or files for another format/version.
            raise PersistenceError("invalid encrypted HSM file format")

        # The nonce starts immediately after the header, measured in byte offsets.
        nonce_start = len(FILE_MAGIC)
        # Slicing [start:end] takes bytes from start up to but excluding end.
        # Extract precisely the NONCE_SIZE bytes written between header and payload.
        nonce = blob[nonce_start : nonce_start + NONCE_SIZE]
        # An omitted end offset means "through the end"; this includes both
        # encrypted JSON and the appended authentication tag expected by AESGCM.
        ciphertext = blob[nonce_start + NONCE_SIZE :]
        # Only try to interpret JSON after authenticated decryption has succeeded.
        try:
            # Reuse the nonce and the exact FILE_MAGIC AAD supplied during export.
            # A wrong key or modified nonce/ciphertext/tag should make GCM reject
            # the file with InvalidTag instead of releasing unauthenticated data.
            plaintext = AESGCM(master_key).decrypt(nonce, ciphertext, FILE_MAGIC)
            # Decode binary UTF-8 into text, then parse JSON into Python objects.
            # object_pairs_hook installs the duplicate-field rejection helper for
            # every object; parse_constant rejects NaN/Infinity through our helper.
            state = json.loads(plaintext.decode("utf-8"), object_pairs_hook=_unique_object,
                               parse_constant=_reject_constant)
        # InvalidTag means failed GCM authentication; UnicodeDecodeError means bad
        # UTF-8; ValueError covers invalid JSON and our strict callbacks; deeply
        # nested JSON can raise RecursionError. All make the file unacceptable.
        except (InvalidTag, UnicodeDecodeError, ValueError, RecursionError) as exc:
            # Expose a consistent persistence error with the original cause attached.
            raise PersistenceError("HSM file authentication/decryption failed") from exc

        # Passing GCM authentication checks the file under the storage key; it
        # does not establish that the decrypted object has a sensible structure.
        # Validate the expected field layout (its schema) and the key chain next.
        try:
            # A set describes the EXACT permitted field names for state version 1.
            expected = {"version", "role", "chain_length", "commitment", "auth_keys", "disclosed_keys"}
            # Require a dictionary and identical field-name sets: this rejects both
            # missing fields and unexpected extras, regardless of their ordering.
            if type(state) is not dict or set(state) != expected:
                # Stop before retrieving fields from an unsupported data structure.
                raise ValueError("HSM state has missing or unexpected fields")
            # Require the integer 1 exactly; boolean True must not masquerade as
            # version 1 even though True == 1 in many Python comparisons.
            if type(state["version"]) is not int or state["version"] != 1:
                # Other versions need different parsing rules this code does not have.
                raise ValueError("unsupported HSM state version")
            # Read the claimed role; the constructor validates allowed roles later.
            role = state["role"]
            # Read the claimed number of interval keys from the JSON object.
            chain_length = state["chain_length"]
            # Enforce the chain-length cap before decoding indexes or constructing
            # an instance whose chain checks could otherwise demand excessive work.
            _require_chain_length(chain_length)
            # Base64 is text in the JSON format; reject any other field type first.
            if type(state["commitment"]) is not str:
                # A list or number is not a supported representation of public K0.
                raise ValueError("commitment must be an encoded string")
            # Convert K0 back into bytes. The constructor checks the digest length.
            commitment = _unb64(state["commitment"])
            # Rebuild the satellite key map, validating canonical index spellings
            # and bounds before decoding each base64-encoded key.
            auth_keys = _decode_keys(state["auth_keys"], chain_length)
            # Apply the same format checks to the receiver's disclosed-key cache.
            disclosed_keys = _decode_keys(state["disclosed_keys"], chain_length)
            # Construct and return the role-appropriate HSM. __init__ additionally
            # checks sizes, role/map consistency, and every chain relationship.
            # Thus even authenticated JSON cannot bypass the normal constructor.
            return cls(role=role, commitment=commitment, chain_length=chain_length,
                       auth_keys=auth_keys, disclosed_keys=disclosed_keys)
        # Convert missing-field, bad-type, and bad-value exceptions into one public
        # persistence error. _unb64's own PersistenceError can propagate directly.
        except (KeyError, TypeError, ValueError) as exc:
            # Retain the detailed cause while describing the overall import failure.
            raise PersistenceError("malformed HSM state") from exc

    # __repr__ is Python's special method for the object's developer-facing text,
    # used by repr(hsm) and often in interactive sessions or debugging output.
    def __repr__(self) -> str:
        # Parentheses allow a multi-line expression. Adjacent f-strings combine
        # into one string, containing useful counts and role but no key bytes.
        return (
            # !r formats the role with its string quotes; chain_length is numeric.
            f"HSM(role={self._role!r}, chain_length={self._chain_length}, "
            # len counts accepted cache entries. Secret material is deliberately
            # absent, so ordinary repr output does not dump the authentication keys.
            f"validated_disclosures={len(self._disclosed_keys)})"
        )
