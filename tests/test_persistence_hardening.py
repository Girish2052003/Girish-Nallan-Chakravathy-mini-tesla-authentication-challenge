# These tests guard against previously found problems (the F-numbers name audit
# findings). Persistence means saving program state so it can be loaded later.
# A file can have valid encryption yet contain invalid state; both must be checked.
# Other cases check what happens if publishing a saved file is interrupted.
"""Authentic but invalid writer state and interrupted-write regressions (F05/07/10)."""
# Import Base64 conversion to represent secret key bytes as printable text in
# JSON files and environment variables.
import base64
# Import Python's object-copying helpers. This import is not used by the tests
# below; it remains part of the original test source.
import copy
# Import JSON conversion. JSON is a text format for objects containing named
# fields, lists, numbers, and other simple values.
import json
# Import operating-system file operations. Tests inspect a temporary file and
# replace the normal file-publication operation with a simulated failure.
import os
# Import cryptographically strong random-byte generation for keys and nonces.
# A nonce is a per-encryption input; these tests draw random nonces. Random
# sampling makes repeats unlikely but does not guarantee they are impossible.
import secrets
# Import helpers for extracting file permissions from operating-system file data.
import stat

# Import pytest, which runs test_ functions, supplies fixtures (reusable setup),
# and repeats parametrized tests with different inputs. assert requires a true
# condition; pytest.raises requires a named error from the indented operation.
import pytest
# Import AESGCM, authenticated encryption: it hides the saved bytes and detects
# unauthorized changes. These tests know the master key, so they can deliberately
# create correctly encrypted files with bad contents to test validation afterward.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import the simulated HSM key store, HSMError for forbidden key-store operations,
# and PersistenceError for saving or loading failures.
from mini_tesla import HSM, HSMError, PersistenceError
# Import the actual file-format marker FILE_MAGIC and encryption nonce length
# NONCE_SIZE (12 bytes), so test-written files match the real format.
from mini_tesla.hsm import FILE_MAGIC, NONCE_SIZE


# Mark store as a pytest fixture. pytest calls this setup for a test that requests
# the store argument, providing fresh state for each test and each parameter case.
@pytest.fixture
# Define that fixture. pytest supplies tmp_path, a separate temporary folder,
# and monkeypatch, which temporarily changes settings and undoes changes afterward.
def store(tmp_path, monkeypatch):
    # Generate a 32-byte (256-bit) master encryption key for this test's file.
    master = secrets.token_bytes(32)
    # Encode the master key as Base64 text and place it in the environment setting
    # used by the HSM save/load functions. decode() turns the encoded bytes into text.
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(master).decode())
    # Choose state.enc inside the temporary folder. For a Path, / joins path parts.
    path = tmp_path / "state.enc"
    # Create a genuine sender-side HSM with three usable key intervals.
    hsm = HSM.create_satellite(3)
    # Save its state using the real encryption/export code, providing a valid starting file.
    hsm.export_encrypted(path)
    # Read the complete saved file as raw bytes.
    raw = path.read_bytes()
    # Find where the nonce starts by counting the bytes in the leading format marker.
    start = len(FILE_MAGIC)
    # Slice out the nonce using [start:end] and the encrypted remainder using [start:].
    # Decrypt with the known master key; FILE_MAGIC is also checked as associated
    # data, meaning visible file information protected against changes. json.loads
    # then turns the decrypted JSON bytes into a Python dictionary of state fields.
    data = json.loads(AESGCM(master).decrypt(raw[start:start+NONCE_SIZE], raw[start+NONCE_SIZE:], FILE_MAGIC))

    # Define a helper inside the fixture. It remembers this fixture's path and
    # master key, letting tests rewrite the file with deliberately chosen contents.
    def write(state):
        # If state is already a str (text), encode it directly into bytes so even hand-
        # crafted JSON can be tested. Otherwise json.dumps first converts the Python
        # value to JSON text. The if/else expression chooses just one of these paths.
        plaintext = state.encode() if isinstance(state, str) else json.dumps(state).encode()
        # Draw another random 12-byte nonce for this rewrite.
        nonce = secrets.token_bytes(NONCE_SIZE)
        # Encrypt the chosen bytes with a valid master key and authentication check,
        # then write the marker, nonce, and encrypted result joined with +. Thus later
        # rejection can test bad state inside a cryptographically authentic file.
        path.write_bytes(FILE_MAGIC + nonce + AESGCM(master).encrypt(nonce, plaintext, FILE_MAGIC))
    # Return four useful values: the genuine HSM, file path, decoded starting state,
    # and the write function itself. Returning write without parentheses does not
    # call it; each test can call that helper after preparing its chosen bad state.
    return hsm, path, data, write


# Run the next test once per supplied state. None becomes JSON null; [] is an
# empty list; 7 is a number. The text values "null" and "[]" directly exercise
# those JSON forms, while the escaped-quote text is an object missing most fields.
@pytest.mark.parametrize("state", [None, [], 7, "null", "[]", "{\"version\":1}"])
# Check that authentic encryption does not make an invalid top-level JSON shape
# acceptable. pytest supplies both the fresh store fixture and the selected state.
def test_non_schema_states_raise_persistence_error(store, state):
    # Unpack the fixture's four results, keeping the file path and rewrite function.
    # The repeated _ names conventionally mark values this test does not use.
    _, path, _, write = store
    # Write this case's invalid state inside a correctly encrypted file.
    write(state)
    # Require PersistenceError, the public load/save error, instead of accepting
    # an incomplete state or leaking an unexpected internal parsing error.
    with pytest.raises(PersistenceError):
        # Attempt to decrypt and reconstruct an HSM from the deliberately invalid state.
        HSM.import_encrypted(path)


# Repeat the next test once for each (field, value) pair. A schema is the required
# set of fields and their allowed types and values; each case breaks one rule.
@pytest.mark.parametrize("field,value", [
    # Version must be the actual integer 1. True (Boolean) and 1.0 (floating point)
    # can compare equal to 1 in Python but have wrong types; version 2 is unsupported.
    ("version", True), ("version", 1.0), ("version", 2),
    # Role must be the text "satellite" or "receiver"; an empty list, unknown text,
    # and None (no value) must all fail.
    ("role", []), ("role", "other"), ("role", None),
    # Chain length must be a strict integer: True is a truth value, 3.0 is a float
    # even though it looks integral, and 3.9 must not be silently rounded to 3.
    ("chain_length", True), ("chain_length", 3.0), ("chain_length", 3.9),
    # The text "3" must not be converted to a number automatically; 0 and -1 are
    # below the minimum of one usable key interval.
    ("chain_length", "3"), ("chain_length", 0), ("chain_length", -1),
    # 4097 is one beyond the 4096-interval cap. Commitment must be encoded text
    # for a 32-byte public chain hash; None is missing and "AA==" decodes to just one byte.
    ("chain_length", 4097), ("commitment", None), ("commitment", "AA=="),
    # The private-key and disclosed-key fields must be dictionaries of index/key
    # pairs. Empty lists and None are wrong container types, even when they look empty.
    ("auth_keys", []), ("auth_keys", None), ("disclosed_keys", []), ("disclosed_keys", None),
])
# Check that malformed individual state fields fail closed: loading stops with
# an error instead of producing a partly valid or permissively interpreted HSM.
def test_invalid_schema_fields_fail_closed(store, field, value):
    # Obtain the saved-file path, decoded state dictionary, and encrypted rewrite
    # helper from a fresh store fixture; ignore the genuine HSM using _.
    _, path, state, write = store
    # Replace only this case's selected dictionary field with its invalid value.
    state[field] = value
    # Encrypt and write that altered state using the fixture's valid master key.
    write(state)
    # Require the defined PersistenceError when loading encounters the bad field.
    with pytest.raises(PersistenceError):
        # Attempt to restore the altered file through the normal import interface.
        HSM.import_encrypted(path)


# Repeat for six kinds of structural corruption. The labels select branches
# below: broken key link, short key, missing key, nonstandard index spelling,
# unexpected field, and missing required field.
@pytest.mark.parametrize("change", ["wrong_link", "short_key", "missing_key", "noncanonical", "extra_field", "missing_field"])
# Check sender invariants, meaning conditions that every sender key store must
# always satisfy, even when the saved file was written with the correct master key.
def test_satellite_invariants_are_checked(store, change):
    # Use a fresh fixture's three-key state, saved-file path, and encrypted writer.
    # _ marks the original HSM as unused in this test.
    _, path, state, write = store
    # For the broken-link case, change one key while keeping the expected key length.
    if change == "wrong_link":
        # Replace interval 2's key with 32 copies of byte "x", encoded as Base64 text.
        # This arbitrary key does not link to the trusted chain commitment by hashing.
        state["auth_keys"]["2"] = base64.b64encode(b"x" * 32).decode()
    # Otherwise, for the short-key case, target byte length instead of the chain link.
    elif change == "short_key":
        # Set interval 2's key text to "AA==", Base64 for one zero byte instead of 32 bytes.
        state["auth_keys"]["2"] = "AA=="
    # Otherwise, for the missing-key case, remove part of the sender's required full chain.
    elif change == "missing_key":
        # del deletes the dictionary entry for interval 2; a sender must retain every
        # key from interval 1 through its declared chain length.
        del state["auth_keys"]["2"]
    # Otherwise, select the case with a noncanonical index, meaning a number written
    # in a form the format deliberately does not permit.
    elif change == "noncanonical":
        # Add a second spelling "01" for interval 1 using the same key. Leading zeros
        # are disallowed so one interval cannot have ambiguous alternate names.
        state["auth_keys"]["01"] = state["auth_keys"]["1"]
    # Otherwise, select the case where the state contains an unrecognized field.
    elif change == "extra_field":
        # Insert a new field named unexpected; the format requires an exact field set.
        state["unexpected"] = 1
    # The remaining supplied case is missing_field, which removes a required field.
    else:
        # Delete disclosed_keys entirely. Even a sender with no disclosed receiver keys
        # must contain this required field, normally an empty dictionary.
        del state["disclosed_keys"]
    # Rewrite the changed state with genuine authenticated encryption, isolating
    # state validation from the separate ability to detect ciphertext tampering.
    write(state)
    # Require PersistenceError for whichever invalid state this parameter case created.
    with pytest.raises(PersistenceError):
        # Try importing the malformed sender state through the real file loader.
        HSM.import_encrypted(path)


# Repeat using each index/key pair. "0" and "-1" are invalid nonpositive indices;
# "4" exceeds this fixture's three-key chain. b"x" * 32 repeats one byte to make
# a correctly sized but unrelated key, keeping key length from causing rejection.
@pytest.mark.parametrize("index,key", [("0", b"x"*32), ("-1", b"x"*32), ("4", b"x"*32),
                                       # "1" is a valid index but its key fails the commitment check; "01" has a forbidden
                                       # leading zero and "1.0" has a decimal point instead of the required integer spelling.
                                       ("1", b"x"*32), ("01", b"x"*32), ("1.0", b"x"*32)])
# Check that a receiver's cached (saved) disclosed keys have both valid interval
# names and a verifiable relationship to the trusted public chain commitment.
def test_receiver_cached_keys_require_valid_indices_and_commitment(store, index, key):
    # Take the fixture's fresh state, file path, and encrypted rewrite helper;
    # the original HSM value is unused here.
    _, path, state, write = store
    # Change the saved role from sender to receiver so receiver-cache rules apply.
    state["role"] = "receiver"
    # Empty the private authentication-key dictionary, since a receiver must not
    # hold the sender's still-secret keys.
    state["auth_keys"] = {}
    # Create a one-entry disclosed-key dictionary with this case's chosen index
    # and a Base64 text representation of its 32-byte test key.
    state["disclosed_keys"] = {index: base64.b64encode(key).decode()}
    # Write the constructed receiver state using valid authenticated encryption.
    write(state)
    # Require PersistenceError for the invalid index or nonmatching cached key.
    with pytest.raises(PersistenceError):
        # Attempt to restore the malformed receiver key cache from the saved file.
        HSM.import_encrypted(path)


# Check the positive case: a receiver may legitimately save only some disclosed
# interval keys. Sparse means there are gaps, not that the saved keys are invalid.
def test_receiver_valid_sparse_disclosures_round_trip(store):
    # Keep all fixture values: the real sender HSM, encrypted-file path, decoded
    # three-key state, and helper for writing an authentic modified file.
    hsm, path, state, write = store
    # Make the saved state describe a receiver rather than a sender.
    state["role"] = "receiver"
    # Copy genuine keys 1 and 3 into the receiver's disclosed-key cache, deliberately
    # leaving out interval 2. Quoted numbers are text keys in the saved JSON format.
    state["disclosed_keys"] = {"1": state["auth_keys"]["1"], "3": state["auth_keys"]["3"]}
    # Remove the sender's private key dictionary from the receiver state.
    state["auth_keys"] = {}
    # Encrypt and save this valid receiver state with its two separated disclosures.
    write(state)
    # Import the receiver from the file, which should succeed because both keys
    # belong to the genuine chain even though an intermediate cache entry is absent.
    restored = HSM.import_encrypted(path)
    # Have the original sender create an interval 3 MAC (message authentication
    # code, or tag) for b"message", then require the restored receiver to verify it.
    # This checks the restored key's operation, not just its presence in saved data.
    assert restored.verify_mac(3, b"message", hsm.generate_mac(3, b"message"))
    # Require the restored receiver to report that key 1 was saved and validated.
    assert restored.has_disclosed_key(1)
    # Require key 2 to remain absent from the cache, preserving the intentional gap.
    assert not restored.has_disclosed_key(2)


# Run the next test twice: False tests a repeated top-level field; True tests
# a repeated field inside the nested auth_keys object.
@pytest.mark.parametrize("nested", [False, True])
# Check that duplicate JSON field names are forbidden even when both copies
# hold the same value, avoiding ambiguity between different JSON readers.
def test_duplicate_json_fields_are_rejected_even_if_identical(store, nested):
    # Use the fixture's file path, valid starting state, and encrypted rewrite helper.
    # The original HSM is not needed for this textual file-format test.
    _, path, state, write = store
    # Convert the valid state dictionary to JSON text so duplicate names can be
    # inserted manually; a Python dictionary itself stores only one value per name.
    raw = json.dumps(state)
    # Choose the inner-object branch when this parameter is True.
    if nested:
        # Insert an extra "1" entry at the start of auth_keys, using its actual existing
        # value encoded as JSON. The original "1" entry stays too, creating a duplicate
        # with identical contents inside the nested object.
        raw = raw.replace('"auth_keys": {', '"auth_keys": {"1": ' + json.dumps(state["auth_keys"]["1"]) + ', ')
    # For the False case, put the duplicate at the outermost object level instead.
    else:
        # Prepend another "version": 1 field. raw[1:] keeps everything after the original
        # opening brace, so the original version field remains later in the same object.
        raw = '{"version": 1, ' + raw[1:]
    # Encrypt the manually constructed raw text directly, preserving the duplicate
    # fields that ordinary dictionary-based JSON writing would have removed.
    write(raw)
    # Require PersistenceError rather than accepting either duplicate-field form.
    with pytest.raises(PersistenceError):
        # Load the file so the real JSON parser and its duplicate-name rejection run.
        HSM.import_encrypted(path)


# Try every invalid numeric value: True is Boolean; 1.0 is a float; NaN means
# "not a number"; infinity is not a finite whole number; -1 and 0 are not positive;
# and "2" is text. None should be silently accepted as valid time policy.
@pytest.mark.parametrize("value", [True, 1.0, float("nan"), float("inf"), -1, 0, "2"])
# Combine every value above with both fields: the current logical interval and
# the waiting period before disclosure. Stacked decorators run all combinations.
@pytest.mark.parametrize("field", ["current_interval", "disclosure_delay"])
# Check the HSM itself rejects invalid clock or delay values, even when someone
# calls it directly instead of using the higher-level sender interface.
def test_hsm_disclosure_rejects_non_integer_policy(field, value):
    # Create a valid two-interval sender HSM so only the supplied timing value is bad.
    hsm = HSM.create_satellite(2)
    # Begin with valid current time 2 and delay 1, then overwrite the selected field
    # with this case's value. The later dictionary entry wins when a name repeats.
    args = {"current_interval": 2, "disclosure_delay": 1, field: value}
    # Require HSMError, the key store's defined error for an unacceptable operation.
    with pytest.raises(HSMError):
        # Ask for key 1, expanding args with ** into named current_interval and
        # disclosure_delay arguments. Under the original valid values release would be
        # allowed; the substituted invalid value must instead be refused.
        hsm.disclose_key(1, **args)


# Repeat with invalid chain lengths: True and 1.0 have wrong numeric types;
# NaN is not a usable number; 4097 exceeds the cap of 4096; "2" is text; 0 would
# create no usable interval. These are values, not merely different spellings of integers.
@pytest.mark.parametrize("value", [True, 1.0, float("nan"), 4097, "2", 0])
# Check chain creation requires a real integer within the supported size range.
def test_chain_length_is_a_strict_bounded_integer(value):
    # Require ValueError for the selected invalid chain-length argument.
    with pytest.raises(ValueError):
        # Try creating a sender key store with that bad length.
        HSM.create_satellite(value)


# Check the HSM constructor validates key relationships as well as key sizes.
def test_constructor_checks_inconsistent_keys():
    # Create a genuine two-key sender HSM to obtain a legitimate public commitment.
    hsm = HSM.create_satellite(2)
    # Require ValueError when the next constructor receives keys unrelated to that commitment.
    with pytest.raises(ValueError):
        # Construct a sender-role HSM claiming the genuine commitment and two intervals.
        HSM(role="satellite", commitment=hsm.commitment, chain_length=2,
            # Supply complete-looking entries for intervals 1 and 2, each 32 bytes long,
            # but use repeated x and y bytes instead of the actual chain. Correct index and
            # length alone must not pass the checks connecting keys to the commitment.
            auth_keys={1: b"x"*32, 2: b"y"*32})


# Check that the file loader enforces its byte-size limit before trying to use
# an oversized state file, bounding how much untrusted file data it processes.
def test_oversized_import_is_rejected(store):
    # Take only the fixture's temporary file path. The other three returned values
    # are deliberately assigned to the unused-name convention _.
    _, path, _, _ = store
    # Write a real format marker followed by 1,048,577 x bytes, already one byte
    # beyond the 1,048,576-byte total-file cap before counting the marker. Underscores
    # in the numeric literal are visual separators and do not change the value.
    path.write_bytes(FILE_MAGIC + b"x" * (1_048_576 + 1))
    # Require PersistenceError whose explanation matches "large", identifying the
    # size limit as the rejection reason rather than a later decryption failure.
    with pytest.raises(PersistenceError, match="large"):
        # Attempt to import the deliberately oversized file.
        HSM.import_encrypted(path)


# Check atomic export: a replacement file should become visible all at once,
# and failure before replacement must leave the old file intact. The store fixture
# provides a valid saved file; pytest's monkeypatch replaces an operation only for
# this test and automatically restores it afterward.
def test_atomic_export_preserves_old_file_on_replace_failure(store, monkeypatch):
    # Keep the fixture's genuine HSM and saved-file path; the decoded state and
    # rewrite helper are not needed for testing the real exporter.
    hsm, path, _, _ = store
    # Read and retain the old encrypted file bytes as an exact comparison reference.
    original = path.read_bytes()
    # Create an empty list to record permissions observed on the new temporary file.
    observed_modes = []
    # Define a replacement for os.replace. It accepts the same source and destination
    # arguments but deliberately fails before moving the temporary file into place.
    def fail_replace(source, destination):
        # Inspect the source file's operating-system metadata, extract only its permission
        # bits with S_IMODE, and append them to the observation list. This runs at the
        # moment the exporter tries to publish the completed temporary file.
        observed_modes.append(stat.S_IMODE(os.stat(source).st_mode))
        # Before simulating failure, require the destination file still to equal the
        # original bytes, proving export did not overwrite the old file while preparing.
        assert path.read_bytes() == original
        # Raise OSError to simulate an operating-system failure during file replacement.
        # The real exporter should translate this into its public PersistenceError.
        raise OSError("simulated interrupted publication")
    # Temporarily replace os.replace with fail_replace so the actual exporter will
    # hit this controlled failure. Pass the function itself without calling it now.
    monkeypatch.setattr(os, "replace", fail_replace)
    # Require the export attempt to report PersistenceError after the injected failure.
    with pytest.raises(PersistenceError):
        # Call the real encrypted exporter for the existing path, exercising its temporary
        # file creation, attempted replacement, error conversion, and cleanup.
        hsm.export_encrypted(path)
    # After export fails, require the old file to remain byte-for-byte unchanged.
    assert path.read_bytes() == original
    # Require exactly one observed temporary file with permissions 0o600. The 0o
    # prefix denotes octal; 600 permits only the owner to read and write, and gives
    # no permissions to other users.
    assert observed_modes == [0o600]
    # List entries in the temporary folder and require only the original file path.
    # This checks that failure cleanup removed the unfinished temporary file.
    assert list(path.parent.iterdir()) == [path]


# Check export replaces a symbolic link itself without overwriting its target.
# A symbolic link is a filesystem entry that points at another path; following
# such a link during writing could unexpectedly damage an unrelated file.
def test_successful_export_replaces_symlink_without_writing_its_target(store):
    # Keep the fixture's genuine HSM and saved path; its other two values are unused.
    hsm, path, _, _ = store
    # Choose an unrelated target filename in the same temporary folder; parent is
    # the containing folder and / appends the new filename.
    target = path.parent / "unrelated"
    # Put recognizable bytes in that unrelated file so accidental changes are detectable.
    target.write_bytes(b"leave intact")
    # Remove the existing encrypted file at path, leaving room to install a link there.
    path.unlink()
    # Create a symbolic link at the saved-file path that points to the unrelated file.
    path.symlink_to(target)
    # Export the HSM to that path. Publishing a separately written file should
    # replace the link entry instead of following it and writing into its target.
    hsm.export_encrypted(path)
    # Require the target's marker bytes to remain exactly "leave intact".
    assert target.read_bytes() == b"leave intact"
    # Require the saved path to no longer be a symbolic link after successful export.
    assert not path.is_symlink()
    # Extract the new saved file's permissions and require octal 600: owner read/write
    # only. stat obtains file data; S_IMODE keeps the permission bits for comparison.
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # Load the newly saved file and require its public commitment to equal the
    # original HSM's commitment, showing replacement left a usable encrypted state.
    assert HSM.import_encrypted(path).commitment == hsm.commitment
