# These tests exercise delayed authentication: a sender attaches a secret-key tag,
# then reveals the key later so a receiver can check messages saved beforehand.
# A tag is a short check value calculated from both a message and its secret key.
# Python ignores lines beginning with #; they explain the executable lines below.
# The future import lets type hints (such as Satellite below) be recorded without
# looking up their values immediately. Type hints describe intended inputs.
from __future__ import annotations

# Import Base64 conversion, which represents arbitrary bytes as printable text
# so an encryption key can be put in an environment variable.
import base64
# Import hash algorithms; SHA-256 is the algorithm used by the forged-tag test.
import hashlib
# Import HMAC, a calculation combining a secret key and message into a tag.
# The test uses it directly to model someone who has learned a disclosed key.
import hmac
# Import cryptographically strong random-byte generation for test keys.
import secrets
# Import replace, which makes a copy of a data object with selected fields
# changed. Tests use it to alter packets without changing the original packet.
from dataclasses import replace

# Import pytest, the test runner. It calls functions whose names start with
# test_. An assert fails a test when its condition is false; pytest.raises checks
# that an operation produces the named error instead of succeeding.
import pytest

# Import the application's public classes and helper function. The parentheses
# allow this one import statement to continue over several lines.
from mini_tesla import (
    # The receiver raises this error when a revealed key is unacceptable.
    DisclosureRejected,
    # The sender raises this error when asked to reveal a key too soon.
    EarlyDisclosureError,
    # AuthPacket holds message bytes, interval, sequence number, delay, and tag.
    AuthPacket,
    # HSM is the simulated protected key store used to generate or check tags.
    HSM,
    # HSMError is the general error for a forbidden key-store operation.
    HSMError,
    # PacketRejected reports an incoming packet that violates receiver rules.
    PacketRejected,
    # PersistenceError reports a failure saving or loading an encrypted key store.
    # Persistence means keeping state in a file so it can be restored later.
    PersistenceError,
    # Receiver stores arriving packets and checks them after a key is revealed.
    Receiver,
    # ReplayDetected reports a repeated packet or a packet for a closed interval.
    ReplayDetected,
    # Satellite is the sender that creates packets using its private keys.
    Satellite,
    # This function reads and decodes the master encryption key from the process
    # settings called environment variables.
    master_key_from_env,
)


# Define a reusable setup function. def introduces a function; its indented
# lines run when it is called. The * requires named options such as delay=2.
# An int hint means a whole number is expected; = 8 and = 1 are default values.
# The chain has eight usable time intervals unless a test requests another size.
def pair(*, chain_length: int = 8, delay: int = 1):
    # Create a fresh sender with its own keys and the requested disclosure delay,
    # meaning how many logical time steps must pass before a key may be revealed.
    satellite = Satellite(chain_length=chain_length, disclosure_delay=delay)
    # Create the matching receiver using public setup information from that sender.
    receiver = Receiver(
        # Trust this sender's commitment, the public hash value against which the
        # receiver checks that later revealed keys belong to the expected key chain.
        commitment=satellite.commitment,
        # Give the receiver the same number of usable key intervals as the sender.
        chain_length=chain_length,
        # Require the same waiting period on both sides.
        disclosure_delay=delay,
    )
    # Return both objects. A caller can assign the two returned values to two
    # names, as in satellite, receiver = pair(). Both clocks initially read 1.
    return satellite, receiver


# Define a helper that advances both clocks one step and processes a chosen
# interval's revealed key. The hints describe the two objects and whole-number
# interval expected. Its callers use it when one step is enough for disclosure.
def disclose_current(satellite: Satellite, receiver: Receiver, interval: int):
    # Move the sender's logical clock forward by one interval.
    satellite.advance()
    # Move the receiver's logical clock forward by the same amount.
    receiver.advance()
    # Ask the sender to reveal the key for the specified earlier interval.
    key = satellite.disclose(interval)
    # Have the receiver validate that key and check the saved packets, then return
    # its list of results to the test. A result says whether a packet was accepted.
    return receiver.process_disclosure(interval, key)


# Check the normal path: a valid packet must wait for its key before acceptance.
def test_valid_message_is_authenticated_only_after_key_disclosure():
    # Create a fresh sender and matching receiver at interval 1, with a one-step delay.
    satellite, receiver = pair()
    # Create an authenticated packet. The b prefix makes the message raw bytes,
    # the format the protocol accepts; telemetry means measured status information.
    packet = satellite.authenticate(b"valid telemetry")
    # Deliver the packet and require the reply "buffered", meaning saved for later.
    # The == operator compares values; assert reports a failure if they differ.
    assert receiver.receive(packet) == "buffered"
    # Check that exactly one packet is waiting for the undisclosed key.
    assert receiver.buffered_count == 1

    # Advance both clocks to 2, reveal interval 1's key, and collect the checks.
    results = disclose_current(satellite, receiver, 1)
    # For each result r, collect its accepted flag and explanation into a pair.
    # Require exactly one pair: True means accepted, for the reason "authenticated".
    assert [(r.accepted, r.reason) for r in results] == [(True, "authenticated")]
    # Require the waiting area to be empty after its packet has been checked.
    assert receiver.buffered_count == 0


# Check that changing a message while keeping its original tag is detected.
def test_modified_message_is_rejected():
    # Create a new matching sender and receiver with a one-interval disclosure delay.
    satellite, receiver = pair()
    # Authenticate the byte message "mode=safe" to obtain a genuine packet and tag.
    packet = satellite.authenticate(b"mode=safe")
    # Copy the packet with a different payload, meaning message content, but keep
    # the old tag. Deliver this altered copy before the key is available to check it.
    receiver.receive(replace(packet, payload=b"mode=unsafe"))
    # Advance both clocks and reveal interval 1's key to check the altered packet.
    results = disclose_current(satellite, receiver, 1)
    # Select the first result with [0] (Python counts positions from zero) and
    # require its accepted flag to be exactly False, meaning rejection.
    assert results[0].accepted is False
    # Check that the stated reason is a bad tag: the old tag does not match the
    # changed message bytes.
    assert results[0].reason == "invalid authentication tag"


# Check that even a one-bit change in the authentication tag is rejected.
def test_modified_tag_is_rejected():
    # Set up a fresh matching sender and receiver, both initially at interval 1.
    satellite, receiver = pair()
    # Create a genuine packet for the byte message "status=ok".
    packet = satellite.authenticate(b"status=ok")
    # Copy its tag into a bytearray, a byte sequence whose individual bytes can
    # be edited. The original bytes object cannot be edited in place.
    tag = bytearray(packet.tag)
    # [-1] selects the last byte. ^= flips the bits selected by 0x80, hexadecimal
    # 128, so exactly the top bit of that byte changes.
    tag[-1] ^= 0x80
    # Convert the edited tag back to fixed bytes, put it in a packet copy, and
    # send that copy to the receiver while the key is still secret.
    receiver.receive(replace(packet, tag=bytes(tag)))
    # Reveal interval 1's key after advancing both clocks. The first result [0]
    # must be False because the altered tag no longer matches the message.
    assert disclose_current(satellite, receiver, 1)[0].accepted is False


# Check that an invalid revealed key cannot discard a legitimate waiting packet.
def test_invalid_disclosed_key_is_rejected_and_buffer_survives():
    # Create a fresh sender and matching receiver with the default one-step delay.
    satellite, receiver = pair()
    # Generate a genuine packet and immediately deliver it to the waiting buffer.
    receiver.receive(satellite.authenticate(b"payload"))
    # Advance the sender from interval 1 to 2, when it may reveal interval 1's key.
    satellite.advance()
    # Advance the receiver to 2 as well, so a disclosure is no longer too early.
    receiver.advance()

    # Require a DisclosureRejected error from the indented operation. pytest.raises
    # fails the test if that operation succeeds or raises an unrelated error.
    with pytest.raises(DisclosureRejected):
        # Offer 32 random bytes as interval 1's key. They have the correct key length
        # but do not belong to the sender's key chain, modeling a bogus disclosure.
        receiver.process_disclosure(1, secrets.token_bytes(32))
    # Check that the failed disclosure left the one waiting packet in place.
    assert receiver.buffered_count == 1
    # Reveal the sender's real interval 1 key and check that the first saved packet
    # is accepted. This shows a bad disclosure did not prevent a later valid one.
    assert receiver.process_disclosure(1, satellite.disclose(1))[0].accepted is True


# Check that a packet cannot be accepted again after its key was processed.
# Sending an old message again is called a replay.
def test_previously_accepted_message_replay_is_rejected():
    # Create a new sender and receiver with matching keys and a one-step delay.
    satellite, receiver = pair()
    # Generate the genuine byte message "unique" and retain the resulting packet.
    packet = satellite.authenticate(b"unique")
    # Deliver it once while its authentication key is still secret.
    receiver.receive(packet)
    # Advance time, disclose interval 1's key, and require the first result's
    # accepted flag to be true before testing the replay.
    assert disclose_current(satellite, receiver, 1)[0].accepted
    # Require the named replay error when the next indented call resends the packet.
    with pytest.raises(ReplayDetected):
        # Deliver the same packet again, now that its interval has been closed by disclosure.
        receiver.receive(packet)


# Check that an exact duplicate is rejected even before any key is disclosed.
def test_duplicate_buffered_identity_is_rejected():
    # Create fresh matching endpoints at interval 1 with a one-interval delay.
    satellite, receiver = pair()
    # Make one genuine byte message and keep its packet for repeated delivery.
    packet = satellite.authenticate(b"unique")
    # The first delivery saves the packet for later verification.
    receiver.receive(packet)
    # Expect ReplayDetected, meaning the receiver recognizes the repeated candidate.
    # A candidate is a received packet whose authenticity is still unproven.
    with pytest.raises(ReplayDetected):
        # Send the identical packet a second time while the first copy is still buffered.
        receiver.receive(packet)


# Check that valid packets need not arrive in the order they were created.
def test_multiple_packets_can_arrive_out_of_order_before_disclosure():
    # Start a fresh matching sender and receiver with one-step key disclosure.
    satellite, receiver = pair()
    # Create the first byte message; the sender gives it the first sequence number.
    first = satellite.authenticate(b"first")
    # Create a second byte message with the next sequence number in the same interval.
    second = satellite.authenticate(b"second")
    # Deliver the later-created packet first to simulate network reordering.
    receiver.receive(second)
    # Deliver the earlier-created packet second, still before its key is public.
    receiver.receive(first)
    # Advance both clocks and reveal their shared interval 1 key to check both packets.
    results = disclose_current(satellite, receiver, 1)
    # len counts list entries; require one result for each of the two packets.
    assert len(results) == 2
    # all requires every accepted flag in the results to be true. The expression
    # for r in results visits each result, so both packets must pass.
    assert all(r.accepted for r in results)


# Check that processing one interval does not prevent processing the next one.
def test_more_than_one_disclosure_interval_is_processed():
    # Create fresh matching endpoints beginning at interval 1, with a one-step delay.
    satellite, receiver = pair()
    # Generate a genuine byte message at interval 1 and store it in the receiver.
    receiver.receive(satellite.authenticate(b"interval one"))
    # Move both clocks to 2, reveal key 1, and require the first packet to pass.
    assert disclose_current(satellite, receiver, 1)[0].accepted

    # The sender is now at interval 2; create and store a message using its next key.
    receiver.receive(satellite.authenticate(b"interval two"))
    # Move both clocks to 3, reveal key 2, and require this second interval's packet
    # to pass too. [0] selects the first result for that disclosure.
    assert disclose_current(satellite, receiver, 2)[0].accepted


# Check the exact time boundary for releasing a key after a two-step delay.
def test_satellite_hsm_blocks_early_key_disclosure():
    # Create a sender that waits two intervals. The receiver returned by pair is
    # assigned to _, a conventional name for a value this test does not use.
    satellite, _ = pair(delay=2)
    # Expect an early-disclosure error at the sender's starting interval, 1.
    with pytest.raises(EarlyDisclosureError):
        # Request interval 1's key immediately; the permitted disclosure time is 1 + 2 = 3.
        satellite.disclose(1)
    # Advance the sender once, from interval 1 to interval 2.
    satellite.advance()
    # Expect the same error because interval 2 is still earlier than interval 3.
    with pytest.raises(EarlyDisclosureError):
        # Request the same interval 1 key one step before its allowed release time.
        satellite.disclose(1)
    # Advance once more to interval 3, exactly the disclosure boundary.
    satellite.advance()
    # Require successful disclosure returning a 32-byte key. len measures the bytes;
    # this establishes that the boundary itself is allowed.
    assert len(satellite.disclose(1)) == 32


# Check that packet admission stops when its key could already be public.
# Anyone with that key could create a valid tag, so arrival time matters.
def test_receiver_rejects_packet_that_arrives_when_key_could_be_disclosed():
    # Set up matching endpoints with a one-step disclosure delay.
    satellite, receiver = pair(delay=1)
    # Make a genuine interval 1 packet but hold it instead of delivering it yet.
    packet = satellite.authenticate(b"late")
    # Move only the receiver to interval 2, the earliest disclosure time for key 1.
    receiver.advance()
    # Require PacketRejected from the next call, even though the packet was genuine.
    with pytest.raises(PacketRejected):
        # Deliver the held packet at the unsafe boundary; the receiver must refuse it
        # without needing to have seen the disclosed key itself.
        receiver.receive(packet)


# Check that a receiver refuses packets claiming a time interval it has not reached.
def test_receiver_rejects_future_interval_packet():
    # Create matching endpoints at interval 1 with a two-interval delay.
    satellite, receiver = pair(delay=2)
    # Advance only the sender to interval 2; the receiver remains at 1.
    satellite.advance()
    # Make a genuine packet labeled with the sender's now-current interval, 2.
    future = satellite.authenticate(b"future")
    # Expect PacketRejected because interval 2 is in this receiver's future.
    with pytest.raises(PacketRejected):
        # Try delivering the future-labeled packet to the receiver still at interval 1.
        receiver.receive(future)



# Check that a tag with the wrong length is rejected on arrival.
def test_malformed_tag_length_is_rejected_before_buffering():
    # Create a fresh matching sender and receiver with the usual one-step delay.
    satellite, receiver = pair()
    # Generate a correctly formed packet to serve as the basis for a malformed copy.
    packet = satellite.authenticate(b"payload")
    # Require PacketRejected at receive time, before delayed tag verification.
    with pytest.raises(PacketRejected):
        # Replace the tag with the five bytes of "short", instead of the required 32,
        # and attempt to deliver that copy.
        receiver.receive(replace(packet, tag=b"short"))


# Check that raw bytes alone cannot be passed off as a structured packet.
def test_non_packet_input_is_rejected():
    # Create a matching pair but keep only its receiver; _ marks the unused sender.
    _, receiver = pair()
    # Expect PacketRejected for the deliberately wrong kind of input below.
    with pytest.raises(PacketRejected):
        # Pass a bytes value where an AuthPacket object is required. The existing
        # "type: ignore" comment tells static type-checking tools this mismatch is
        # intentional; it does not change what Python executes.
        receiver.receive(b"not-a-packet")  # type: ignore[arg-type]


# Check that the bytes used to calculate a tag include identifying fields and
# the payload. Otherwise an attacker could change those parts without changing
# the input to the authentication calculation.
def test_authenticated_representation_covers_protocol_metadata():
    # Create a fresh sender; _ receives the unused receiver returned by pair.
    satellite, _ = pair()
    # Generate a genuine packet whose original fields provide a reference.
    packet = satellite.authenticate(b"payload")
    # Require different authenticated bytes after changing the sequence number to
    # 999. != means "is not equal to"; replace leaves the original packet intact.
    assert packet.authenticated_bytes() != replace(packet, sequence=999).authenticated_bytes()
    # Require different authenticated bytes after changing the time interval to 2.
    assert packet.authenticated_bytes() != replace(packet, interval=2).authenticated_bytes()
    # Require different authenticated bytes after replacing the payload with "other".
    assert packet.authenticated_bytes() != replace(packet, payload=b"other").authenticated_bytes()


# Check a round trip: save a key store and load an equivalent one from the file.
# pytest supplies tmp_path, a separate temporary folder, and monkeypatch, a helper
# that changes process settings for this test and restores them afterward.
def test_encrypted_hsm_export_import_round_trip(tmp_path, monkeypatch):
    # Create a sender-side HSM with a fresh four-interval key chain.
    hsm = HSM.create_satellite(4)
    # Generate a 32-byte (256-bit) master key used to encrypt the saved key store.
    master_key = secrets.token_bytes(32)
    # Convert that key to Base64 and then ASCII text, and put it in the environment
    # setting the save/load code reads. This temporary setting ends with the test.
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(master_key).decode("ascii"))
    # Build the filename inside pytest's temporary folder. / joins folder and
    # filename for Path objects here; it is not numeric division.
    path = tmp_path / "hsm.enc"

    # Save the HSM's state in encrypted form using the environment's master key.
    hsm.export_encrypted(path)
    # Read the file's raw bytes so the test can inspect what was actually saved.
    raw = path.read_bytes()
    # Require the plain commitment bytes to be absent from the file. This is a
    # specific check that this value was not written directly as readable state.
    assert hsm.commitment not in raw

    # Decrypt and load the saved state into a second HSM using the same master key.
    restored = HSM.import_encrypted(path)
    # Require the restored store to have the same public chain commitment.
    assert restored.commitment == hsm.commitment
    # Require the restored store to report the same number of key intervals.
    assert restored.chain_length == hsm.chain_length
    # Compute a MAC (message authentication code, or tag) for identical interval 1
    # bytes in both stores. Equal tags show the restored key can perform the same
    # operation as the original key.
    assert restored.generate_mac(1, b"abc") == hsm.generate_mac(1, b"abc")


# Check that a saved key store cannot be loaded using the wrong encryption key.
# pytest gives this test a temporary folder and a monkeypatch helper that restores
# changed environment settings afterward.
def test_encrypted_hsm_import_rejects_wrong_master_key(tmp_path, monkeypatch):
    # Create a fresh sender-side key store with three usable intervals.
    hsm = HSM.create_satellite(3)
    # Choose hsm.enc inside this test's temporary folder; / joins the path parts.
    path = tmp_path / "hsm.enc"

    # Generate the original 32-byte master encryption key.
    first_key = secrets.token_bytes(32)
    # Temporarily expose that key to the save/load code as Base64-encoded ASCII text.
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(first_key).decode("ascii"))
    # Encrypt the HSM state with the original key and write it to the chosen file.
    hsm.export_encrypted(path)

    # Generate a separate random 32-byte key to simulate an incorrect decryption key.
    wrong_key = secrets.token_bytes(32)
    # Replace the environment setting with the different key before loading.
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(wrong_key).decode("ascii"))
    # Require PersistenceError, the application's save/load error, from the load.
    with pytest.raises(PersistenceError):
        # Try decrypting the existing file with the wrong key; this must fail.
        HSM.import_encrypted(path)


# Check that saving requires an explicitly configured master encryption key.
# pytest supplies a temporary folder plus monkeypatch for temporary environment
# changes that are automatically undone after this test.
def test_hsm_persistence_requires_master_key_environment_variable(tmp_path, monkeypatch):
    # Remove the master-key setting. raising=False means removal is also allowed
    # when the setting was already missing.
    monkeypatch.delenv("MINITESLA_MASTER_KEY", raising=False)
    # Create a valid sender-side key store with two intervals, isolating the missing
    # master key as the reason saving should fail.
    hsm = HSM.create_satellite(2)
    # Require PersistenceError rather than silent saving without the required key.
    with pytest.raises(PersistenceError):
        # Attempt to save an encrypted file inside the test's temporary folder.
        hsm.export_encrypted(tmp_path / "hsm.enc")


# Check that the environment loader returns the original binary key.
# pytest provides monkeypatch so changing the process setting is limited to this test.
def test_master_key_is_loaded_from_environment(monkeypatch):
    # Generate a fresh 32-byte key as the expected decoded result.
    key = secrets.token_bytes(32)
    # Encode the bytes as Base64 text and temporarily store them under the expected
    # environment variable name.
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(key).decode("ascii"))
    # Load the setting and require exactly the original bytes, checking the text-to-
    # bytes conversion as well as use of the correct environment variable.
    assert master_key_from_env() == key


# Check that malformed key text is rejected. pytest's monkeypatch helper restores
# the environment after the deliberately bad setting used here.
def test_master_key_rejects_bad_environment_value(monkeypatch):
    # Set the key to text containing an exclamation mark, which is invalid Base64.
    monkeypatch.setenv("MINITESLA_MASTER_KEY", "not-base64!")
    # Require the application's PersistenceError for the invalid setting.
    with pytest.raises(PersistenceError):
        # Call the loader so it attempts to decode the malformed master-key text.
        master_key_from_env()


# Check that editing an encrypted file is detected during loading.
# pytest supplies a separate temporary folder and monkeypatch to set the required
# master key temporarily without leaving it changed for later tests.
def test_tampered_encrypted_hsm_file_is_rejected(tmp_path, monkeypatch):
    # Create a fresh sender-side HSM holding three interval keys.
    hsm = HSM.create_satellite(3)
    # Generate a random 32-byte master key for the encrypted file.
    master_key = secrets.token_bytes(32)
    # Put the key in the expected environment setting after Base64 and ASCII conversion.
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(master_key).decode("ascii"))
    # Choose the encrypted file path within this test's temporary folder.
    path = tmp_path / "hsm.enc"
    # Write a genuine encrypted HSM file before deliberately damaging it.
    hsm.export_encrypted(path)

    # Read the file into a bytearray so one of its bytes can be changed in place.
    blob = bytearray(path.read_bytes())
    # [-1] chooses the last byte. XOR-assignment (^=) with hexadecimal 0x01 flips
    # its lowest bit, modeling even a very small unauthorized file modification.
    blob[-1] ^= 0x01
    # Convert the edited sequence back to bytes and overwrite the test file.
    path.write_bytes(bytes(blob))

    # Require PersistenceError because authenticated encryption must detect the edit.
    with pytest.raises(PersistenceError):
        # Try to load the damaged file with the correct master key still configured.
        HSM.import_encrypted(path)


# Check that a packet naming an unsupported protocol version is refused.
def test_receiver_rejects_unsupported_protocol_version():
    # Create a matching sender and receiver using the supported protocol settings.
    satellite, receiver = pair()
    # Generate an otherwise valid packet as the starting point for a modified copy.
    packet = satellite.authenticate(b"payload")
    # Expect PacketRejected from receipt of the version-modified copy.
    with pytest.raises(PacketRejected):
        # Change only the version to 99, which fits the byte field but is unsupported
        # (the implemented version is 1), then deliver it.
        receiver.receive(replace(packet, version=99))


# Check the boundary on message size at the sender.
def test_satellite_rejects_oversized_payload():
    # Create a fresh sender; _ keeps the unused receiver returned by the helper.
    satellite, _ = pair()
    # Require ValueError, Python's usual error for an unacceptable argument value.
    with pytest.raises(ValueError):
        # Repeat byte "x" 1,048,577 times: one byte beyond the 1,048,576-byte limit.
        # The underscores make a number easier to read and do not change its value.
        satellite.authenticate(b"x" * (1_048_576 + 1))


# Check that the sender stops creating packets once every key interval is used.
def test_satellite_rejects_authentication_after_key_chain_exhaustion():
    # Create a sender with just one usable interval; the returned receiver is unused.
    satellite, _ = pair(chain_length=1)
    # Make a packet at interval 1 to exercise the last allowed key interval.
    satellite.authenticate(b"last valid interval")
    # Move the sender to interval 2, for which this one-key chain has no key.
    satellite.advance()
    # Require an exception whose message contains "key chain is exhausted".
    # match checks the error text; Exception accepts any ordinary exception class.
    with pytest.raises(Exception, match="key chain is exhausted"):
        # Attempt another authentication after the chain's usable interval has ended.
        satellite.authenticate(b"too late")


# Check that each HSM role permits only its assigned cryptographic operations.
def test_hsm_roles_enforce_crypto_operation_separation():
    # Create a sender with private authentication keys and a receiver that obtains
    # keys only through later validated disclosures.
    satellite, receiver = pair()
    # Require an HSMError for trying to use the receiver as a sender.
    with pytest.raises(HSMError):
        # Ask the receiver's key store to generate an interval 1 tag; its role forbids this.
        receiver.hsm.generate_mac(1, b"data")
    # Require an HSMError for trying to use the sender's HSM as a receiver.
    with pytest.raises(HSMError):
        # Ask the sender's key store to verify a tag. b"0" * 32 is a 32-byte placeholder;
        # the role restriction applies before this tag's correctness matters.
        satellite.hsm.verify_mac(1, b"data", b"0" * 32)


# Check why delayed authentication also requires an arrival-time rule: after a
# key is public, an attacker can calculate a correct HMAC for an invented message.
def test_valid_hmac_forged_after_disclosure_is_rejected_before_verification():
    # Start matching sender and receiver clocks at interval 1 with a one-step delay.
    satellite, receiver = pair()
    # Generate a genuine packet before its key becomes public.
    original = satellite.authenticate(b"original")
    # Save that genuine packet at the receiver while it can still be trusted on timing.
    receiver.receive(original)

    # Advance the sender to interval 2 so it may reveal key 1.
    satellite.advance()
    # Advance the receiver to the same disclosure time.
    receiver.advance()
    # Read interval 1's now-public key, which the simulated attacker can also know.
    disclosed_key = satellite.disclose(1)
    # Process the real disclosure and require the first saved packet to be accepted.
    # This establishes the normal flow before the forged packet is introduced.
    assert receiver.process_disclosure(1, disclosed_key)[0].accepted

    # Build an attacker-created packet rather than using the sender's authenticate
    # method. Its tag will be calculated directly from the public key below.
    forged = AuthPacket(
        # Claim interval 1, whose key is now known to the attacker.
        interval=1,
        # Use a new sequence number, 999, so this is not simply the original packet repeated.
        sequence=999,
        # Use the receiver's expected one-interval disclosure delay.
        disclosure_delay=1,
        # Choose message bytes controlled by the simulated attacker.
        payload=b"attacker-controlled",
        # Temporarily leave the tag empty so the packet's other authenticated fields
        # can be encoded before the finished tag is attached.
        tag=b"",
    )
    # Start an HMAC calculation to produce a mathematically correct forged tag.
    valid_forged_tag = hmac.new(
        # Use the legitimately disclosed key, now available outside the sender.
        disclosed_key,
        # Authenticate the forged packet's encoded fields and payload, exactly as a
        # legitimate tag would cover them.
        forged.authenticated_bytes(),
        # Select SHA-256, the same hash algorithm used by genuine protocol tags.
        hashlib.sha256,
    # Finish the calculation and obtain its raw tag bytes with digest().
    ).digest()
    # Make a packet copy containing the calculated valid tag.
    forged = replace(forged, tag=valid_forged_tag)

    # Require PacketRejected despite that valid tag: learning the key must not let
    # an attacker introduce a new packet for the already disclosed interval.
    with pytest.raises(PacketRejected):
        # Deliver the forged packet after key disclosure, when the receiver's admission
        # rules must reject it before any buffered-message tag verification.
        receiver.receive(forged)
