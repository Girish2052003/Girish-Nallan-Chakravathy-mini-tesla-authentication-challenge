# These tests deliberately try both valid requests and attacks against setup.
# Setup means the first exchange that lets a receiver trust a satellite's key chain.
# A key chain is a series of related secret keys, revealed one at a time later.
# TESLA uses those later revelations to check messages saved before the keys were public.
# The triple-quoted text below is the file's short description, called a docstring.
#
# Python reading guide: a name followed by (...) calls a function to do some work.
# A dot, as in receiver.receive, selects something belonging to that object.
# An equals sign stores a value; == compares values, and != means "not equal."
# Indented lines belong to the def, with, or other statement just above them.
# A test is a small example that fails if the program behaves unexpectedly.
"""Adversarial checks of authenticated TESLA trust bootstrap."""

# Import replace, which copies a record while changing selected named fields.
# This lets an attack change one part of a signed setup without editing the original.
from dataclasses import replace
# Import secrets to make random bytes that are hard for an attacker to guess.
import secrets

# Import pytest, the test runner that finds test_ functions and checks failures.
import pytest
# Import the Ed25519 signing-key type from the cryptography package.
# A private key makes digital signatures; its public key checks those signatures.
# The long dotted path identifies where the package provides this type.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Import the program's own setup helpers and types into this test file.
# Parentheses allow this one import statement to continue onto several lines.
from mini_tesla import (
    # ReceiverBootstrap checks a setup before creating a receiver; Satellite sends data.
    # SetupRejected names a setup error; SignedSetup is the record holding signed settings.
    # SignedSetup is imported here even though these tests obtain records through helpers.
    ReceiverBootstrap, Satellite, SetupRejected, SignedSetup,
    # sign_satellite_setup creates the satellite's signed reply to a receiver challenge.
    sign_satellite_setup,
)


# The @ line gives pytest an instruction about the function immediately below.
# A fixture is reusable test preparation. Pytest calls this one afresh for each test
# that lists setup_pair as an argument, so changes in one test do not affect another.
@pytest.fixture
# Define the preparation function; its returned objects become the setup_pair value.
def setup_pair():
    # Generate a new secret signing key for the legitimate satellite.
    signing_key = Ed25519PrivateKey.generate()
    # Make a sender with five interval keys; each key becomes public two time steps later.
    # Its first time step, called an interval, is numbered 1.
    satellite = Satellite(chain_length=5, disclosure_delay=2)
    # Pinning means choosing the trusted public key locally before any network exchange.
    # TOFU means "trust on first use": accepting whichever key arrives first.
    # This test provides the known key directly, rather than learning trust from a reply.
    # Public key pinning is a trusted local configuration action, not network TOFU.
    # Create the receiver's setup checker; the following named arguments configure it.
    bootstrap = ReceiverBootstrap(
        # Give it the public part of the real signing key so it can check the sender's identity.
        trusted_public_key=signing_key.public_key(),
        # Require the reply to claim this exact satellite name.
        expected_satellite_id="satellite-alpha",
        # lambda creates a tiny function with no arguments. Each call reads the sender's
        # current interval, so this simulated trusted clock follows later sender advances.
        # This test supplies a trusted clock; it does not implement real clock synchronization.
        trusted_interval_source=lambda: satellite.current_interval,
    )
    # Ask the sender to sign its current settings and this receiver's random challenge.
    response = sign_satellite_setup(
        # Pass the sender itself and the private key that is allowed to sign for it.
        satellite, signing_key=signing_key,
        # Include the expected name and the receiver's challenge: random bytes used once
        # to tie the reply to this setup attempt and make old replies distinguishable.
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    # Return four objects in order as a tuple, a group of values: sender, secret key,
    # receiver setup checker, and signed reply. Tests pick out the ones they need.
    return satellite, signing_key, bootstrap, response


# Check the complete successful path: trusted setup, saved message, then verification.
# The setup_pair argument asks pytest for a fresh sender and a matching signed reply.
def test_valid_signed_setup_then_tesla_authentication(setup_pair):
    # Unpack the four fixture values into names. The _ name marks the unused signing key.
    satellite, _, bootstrap, signed = setup_pair
    # Verify the signed reply and create a receiver with those trusted settings.
    receiver = bootstrap.establish(signed)
    # assert makes the test fail if its condition is false. Check that both sides use
    # the same commitment, the public starting value used to verify revealed chain keys.
    # The receiver stores it in hsm, the simulation of a protected key-handling component.
    assert receiver.hsm.commitment == satellite.commitment
    # Check that the signed two-interval key-revelation delay reached the receiver.
    assert receiver.disclosure_delay == 2
    # Make a message with a secret-key authentication tag. b before the quotes means
    # raw bytes, and this payload represents real data reported by the satellite.
    packet = satellite.authenticate(b"real telemetry")
    # Deliver the message and check it is saved ("buffered") pending its key's release.
    # A saved message is not yet trusted; verification must wait for that key.
    assert receiver.receive(packet) == "buffered"
    # Move the sender forward two intervals, from 1 to 3; its first key is now releasable.
    satellite.advance(2)
    # Check that the receiver's live trusted clock also reports interval 3.
    assert receiver.current_interval == 3
    # Reveal the key for interval 1 and give it to the receiver to check saved messages.
    # The inner satellite.disclose(1) call runs before process_disclosure uses its result.
    results = receiver.process_disclosure(1, satellite.disclose(1))
    # len counts the results; [0] selects the first one because Python starts at zero.
    # Require both exactly one result and its accepted flag to be true.
    assert len(results) == 1 and results[0].accepted


# Check that an attacker cannot pass as the real satellite by making a new key chain.
# Pytest supplies a fresh receiver setup checker that already trusts the real public key.
def test_attacker_generated_chain_and_signature_cannot_impersonate_satellite(setup_pair):
    # Keep only the fixture's setup checker; _ marks the three values unused here.
    _, _, bootstrap, _ = setup_pair
    # Give the attacker a separate private signing key, unrelated to the trusted key.
    attacker_key = Ed25519PrivateKey.generate()
    # Give the attacker a valid-looking sender with its own five keys and two-step delay.
    attacker_satellite = Satellite(chain_length=5, disclosure_delay=2)
    # Create an attacker's signed reply. Its structure is valid, but its signer is wrong.
    forged = sign_satellite_setup(
        # Use the attacker's sender and private key to make the reply.
        attacker_satellite, signing_key=attacker_key,
        # Copy the legitimate name and the correct challenge, so those fields look right.
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    # with pytest.raises expects the indented action to report the SetupRejected error.
    # The test fails if no such error occurs; match also requires "signature" in its message.
    with pytest.raises(SetupRejected, match="signature"):
        # Submit the forgery to the checker that trusts the real key; signature checking must fail.
        bootstrap.establish(forged)


# parametrize runs the next test once for each item in this list, passing it as change.
# Each {...} item is a dictionary: a field name paired with its replacement value.
@pytest.mark.parametrize("change", [
    # Replace the commitment with 32 copies of byte x, breaking the signed chain identity.
    {"commitment": b"x" * 32},
    # Claim four keys instead of the signed five, changing the chain's stated length.
    {"chain_length": 4},
    # Claim a three-interval delay instead of the signed two.
    {"disclosure_delay": 3},
    # Claim a different satellite identity.
    {"satellite_id": "satellite-beta"},
    # Claim setup format version 2, which this implementation does not support.
    {"version": 2},
])
# Check each one-field change to signed setup settings is rejected.
# Pytest supplies both a fresh setup_pair fixture and the current change dictionary.
def test_any_signed_setup_metadata_modification_fails(setup_pair, change):
    # Keep the receiver setup checker and its valid signed reply; ignore the other values.
    _, _, bootstrap, signed = setup_pair
    # Require a SetupRejected error from the changed reply; no exact message is required.
    with pytest.raises(SetupRejected):
        # Copy the reply with the selected change, then ask the checker to accept that copy.
        # **change expands the dictionary into named arguments for replace; the old signature stays.
        bootstrap.establish(replace(signed, **change))


# Check that altering even one bit of a signature makes the setup fail.
# The setup_pair fixture provides a valid reply and the checker that should accept it.
def test_modified_signature_is_rejected(setup_pair):
    # Keep that checker and reply; _ marks unused sender and signing-key values.
    _, _, bootstrap, signed = setup_pair
    # Copy the signature into a bytearray, a byte sequence whose contents can be edited.
    wrong = bytearray(signed.signature)
    # [-1] selects the last byte. ^= 1 flips just its lowest binary digit (bit),
    # keeping the signature's length unchanged but changing its content.
    wrong[-1] ^= 1
    # Expect SetupRejected and require its message to mention the signature.
    with pytest.raises(SetupRejected, match="signature"):
        # Turn the edited bytes back into an unchangeable bytes value, put them into a
        # copy of the signed reply, and submit that altered reply for rejection.
        bootstrap.establish(replace(signed, signature=bytes(wrong)))


# Check that replaying a genuine old reply does not answer a new receiver's challenge.
# The fixture supplies the first receiver's checker, signing key, and valid old reply.
def test_old_signed_setup_does_not_satisfy_new_receiver_challenge(setup_pair):
    # Keep those three values; the sender itself is not needed for the replay attempt.
    _, key, old_bootstrap, old_signed = setup_pair
    # Start an independent receiver setup attempt, which generates a fresh challenge.
    new_bootstrap = ReceiverBootstrap(
        # Trust the same legitimate public key, so this is not a wrong-signer test.
        trusted_public_key=key.public_key(),
        # Expect the same satellite identity as the old reply.
        expected_satellite_id="satellite-alpha",
        # Supply a tiny trusted-clock function that always returns interval 1.
        trusted_interval_source=lambda: 1,
    )
    # assert checks that the independently generated challenges are different.
    assert new_bootstrap.challenge != old_bootstrap.challenge
    # Expect rejection specifically mentioning that the fresh receiver challenge is wrong.
    with pytest.raises(SetupRejected, match="fresh receiver challenge"):
        # Present the old signed reply to the new checker; the old challenge must not match.
        new_bootstrap.establish(old_signed)


# Check that even a real satellite signature fails when the receiver trusts another key.
# This tests the importance of configuring the correct trusted identity key.
def test_valid_signature_under_untrusted_identity_key_is_rejected(setup_pair):
    # Take only the real signing key from the fixture; _ marks the unused objects.
    _, real_key, _, _ = setup_pair
    # Make a fresh sender with five keys and a two-interval delay for this separate reply.
    satellite = Satellite(chain_length=5, disclosure_delay=2)
    # Create a receiver setup checker with a deliberately incorrect trusted identity key.
    wrong_identity = ReceiverBootstrap(
        # Generate an unrelated private key and give the checker its public part.
        trusted_public_key=Ed25519PrivateKey.generate().public_key(),
        # Still require the real satellite's name, so only the key is wrong.
        expected_satellite_id="satellite-alpha",
        # Keep the simulated trusted time at interval 1 with a no-argument lambda function.
        trusted_interval_source=lambda: 1,
    )
    # A nonce is a random value intended for one use; here it means the receiver challenge.
    # The challenge will be correct, but the checker's chosen public key will not be.
    # Real signature for the right nonce still fails under a wrongly pinned key.
    # Build a reply genuinely signed by the real satellite's private key.
    signed = sign_satellite_setup(
        # Use the fresh sender and the legitimate private key taken from the fixture.
        satellite, signing_key=real_key,
        # Include the expected name and this incorrectly configured checker's own challenge.
        satellite_id="satellite-alpha", challenge=wrong_identity.challenge,
    )
    # Expect SetupRejected with "signature" in the message, proving the identity check fails.
    with pytest.raises(SetupRejected, match="signature"):
        # Submit the legitimate reply to the checker that trusts the unrelated public key.
        wrong_identity.establish(signed)


# Check that an attacker cannot use up the receiver's challenge with a failed reply.
# The fixture provides a valid reply to try again after the deliberately invalid one.
def test_failed_attempt_does_not_consume_legitimate_challenge(setup_pair):
    # Keep the fresh setup checker and valid signed reply; ignore the other fixture values.
    _, _, bootstrap, signed = setup_pair
    # Expect a SetupRejected error during the first, deliberately bad attempt.
    with pytest.raises(SetupRejected):
        # Replace the real signature with 64 repeated exclamation-mark bytes and submit it.
        # The length looks right, but those bytes do not prove who signed the settings.
        bootstrap.establish(replace(signed, signature=b"!" * 64))
    # Now submit the original reply. assert checks the new receiver stores its commitment,
    # showing that the failed attempt left the same challenge available for legitimate use.
    assert bootstrap.establish(signed).hsm.commitment == signed.commitment


# Check that a successful setup uses up its challenge and cannot be accepted twice.
# The fixture supplies a fresh checker and a genuinely signed reply.
def test_successful_bootstrap_consumes_challenge(setup_pair):
    # Keep the checker and reply; ignore the sender and private key.
    _, _, bootstrap, signed = setup_pair
    # Accept the genuine reply once, marking the challenge as used.
    bootstrap.establish(signed)
    # Expect SetupRejected with "consumed" in the message when the same checker is reused.
    with pytest.raises(SetupRejected, match="consumed"):
        # Submit the identical valid reply again; successful setup must still be single use.
        bootstrap.establish(signed)


# Run the following test once per malformed field replacement, passed in as change.
# Each dictionary deliberately violates a size, allowed-content, or value-type rule.
@pytest.mark.parametrize("change", [
    # Use an empty byte sequence instead of the required 32-byte receiver challenge.
    {"challenge": b""},
    # Use an empty commitment instead of the required 32-byte chain starting value.
    {"commitment": b""},
    # Use 63 x bytes for a signature that must contain exactly 64 bytes.
    {"signature": b"x" * 63},
    # Use an empty satellite name, which is not an allowed identity.
    {"satellite_id": ""},
    # Use a name containing spaces and a snowman; the allowed name alphabet excludes them.
    {"satellite_id": "bad unicode ☃"},
    # Repeat A 65 times, exceeding the satellite name's 64-character limit.
    {"satellite_id": "A" * 65},
    # Claim a chain with zero keys, below the minimum of one.
    {"chain_length": 0},
    # Claim 4097 keys, above this implementation's maximum of 4096.
    {"chain_length": 4097},
    # Use True, a yes/no value, where a whole-number chain length is required.
    # Python can treat True like 1 in arithmetic, so the explicit type check matters.
    {"chain_length": True},
    # Use zero delay, although at least one interval must pass before a key is released.
    {"disclosure_delay": 0},
    # float("nan") makes a special numeric value meaning "not a number";
    # it is not an acceptable whole-number delay.
    {"disclosure_delay": float("nan")},
    # ** means raising to a power: 2**32 is one larger than the largest allowed delay.
    {"disclosure_delay": 2**32},
    # Use the yes/no value True instead of a whole-number setup version.
    {"version": True},
])
# Check every listed malformed setup is rejected, even when based on a valid reply.
# Pytest provides a fresh setup_pair and one field replacement for each test run.
def test_malformed_setup_is_never_accepted(setup_pair, change):
    # Keep the setup checker and original signed reply; the other fixture values are unused.
    _, _, bootstrap, signed = setup_pair
    # Require the malformed reply to raise the program's SetupRejected error.
    with pytest.raises(SetupRejected):
        # replace makes an altered copy; **change supplies its selected field and bad value.
        # Submit the copy for validation while leaving the original fixture reply untouched.
        bootstrap.establish(replace(signed, **change))


# Check that receiver creation requires an actual trusted public-key object.
# It must not silently accept some other object and turn it into a trusted identity.
def test_no_untrusted_auto_key_provisioning():
    # Generate a signing key representing one controlled by an attacker.
    attacker_key = Ed25519PrivateKey.generate()
    # Expect TypeError, meaning an input has the wrong kind of value, mentioning "public key".
    with pytest.raises(TypeError, match="public key"):
        # Try to construct a receiver setup checker with the deliberately wrong input below.
        ReceiverBootstrap(
            # Pass the key's private_bytes method itself: a callable operation, not a public key.
            # There are no parentheses to call it here. The existing type: ignore comment asks
            # static type-checking tools to allow this intentional misuse in a test; Python ignores it.
            trusted_public_key=attacker_key.private_bytes,  # type: ignore[arg-type]
            # Provide an otherwise normal expected satellite name.
            expected_satellite_id="satellite-alpha",
            # Provide a normal no-argument trusted-clock function returning interval 1.
            trusted_interval_source=lambda: 1,
        )


# Check that the sender refuses both a malformed challenge and a non-private signing key.
# The fixture supplies a sender, its private key, and the receiver's valid challenge.
def test_sender_rejects_invalid_challenge_and_signer(setup_pair):
    # Keep those three fixture objects; the already signed reply is not needed.
    satellite, key, bootstrap, _ = setup_pair
    # Require a SetupRejected error from the first signing attempt.
    with pytest.raises(SetupRejected):
        # Attempt to sign another setup with the fixture's sender, which has already signed one.
        # Because the sender is already used, this test does not isolate the short-challenge check.
        sign_satellite_setup(
            # Pass that sender and its genuine private signing key.
            satellite, signing_key=key,
            # Use the expected identity but an intentionally short challenge instead of 32 bytes.
            satellite_id="satellite-alpha", challenge=b"too short",
        )
    # Expect TypeError on the second attempt because the supplied signing key has the wrong type.
    with pytest.raises(TypeError):
        # Try signing again, this time deliberately supplying only a public key.
        sign_satellite_setup(
            # Public keys check signatures; they cannot create them. The type: ignore comment
            # suppresses a type-checker's warning about this deliberately wrong argument.
            satellite, signing_key=key.public_key(),  # type: ignore[arg-type]
            # Use the correct satellite name and valid receiver challenge for this wrong-key attempt.
            satellite_id="satellite-alpha", challenge=bootstrap.challenge,
        )


# Check that identical settings produce identical bytes to sign, and a changed delay does not.
# This checks the encoding of settings, not whether two freshly made signatures are equal.
def test_session_config_signed_bytes_are_deterministic(setup_pair):
    # Keep only the valid signed reply from the fixture; the _ positions are unused.
    _, _, _, signed = setup_pair
    # assert compares the reply's signing input with a copy having no changes.
    # The two signed_bytes() calls must produce exactly the same byte sequence.
    assert signed.signed_bytes() == replace(signed).signed_bytes()
    # Require a different byte sequence when making the changed copy described below.
    # The comparison continues onto the next lines inside replace(...).
    assert signed.signed_bytes() != replace(
        # Copy the original reply but increase its key-revelation delay by one interval.
        signed, disclosure_delay=signed.disclosure_delay + 1,
    # Finish making that copy and encode its settings for the inequality check above.
    ).signed_bytes()


# Check that each new receiver creates its own 32-byte random challenge (nonce).
# No sender object is needed to generate these values.
def test_nonce_is_fresh_and_not_derived_from_sender():
    # Make one legitimate private key so both receivers can trust the same public key.
    key = Ed25519PrivateKey.generate()
    # Create the first setup checker using that public key, the expected satellite name,
    # and a lambda function that always reports interval 1; save the checker as a.
    a = ReceiverBootstrap(trusted_public_key=key.public_key(), expected_satellite_id="satellite-alpha", trusted_interval_source=lambda: 1)
    # Create a separate checker b with exactly the same trusted settings.
    # Its challenge should still be newly generated rather than copied from a.
    b = ReceiverBootstrap(trusted_public_key=key.public_key(), expected_satellite_id="satellite-alpha", trusted_interval_source=lambda: 1)
    # len counts bytes. assert requires both challenges to have the required length 32;
    # and means both comparisons must be true.
    assert len(a.challenge) == 32 and len(b.challenge) == 32
    # Require the two randomly generated challenges to differ despite identical settings.
    assert a.challenge != b.challenge


# Check that random bytes cannot stand in for a structured SignedSetup record.
# The fixture provides a receiver setup checker expecting that record type.
def test_wrong_type_cannot_be_accepted(setup_pair):
    # Keep only the checker; _ marks all other fixture values as unused.
    _, _, bootstrap, _ = setup_pair
    # Expect SetupRejected because the incoming value has the wrong kind of object.
    with pytest.raises(SetupRejected):
        # Submit 128 unpredictable bytes instead of a setup record. type: ignore tells
        # static type-checking tools this wrong argument is intentional; it does not change execution.
        bootstrap.establish(secrets.token_bytes(128))  # type: ignore[arg-type]


# Check that a bad local receiver limit does not use up an otherwise valid challenge.
# The fixture provides a trusted checker and valid signed reply for both attempts.
def test_receiver_policy_is_locally_validated_without_consuming_challenge(setup_pair):
    # Keep that checker and reply; ignore the sender and private key.
    _, _, bootstrap, signed = setup_pair
    # Expect ValueError, the error used here for an invalid configuration value.
    with pytest.raises(ValueError):
        # Try establishing with room for zero saved packets, below the required minimum.
        # This limit belongs to the receiver's local policy; it is not supplied by the sender.
        bootstrap.establish(signed, max_buffered_packets=0)
    # Retry using default limits, then assert the receiver stores the signed commitment.
    # Success proves the earlier local-configuration error did not consume the challenge.
    assert bootstrap.establish(signed).hsm.commitment == signed.commitment


# Check that one sender key chain cannot be signed for two different receiver sessions.
# The fixture's sender has already signed the fixture receiver's challenge.
def test_sender_cannot_sign_same_chain_for_two_new_receivers(setup_pair):
    # Keep that already used sender and its signing key; ignore the other fixture values.
    satellite, key, _, _ = setup_pair
    # Create a second receiver setup attempt, which produces another random challenge.
    another_receiver = ReceiverBootstrap(
        # Give this second checker the legitimate public verification key.
        trusted_public_key=key.public_key(),
        # Require the same satellite name as in the original setup.
        expected_satellite_id="satellite-alpha",
        # Use a no-argument trusted-clock function returning interval 1.
        trusted_interval_source=lambda: 1,
    )
    # Expect SetupRejected with "fresh, unused" in its message: this chain is already assigned.
    with pytest.raises(SetupRejected, match="fresh, unused"):
        # Attempt to sign a setup for the second receiver using the first receiver's chain.
        sign_satellite_setup(
            # Supply the already used sender, its legitimate private key, and expected identity.
            satellite, signing_key=key, satellite_id="satellite-alpha",
            # Bind this attempted signature to the second receiver's different challenge.
            challenge=another_receiver.challenge,
        )


# Check two other ways a chain becomes unsuitable for first setup: sending a message
# or letting time advance. Each case uses a different newly created sender.
def test_sender_cannot_sign_chain_after_messages_or_time_progress():
    # Make a private key for legitimately signing either test sender's settings.
    key = Ed25519PrivateKey.generate()
    # Create the first sender with four keys and a one-interval key-release delay.
    used = Satellite(chain_length=4, disclosure_delay=1)
    # Authenticate one byte-string message, making this chain no longer unused.
    used.authenticate(b"already used")
    # Expect SetupRejected explaining that signing requires a fresh, unused chain.
    with pytest.raises(SetupRejected, match="fresh, unused"):
        # Attempt the first setup signature after the sender has already made a message.
        sign_satellite_setup(
            # Use the message-producing sender, real signing key, and expected satellite identity.
            used, signing_key=key, satellite_id="satellite-alpha",
            # Provide a properly sized random 32-byte challenge so the used chain is the problem.
            challenge=secrets.token_bytes(32),
        )
    # Create a separate sender with four keys and a one-interval delay for the time test.
    advanced = Satellite(chain_length=4, disclosure_delay=1)
    # Advance its clock once, from interval 1 to interval 2, without sending a message.
    advanced.advance()
    # Again expect SetupRejected with "fresh, unused" in the explanation.
    with pytest.raises(SetupRejected, match="fresh, unused"):
        # Attempt a setup signature after this second sender's time has advanced.
        sign_satellite_setup(
            # Supply the advanced sender, legitimate private key, and expected satellite name.
            advanced, signing_key=key, satellite_id="satellite-alpha",
            # Give this attempt a valid-size random challenge too.
            challenge=secrets.token_bytes(32),
        )


# Check a rejected first signing attempt does not waste a fresh sender's key chain.
# A later attempt with valid input should still succeed.
def test_rejected_setup_does_not_burn_unused_satellite_chain():
    # Generate the satellite's private signing key.
    key = Ed25519PrivateKey.generate()
    # Create a completely unused sender with four keys and a one-interval disclosure delay.
    satellite = Satellite(chain_length=4, disclosure_delay=1)
    # Expect the malformed challenge below to cause SetupRejected.
    with pytest.raises(SetupRejected):
        # Try creating the sender's first signed setup.
        sign_satellite_setup(
            # Supply the unused sender, legitimate private key, and valid satellite name.
            satellite, signing_key=key, satellite_id="satellite-alpha",
            # Use only three challenge bytes instead of the required 32, making this attempt invalid.
            challenge=b"bad",
        )
    # Retry the same sender's first setup with a properly formed challenge.
    signed = sign_satellite_setup(
        # Reuse the sender and signing identity from the rejected attempt.
        satellite, signing_key=key, satellite_id="satellite-alpha",
        # Generate 32 unpredictable bytes, meeting the challenge's size requirement.
        challenge=secrets.token_bytes(32),
    )
    # assert and len check that the returned reply contains a 64-byte signature.
    # This demonstrates that the malformed attempt did not mark the chain as already used.
    assert len(signed.signature) == 64

# A regression test protects a security rule from being accidentally broken later.
# K[1] below means the first interval's secret key; a genuine signature can still arrive too late.
# Critical regression: a valid signature may be delivered AFTER the
# satellite has disclosed K[1]. Signature verification must not reset time.
# Check that a valid signed setup is rejected if the first key has already become public.
# The fixture gives a two-interval delay and a receiver clock that follows the sender.
def test_delayed_genuine_signed_setup_is_rejected_after_first_disclosure(setup_pair):
    # Keep the sender, setup checker, and genuine reply; the private key is unused here.
    satellite, _, bootstrap, signed = setup_pair
    # Fixture delay = 2; K1 becomes public at sender interval 3.
    # Move the sender from interval 1 to 3, also moving the trusted clock seen by the checker.
    satellite.advance(2)
    # Release interval 1's key now that its two-interval wait has elapsed.
    satellite.disclose(1)
    # Expect SetupRejected with "safe first-key" in its message, identifying the timing rule.
    with pytest.raises(SetupRejected, match="safe first-key"):
        # Deliver the still-genuine setup reply too late; a signature must not reset the clock.
        bootstrap.establish(signed)


# Check that setup near the key-release boundary uses the allowed clock difference.
# The sender may be ahead of the receiver, so even a valid signature needs a time check.
def test_delayed_setup_near_boundary_respects_clock_skew_bound():
    # Generate the sender's private identity-signing key.
    key = Ed25519PrivateKey.generate()
    # Make a sender with four keys, starting at interval 1, and a two-interval disclosure delay.
    satellite = Satellite(chain_length=4, disclosure_delay=2)
    # Put receiver time 1 in a one-item list so later lines can change the value read by the clock.
    receiver_clock = [1]
    # Create a setup checker using a separate simulated receiver clock.
    bootstrap = ReceiverBootstrap(
        # Configure trust in the legitimate sender's public key.
        trusted_public_key=key.public_key(),
        # Require the expected satellite identity.
        expected_satellite_id="satellite-alpha",
        # lambda makes a no-argument function; [0] reads the list's first item on each call.
        # Reading it later picks up the updated time instead of permanently remembering 1.
        trusted_interval_source=lambda: receiver_clock[0],
    )
    # Obtain a valid signed setup while both simulated clocks still report interval 1.
    signed = sign_satellite_setup(
        # Supply the fresh sender and its legitimate private signing key.
        satellite, signing_key=key,
        # Sign the expected identity and this checker's newly generated challenge.
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    # Advance the real sender one step, to interval 2.
    satellite.advance()
    # Set the simulated receiver's trusted reading to interval 2 as well.
    receiver_clock[0] = 2
    # B is the allowed number of intervals by which the sender could be ahead.
    # With receiver time 2 and B=1, the safe assumption is that sender time could already be 3.
    # B=1 allows the sender to have reached interval 3 and disclosed K1.
    # Expect SetupRejected mentioning the first-key safety deadline.
    with pytest.raises(SetupRejected, match="safe first-key"):
        # Try the valid reply while allowing the sender to be one interval ahead;
        # interval 3 would allow key 1 to be public, so setup must be refused.
        bootstrap.establish(signed, max_sender_ahead=1)
    # This next attempt models a different, independently justified clock bound.
    # It is only safe to use zero when trusted information really rules out the sender being ahead.
    # R means receiver time and S means sender time in the original explanation below.
    # The failed attempt does not consume this nonce. With an independently
    # established B=0 bound, R=2 implies S <= 2 and K1 remains undisclosed.
    # Retry the same unconsumed challenge with an allowed sender lead of zero.
    # At receiver interval 2, this bound guarantees the first key is still secret.
    receiver = bootstrap.establish(signed, max_sender_ahead=0)
    # assert checks the established receiver starts at trusted interval 2, not back at 1.
    assert receiver.current_interval == 2


# Check that a fresh clock reading blocks forged messages made after a key becomes public.
# Once anyone knows an interval key, a matching authentication tag alone proves nothing.
def test_live_trusted_clock_blocks_post_disclosure_hmac_forgery():
    # Import hashing tools; SHA-256 computes a fixed-size mathematical summary of bytes.
    import hashlib
    # Import HMAC, which combines a key and message bytes to make an authentication tag.
    # Normally only the secret-key holder can make that tag; this attack uses a released key.
    import hmac
    # Import the packet record and the error that reports a refused incoming packet.
    from mini_tesla import AuthPacket, PacketRejected

    # Generate a legitimate private key to make the initial setup fully authentic.
    key = Ed25519PrivateKey.generate()
    # Create a sender with four interval keys and a two-interval disclosure delay.
    satellite = Satellite(chain_length=4, disclosure_delay=2)
    # Store the simulated trusted receiver time in a one-item list, initially interval 1.
    clock = [1]
    # Create a receiver setup checker with a clock it can consult again after setup.
    bootstrap = ReceiverBootstrap(
        # Trust the real sender's public verification key.
        trusted_public_key=key.public_key(),
        # Require the real satellite's configured name.
        expected_satellite_id="satellite-alpha",
        # The lambda function reads clock[0], the first list item, each time it is called.
        trusted_interval_source=lambda: clock[0],
    )
    # Have the genuine sender make its initial signed setup reply.
    signed = sign_satellite_setup(
        # Supply the sender and the private key authorized to sign its identity.
        satellite, signing_key=key,
        # Include the correct name and this receiver's random challenge.
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    # Accept the genuine setup at interval 1 and obtain the receiver under test.
    receiver = bootstrap.establish(signed)
    # Advance the sender two steps to interval 3, when interval 1's key may be released.
    satellite.advance(2)
    # Move the separate trusted receiver clock to interval 3 too.
    clock[0] = 3
    # Release interval 1's key and save it as information the attacker can now know.
    disclosed_key = satellite.disclose(1)
    # Build an attacker-controlled packet claiming old interval 1 and sequence number 777.
    # The sequence distinguishes this message; the claimed disclosure delay matches the real value.
    forged = AuthPacket(interval=1, sequence=777, disclosure_delay=2,
                        # Set its payload to malicious byte-string data and temporarily leave its tag empty.
                        payload=b"malicious", tag=b"")
    # Make a copy of that packet with a mathematically correct authentication tag.
    forged = replace(
        # Feed the publicly revealed key, the packet's exact authenticated byte encoding,
        # and SHA-256 into HMAC. digest() returns the tag bytes to put in the forged copy.
        forged, tag=hmac.new(disclosed_key, forged.authenticated_bytes(), hashlib.sha256).digest()
    )
    # Expect PacketRejected with "key-disclosure interval" in its message, proving the
    # timing check refuses the attack even though its tag matches the now-public key.
    with pytest.raises(PacketRejected, match="key-disclosure interval"):
        # Try delivering the forged old-interval packet after its key-release time.
        receiver.receive(forged)
    # assert checks no message was saved: the receiver must reject the packet immediately.
    assert receiver.buffered_count == 0


# Check that a receiver established with trusted time cannot have its clock moved by hand.
# The fixture supplies a valid setup using a clock that reads the sender's current interval.
def test_verified_receiver_clock_cannot_be_advanced_manually(setup_pair):
    # Import ProtocolError, the error used for an invalid protocol operation.
    from mini_tesla import ProtocolError
    # Keep the fixture's setup checker and genuine signed reply; ignore its other values.
    _, _, bootstrap, signed = setup_pair
    # Verify the setup and create a receiver whose time comes from the trusted function.
    receiver = bootstrap.establish(signed)
    # Expect ProtocolError with "manually" in its message when bypassing that clock is attempted.
    with pytest.raises(ProtocolError, match="manually"):
        # Attempt to advance the receiver directly; it must require its trusted time source instead.
        receiver.advance()


# Check that a receiver refuses further processing when trusted time moves backward.
# "Fails closed" means refusing the operation when safety can no longer be established.
def test_verified_receiver_fails_closed_on_clock_rollback():
    # Import the protocol-operation error expected from the backward clock reading.
    from mini_tesla import ProtocolError
    # Generate the legitimate sender's private signing key.
    key = Ed25519PrivateKey.generate()
    # Create a sender with four keys and a two-interval key-disclosure delay.
    satellite = Satellite(chain_length=4, disclosure_delay=2)
    # Store simulated receiver time 1 in a list so it can be changed after setup.
    clock = [1]
    # Create a receiver setup checker that will keep consulting the simulated clock.
    bootstrap = ReceiverBootstrap(
        # Give it the legitimate public key for signature verification.
        trusted_public_key=key.public_key(),
        # Require the expected satellite name.
        expected_satellite_id="satellite-alpha",
        # Supply a lambda function that reads the first item, clock[0], on every call.
        trusted_interval_source=lambda: clock[0],
    )
    # Make a genuine setup reply while the trusted receiver time is still 1.
    signed = sign_satellite_setup(
        # Use the sender and its private identity-signing key.
        satellite, signing_key=key,
        # Sign the expected name and the receiver's own random challenge.
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    # Verify the reply and establish the receiver successfully at interval 1.
    receiver = bootstrap.establish(signed)
    # Move the simulated receiver clock forward to interval 2.
    clock[0] = 2
    # Read receiver time and assert it is 2, making the receiver record that it has seen 2.
    assert receiver.current_interval == 2
    # Move the clock back to 1, deliberately violating the rule that time cannot decrease.
    clock[0] = 1
    # Expect ProtocolError with "backward" in its message on the next attempted receive.
    with pytest.raises(ProtocolError, match="backward"):
        # Create a genuine byte-string message, then try delivering it. Even a genuine message
        # must not be processed after the clock rolls back and timing guarantees become unreliable.
        receiver.receive(satellite.authenticate(b"should fail"))


# parametrize repeats the next test once per bad trusted-clock value in this list.
# 0 and -1 are too early; True is a yes/no value; 1.5 is fractional; float("nan")
# means "not a number"; "1" is text; None means no value; 2**32 exceeds the maximum.
# Each test run receives its selected invalid value through the argument named bad.
@pytest.mark.parametrize("bad", [0, -1, True, 1.5, float("nan"), "1", None, 2**32])
# Check that a correct signature cannot make an invalid trusted time reading acceptable.
def test_invalid_trusted_time_rejects_signed_setup(bad):
    # Generate a legitimate private signing key so the setup signature itself will be valid.
    key = Ed25519PrivateKey.generate()
    # Make a fresh sender with four keys and a two-interval disclosure delay.
    satellite = Satellite(chain_length=4, disclosure_delay=2)
    # Construct the receiver's setup checker with a deliberately faulty clock function.
    bootstrap = ReceiverBootstrap(
        # Trust the correct public verification key.
        trusted_public_key=key.public_key(),
        # Require the correct satellite identity.
        expected_satellite_id="satellite-alpha",
        # This no-argument lambda returns the current test case's bad value instead of valid time.
        trusted_interval_source=lambda: bad,
    )
    # Make a legitimate reply, leaving only the trusted-clock reading invalid.
    signed = sign_satellite_setup(
        # Use the fresh sender and genuine private signing key.
        satellite, signing_key=key,
        # Sign the expected satellite identity and this checker's challenge.
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    # Expect SetupRejected and require the error message to mention an invalid interval.
    with pytest.raises(SetupRejected, match="invalid interval"):
        # Attempt setup; signature success must still be followed by rejection of the bad clock.
        bootstrap.establish(signed)


# Check that callers cannot omit the required trusted clock when creating a setup checker.
# A signed reply alone cannot tell the receiver whether an interval key is already public.
def test_signed_bootstrap_no_longer_accepts_without_trusted_time():
    # Generate a legitimate private key to provide an otherwise correct public-key input.
    key = Ed25519PrivateKey.generate()
    # Expect TypeError, which Python raises here because a required named argument is missing.
    with pytest.raises(TypeError):
        # Try constructing the checker with just the following two arguments and no clock source.
        ReceiverBootstrap(
            # Supply the legitimate public verification key.
            trusted_public_key=key.public_key(),
            # Supply the expected satellite name; trusted_interval_source is deliberately absent.
            expected_satellite_id="satellite-alpha",
        )
