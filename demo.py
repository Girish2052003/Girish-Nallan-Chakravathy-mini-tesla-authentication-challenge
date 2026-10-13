"""Executable demonstration of the required Mini-TESLA scenarios."""

# Read this file as a small story: set up a trusted sender, send messages,
# wait for their keys, and show which messages the receiver accepts.
# Lines beginning with # explain the program; Python does not run them.
# A function is a named set of steps. An indented block belongs to the line
# above it. A value such as b"hello" is bytes (the exact data computers send).

# Keep type hints, such as str and None below, as deferred annotations.
# These hints describe expected values; they do not check those values for us.
from __future__ import annotations

# secrets supplies random bytes suitable for security work.
import secrets
# replace copies a fixed data record while changing only the named fields.
from dataclasses import replace

# Ed25519 provides a digital signature: a private key signs, and its matching
# public key lets the receiver check who signed without learning the private key.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Bring our project's building blocks into this file. The ...Rejected and
# ...Detected names are errors we can catch and print; Satellite sends data;
# ReceiverBootstrap checks the signed setup; sign_satellite_setup signs it.
from mini_tesla import (
    DisclosureRejected, ReceiverBootstrap, ReplayDetected, Satellite,
    SetupRejected, sign_satellite_setup,
)


# Define a reusable printer. label is the text identifying this batch;
# results is the collection of message decisions; -> None means no return value.
def print_results(label: str, results) -> None:
    # Visit each decision in the collection, one at a time.
    for result in results:
        # Choose the word ACCEPT only when this particular result says True.
        verdict = "ACCEPT" if result.accepted else "REJECT"
        # An f-string inserts values inside {...}; show the message number and
        # the reason, so the person running the demo can see what happened.
        print(f"[{label}] {verdict}: seq={result.packet.sequence} reason={result.reason}")


# Collect the demo steps in one function so importing this file does not run them.
def main() -> None:
    # Give the sender six message-key intervals. A delay of one means interval
    # 1's key may be made public starting in interval 2, and so on.
    satellite = Satellite(chain_length=6, disclosure_delay=1)
    # Trusted provisioning: in this single-process demo, the sender's public
    # identity key is pinned directly. A real deployment must provision it
    # independently (e.g. from a trusted configuration or authenticated PKI).
    # Create a private signing key using the library's secure randomness.
    signing_key = Ed25519PrivateKey.generate()
    # Prepare the receiver's setup checker using three trusted inputs below.
    bootstrap = ReceiverBootstrap(
        # Pin (choose in advance) the public key that identifies our real sender.
        trusted_public_key=signing_key.public_key(),
        # Require the signed sender name to match this expected name.
        expected_satellite_id="satellite-alpha",
        # lambda creates a tiny function. Each call reads the sender's CURRENT
        # interval, not a saved old value. Sharing this clock is a demo shortcut;
        # a real receiver needs its own trustworthy estimate of sender time.
        trusted_interval_source=lambda: satellite.current_interval,
    )

    # An attacker can create an entirely valid alternative TESLA key chain,
    # but cannot authenticate its fake commitment under the pinned public key.
    # Give the fake sender its own valid chain; a valid chain alone is not identity.
    attacker = Satellite(chain_length=6, disclosure_delay=1)
    # The attacker signs a setup using a DIFFERENT private key. Even knowing
    # the receiver's public challenge (fresh request value) cannot fix that.
    attacker_setup = sign_satellite_setup(
        attacker, signing_key=Ed25519PrivateKey.generate(),
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    # try starts an operation that may raise an error we expect to handle.
    try:
        # Ask the setup checker to create a receiver from the fake setup.
        bootstrap.establish(attacker_setup)
    # Catch only the expected setup error; "as exc" gives its explanation a name.
    except SetupRejected as exc:
        # Print the rejection instead of ending this demonstration.
        print("[fake satellite setup] REJECT:", exc)

    # The real sender signs its commitment, timing settings, identity, and the
    # receiver's fresh challenge using the private key we trust above.
    signed_setup = sign_satellite_setup(
        satellite, signing_key=signing_key, satellite_id="satellite-alpha",
        challenge=bootstrap.challenge,
    )
    # Check the signature/challenge/time settings and create the ready receiver.
    receiver = bootstrap.establish(signed_setup)
    # Reaching this line means setup completed without raising an error.
    print("[signed bootstrap] ACCEPT: identity and fresh signed commitment verified")
    # Try using the same completed setup a second time to demonstrate replay.
    try:
        # The bootstrap object has already consumed this setup's challenge.
        bootstrap.establish(signed_setup)
    # A replay is a copied old exchange presented as though it were new.
    except SetupRejected as exc:
        # Show why the repeated setup is rejected, then continue the story.
        print("[setup replay] REJECT:", exc)
    # The commitment is public: it is the hash-chain anchor, not a secret key.
    # .hex() prints each byte as two readable hexadecimal characters.
    print("Authenticated commitment:", receiver.hsm.commitment.hex())

    # Authenticate makes a packet containing these exact message bytes and an
    # HMAC tag (a key-based check value). It does not reveal the secret key yet.
    valid = satellite.authenticate(b"orbit=nominal;clock=12345")
    # Make a second genuine packet that an attacker will alter in transit.
    original_for_tamper = satellite.authenticate(b"command=hold-attitude")
    # Copy that packet with a changed message but the ORIGINAL tag. The tag will
    # not match the altered message once the receiver can finally check it.
    tampered = replace(original_for_tamper, payload=b"command=deorbit-now")
    # receive stores a timely candidate. Being buffered does not mean trusted.
    receiver.receive(tampered)
    # Store the genuine message too; this also demonstrates arriving out of order.
    receiver.receive(valid)

    # Move the sender to interval 2; the receiver's live-time function sees it.
    satellite.advance()
    # Now interval 1's waiting period is over, so its key may become public.
    key1 = satellite.disclose(1)
    # Validate the disclosed key against the commitment, check buffered tags,
    # and print both the tampered rejection and the genuine acceptance.
    print_results("interval 1", receiver.process_disclosure(1, key1))

    # Resubmit the already accepted packet to test duplicate protection.
    try:
        # Use the same interval, message number, payload, and tag as before.
        receiver.receive(valid)
    # The receiver reports this copied packet as a replay.
    except ReplayDetected as exc:
        # Display the replay error caught above without stopping the demo.
        print("[replay] REJECT:", exc)

    # Create and buffer a fresh message using interval 2's still-secret key.
    packet2 = satellite.authenticate(b"telemetry=temp:19.4")
    # Store this new message while its key is still private.
    receiver.receive(packet2)
    # Move to interval 3, when interval 2's disclosure is allowed.
    satellite.advance()

    # Try pretending that 32 unrelated random bytes are interval 2's real key.
    try:
        # Give the receiver the fake key together with its claimed interval.
        receiver.process_disclosure(2, secrets.token_bytes(32))
    # They will almost certainly fail the chain check; rejection preserves the
    # waiting message so that the real key can still authenticate it afterward.
    except DisclosureRejected as exc:
        # Show the failed chain check so the reader can distinguish it from a bad tag.
        print("[bad disclosure] REJECT:", exc)

    # Supply the actual key and show that the same buffered message now succeeds.
    key2 = satellite.disclose(2)
    # Check the stored interval 2 message and print its acceptance decision.
    print_results("interval 2", receiver.process_disclosure(2, key2))

    # Create one more genuine message, this time for a tag-tampering example.
    packet3 = satellite.authenticate(b"telemetry=power:stable")
    # bytes cannot be edited in place; bytearray creates an editable copy.
    bad_tag = bytearray(packet3.tag)
    # [0] selects the first byte. XOR with 0x01 flips just its lowest bit.
    bad_tag[0] ^= 0x01
    # Turn the changed tag back into bytes and buffer the altered packet.
    receiver.receive(replace(packet3, tag=bytes(bad_tag)))
    # Wait until interval 4, then release interval 3's correct key.
    satellite.advance()
    # Ask the HSM to release the interval 3 key now that its waiting period is over.
    key3 = satellite.disclose(3)
    # Even with the correct key, the changed tag fails, so print REJECT.
    print_results("interval 3", receiver.process_disclosure(3, key3))


# Run main only for "python demo.py"; importing demo from another file skips it.
if __name__ == "__main__":
    # Start the complete demonstration defined above.
    main()
