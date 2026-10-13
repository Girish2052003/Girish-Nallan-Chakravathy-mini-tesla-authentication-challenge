# An invariant is a rule expected to remain true. This script checks selected
# inputs and attack sequences against the real Python code, not every possible
# protocol history. A # line is a comment; Python does not execute it.
# The quoted description below is a docstring, which Python keeps as documentation.
"""Finite input-grid checks and three fixed adversarial traces.

This exercises real Python code. It is not exhaustive protocol-state exploration,
a model checker, or a proof of the implementation or cryptographic primitives.
"""

# Defer evaluation of type annotations such as -> int; these describe expected types.
from __future__ import annotations

# Load SHA-256, a hash that maps bytes to a fixed-size digest used to link keys.
import hashlib
# Load HMAC, the keyed message-authentication check, and its timing-resistant byte comparison.
import hmac

# Import the actual packet, sender, and receiver classes plus their rejection errors.
# A class describes objects; an exception is an error that can be caught and checked.
from mini_tesla import AuthPacket, EarlyDisclosureError, PacketRejected, Receiver, ReplayDetected, Satellite


# Define the packet-admission grid and return its completed case count as an int (integer).
# In the docstring, iff means if and only if: both directions of the rule must hold.
def check_receive_timing() -> int:
    """Verify the receiver buffers iff the packet is current and still secret."""

    # Start the completed receive-case count at zero.
    checked = 0
    # Use four message/key intervals, keeping the grid small and repeatable.
    chain_length = 4
    # Repeat for sender-ahead margins 0, 1, and 2; range stops before the endpoint.
    for bound in range(3):
        # For each margin, try key-release delays 1, 2, and 3.
        for delay in range(1, 4):
            # Try each message interval 1 through 4, including the final key in the chain.
            for packet_interval in range(1, chain_length + 1):
                # Try receiver times through chain_length + delay + 1, covering early, safe,
                # release-time, and late arrivals; each loop combination gets its own objects.
                for receiver_interval in range(1, chain_length + delay + 2):
                    # Create a fresh sender so key state from previous cases cannot affect this one.
                    satellite = Satellite(chain_length=chain_length, disclosure_delay=delay)
                    # Create a matching receiver for this trial; keyword arguments name its settings.
                    receiver = Receiver(
                        # Use the sender's public commitment, the trusted hash-chain endpoint used to check keys.
                        commitment=satellite.commitment,
                        # Tell the receiver the same four-key chain size.
                        chain_length=chain_length,
                        # Use the same release delay so this test isolates timing instead of policy mismatches.
                        disclosure_delay=delay,
                        # Give the receiver the selected upper bound on sender lead.
                        max_sender_ahead=bound,
                    )
                    # The sender starts at 1; advance only when the desired message interval is later.
                    if packet_interval > 1:
                        # Move exactly to the trial's message interval without requesting an invalid zero-step advance.
                        satellite.advance(packet_interval - 1)
                    # Have the real sender create a message and its authentication tag (a keyed byte check).
                    packet = satellite.authenticate(
                        # Include the case values in a readable message and encode that text as bytes.
                        f"probe:{delay}:{packet_interval}:{receiver_interval}".encode()
                    )
                    # The receiver also starts at 1; move it only for later target times.
                    if receiver_interval > 1:
                        # Place the receiver at the independently selected arrival time.
                        receiver.advance(receiver_interval - 1)

                    # Calculate the expected admission decision separately from Receiver.receive.
                    # Parentheses let the condition continue across lines; and requires both parts.
                    should_buffer = (
                        # A message must not claim an interval in the receiver's future.
                        receiver_interval >= packet_interval
                        # Even the latest possible sender time must be before key release. Once the
                        # key is public, attackers can make matching tags, so a late message is unsafe.
                        and receiver_interval + bound < packet_interval + delay
                    )
                    # Try the actual receive operation and distinguish a policy rejection from success.
                    try:
                        # Ask the receiver to store this candidate pending later key disclosure.
                        result = receiver.receive(packet)
                    # Catch the expected rejection family; unrelated errors are real script failures.
                    except PacketRejected:
                        # A rejection passes this case only when the independently calculated decision is false.
                        # assert raises AssertionError on a false condition; do not run with -O, which skips asserts.
                        assert not should_buffer
                    # This branch runs only when receive returned without the caught rejection.
                    else:
                        # Successful receipt must have satisfied both timing conditions.
                        assert should_buffer
                        # Require the precise buffered result: storage does not yet mean the sender was authenticated.
                        assert result == "buffered"
                    # Count this case only after its expected success or rejection has been checked.
                    checked += 1
    # Return the grid size for the combined report.
    return checked


# Define the grid that tests key release times and the public chain anchor.
# A commitment is the public chain endpoint; hashing key i exactly i times should reach it.
def check_disclosure_timing_and_commitment() -> int:
    """Verify a key is disclosable iff its delay has elapsed and hashes to K[0]."""

    # Start the completed key-disclosure count at zero.
    checked = 0
    # Test the four key positions in a short finite chain.
    chain_length = 4
    # Repeat for release delays 1, 2, and 3.
    for delay in range(1, 4):
        # Try disclosing every key position from 1 through chain_length.
        for key_interval in range(1, chain_length + 1):
            # Visit times before, at, and after disclosure, including beyond the last key's deadline.
            for current_interval in range(1, chain_length + delay + 2):
                # Start each case with a fresh sender and key chain.
                satellite = Satellite(chain_length=chain_length, disclosure_delay=delay)
                # Only move the sender if this case needs a time later than its initial time of 1.
                if current_interval > 1:
                    # Advance to the selected current interval.
                    satellite.advance(current_interval - 1)

                # Release is allowed at the key interval plus delay, including equality (>=).
                should_disclose = current_interval >= key_interval + delay
                # Attempt actual disclosure; an early-disclosure error is expected for some grid cells.
                try:
                    # Request the secret bytes for this particular key interval from the sender.
                    key = satellite.disclose(key_interval)
                # Catch the specific early-release refusal, not arbitrary implementation errors.
                except EarlyDisclosureError:
                    # The refusal is correct only when the key's release time has not arrived.
                    assert not should_disclose
                # If disclosure succeeded, check both its timing and its key-chain linkage.
                else:
                    # Returning key bytes before the deadline would be a security failure.
                    assert should_disclose
                    # Copy the returned bytes into a working variable for repeated hashing.
                    candidate = key
                    # Hash exactly key_interval times; _ marks a loop value we do not need to read.
                    for _ in range(key_interval):
                        # Replace the working bytes with their SHA-256 digest at each chain step.
                        candidate = hashlib.sha256(candidate).digest()
                    # Require the final digest to equal the sender's public anchor. compare_digest
                    # compares bytes without stopping early at the first differing byte.
                    assert hmac.compare_digest(candidate, satellite.commitment)
                # Count one disclosure case after checking either the expected refusal or the valid key.
                checked += 1
    # Return the number of completed disclosure cases.
    return checked


# Define attack checks: replay resends an old packet; forgery creates an attacker packet
# with a real tag after its key is public. This covers fixed traces, not all attacks.
def check_replay_and_post_disclosure_forgery() -> int:
    """Verify accepted identities and disclosed-key forgeries cannot be replayed."""

    # Count the replay and forgery checks separately from their setup steps.
    checked = 0
    # Repeat both attacks for each disclosure delay 1, 2, and 3.
    for delay in range(1, 4):
        # Create a new sender and chain for this delay so the three traces are independent.
        satellite = Satellite(chain_length=4, disclosure_delay=delay)
        # Create the matching receiver with the default zero clock margin.
        receiver = Receiver(
            # Trust this sender's chain anchor for checking released keys.
            commitment=satellite.commitment,
            # Read the chain size from the sender rather than using a different receiver size.
            chain_length=satellite.chain_length,
            # Match the sender's disclosure schedule.
            disclosure_delay=delay,
        )
        # Create a genuine packet at initial interval 1; b marks a bytes value, not text.
        packet = satellite.authenticate(b"accepted-once")
        # Require initial storage before release; this sets up a packet that can later be authenticated.
        assert receiver.receive(packet) == "buffered"

        # Move the sender to interval 1 + delay, the first key's release time.
        satellite.advance(delay)
        # Move the receiver to the same time so processing the disclosure is allowed.
        receiver.advance(delay)
        # Obtain key 1 now that it may be public.
        disclosed = satellite.disclose(1)
        # Validate key 1 and use it to check the stored candidate's tag.
        results = receiver.process_disclosure(1, disclosed)
        # Require exactly one result and successful authentication of that packet.
        # len counts results; [0] selects the first result because Python indexes start at zero.
        assert len(results) == 1 and results[0].accepted

        # Attempt the replay while checking for its specific expected rejection.
        try:
            # Deliver exactly the same packet again after it has already been authenticated.
            receiver.receive(packet)
        # ReplayDetected is the expected outcome for this now-closed key interval.
        except ReplayDetected:
            # pass means no extra action: catching the expected rejection is a passing check.
            pass
        # This branch runs if replay receipt returned normally.
        else:
            # Raise a real test failure because accepting or buffering this replay was forbidden.
            raise AssertionError("accepted packet replay was not rejected")

        # Build the attacker's packet fields first, before computing its valid tag.
        forged = AuthPacket(
            # Claim interval 1, whose key the attacker can now know.
            interval=1,
            # Use a new sequence number, showing the attack is more than an exact duplicate.
            sequence=999,
            # Keep the delay valid so rejection cannot be credited to a schedule mismatch.
            disclosure_delay=delay,
            # Choose attacker-controlled bytes as the forged message body.
            payload=b"forged-after-disclosure",
            # Use an empty temporary tag; the authenticated byte encoding excludes this field.
            tag=b"",
        )
        # Compute a real HMAC tag with the disclosed key, just as an attacker could.
        # HMAC combines a secret key and message; after release that key is no longer secret.
        forged_tag = hmac.new(
            # Supply the now-public key bytes, requiring no access to the sender's private state.
            disclosed,
            # Cover the canonical packet encoding, meaning the exact agreed bytes of its fields.
            forged.authenticated_bytes(),
            # Choose SHA-256 as HMAC's underlying hash function.
            hashlib.sha256,
        # Finish the HMAC calculation and take its raw tag bytes.
        ).digest()
        # Build a complete forged packet that carries that correctly calculated tag.
        forged = AuthPacket(
            # Retain the already-public interval number.
            interval=forged.interval,
            # Retain the new sequence number so this is a distinct attacker message.
            sequence=forged.sequence,
            # Retain the valid disclosure-delay field.
            disclosure_delay=forged.disclosure_delay,
            # Retain the exact payload used to calculate the HMAC.
            payload=forged.payload,
            # Attach the matching tag instead of the temporary empty bytes.
            tag=forged_tag,
        )
        # Try receipt after disclosure; a correct tag alone must not permit admission.
        try:
            # Submit the finished forged packet to the real receiver.
            receiver.receive(forged)
        # Any PacketRejected subtype is allowed here, including the disclosed-key replay guard.
        except PacketRejected:
            # The expected rejection completes this attack check without an error.
            pass
        # Returning normally would mean the receiver let this late forged packet in.
        else:
            # Fail even if the forged packet was only buffered: the admission rule must reject it.
            raise AssertionError("valid-MAC packet created after disclosure was accepted")
        # Count the two checked attacks for this delay, not the supporting setup assertions.
        checked += 2
    # Return six attack checks after all three delays.
    return checked


# Define the entry function; -> None describes that it returns no result value.
def main() -> None:
    # Run the packet-arrival grid and retain its completed-case count.
    receive_states = check_receive_timing()
    # Run the key-release grid and retain its completed-case count.
    disclosure_states = check_disclosure_timing_and_commitment()
    # Run the three replay/forgery traces and retain their check count.
    replay_states = check_replay_and_post_disclosure_forgery()
    # Add all three counts; reaching here means none of their required checks failed.
    total = receive_states + disclosure_states + replay_states

    # Print the combined finite-check total; f inserts brace-enclosed values into text.
    print(f"Finite implementation checks passed: {total} cases/checks")
    # Report how many packet-arrival combinations were exercised.
    print(f"  receive timing grid:   {receive_states}")
    # Report how many key-release combinations were exercised.
    print(f"  disclosure timing grid: {disclosure_states}")
    # Report the replay and post-disclosure forgery checks.
    print(f"  replay/forgery checks: {replay_states}")


# Run checks only when launched as a script, not when another module imports these functions.
if __name__ == "__main__":
    # Call the entry function that executes and reports every grid and attack trace.
    main()
