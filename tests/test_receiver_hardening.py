# A regression test checks that a previously identified problem stays fixed.
# These cases cover malformed packets, duplicate messages, storage limits, and
# clock safety. The F-numbers below identify findings from the project's audit.
"""Regression cases for independent audit findings F01, F03, F04 and F06."""
# Import replace, which copies a data object while changing selected fields.
# This lets a test construct a damaged packet without altering its genuine original.
from dataclasses import replace
# Import hash algorithms so the known-key attack can use the real SHA-256 algorithm.
import hashlib
# Import HMAC, a calculation using a key and message to produce a short check
# value called an authentication tag. An attacker who learns a key can make tags.
import hmac

# Import pytest, the tool that discovers and runs test_ functions. assert checks
# a condition; pytest.raises requires a named error. A parametrize decorator
# (the @ line above a function) repeats a test with different supplied inputs.
import pytest

# Import the packet type AuthPacket (not used directly in this file), the sender
# Satellite, and Receiver, which saves packets until their keys become public.
# PacketRejected is the incoming-packet error; ReplayDetected is its more specific
# form for repeated candidates or packets from an already disclosed interval.
from mini_tesla import AuthPacket, PacketRejected, Receiver, ReplayDetected, Satellite
# Import ProtocolError, the general error for an operation the protocol cannot allow.
from mini_tesla.protocol import ProtocolError


# Define a setup helper. **policy collects named options, such as
# max_buffered_packets=2, into a dictionary of option names and their values.
# An interval is one logical clock step; both new clocks start at interval 1.
def pair(**policy):
    # Create a sender with eight key intervals. pop takes disclosure_delay out of
    # the options and returns it, using 1 if absent. Removing it prevents passing
    # the same named option twice when constructing the receiver below.
    sender = Satellite(chain_length=8, disclosure_delay=policy.pop("disclosure_delay", 1))
    # Create a receiver trusting the sender's commitment, a public hash value used
    # to check later revealed keys, and give it the same eight-interval chain length.
    receiver = Receiver(commitment=sender.commitment, chain_length=8,
                        # Use the sender's waiting period for key disclosure. **policy expands the
                        # remaining dictionary entries into named receiver options.
                        disclosure_delay=sender.disclosure_delay, **policy)
    # Return both objects so each test can assign them to sender and receiver.
    return sender, receiver


# Run the following test once per (field, value) pair. pytest supplies those two
# values as function arguments. Each case changes just one packet metadata field;
# metadata is information about a message, such as its time and sequence number.
@pytest.mark.parametrize("field,value", [
    # Try a truth value, a decimal-style number, and a missing value as the version.
    # Python treats True and 1.0 as equal to 1 in some comparisons, but neither is
    # an actual int; the protocol requires the exact whole-number type.
    ("version", True), ("version", 1.0), ("version", None),
    # Try the same type confusion for interval: True, 1.0, the text "1", and None.
    # None means no value; a text digit is still text, not a whole number.
    ("interval", True), ("interval", 1.0), ("interval", "1"), ("interval", None),
    # ** means exponentiation. 2**32 is one past the largest unsigned 32-bit value,
    # 2**32 - 1; 0 is below the first permitted interval, which is 1.
    ("interval", 2**32), ("interval", 0),
    # Sequence numbers must also be actual positive integers. True and 1.0 have the
    # wrong types, 0 is below the minimum, and 2**64 exceeds the 64-bit field by one.
    ("sequence", True), ("sequence", 1.0), ("sequence", 0), ("sequence", 2**64),
    # Delay must be a positive integer too. float("nan") makes a special floating
    # value meaning "not a number", which must not slip past comparisons.
    ("disclosure_delay", True), ("disclosure_delay", 1.0), ("disclosure_delay", float("nan")),
])
# Check that a malformed candidate is refused before it can disrupt later
# verification of legitimate packets in the same interval.
def test_invalid_metadata_cannot_poison_a_disclosure_batch(field, value):
    # Create a fresh matching sender and receiver, both at interval 1 with a one-step delay.
    sender, receiver = pair()
    # Create a genuine packet for the raw byte message "legitimate"; b marks bytes.
    good = sender.authenticate(b"legitimate")
    # Build a one-entry dictionary using this case's field name and value. ** turns
    # it into a named argument to replace, producing the deliberately malformed copy.
    bad = replace(good, **{field: value})
    # Require PacketRejected from the next indented statement; the test fails if
    # it succeeds or reports an unrelated error.
    with pytest.raises(PacketRejected):
        # Submit the malformed packet while it would otherwise be early enough to buffer.
        receiver.receive(bad)
    # Submit the untouched genuine packet after the malformed one has been rejected.
    receiver.receive(good)
    # Move the sender to interval 2, when it may reveal interval 1's key.
    sender.advance()
    # Move the receiver to the same disclosure time.
    receiver.advance()
    # Reveal the sender's interval 1 key and ask the receiver to check its saved packets.
    results = receiver.process_disclosure(1, sender.disclose(1))
    # Require exactly one result and require it to be accepted. len counts results,
    # [0] selects the first, and and means both checks must hold.
    assert len(results) == 1 and results[0].accepted
    # Require no packets left waiting, showing the invalid input did not damage
    # completion of the legitimate packet's batch.
    assert receiver.buffered_count == 0


# Check both sides of the maximum 64-bit sequence-number boundary.
def test_maximum_uint64_sequence_can_be_authenticated():
    # Start a matching sender and receiver at interval 1 with a one-interval delay.
    sender, receiver = pair()
    # Jump the sender's internal next-number counter to 2**64 - 1, the largest
    # unsigned 64-bit integer. The test deliberately touches an internal field to
    # reach this boundary without generating billions of packets.
    sender._next_sequence = 2**64 - 1
    # Generate and buffer a packet using that last representable sequence number.
    receiver.receive(sender.authenticate(b"last sequence"))
    # Require ProtocolError from the next attempt. match="sequence" also requires
    # the error message to mention sequence, identifying which limit was reached.
    with pytest.raises(ProtocolError, match="sequence"):
        # Try making another packet, which would need the unrepresentable number 2**64.
        sender.authenticate(b"overflow")
    # Advance the sender to 2 to release the key for the already-buffered valid packet.
    sender.advance()
    # Advance the receiver to 2 so it can process that disclosure.
    receiver.advance()
    # Reveal key 1 and require the first verification result to be accepted, showing
    # that refusing the overflow did not invalidate the last allowed packet.
    assert receiver.process_disclosure(1, sender.disclose(1))[0].accepted


# Check that a forged packet arriving first cannot monopolize a legitimate
# message's identity. Identity here means the pair (interval, sequence number).
def test_bogus_first_candidate_does_not_reserve_authentication_identity():
    # Create fresh matching endpoints with a one-interval disclosure delay.
    sender, receiver = pair()
    # Generate the genuine packet for byte message "real" and keep the original.
    good = sender.authenticate(b"real")
    # First deliver a copy whose payload was changed to "fake" but whose tag was
    # not recalculated. It shares the genuine packet's identity but will fail verification.
    receiver.receive(replace(good, payload=b"fake"))
    # Deliver the genuine packet too; a different candidate with the same identity
    # must still get a chance to be authenticated.
    receiver.receive(good)
    # Require ReplayDetected for an exact duplicate of the already-buffered genuine
    # candidate, even though different candidates for this identity were allowed.
    with pytest.raises(ReplayDetected):
        # Deliver the untouched genuine packet for a second time.
        receiver.receive(good)
    # Advance the sender to 2, making key 1 eligible for disclosure.
    sender.advance()
    # Advance the receiver to the same time so it can check the candidates.
    receiver.advance()
    # Reveal key 1 and collect results for both distinct saved candidates.
    results = receiver.process_disclosure(1, sender.disclose(1))
    # Collect accepted flags in arrival order. The altered message must be False
    # (rejected), followed by True (accepted) for the genuine message.
    assert [r.accepted for r in results] == [False, True]
    # Require ReplayDetected now that the interval's key has been disclosed.
    with pytest.raises(ReplayDetected):
        # Try sending the genuine packet again after its successful verification.
        receiver.receive(good)


# Check that even two correctly tagged candidates sharing one identity cannot
# both be accepted. A valid tag does not make a duplicate identity a new message.
def test_two_valid_candidates_with_one_identity_are_accepted_at_most_once():
    # Create a fresh sender and matching receiver at interval 1.
    sender, receiver = pair()
    # Generate the first genuine packet, including its interval and sequence identity.
    first = sender.authenticate(b"first")
    # Copy that packet with a different byte message and empty tag, while keeping
    # its interval and sequence number the same.
    second = replace(first, payload=b"second", tag=b"")
    # Use the real sender's HSM (its protected key-store interface) to calculate a
    # correct interval 1 tag for the second message's encoded fields, then attach it.
    # This intentionally creates two valid tags so the identity rule is tested.
    second = replace(second, tag=sender.hsm.generate_mac(1, second.authenticated_bytes()))
    # Buffer the first valid candidate before key disclosure.
    receiver.receive(first)
    # Buffer the second distinct candidate with the same identity.
    receiver.receive(second)
    # Advance the sender to interval 2 so key 1 can be revealed.
    sender.advance()
    # Advance the receiver to interval 2 so disclosure can be processed.
    receiver.advance()
    # Reveal key 1 and collect the accepted flags in arrival order. Require True
    # for the first candidate and False for the second, enforcing one acceptance.
    assert [r.accepted for r in receiver.process_disclosure(1, sender.disclose(1))] == [True, False]


# Check the storage limit on competing candidates for one message identity.
def test_candidate_count_is_bounded_per_identity():
    # Configure the receiver to allow only two candidates with the same interval
    # and sequence number, while using the normal one-interval disclosure delay.
    sender, receiver = pair(max_candidates_per_identity=2)
    # Generate a genuine packet whose identity will be reused by the candidates.
    packet = sender.authenticate(b"real")
    # Buffer one copy with altered payload "one" and the unchanged tag.
    receiver.receive(replace(packet, payload=b"one"))
    # Buffer a second distinct copy with payload "two", filling the two-candidate limit.
    receiver.receive(replace(packet, payload=b"two"))
    # Require PacketRejected with "candidate" in its explanation for the next arrival.
    with pytest.raises(PacketRejected, match="candidate"):
        # Try submitting the genuine packet as a third candidate. It is refused because
        # the identity's storage is full, illustrating that flooding can block valid traffic.
        receiver.receive(packet)
    # Check that rejecting the third candidate left exactly the first two buffered.
    assert receiver.buffered_count == 2


# Repeat the next test for each policy dictionary, allowing the same boundary
# check to exercise two independent packet-count limits.
@pytest.mark.parametrize("policy", [
    # One case caps all waiting packets at two; the other caps packets in a single
    # time interval at two. Each dictionary changes only its named setting.
    {"max_buffered_packets": 2}, {"max_packets_per_interval": 2},
])
# Check that exceeding a packet limit does not partly change stored state.
def test_packet_limits_reject_without_partial_mutation(policy):
    # Create matching endpoints; **policy passes this case's dictionary as named
    # receiver options. Other options retain their defaults.
    sender, receiver = pair(**policy)
    # Generate and buffer a first genuine interval 1 message.
    receiver.receive(sender.authenticate(b"one"))
    # Generate and buffer a second genuine message, reaching the selected limit of two.
    receiver.receive(sender.authenticate(b"two"))
    # Require PacketRejected whose message mentions "limit" for the next receive.
    with pytest.raises(PacketRejected, match="limit"):
        # Generate a third genuine packet and try to buffer it beyond the allowed count.
        receiver.receive(sender.authenticate(b"three"))
    # Require the receiver's count to remain two after the rejected third packet.
    assert receiver.buffered_count == 2
    # Advance the sender to 2, when the first interval's key may be revealed.
    sender.advance()
    # Advance the receiver to 2 as well.
    receiver.advance()
    # Reveal key 1 and require every returned result to be accepted. all checks
    # each accepted flag, showing the original buffered packets remain usable.
    assert all(r.accepted for r in receiver.process_disclosure(1, sender.disclose(1)))
    # Require zero charged bytes after processing, so rejected input did not leave
    # incorrect storage accounting behind.
    assert receiver.buffered_bytes == 0


# Check that the byte budget includes packet metadata and the tag as well as
# the payload, preventing tiny-message floods from bypassing the real wire-byte limit.
def test_total_byte_limit_counts_wire_metadata_and_tag():
    # Create a sender and ignore its default receiver using _; this test builds
    # a separate receiver with a specially chosen byte budget below.
    sender, _ = pair()
    # Generate a packet with the one-byte payload "x".
    packet = sender.authenticate(b"x")
    # Count the encoded authenticated fields plus payload, then add the tag length.
    # len counts bytes here; this is the charged packet size, not Python object memory.
    size = len(packet.authenticated_bytes()) + len(packet.tag)
    # Create a matching receiver whose entire byte budget fits exactly this one
    # packet. Its omitted delay option defaults to one interval.
    receiver = Receiver(commitment=sender.commitment, chain_length=8, max_buffered_bytes=size)
    # Buffer the packet at the exact allowed byte boundary.
    receiver.receive(packet)
    # Require the recorded byte use to equal the full calculated packet size.
    assert receiver.buffered_bytes == size
    # Expect PacketRejected mentioning "byte" when any additional packet is sent.
    with pytest.raises(PacketRejected, match="byte"):
        # Try a genuine packet with an empty payload, b"". Its header and tag still
        # consume bytes, so an empty message cannot fit into the already-full budget.
        receiver.receive(sender.authenticate(b""))
    # Require the charged byte count to remain unchanged after that rejection.
    assert receiver.buffered_bytes == size


# Check that packets whose keys never arrive eventually expire, making storage
# available for fresh traffic instead of keeping it occupied forever.
def test_missing_disclosure_expires_and_capacity_is_reusable():
    # Allow one buffered packet and two extra intervals of waiting for disclosure.
    # With the default delay of 1, an interval 1 packet expires at 1 + 1 + 2 = 4.
    sender, receiver = pair(disclosure_grace=2, max_buffered_packets=1)
    # Create a genuine interval 1 packet that this test will leave unverified.
    packet = sender.authenticate(b"expired")
    # Buffer it, occupying the only packet slot.
    receiver.receive(packet)
    # Move the receiver from 1 to 3, one step before expiration. The sender stays at 1.
    receiver.advance(2)  # local 3: one before expiry at 1 + 1 + 2
    # Require the packet to remain stored before the expiration boundary.
    assert receiver.buffered_count == 1
    # Move the receiver to interval 4, exactly when the missing-disclosure wait expires.
    receiver.advance()  # expiry boundary
    # The chained equality requires both the packet count and charged bytes to be
    # zero, confirming that expiration freed the storage and its accounting.
    assert receiver.buffered_count == receiver.buffered_bytes == 0
    # Require PacketRejected for trying to reintroduce a packet that is already too old.
    with pytest.raises(PacketRejected):
        # Resend the original interval 1 packet after its expiration.
        receiver.receive(packet)
    # Move the sender forward three steps from 1 to 4 so it catches up to the receiver.
    sender.advance(3)
    # Reveal the old key 1 now. Require an empty result list [] because its waiting
    # packet was discarded, even though the key itself can still be validated.
    assert receiver.process_disclosure(1, sender.disclose(1)) == []
    # Create and buffer a new genuine message for the sender's current interval, 4.
    receiver.receive(sender.authenticate(b"fresh"))
    # Require one buffered packet again, showing the freed slot can be reused.
    assert receiver.buffered_count == 1


# Check repeated batches do not leave behind a growing set of accepted message
# identities. Interval closure must still reject old packets after each batch.
def test_completed_batches_do_not_grow_a_message_replay_database():
    # Create matching endpoints with space for three buffered packets.
    sender, receiver = pair(max_buffered_packets=3)
    # Repeat for intervals 1 through 8. range includes its first number and excludes
    # its last, so range(1, 9) covers all eight usable key intervals.
    for interval in range(1, 9):
        # Make a list of three genuine byte messages in the current interval. Each call
        # receives a new sequence number; _ means the loop counter itself is unused.
        packets = [sender.authenticate(b"x") for _ in range(3)]
        # Visit each newly created packet in turn.
        for packet in packets:
            # Buffer that packet before the current interval's key becomes public.
            receiver.receive(packet)
        # Advance the sender one step so the just-used interval's key may be disclosed.
        sender.advance()
        # Advance the receiver one step to the same disclosure time.
        receiver.advance()
        # Reveal the loop's interval key and require all returned verification results
        # to be accepted. Each loop processes a different interval's three-message batch.
        assert all(r.accepted for r in receiver.process_disclosure(interval, sender.disclose(interval)))
        # Require both buffered packet count and buffered bytes to be zero after the batch.
        assert receiver.buffered_count == receiver.buffered_bytes == 0
        # Look for the old-style _accepted_ids attribute, defaulting to an empty set
        # if it is absent. not requires the value to be empty or absent, so completed
        # messages must not accumulate in a permanent per-message replay collection.
        assert not getattr(receiver, "_accepted_ids", set())
        # Still require PacketRejected for an old packet after the batch has been removed.
        # ReplayDetected, a more specific subclass of PacketRejected, also satisfies this.
        with pytest.raises(PacketRejected):
            # Resend packets[0], the first message of the batch whose key was just disclosed.
            receiver.receive(packets[0])


# Check that buffering makes an independent packet snapshot, so a caller cannot
# change a previously received packet behind the receiver's back.
def test_receiver_snapshots_packet_before_later_caller_mutation():
    # Create a fresh matching sender and receiver with a one-step disclosure delay.
    sender, receiver = pair()
    # Generate a genuine packet whose starting sequence number is 1.
    packet = sender.authenticate(b"original")
    # Deliver it so the receiver has the opportunity to copy its original fields.
    receiver.receive(packet)
    # Deliberately bypass the packet's normal read-only protection using Python's
    # low-level object setter. Change the caller's sequence to 2**64, which is one
    # above the valid field limit; shared mutable state would now be dangerous.
    object.__setattr__(packet, "sequence", 2**64)
    # Advance the sender to interval 2 so key 1 can be disclosed.
    sender.advance()
    # Advance the receiver to the same disclosure time.
    receiver.advance()
    # Reveal key 1 and retain the first result [0] from checking the saved packet.
    result = receiver.process_disclosure(1, sender.disclose(1))[0]
    # Require successful verification and the original sequence number 1 in the
    # result. and requires both checks, proving the later caller edit was not used.
    assert result.accepted and result.packet.sequence == 1


# Check safety when the sender can be one interval ahead of the receiver.
# The receiver must account for that allowed clock gap before accepting a packet,
# because the sender might have released its key sooner than local time suggests.
def test_sender_ahead_bound_blocks_known_key_forgery_and_allows_safe_traffic():
    # Create matching endpoints with a two-step delay and a trusted upper bound
    # of one extra interval on sender time relative to receiver time.
    sender, receiver = pair(disclosure_delay=2, max_sender_ahead=1)
    # Generate a genuine interval 1 packet while its key is still secret.
    packet = sender.authenticate(b"honest")
    # At receiver time 1, the sender could be at most 1 + 1 = 2, earlier than the
    # key's disclosure boundary 1 + 2 = 3. This packet is therefore safe to buffer.
    receiver.receive(packet)  # receiver 1, upper bound 2 < disclosure 3
    # Move the sender from 1 to 3, reaching its disclosure boundary. The next line
    # moves the receiver to 2, giving the intended one-interval clock gap at receipt.
    sender.advance(2)  # sender is now 3; receiver advances to 2 next
    # Move the receiver from 1 to 2 while the sender is already at 3.
    receiver.advance()
    # Reveal key 1 at sender time 3; an attacker can now know this key too.
    key = sender.disclose(1)
    # Copy the old packet with a new sequence number 99 and attacker-chosen payload,
    # leaving its tag empty temporarily. It still claims the now-unsafe interval 1.
    forged = replace(packet, sequence=99, payload=b"forged", tag=b"")
    # Calculate a correct HMAC-SHA256 from the public key and forged packet bytes,
    # then attach the resulting digest as the tag. Cryptography alone cannot detect
    # this forgery because the attacker has used the real disclosed key.
    forged = replace(forged, tag=hmac.new(key, forged.authenticated_bytes(), hashlib.sha256).digest())
    # Require PacketRejected: receiver time 2 plus the allowed gap 1 reaches the
    # key-release boundary 3, even though receiver time alone has not reached it.
    with pytest.raises(PacketRejected):
        # Attempt to deliver the forged packet at that unsafe receiver time.
        receiver.receive(forged)
    # Advance the receiver from 2 to 3 so it can process interval 1's actual disclosure.
    receiver.advance()
    # Process key 1 and require the first saved packet to pass. This is the honest
    # packet received before the unsafe boundary, showing safe traffic still works.
    assert receiver.process_disclosure(1, key)[0].accepted


# Repeat the next test for each named setting. These first settings control
# key-release delay, total waiting packet count, and total charged packet bytes.
@pytest.mark.parametrize("name", ["disclosure_delay", "max_buffered_packets", "max_buffered_bytes",
                                  # The remaining settings cap packets per interval, candidates per identity,
                                  # and extra waiting time for a missing disclosure. All require positive integers.
                                  "max_packets_per_interval", "max_candidates_per_identity", "disclosure_grace"])
# Combine every setting name above with every bad value here. True is Boolean,
# 1.0 is floating point, NaN means "not a number", 0 and -1 are not positive,
# and "1" is text. Stacked parametrize decorators produce every combination.
@pytest.mark.parametrize("value", [True, 1.0, float("nan"), 0, -1, "1"])
# Check that invalid numeric policy values are rejected when objects are built,
# rather than being silently converted or causing confusing failures later.
def test_invalid_positive_policies_are_rejected(name, value):
    # Require ValueError, indicating the selected configuration value is unacceptable.
    with pytest.raises(ValueError):
        # Build a one-entry dictionary for this name/value case and expand it with **
        # into a named option for pair; construction must reject the invalid value.
        pair(**{name: value})


# Run once for each invalid sender-clock gap. A Boolean, floating value, NaN,
# negative number, and text digit are forbidden. Integer 0 is deliberately absent:
# zero is a valid bound meaning the sender is never ahead.
@pytest.mark.parametrize("value", [True, 1.0, float("nan"), -1, "0"])
# Check the sender-ahead setting uses a strict nonnegative integer rule.
def test_invalid_sender_ahead_bound_is_rejected(value):
    # Require ValueError when constructing endpoints with the invalid bound below.
    with pytest.raises(ValueError):
        # Pass this case's bad value as max_sender_ahead to the setup helper.
        pair(max_sender_ahead=value)


# Check the public clock property cannot be assigned an earlier time. Rewinding
# could otherwise make packets look timely after their keys were already public.
def test_public_clocks_cannot_be_rewound():
    # Create a new sender and matching receiver, both starting at interval 1.
    sender, receiver = pair()
    # Test each object in turn by assigning it to the temporary name endpoint.
    for endpoint in (sender, receiver):
        # Advance that object's clock to interval 2 before trying to rewind it.
        endpoint.advance()
        # Require AttributeError, Python's error for this attempt to set a read-only
        # property. pytest.raises checks the indented assignment.
        with pytest.raises(AttributeError):
            # Attempt to assign the old value 1 directly to the public current_interval
            # property; only forward advancement should be exposed through this clock API.
            endpoint.current_interval = 1
