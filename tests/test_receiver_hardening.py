"""Regression cases for independent audit findings F01, F03, F04 and F06."""
from dataclasses import replace
import hashlib
import hmac

import pytest

from mini_tesla import AuthPacket, PacketRejected, Receiver, ReplayDetected, Satellite
from mini_tesla.protocol import ProtocolError


def pair(**policy):
    sender = Satellite(chain_length=8, disclosure_delay=policy.pop("disclosure_delay", 1))
    receiver = Receiver(commitment=sender.commitment, chain_length=8,
                        disclosure_delay=sender.disclosure_delay, **policy)
    return sender, receiver


@pytest.mark.parametrize("field,value", [
    ("version", True), ("version", 1.0), ("version", None),
    ("interval", True), ("interval", 1.0), ("interval", "1"), ("interval", None),
    ("interval", 2**32), ("interval", 0),
    ("sequence", True), ("sequence", 1.0), ("sequence", 0), ("sequence", 2**64),
    ("disclosure_delay", True), ("disclosure_delay", 1.0), ("disclosure_delay", float("nan")),
])
def test_invalid_metadata_cannot_poison_a_disclosure_batch(field, value):
    sender, receiver = pair()
    good = sender.authenticate(b"legitimate")
    bad = replace(good, **{field: value})
    with pytest.raises(PacketRejected):
        receiver.receive(bad)
    receiver.receive(good)
    sender.advance()
    receiver.advance()
    results = receiver.process_disclosure(1, sender.disclose(1))
    assert len(results) == 1 and results[0].accepted
    assert receiver.buffered_count == 0


def test_maximum_uint64_sequence_can_be_authenticated():
    sender, receiver = pair()
    sender._next_sequence = 2**64 - 1
    receiver.receive(sender.authenticate(b"last sequence"))
    with pytest.raises(ProtocolError, match="sequence"):
        sender.authenticate(b"overflow")
    sender.advance()
    receiver.advance()
    assert receiver.process_disclosure(1, sender.disclose(1))[0].accepted


def test_bogus_first_candidate_does_not_reserve_authentication_identity():
    sender, receiver = pair()
    good = sender.authenticate(b"real")
    receiver.receive(replace(good, payload=b"fake"))
    receiver.receive(good)
    with pytest.raises(ReplayDetected):
        receiver.receive(good)
    sender.advance()
    receiver.advance()
    results = receiver.process_disclosure(1, sender.disclose(1))
    assert [r.accepted for r in results] == [False, True]
    with pytest.raises(ReplayDetected):
        receiver.receive(good)


def test_two_valid_candidates_with_one_identity_are_accepted_at_most_once():
    sender, receiver = pair()
    first = sender.authenticate(b"first")
    second = replace(first, payload=b"second", tag=b"")
    second = replace(second, tag=sender.hsm.generate_mac(1, second.authenticated_bytes()))
    receiver.receive(first)
    receiver.receive(second)
    sender.advance()
    receiver.advance()
    assert [r.accepted for r in receiver.process_disclosure(1, sender.disclose(1))] == [True, False]


def test_candidate_count_is_bounded_per_identity():
    sender, receiver = pair(max_candidates_per_identity=2)
    packet = sender.authenticate(b"real")
    receiver.receive(replace(packet, payload=b"one"))
    receiver.receive(replace(packet, payload=b"two"))
    with pytest.raises(PacketRejected, match="candidate"):
        receiver.receive(packet)
    assert receiver.buffered_count == 2


@pytest.mark.parametrize("policy", [
    {"max_buffered_packets": 2}, {"max_packets_per_interval": 2},
])
def test_packet_limits_reject_without_partial_mutation(policy):
    sender, receiver = pair(**policy)
    receiver.receive(sender.authenticate(b"one"))
    receiver.receive(sender.authenticate(b"two"))
    with pytest.raises(PacketRejected, match="limit"):
        receiver.receive(sender.authenticate(b"three"))
    assert receiver.buffered_count == 2
    sender.advance()
    receiver.advance()
    assert all(r.accepted for r in receiver.process_disclosure(1, sender.disclose(1)))
    assert receiver.buffered_bytes == 0


def test_total_byte_limit_counts_wire_metadata_and_tag():
    sender, _ = pair()
    packet = sender.authenticate(b"x")
    size = len(packet.authenticated_bytes()) + len(packet.tag)
    receiver = Receiver(commitment=sender.commitment, chain_length=8, max_buffered_bytes=size)
    receiver.receive(packet)
    assert receiver.buffered_bytes == size
    with pytest.raises(PacketRejected, match="byte"):
        receiver.receive(sender.authenticate(b""))
    assert receiver.buffered_bytes == size


def test_missing_disclosure_expires_and_capacity_is_reusable():
    sender, receiver = pair(disclosure_grace=2, max_buffered_packets=1)
    packet = sender.authenticate(b"expired")
    receiver.receive(packet)
    receiver.advance(2)  # local 3: one before expiry at 1 + 1 + 2
    assert receiver.buffered_count == 1
    receiver.advance()  # expiry boundary
    assert receiver.buffered_count == receiver.buffered_bytes == 0
    with pytest.raises(PacketRejected):
        receiver.receive(packet)
    sender.advance(3)
    assert receiver.process_disclosure(1, sender.disclose(1)) == []
    receiver.receive(sender.authenticate(b"fresh"))
    assert receiver.buffered_count == 1


def test_completed_batches_do_not_grow_a_message_replay_database():
    sender, receiver = pair(max_buffered_packets=3)
    for interval in range(1, 9):
        packets = [sender.authenticate(b"x") for _ in range(3)]
        for packet in packets:
            receiver.receive(packet)
        sender.advance()
        receiver.advance()
        assert all(r.accepted for r in receiver.process_disclosure(interval, sender.disclose(interval)))
        assert receiver.buffered_count == receiver.buffered_bytes == 0
        assert not getattr(receiver, "_accepted_ids", set())
        with pytest.raises(PacketRejected):
            receiver.receive(packets[0])


def test_receiver_snapshots_packet_before_later_caller_mutation():
    sender, receiver = pair()
    packet = sender.authenticate(b"original")
    receiver.receive(packet)
    object.__setattr__(packet, "sequence", 2**64)
    sender.advance()
    receiver.advance()
    result = receiver.process_disclosure(1, sender.disclose(1))[0]
    assert result.accepted and result.packet.sequence == 1


def test_sender_ahead_bound_blocks_known_key_forgery_and_allows_safe_traffic():
    sender, receiver = pair(disclosure_delay=2, max_sender_ahead=1)
    packet = sender.authenticate(b"honest")
    receiver.receive(packet)  # receiver 1, upper bound 2 < disclosure 3
    sender.advance(2)  # sender 3, receiver 2, disclosure can be public
    receiver.advance()
    key = sender.disclose(1)
    forged = replace(packet, sequence=99, payload=b"forged", tag=b"")
    forged = replace(forged, tag=hmac.new(key, forged.authenticated_bytes(), hashlib.sha256).digest())
    with pytest.raises(PacketRejected):
        receiver.receive(forged)
    receiver.advance()
    assert receiver.process_disclosure(1, key)[0].accepted


@pytest.mark.parametrize("name", ["disclosure_delay", "max_buffered_packets", "max_buffered_bytes",
                                  "max_packets_per_interval", "max_candidates_per_identity", "disclosure_grace"])
@pytest.mark.parametrize("value", [True, 1.0, float("nan"), 0, -1, "1"])
def test_invalid_positive_policies_are_rejected(name, value):
    with pytest.raises(ValueError):
        pair(**{name: value})


@pytest.mark.parametrize("value", [True, 1.0, float("nan"), -1, "0"])
def test_invalid_sender_ahead_bound_is_rejected(value):
    with pytest.raises(ValueError):
        pair(max_sender_ahead=value)


def test_public_clocks_cannot_be_rewound():
    sender, receiver = pair()
    for endpoint in (sender, receiver):
        endpoint.advance()
        with pytest.raises(AttributeError):
            endpoint.current_interval = 1
