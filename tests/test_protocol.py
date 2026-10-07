from __future__ import annotations

import base64
import secrets
from dataclasses import replace

import pytest

from mini_tesla import (
    DisclosureRejected,
    EarlyDisclosureError,
    HSM,
    PacketRejected,
    PersistenceError,
    Receiver,
    ReplayDetected,
    Satellite,
    master_key_from_env,
)


def pair(*, chain_length: int = 8, delay: int = 1):
    satellite = Satellite(chain_length=chain_length, disclosure_delay=delay)
    receiver = Receiver(
        commitment=satellite.commitment,
        chain_length=chain_length,
        disclosure_delay=delay,
    )
    return satellite, receiver


def disclose_current(satellite: Satellite, receiver: Receiver, interval: int):
    satellite.advance()
    receiver.advance()
    key = satellite.disclose(interval)
    return receiver.process_disclosure(interval, key)


def test_valid_message_is_authenticated_only_after_key_disclosure():
    satellite, receiver = pair()
    packet = satellite.authenticate(b"valid telemetry")
    assert receiver.receive(packet) == "buffered"
    assert receiver.buffered_count == 1

    results = disclose_current(satellite, receiver, 1)
    assert [(r.accepted, r.reason) for r in results] == [(True, "authenticated")]
    assert receiver.buffered_count == 0


def test_modified_message_is_rejected():
    satellite, receiver = pair()
    packet = satellite.authenticate(b"mode=safe")
    receiver.receive(replace(packet, payload=b"mode=unsafe"))
    results = disclose_current(satellite, receiver, 1)
    assert results[0].accepted is False
    assert results[0].reason == "invalid authentication tag"


def test_modified_tag_is_rejected():
    satellite, receiver = pair()
    packet = satellite.authenticate(b"status=ok")
    tag = bytearray(packet.tag)
    tag[-1] ^= 0x80
    receiver.receive(replace(packet, tag=bytes(tag)))
    assert disclose_current(satellite, receiver, 1)[0].accepted is False


def test_invalid_disclosed_key_is_rejected_and_buffer_survives():
    satellite, receiver = pair()
    receiver.receive(satellite.authenticate(b"payload"))
    satellite.advance()
    receiver.advance()

    with pytest.raises(DisclosureRejected):
        receiver.process_disclosure(1, secrets.token_bytes(32))
    assert receiver.buffered_count == 1
    assert receiver.process_disclosure(1, satellite.disclose(1))[0].accepted is True


def test_previously_accepted_message_replay_is_rejected():
    satellite, receiver = pair()
    packet = satellite.authenticate(b"unique")
    receiver.receive(packet)
    assert disclose_current(satellite, receiver, 1)[0].accepted
    with pytest.raises(ReplayDetected):
        receiver.receive(packet)


def test_duplicate_buffered_identity_is_rejected():
    satellite, receiver = pair()
    packet = satellite.authenticate(b"unique")
    receiver.receive(packet)
    with pytest.raises(ReplayDetected):
        receiver.receive(packet)


def test_multiple_packets_can_arrive_out_of_order_before_disclosure():
    satellite, receiver = pair()
    first = satellite.authenticate(b"first")
    second = satellite.authenticate(b"second")
    receiver.receive(second)
    receiver.receive(first)
    results = disclose_current(satellite, receiver, 1)
    assert len(results) == 2
    assert all(r.accepted for r in results)


def test_more_than_one_disclosure_interval_is_processed():
    satellite, receiver = pair()
    receiver.receive(satellite.authenticate(b"interval one"))
    assert disclose_current(satellite, receiver, 1)[0].accepted

    receiver.receive(satellite.authenticate(b"interval two"))
    assert disclose_current(satellite, receiver, 2)[0].accepted


def test_satellite_hsm_blocks_early_key_disclosure():
    satellite, _ = pair(delay=2)
    with pytest.raises(EarlyDisclosureError):
        satellite.disclose(1)
    satellite.advance()
    with pytest.raises(EarlyDisclosureError):
        satellite.disclose(1)
    satellite.advance()
    assert len(satellite.disclose(1)) == 32


def test_receiver_rejects_packet_that_arrives_when_key_could_be_disclosed():
    satellite, receiver = pair(delay=1)
    packet = satellite.authenticate(b"late")
    receiver.advance()
    with pytest.raises(PacketRejected):
        receiver.receive(packet)


def test_receiver_rejects_future_interval_packet():
    satellite, receiver = pair(delay=2)
    satellite.advance()
    future = satellite.authenticate(b"future")
    with pytest.raises(PacketRejected):
        receiver.receive(future)



def test_malformed_tag_length_is_rejected_before_buffering():
    satellite, receiver = pair()
    packet = satellite.authenticate(b"payload")
    with pytest.raises(PacketRejected):
        receiver.receive(replace(packet, tag=b"short"))


def test_non_packet_input_is_rejected():
    _, receiver = pair()
    with pytest.raises(PacketRejected):
        receiver.receive(b"not-a-packet")  # type: ignore[arg-type]


def test_authenticated_representation_covers_protocol_metadata():
    satellite, _ = pair()
    packet = satellite.authenticate(b"payload")
    assert packet.authenticated_bytes() != replace(packet, sequence=999).authenticated_bytes()
    assert packet.authenticated_bytes() != replace(packet, interval=2).authenticated_bytes()
    assert packet.authenticated_bytes() != replace(packet, payload=b"other").authenticated_bytes()


def test_encrypted_hsm_export_import_round_trip(tmp_path, monkeypatch):
    hsm = HSM.create_satellite(4)
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(master_key).decode("ascii"))
    path = tmp_path / "hsm.enc"

    hsm.export_encrypted(path)
    raw = path.read_bytes()
    assert hsm.commitment not in raw

    restored = HSM.import_encrypted(path)
    assert restored.commitment == hsm.commitment
    assert restored.chain_length == hsm.chain_length
    assert restored.generate_mac(1, b"abc") == hsm.generate_mac(1, b"abc")


def test_encrypted_hsm_import_rejects_wrong_master_key(tmp_path, monkeypatch):
    hsm = HSM.create_satellite(3)
    path = tmp_path / "hsm.enc"

    first_key = secrets.token_bytes(32)
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(first_key).decode("ascii"))
    hsm.export_encrypted(path)

    wrong_key = secrets.token_bytes(32)
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(wrong_key).decode("ascii"))
    with pytest.raises(PersistenceError):
        HSM.import_encrypted(path)


def test_hsm_persistence_requires_master_key_environment_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("MINITESLA_MASTER_KEY", raising=False)
    hsm = HSM.create_satellite(2)
    with pytest.raises(PersistenceError):
        hsm.export_encrypted(tmp_path / "hsm.enc")


def test_master_key_is_loaded_from_environment(monkeypatch):
    key = secrets.token_bytes(32)
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(key).decode("ascii"))
    assert master_key_from_env() == key


def test_master_key_rejects_bad_environment_value(monkeypatch):
    monkeypatch.setenv("MINITESLA_MASTER_KEY", "not-base64!")
    with pytest.raises(PersistenceError):
        master_key_from_env()
