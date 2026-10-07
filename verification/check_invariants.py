"""Bounded exhaustive checks for the Mini-TESLA protocol invariants.

This is not a proof of SHA-256, HMAC, or AES-GCM. Those primitives are treated as
trusted cryptographic building blocks. The script systematically explores a
finite state space of protocol intervals and disclosure delays against the real
Satellite/Receiver implementation.
"""

from __future__ import annotations

import hashlib
import hmac

from mini_tesla import AuthPacket, EarlyDisclosureError, PacketRejected, Receiver, ReplayDetected, Satellite


def check_receive_timing() -> int:
    """Verify the receiver buffers iff the packet is current and still secret."""

    checked = 0
    chain_length = 4
    for delay in range(1, 4):
        for packet_interval in range(1, chain_length + 1):
            for receiver_interval in range(1, chain_length + delay + 2):
                satellite = Satellite(chain_length=chain_length, disclosure_delay=delay)
                receiver = Receiver(
                    commitment=satellite.commitment,
                    chain_length=chain_length,
                    disclosure_delay=delay,
                )
                if packet_interval > 1:
                    satellite.advance(packet_interval - 1)
                packet = satellite.authenticate(
                    f"probe:{delay}:{packet_interval}:{receiver_interval}".encode()
                )
                if receiver_interval > 1:
                    receiver.advance(receiver_interval - 1)

                should_buffer = (
                    receiver_interval >= packet_interval
                    and receiver_interval < packet_interval + delay
                )
                try:
                    result = receiver.receive(packet)
                except PacketRejected:
                    assert not should_buffer
                else:
                    assert should_buffer
                    assert result == "buffered"
                checked += 1
    return checked


def check_disclosure_timing_and_commitment() -> int:
    """Verify a key is disclosable iff its delay has elapsed and hashes to K[0]."""

    checked = 0
    chain_length = 4
    for delay in range(1, 4):
        for key_interval in range(1, chain_length + 1):
            for current_interval in range(1, chain_length + delay + 2):
                satellite = Satellite(chain_length=chain_length, disclosure_delay=delay)
                if current_interval > 1:
                    satellite.advance(current_interval - 1)

                should_disclose = current_interval >= key_interval + delay
                try:
                    key = satellite.disclose(key_interval)
                except EarlyDisclosureError:
                    assert not should_disclose
                else:
                    assert should_disclose
                    candidate = key
                    for _ in range(key_interval):
                        candidate = hashlib.sha256(candidate).digest()
                    assert hmac.compare_digest(candidate, satellite.commitment)
                checked += 1
    return checked


def check_replay_and_post_disclosure_forgery() -> int:
    """Verify accepted identities and disclosed-key forgeries cannot be replayed."""

    checked = 0
    for delay in range(1, 4):
        satellite = Satellite(chain_length=4, disclosure_delay=delay)
        receiver = Receiver(
            commitment=satellite.commitment,
            chain_length=satellite.chain_length,
            disclosure_delay=delay,
        )
        packet = satellite.authenticate(b"accepted-once")
        assert receiver.receive(packet) == "buffered"

        satellite.advance(delay)
        receiver.advance(delay)
        disclosed = satellite.disclose(1)
        results = receiver.process_disclosure(1, disclosed)
        assert len(results) == 1 and results[0].accepted

        try:
            receiver.receive(packet)
        except ReplayDetected:
            pass
        else:
            raise AssertionError("accepted packet replay was not rejected")

        forged = AuthPacket(
            interval=1,
            sequence=999,
            disclosure_delay=delay,
            payload=b"forged-after-disclosure",
            tag=b"",
        )
        forged_tag = hmac.new(
            disclosed,
            forged.authenticated_bytes(),
            hashlib.sha256,
        ).digest()
        forged = AuthPacket(
            interval=forged.interval,
            sequence=forged.sequence,
            disclosure_delay=forged.disclosure_delay,
            payload=forged.payload,
            tag=forged_tag,
        )
        try:
            receiver.receive(forged)
        except PacketRejected:
            pass
        else:
            raise AssertionError("valid-MAC packet created after disclosure was accepted")
        checked += 2
    return checked


def main() -> None:
    receive_states = check_receive_timing()
    disclosure_states = check_disclosure_timing_and_commitment()
    replay_states = check_replay_and_post_disclosure_forgery()
    total = receive_states + disclosure_states + replay_states

    print(f"Bounded verification passed: {total} protocol states/checks")
    print(f"  receive timing states: {receive_states}")
    print(f"  disclosure states:     {disclosure_states}")
    print(f"  replay/forgery checks: {replay_states}")


if __name__ == "__main__":
    main()
