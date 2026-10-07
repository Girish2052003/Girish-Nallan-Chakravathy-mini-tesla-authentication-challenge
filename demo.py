"""Executable demonstration of the required Mini-TESLA scenarios."""

from __future__ import annotations

import secrets
from dataclasses import replace

from mini_tesla import DisclosureRejected, Receiver, ReplayDetected, Satellite


def print_results(label: str, results) -> None:
    for result in results:
        verdict = "ACCEPT" if result.accepted else "REJECT"
        print(f"[{label}] {verdict}: seq={result.packet.sequence} reason={result.reason}")


def main() -> None:
    satellite = Satellite(chain_length=6, disclosure_delay=1)
    receiver = Receiver(
        commitment=satellite.commitment,
        chain_length=satellite.chain_length,
        disclosure_delay=satellite.disclosure_delay,
    )

    print("Trusted commitment:", satellite.commitment.hex())

    valid = satellite.authenticate(b"orbit=nominal;clock=12345")
    original_for_tamper = satellite.authenticate(b"command=hold-attitude")
    tampered = replace(original_for_tamper, payload=b"command=deorbit-now")
    receiver.receive(tampered)
    receiver.receive(valid)

    satellite.advance()
    receiver.advance()
    key1 = satellite.disclose(1)
    print_results("interval 1", receiver.process_disclosure(1, key1))

    try:
        receiver.receive(valid)
    except ReplayDetected as exc:
        print("[replay] REJECT:", exc)

    packet2 = satellite.authenticate(b"telemetry=temp:19.4")
    receiver.receive(packet2)
    satellite.advance()
    receiver.advance()

    try:
        receiver.process_disclosure(2, secrets.token_bytes(32))
    except DisclosureRejected as exc:
        print("[bad disclosure] REJECT:", exc)

    key2 = satellite.disclose(2)
    print_results("interval 2", receiver.process_disclosure(2, key2))

    packet3 = satellite.authenticate(b"telemetry=power:stable")
    bad_tag = bytearray(packet3.tag)
    bad_tag[0] ^= 0x01
    receiver.receive(replace(packet3, tag=bytes(bad_tag)))
    satellite.advance()
    receiver.advance()
    key3 = satellite.disclose(3)
    print_results("interval 3", receiver.process_disclosure(3, key3))


if __name__ == "__main__":
    main()
