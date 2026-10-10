"""Executable demonstration of the required Mini-TESLA scenarios."""

from __future__ import annotations

import secrets
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mini_tesla import (
    DisclosureRejected, ReceiverBootstrap, ReplayDetected, Satellite,
    SetupRejected, sign_satellite_setup,
)


def print_results(label: str, results) -> None:
    for result in results:
        verdict = "ACCEPT" if result.accepted else "REJECT"
        print(f"[{label}] {verdict}: seq={result.packet.sequence} reason={result.reason}")


def main() -> None:
    satellite = Satellite(chain_length=6, disclosure_delay=1)
    # Trusted provisioning: in this single-process demo, the sender's public
    # identity key is pinned directly. A real deployment must provision it
    # independently (e.g. from a trusted configuration or authenticated PKI).
    signing_key = Ed25519PrivateKey.generate()
    bootstrap = ReceiverBootstrap(
        trusted_public_key=signing_key.public_key(),
        expected_satellite_id="satellite-alpha",
        trusted_interval_source=lambda: satellite.current_interval,
    )

    # An attacker can create an entirely valid alternative TESLA key chain,
    # but cannot authenticate its fake commitment under the pinned public key.
    attacker = Satellite(chain_length=6, disclosure_delay=1)
    attacker_setup = sign_satellite_setup(
        attacker, signing_key=Ed25519PrivateKey.generate(),
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    try:
        bootstrap.establish(attacker_setup)
    except SetupRejected as exc:
        print("[fake satellite setup] REJECT:", exc)

    signed_setup = sign_satellite_setup(
        satellite, signing_key=signing_key, satellite_id="satellite-alpha",
        challenge=bootstrap.challenge,
    )
    receiver = bootstrap.establish(signed_setup)
    print("[signed bootstrap] ACCEPT: identity and fresh signed commitment verified")
    try:
        bootstrap.establish(signed_setup)
    except SetupRejected as exc:
        print("[setup replay] REJECT:", exc)
    print("Authenticated commitment:", receiver.hsm.commitment.hex())

    valid = satellite.authenticate(b"orbit=nominal;clock=12345")
    original_for_tamper = satellite.authenticate(b"command=hold-attitude")
    tampered = replace(original_for_tamper, payload=b"command=deorbit-now")
    receiver.receive(tampered)
    receiver.receive(valid)

    satellite.advance()
    key1 = satellite.disclose(1)
    print_results("interval 1", receiver.process_disclosure(1, key1))

    try:
        receiver.receive(valid)
    except ReplayDetected as exc:
        print("[replay] REJECT:", exc)

    packet2 = satellite.authenticate(b"telemetry=temp:19.4")
    receiver.receive(packet2)
    satellite.advance()

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
    key3 = satellite.disclose(3)
    print_results("interval 3", receiver.process_disclosure(3, key3))


if __name__ == "__main__":
    main()
