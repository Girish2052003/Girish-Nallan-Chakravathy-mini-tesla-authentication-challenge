"""Bounded implementation grid for challenge-signed bootstrap time admission.

Tests actual Ed25519 signatures and Python ReceiverBootstrap; not a formal
proof of the signatures or a refinement proof of the TLA+ model.
"""
from __future__ import annotations
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mini_tesla import ReceiverBootstrap, Satellite, SetupRejected, sign_satellite_setup


def main() -> None:
    count = 0
    passed = 0
    rejected = 0
    for delay in range(1, 4):
        for bound in range(3):
            for now in range(1, delay + 5):
                satellite = Satellite(chain_length=5, disclosure_delay=delay)
                key = Ed25519PrivateKey.generate()
                time = [now]
                bootstrap = ReceiverBootstrap(
                    trusted_public_key=key.public_key(),
                    expected_satellite_id="test-satellite",
                    trusted_interval_source=lambda time=time: time[0],
                )
                signed = sign_satellite_setup(
                    satellite, signing_key=key,
                    satellite_id="test-satellite", challenge=bootstrap.challenge,
                )
                safe = now + bound < 1 + delay
                try:
                    receiver = bootstrap.establish(signed, max_sender_ahead=bound)
                except SetupRejected:
                    if safe:
                        raise AssertionError((delay, bound, now, "unexpected rejection"))
                    rejected += 1
                else:
                    if not safe or receiver.current_interval != now:
                        raise AssertionError((delay, bound, now, "unsafe acceptance"))
                    passed += 1
                count += 1
    print(f"Bootstrap time grid passed: {count} cases "
          f"({passed} admitted, {rejected} rejected)")
    assert count == 54

if __name__ == "__main__":
    main()
