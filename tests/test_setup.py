"""Adversarial checks of authenticated TESLA trust bootstrap."""

from dataclasses import replace
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mini_tesla import (
    ReceiverBootstrap, Satellite, SetupRejected, SignedSetup,
    sign_satellite_setup,
)


@pytest.fixture
def setup_pair():
    signing_key = Ed25519PrivateKey.generate()
    satellite = Satellite(chain_length=5, disclosure_delay=2)
    # Public key pinning is a trusted local configuration action, not network TOFU.
    bootstrap = ReceiverBootstrap(
        trusted_public_key=signing_key.public_key(),
        expected_satellite_id="satellite-alpha",
    )
    response = sign_satellite_setup(
        satellite, signing_key=signing_key,
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    return satellite, signing_key, bootstrap, response


def test_valid_signed_setup_then_tesla_authentication(setup_pair):
    satellite, _, bootstrap, signed = setup_pair
    receiver = bootstrap.establish(signed)
    assert receiver.hsm.commitment == satellite.commitment
    assert receiver.disclosure_delay == 2
    packet = satellite.authenticate(b"real telemetry")
    assert receiver.receive(packet) == "buffered"
    satellite.advance(2)
    receiver.advance(2)
    results = receiver.process_disclosure(1, satellite.disclose(1))
    assert len(results) == 1 and results[0].accepted


def test_attacker_generated_chain_and_signature_cannot_impersonate_satellite(setup_pair):
    _, _, bootstrap, _ = setup_pair
    attacker_key = Ed25519PrivateKey.generate()
    attacker_satellite = Satellite(chain_length=5, disclosure_delay=2)
    forged = sign_satellite_setup(
        attacker_satellite, signing_key=attacker_key,
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    with pytest.raises(SetupRejected, match="signature"):
        bootstrap.establish(forged)


@pytest.mark.parametrize("change", [
    {"commitment": b"x" * 32},
    {"chain_length": 4},
    {"disclosure_delay": 3},
    {"satellite_id": "satellite-beta"},
    {"version": 2},
])
def test_any_signed_setup_metadata_modification_fails(setup_pair, change):
    _, _, bootstrap, signed = setup_pair
    with pytest.raises(SetupRejected):
        bootstrap.establish(replace(signed, **change))


def test_modified_signature_is_rejected(setup_pair):
    _, _, bootstrap, signed = setup_pair
    wrong = bytearray(signed.signature)
    wrong[-1] ^= 1
    with pytest.raises(SetupRejected, match="signature"):
        bootstrap.establish(replace(signed, signature=bytes(wrong)))


def test_old_signed_setup_does_not_satisfy_new_receiver_challenge(setup_pair):
    _, key, old_bootstrap, old_signed = setup_pair
    new_bootstrap = ReceiverBootstrap(
        trusted_public_key=key.public_key(),
        expected_satellite_id="satellite-alpha",
    )
    assert new_bootstrap.challenge != old_bootstrap.challenge
    with pytest.raises(SetupRejected, match="fresh receiver challenge"):
        new_bootstrap.establish(old_signed)


def test_valid_signature_under_untrusted_identity_key_is_rejected(setup_pair):
    _, real_key, _, _ = setup_pair
    satellite = Satellite(chain_length=5, disclosure_delay=2)
    wrong_identity = ReceiverBootstrap(
        trusted_public_key=Ed25519PrivateKey.generate().public_key(),
        expected_satellite_id="satellite-alpha",
    )
    # Real signature for the right nonce still fails under a wrongly pinned key.
    signed = sign_satellite_setup(
        satellite, signing_key=real_key,
        satellite_id="satellite-alpha", challenge=wrong_identity.challenge,
    )
    with pytest.raises(SetupRejected, match="signature"):
        wrong_identity.establish(signed)


def test_failed_attempt_does_not_consume_legitimate_challenge(setup_pair):
    _, _, bootstrap, signed = setup_pair
    with pytest.raises(SetupRejected):
        bootstrap.establish(replace(signed, signature=b"!" * 64))
    assert bootstrap.establish(signed).hsm.commitment == signed.commitment


def test_successful_bootstrap_consumes_challenge(setup_pair):
    _, _, bootstrap, signed = setup_pair
    bootstrap.establish(signed)
    with pytest.raises(SetupRejected, match="consumed"):
        bootstrap.establish(signed)


@pytest.mark.parametrize("change", [
    {"challenge": b""},
    {"commitment": b""},
    {"signature": b"x" * 63},
    {"satellite_id": ""},
    {"satellite_id": "bad unicode ☃"},
    {"satellite_id": "A" * 65},
    {"chain_length": 0},
    {"chain_length": 4097},
    {"chain_length": True},
    {"disclosure_delay": 0},
    {"disclosure_delay": float("nan")},
    {"disclosure_delay": 2**32},
    {"version": True},
])
def test_malformed_setup_is_never_accepted(setup_pair, change):
    _, _, bootstrap, signed = setup_pair
    with pytest.raises(SetupRejected):
        bootstrap.establish(replace(signed, **change))


def test_no_untrusted_auto_key_provisioning():
    attacker_key = Ed25519PrivateKey.generate()
    with pytest.raises(TypeError, match="public key"):
        ReceiverBootstrap(
            trusted_public_key=attacker_key.private_bytes,  # type: ignore[arg-type]
            expected_satellite_id="satellite-alpha",
        )


def test_sender_rejects_invalid_challenge_and_signer(setup_pair):
    satellite, key, bootstrap, _ = setup_pair
    with pytest.raises(SetupRejected):
        sign_satellite_setup(
            satellite, signing_key=key,
            satellite_id="satellite-alpha", challenge=b"too short",
        )
    with pytest.raises(TypeError):
        sign_satellite_setup(
            satellite, signing_key=key.public_key(),  # type: ignore[arg-type]
            satellite_id="satellite-alpha", challenge=bootstrap.challenge,
        )


def test_session_config_signed_bytes_are_deterministic(setup_pair):
    _, _, _, signed = setup_pair
    assert signed.signed_bytes() == replace(signed).signed_bytes()
    assert signed.signed_bytes() != replace(
        signed, disclosure_delay=signed.disclosure_delay + 1,
    ).signed_bytes()


def test_nonce_is_fresh_and_not_derived_from_sender():
    key = Ed25519PrivateKey.generate()
    a = ReceiverBootstrap(trusted_public_key=key.public_key(), expected_satellite_id="satellite-alpha")
    b = ReceiverBootstrap(trusted_public_key=key.public_key(), expected_satellite_id="satellite-alpha")
    assert len(a.challenge) == 32 and len(b.challenge) == 32
    assert a.challenge != b.challenge


def test_wrong_type_cannot_be_accepted(setup_pair):
    _, _, bootstrap, _ = setup_pair
    with pytest.raises(SetupRejected):
        bootstrap.establish(secrets.token_bytes(128))  # type: ignore[arg-type]


def test_receiver_policy_is_locally_validated_without_consuming_challenge(setup_pair):
    _, _, bootstrap, signed = setup_pair
    with pytest.raises(ValueError):
        bootstrap.establish(signed, max_buffered_packets=0)
    assert bootstrap.establish(signed).hsm.commitment == signed.commitment


def test_sender_cannot_sign_same_chain_for_two_new_receivers(setup_pair):
    satellite, key, _, _ = setup_pair
    another_receiver = ReceiverBootstrap(
        trusted_public_key=key.public_key(),
        expected_satellite_id="satellite-alpha",
    )
    with pytest.raises(SetupRejected, match="fresh, unused"):
        sign_satellite_setup(
            satellite, signing_key=key, satellite_id="satellite-alpha",
            challenge=another_receiver.challenge,
        )


def test_sender_cannot_sign_chain_after_messages_or_time_progress():
    key = Ed25519PrivateKey.generate()
    used = Satellite(chain_length=4, disclosure_delay=1)
    used.authenticate(b"already used")
    with pytest.raises(SetupRejected, match="fresh, unused"):
        sign_satellite_setup(
            used, signing_key=key, satellite_id="satellite-alpha",
            challenge=secrets.token_bytes(32),
        )
    advanced = Satellite(chain_length=4, disclosure_delay=1)
    advanced.advance()
    with pytest.raises(SetupRejected, match="fresh, unused"):
        sign_satellite_setup(
            advanced, signing_key=key, satellite_id="satellite-alpha",
            challenge=secrets.token_bytes(32),
        )


def test_rejected_setup_does_not_burn_unused_satellite_chain():
    key = Ed25519PrivateKey.generate()
    satellite = Satellite(chain_length=4, disclosure_delay=1)
    with pytest.raises(SetupRejected):
        sign_satellite_setup(
            satellite, signing_key=key, satellite_id="satellite-alpha",
            challenge=b"bad",
        )
    signed = sign_satellite_setup(
        satellite, signing_key=key, satellite_id="satellite-alpha",
        challenge=secrets.token_bytes(32),
    )
    assert len(signed.signature) == 64
