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
        trusted_interval_source=lambda: satellite.current_interval,
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
    assert receiver.current_interval == 3
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
        trusted_interval_source=lambda: 1,
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
        trusted_interval_source=lambda: 1,
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
            trusted_interval_source=lambda: 1,
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
    a = ReceiverBootstrap(trusted_public_key=key.public_key(), expected_satellite_id="satellite-alpha", trusted_interval_source=lambda: 1)
    b = ReceiverBootstrap(trusted_public_key=key.public_key(), expected_satellite_id="satellite-alpha", trusted_interval_source=lambda: 1)
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
        trusted_interval_source=lambda: 1,
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

# Critical regression: a valid signature may be delivered AFTER the
# satellite has disclosed K[1]. Signature verification must not reset time.
def test_delayed_genuine_signed_setup_is_rejected_after_first_disclosure(setup_pair):
    satellite, _, bootstrap, signed = setup_pair
    # Fixture delay = 2; K1 becomes public at sender interval 3.
    satellite.advance(2)
    satellite.disclose(1)
    with pytest.raises(SetupRejected, match="safe first-key"):
        bootstrap.establish(signed)


def test_delayed_setup_near_boundary_respects_clock_skew_bound():
    key = Ed25519PrivateKey.generate()
    satellite = Satellite(chain_length=4, disclosure_delay=2)
    receiver_clock = [1]
    bootstrap = ReceiverBootstrap(
        trusted_public_key=key.public_key(),
        expected_satellite_id="satellite-alpha",
        trusted_interval_source=lambda: receiver_clock[0],
    )
    signed = sign_satellite_setup(
        satellite, signing_key=key,
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    satellite.advance()
    receiver_clock[0] = 2
    # B=1 allows the sender to have reached interval 3 and disclosed K1.
    with pytest.raises(SetupRejected, match="safe first-key"):
        bootstrap.establish(signed, max_sender_ahead=1)
    # The failed attempt does not consume this nonce. With an independently
    # established B=0 bound, R=2 implies S <= 2 and K1 remains undisclosed.
    receiver = bootstrap.establish(signed, max_sender_ahead=0)
    assert receiver.current_interval == 2


def test_live_trusted_clock_blocks_post_disclosure_hmac_forgery():
    import hashlib
    import hmac
    from mini_tesla import AuthPacket, PacketRejected

    key = Ed25519PrivateKey.generate()
    satellite = Satellite(chain_length=4, disclosure_delay=2)
    clock = [1]
    bootstrap = ReceiverBootstrap(
        trusted_public_key=key.public_key(),
        expected_satellite_id="satellite-alpha",
        trusted_interval_source=lambda: clock[0],
    )
    signed = sign_satellite_setup(
        satellite, signing_key=key,
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    receiver = bootstrap.establish(signed)
    satellite.advance(2)
    clock[0] = 3
    disclosed_key = satellite.disclose(1)
    forged = AuthPacket(interval=1, sequence=777, disclosure_delay=2,
                        payload=b"malicious", tag=b"")
    forged = replace(
        forged, tag=hmac.new(disclosed_key, forged.authenticated_bytes(), hashlib.sha256).digest()
    )
    with pytest.raises(PacketRejected, match="key-disclosure interval"):
        receiver.receive(forged)
    assert receiver.buffered_count == 0


def test_verified_receiver_clock_cannot_be_advanced_manually(setup_pair):
    from mini_tesla import ProtocolError
    _, _, bootstrap, signed = setup_pair
    receiver = bootstrap.establish(signed)
    with pytest.raises(ProtocolError, match="manually"):
        receiver.advance()


def test_verified_receiver_fails_closed_on_clock_rollback():
    from mini_tesla import ProtocolError
    key = Ed25519PrivateKey.generate()
    satellite = Satellite(chain_length=4, disclosure_delay=2)
    clock = [1]
    bootstrap = ReceiverBootstrap(
        trusted_public_key=key.public_key(),
        expected_satellite_id="satellite-alpha",
        trusted_interval_source=lambda: clock[0],
    )
    signed = sign_satellite_setup(
        satellite, signing_key=key,
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    receiver = bootstrap.establish(signed)
    clock[0] = 2
    assert receiver.current_interval == 2
    clock[0] = 1
    with pytest.raises(ProtocolError, match="backward"):
        receiver.receive(satellite.authenticate(b"should fail"))


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, float("nan"), "1", None, 2**32])
def test_invalid_trusted_time_rejects_signed_setup(bad):
    key = Ed25519PrivateKey.generate()
    satellite = Satellite(chain_length=4, disclosure_delay=2)
    bootstrap = ReceiverBootstrap(
        trusted_public_key=key.public_key(),
        expected_satellite_id="satellite-alpha",
        trusted_interval_source=lambda: bad,
    )
    signed = sign_satellite_setup(
        satellite, signing_key=key,
        satellite_id="satellite-alpha", challenge=bootstrap.challenge,
    )
    with pytest.raises(SetupRejected, match="invalid interval"):
        bootstrap.establish(signed)


def test_signed_bootstrap_no_longer_accepts_without_trusted_time():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(TypeError):
        ReceiverBootstrap(
            trusted_public_key=key.public_key(),
            expected_satellite_id="satellite-alpha",
        )
