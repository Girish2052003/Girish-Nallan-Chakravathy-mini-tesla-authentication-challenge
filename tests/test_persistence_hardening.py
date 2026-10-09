"""Authentic but invalid writer state and interrupted-write regressions (F05/07/10)."""
import base64
import copy
import json
import os
import secrets
import stat

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mini_tesla import HSM, HSMError, PersistenceError
from mini_tesla.hsm import FILE_MAGIC, NONCE_SIZE


@pytest.fixture
def store(tmp_path, monkeypatch):
    master = secrets.token_bytes(32)
    monkeypatch.setenv("MINITESLA_MASTER_KEY", base64.b64encode(master).decode())
    path = tmp_path / "state.enc"
    hsm = HSM.create_satellite(3)
    hsm.export_encrypted(path)
    raw = path.read_bytes()
    start = len(FILE_MAGIC)
    data = json.loads(AESGCM(master).decrypt(raw[start:start+NONCE_SIZE], raw[start+NONCE_SIZE:], FILE_MAGIC))

    def write(state):
        plaintext = state.encode() if isinstance(state, str) else json.dumps(state).encode()
        nonce = secrets.token_bytes(NONCE_SIZE)
        path.write_bytes(FILE_MAGIC + nonce + AESGCM(master).encrypt(nonce, plaintext, FILE_MAGIC))
    return hsm, path, data, write


@pytest.mark.parametrize("state", [None, [], 7, "null", "[]", "{\"version\":1}"])
def test_non_schema_states_raise_persistence_error(store, state):
    _, path, _, write = store
    write(state)
    with pytest.raises(PersistenceError):
        HSM.import_encrypted(path)


@pytest.mark.parametrize("field,value", [
    ("version", True), ("version", 1.0), ("version", 2),
    ("role", []), ("role", "other"), ("role", None),
    ("chain_length", True), ("chain_length", 3.0), ("chain_length", 3.9),
    ("chain_length", "3"), ("chain_length", 0), ("chain_length", -1),
    ("chain_length", 4097), ("commitment", None), ("commitment", "AA=="),
    ("auth_keys", []), ("auth_keys", None), ("disclosed_keys", []), ("disclosed_keys", None),
])
def test_invalid_schema_fields_fail_closed(store, field, value):
    _, path, state, write = store
    state[field] = value
    write(state)
    with pytest.raises(PersistenceError):
        HSM.import_encrypted(path)


@pytest.mark.parametrize("change", ["wrong_link", "short_key", "missing_key", "noncanonical", "extra_field", "missing_field"])
def test_satellite_invariants_are_checked(store, change):
    _, path, state, write = store
    if change == "wrong_link":
        state["auth_keys"]["2"] = base64.b64encode(b"x" * 32).decode()
    elif change == "short_key":
        state["auth_keys"]["2"] = "AA=="
    elif change == "missing_key":
        del state["auth_keys"]["2"]
    elif change == "noncanonical":
        state["auth_keys"]["01"] = state["auth_keys"]["1"]
    elif change == "extra_field":
        state["unexpected"] = 1
    else:
        del state["disclosed_keys"]
    write(state)
    with pytest.raises(PersistenceError):
        HSM.import_encrypted(path)


@pytest.mark.parametrize("index,key", [("0", b"x"*32), ("-1", b"x"*32), ("4", b"x"*32),
                                       ("1", b"x"*32), ("01", b"x"*32), ("1.0", b"x"*32)])
def test_receiver_cached_keys_require_valid_indices_and_commitment(store, index, key):
    _, path, state, write = store
    state["role"] = "receiver"
    state["auth_keys"] = {}
    state["disclosed_keys"] = {index: base64.b64encode(key).decode()}
    write(state)
    with pytest.raises(PersistenceError):
        HSM.import_encrypted(path)


def test_receiver_valid_sparse_disclosures_round_trip(store):
    hsm, path, state, write = store
    state["role"] = "receiver"
    state["disclosed_keys"] = {"1": state["auth_keys"]["1"], "3": state["auth_keys"]["3"]}
    state["auth_keys"] = {}
    write(state)
    restored = HSM.import_encrypted(path)
    assert restored.verify_mac(3, b"message", hsm.generate_mac(3, b"message"))
    assert restored.has_disclosed_key(1)
    assert not restored.has_disclosed_key(2)


@pytest.mark.parametrize("nested", [False, True])
def test_duplicate_json_fields_are_rejected_even_if_identical(store, nested):
    _, path, state, write = store
    raw = json.dumps(state)
    if nested:
        raw = raw.replace('"auth_keys": {', '"auth_keys": {"1": ' + json.dumps(state["auth_keys"]["1"]) + ', ')
    else:
        raw = '{"version": 1, ' + raw[1:]
    write(raw)
    with pytest.raises(PersistenceError):
        HSM.import_encrypted(path)


@pytest.mark.parametrize("value", [True, 1.0, float("nan"), float("inf"), -1, 0, "2"])
@pytest.mark.parametrize("field", ["current_interval", "disclosure_delay"])
def test_hsm_disclosure_rejects_non_integer_policy(field, value):
    hsm = HSM.create_satellite(2)
    args = {"current_interval": 2, "disclosure_delay": 1, field: value}
    with pytest.raises(HSMError):
        hsm.disclose_key(1, **args)


@pytest.mark.parametrize("value", [True, 1.0, float("nan"), 4097, "2", 0])
def test_chain_length_is_a_strict_bounded_integer(value):
    with pytest.raises(ValueError):
        HSM.create_satellite(value)


def test_constructor_checks_inconsistent_keys():
    hsm = HSM.create_satellite(2)
    with pytest.raises(ValueError):
        HSM(role="satellite", commitment=hsm.commitment, chain_length=2,
            auth_keys={1: b"x"*32, 2: b"y"*32})


def test_oversized_import_is_rejected(store):
    _, path, _, _ = store
    path.write_bytes(FILE_MAGIC + b"x" * (1_048_576 + 1))
    with pytest.raises(PersistenceError, match="large"):
        HSM.import_encrypted(path)


def test_atomic_export_preserves_old_file_on_replace_failure(store, monkeypatch):
    hsm, path, _, _ = store
    original = path.read_bytes()
    observed_modes = []
    def fail_replace(source, destination):
        observed_modes.append(stat.S_IMODE(os.stat(source).st_mode))
        assert path.read_bytes() == original
        raise OSError("simulated interrupted publication")
    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(PersistenceError):
        hsm.export_encrypted(path)
    assert path.read_bytes() == original
    assert observed_modes == [0o600]
    assert list(path.parent.iterdir()) == [path]


def test_successful_export_replaces_symlink_without_writing_its_target(store):
    hsm, path, _, _ = store
    target = path.parent / "unrelated"
    target.write_bytes(b"leave intact")
    path.unlink()
    path.symlink_to(target)
    hsm.export_encrypted(path)
    assert target.read_bytes() == b"leave intact"
    assert not path.is_symlink()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert HSM.import_encrypted(path).commitment == hsm.commitment
