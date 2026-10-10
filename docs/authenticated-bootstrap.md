# Authenticated TESLA bootstrap: what the digital signature actually solves

## The flaw and the goal

A SHA-256 TESLA chain has K[i-1] = SHA256(K[i]), with public commitment K[0].
A disclosed interval key can be checked against K[0], but that mathematical
check does not identify who originally selected K[0]. Without authenticated
provisioning, Eve can create her own valid chain and replace Alice's K[0].

The additional goal is **source authentication of the commitment** before
the receiver uses it. This is a separate security layer, not a change to TESLA
message HMACs or delayed disclosure.

## Two different kinds of key

- **TESLA K[i]:** secret *symmetric* interval authentication key; HMAC-SHA256
  uses it until it is intentionally disclosed after a time delay.
- **Ed25519 identity signing key:** long-term *asymmetric* private key; the
  real satellite keeps it secret and uses it to sign initial setup.
- **Ed25519 identity verification key:** corresponding public key; the
  receiver must obtain and pin the genuine value from trusted configuration.

Signing uses the secret **identity private key**. Verification uses the
pretrusted **identity public key**. Revealing the public key is safe, but an
attacker replacing the pinned value destroys sender authentication.

## Exact six-step handshake

1. Trusted receiver configuration specifies `expected_satellite_id` and
   `trusted_public_key`. This initial trust MUST happen independently of
   the untrusted setup channel. Identity keys must be protected and rotated
   through a separately authenticated provisioning procedure.
2. Receiver creates a 32-byte CSPRNG challenge N. It sends N to the satellite;
   N is public, unpredictable *before* generation, and different each run.
3. Satellite generates its TESLA key chain and commitment K[0]. It constructs
   the setup bytes shown below, containing N, satellite ID, K[0], chain length,
   disclosure delay, and version.
4. Satellite computes signature = Ed25519.Sign(identity_private, setup_bytes).
   It returns the public setup fields plus the 64-byte signature.
5. Receiver strictly encodes the received fields, checks identity and equality
   with its still-pending N, then checks
   Ed25519.Verify(pinned_public, setup_bytes, signature). On **any** failure,
   it does not instantiate a receiver from the untrusted commitment.
6. On successful verification, it creates `Receiver` using the verified K[0]
   and parameters and consumes the bootstrap challenge. Normal delayed HMAC
   operation continues unchanged.

## What exactly gets signed?

Canonical signed bytes are:

```text
ASCII("MINI-TESLA-SATELLITE-SETUP-ED25519\\0")
|| version                  : 1 byte (1)
|| length(satellite_id)     : 1 byte
|| satellite_id             : 1..64 restricted ASCII bytes
|| receiver_challenge       : 32 bytes
|| TESLA commitment K[0]    : 32 bytes
|| chain_length             : 4 bytes, big endian
|| disclosure_delay         : 4 bytes, big endian
```

The setup signature covers the **entire** byte sequence, with a unique domain
label to prevent accidentally treating signatures for another protocol as valid
here. Types, bounds, field lengths, and expected version are checked before
signature verification. The raw signature is not signed recursively.

No independent network identity, algorithm identifier, untrusted public key, or
certificate is allowed to override the receiver's trusted configuration.

## Three attacks that now fail

**Commitment substitution:** Eve constructs her own valid TESLA chain with K0'
and even her own Ed25519 key pair. Her valid signature verifies under Eve's
public key, *not* under Alice's pinned key. Receiver rejects before using K0'.

**Session replay:** Eve records an old genuine setup and signature. When a new
receiver instance creates fresh nonce N2, the old signature was for N1, so
the challenge check fails. A successfully established ReceiverBootstrap also
rejects any second `establish` call. Reusing an old challenge across restarts
would undo the freshness argument: use secure fresh challenges.

**Parameter tampering:** Eve changes chain length, delay, identity, version, or
commitment. Encoding yields different bytes, so the original Ed25519 signature
does not verify. Changing to a different satellite identity is explicitly
rejected even if its own key would have been valid elsewhere.

## Why a fresh challenge instead of a timestamp?

Timestamp-only freshness would need a trusted clock and replay window. TESLA
already relies on a separate timing bound. A new random receiver challenge
provides setup-level freshness without adding another clock assumption.
It is not secret; unpredictability and non-reuse matter.

## Important limits, and why the API has two construction paths

`ReceiverBootstrap(...).establish(signed)` is the recommended path for any
untrusted transport. `Receiver(commitment=..., ...)` remains for the original
self-contained challenge and for callers whose commitment is **already
authenticated elsewhere**. Callers must not route untrusted commitments into
that lower-level constructor.

The demonstration pins a freshly generated identity public key directly in
the same program. This demonstrates the verification mechanism, not a real
out-of-band PKI. For deployment, securely provision and persist the pinned key,
protect the signing private key (ideally with a hardware security mechanism),
authenticate session lifecycle/clock origin, plan key rotation/revocation, and
provide secure recovery. Neither hardware isolation nor clock synchronization
is provided by this module. A relay attacker can still forward genuine signed
setups; a signature authenticates their source, not their physical proximity.

The signature key is **not** a TESLA interval key and is NEVER disclosed after
an interval. That difference is fundamental.

## Review/reproduce

Run `python demo.py`, `pytest`, and
`python verification/check_invariants.py`. Audit signing and verification in
`src/mini_tesla/setup.py`, negative tests in `tests/test_setup.py`, and
the separate TESLA state machine in `src/mini_tesla/protocol.py`.
The original TLA+ model assumes trusted K[0] and has not been extended to model
this Ed25519 bootstrap; it is not a machine-checked proof of the signature layer.
