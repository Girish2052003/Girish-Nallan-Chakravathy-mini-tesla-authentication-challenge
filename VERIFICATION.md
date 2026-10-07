# Verification argument

This file records the security invariants used to review the implementation and the evidence that checks them.

The project does **not** claim a mathematical proof of SHA-256, HMAC-SHA256, AES-256-GCM, Python, or the `cryptography` package. Those are trusted primitives/platform components. The protocol logic is checked with unit/adversarial tests plus a bounded exhaustive state exploration of the actual Python implementation.

## Security invariants

### V1 — One-way-chain commitment

For interval `i`, a disclosed key `K[i]` is accepted by the Receiver only if:

```text
SHA256 applied i times to K[i] == K[0]
```

where `K[0]` is the Receiver's trusted commitment.

Evidence: `HSM.validate_and_store_disclosed_key()`, invalid-key tests, and the bounded disclosure-state check.

### V2 — No early disclosure

The Satellite HSM may disclose interval key `K[i]` only when:

```text
current_interval >= i + disclosure_delay
```

Evidence: `HSM.disclose_key()`, early-disclosure unit tests, and bounded exploration for delays 1..3.

### V3 — Safe buffering condition

A packet for interval `i` is bufferable only when the Receiver is at or after that packet interval, but strictly before the key may be public:

```text
i <= receiver_interval < i + disclosure_delay
```

The left side rejects future-interval packets. The strict right side is the TESLA safety condition.

Evidence: `Receiver._validate_packet_shape()`, `Receiver.receive()`, timing tests, and exhaustive interval/delay exploration in `verification/check_invariants.py`.

### V4 — Authentication only after validated disclosure

A buffered packet can become accepted only inside `Receiver.process_disclosure()`, after the disclosed key has passed V1, and only if HMAC-SHA256 verification succeeds.

Evidence: implementation control flow plus valid/tampered message and tag tests.

### V5 — Replay uniqueness

A logical message identity `(interval, sequence)` cannot be accepted twice. Duplicate buffered identities and already accepted identities are rejected.

Evidence: `_reserved_ids`, `_accepted_ids`, replay tests, and bounded replay checks.

### V6 — Post-disclosure forgery rejection

Even an attacker who knows a legitimately disclosed key and computes a **correct HMAC** cannot inject a new packet for that expired interval, because the Receiver rejects the packet before MAC verification.

Evidence: the bounded checker explicitly constructs a valid HMAC using a disclosed key and confirms Receiver rejection.

### V7 — Deterministic authenticated representation

Security-relevant fields are encoded with fixed-width, network-byte-order integers and an explicit domain separator. The MAC covers protocol version, interval, sequence, disclosure delay, payload length, and payload.

Evidence: `AuthPacket.authenticated_bytes()` and metadata-mutation tests.

### V8 — Persistence confidentiality and integrity

Persisted HSM state is protected with AES-256-GCM using a 256-bit master key sourced from `MINITESLA_MASTER_KEY` and a fresh 96-bit nonce. Wrong-key and ciphertext-tampering attempts fail authentication.

Evidence: persistence tests and `HSM.export_encrypted()/import_encrypted()`.

## Bounded exhaustive verification

Run:

```bash
python verification/check_invariants.py
```

The checker exercises the real implementation over:

- disclosure delays 1, 2, and 3
- packet/key intervals 1 through 4
- receiver/current intervals spanning valid, future, early, exact-disclosure, and late states
- replay after successful authentication
- a post-disclosure forged packet carrying a cryptographically valid HMAC

The state exploration is intentionally small enough to understand and reproduce. It complements tests; it is not presented as an unbounded theorem proof.

## Trusted computing base

The verification argument assumes:

- Python behaves according to its language/runtime specification
- `secrets.token_bytes()` provides cryptographically secure randomness
- SHA-256 and HMAC-SHA256 behave as expected
- AES-GCM in `cryptography` provides authenticated encryption when used with unique nonces per key
- the environment variable containing the AES master key is provisioned securely

These assumptions are explicit so the security claim is not broader than the implementation evidence.
