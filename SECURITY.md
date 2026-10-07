# Security design notes

This repository is a technical-challenge implementation of a simplified TESLA-style protocol. It is not a production HSM, a complete TESLA implementation, or Galileo OSNMA.

## Threat model

The Receiver treats packet contents and disclosed keys as attacker-controlled input. An attacker may copy, modify, delay, duplicate, reorder, replay, or inject packets and may learn an authentication key after its legitimate disclosure time. The design must remain safe even after such a key becomes public.

The attacker is **not** assumed to break SHA-256 preimage resistance, forge HMAC-SHA256 without the key, defeat AES-256-GCM, read the process environment containing the persistence master key, or bypass the Python process boundary. A real hardware HSM would provide stronger isolation than this software model.

The most important adversarial case is post-disclosure forgery: once a TESLA key is public, an attacker can compute a correct HMAC for that expired interval. Therefore the Receiver must reject newly arriving packets for that interval **before** considering MAC validity.

## Trust and timing model

- The satellite generates a SHA-256 one-way chain K[0] ... K[n] where K[i-1] = SHA256(K[i]).
- K[0] is the trusted public commitment. Interval i authenticates messages with K[i].
- The receiver buffers a packet only while receiver_interval < packet_interval + disclosure_delay. This is the critical TESLA safety check: once a key could have been disclosed, a newly arriving packet using that key is no longer safe to buffer.
- A disclosed K[i] is validated by hashing it exactly i times and comparing the result to K[0] using a constant-time comparison.
- Only after successful key validation does the receiver verify buffered HMAC-SHA256 tags.

## HSM boundary

The HSM class deliberately exposes no public getter for undisclosed authentication keys. Satellite MAC creation happens inside the HSM object, and a key leaves it only via disclose_key, which enforces the configured disclosure delay. The receiver has a separate HSM instance initialized only with the chain commitment.

Python cannot provide hardware-backed isolation, so this class models key-protection semantics rather than claiming physical HSM security.

## Deterministic authenticated encoding

The MAC covers a domain separator plus fixed-width network-byte-order fields for protocol version, interval, sequence number, disclosure delay, payload length, and the payload itself. This prevents ambiguity from ad-hoc string concatenation and protects the metadata that drives receiver state.

## Replay handling

A logical packet identity is (interval, sequence). Duplicate buffered identities and identities that were already accepted are rejected. The challenge uses a bounded in-memory replay set; a long-running production design would need an expiry/window policy matching its key schedule and storage constraints.

## Persistence

HSM state is serialized internally and then encrypted and authenticated with AES-256-GCM using a fresh 96-bit nonce. The AES key is supplied through the MINITESLA_MASTER_KEY environment variable as base64-encoded 32-byte material. The file magic/version is authenticated as AES-GCM associated data.

The master key is never written into the repository or encrypted state file. The implementation also requests restrictive `0600` permissions for the encrypted file as a best-effort local hardening measure.

## Verification evidence

- `tests/test_protocol.py` covers positive flows, malformed inputs, tampering, invalid disclosure, replay, timing boundaries, HSM role separation, encrypted-state corruption, and persistence-key failures.
- `verification/check_invariants.py` performs bounded exhaustive state exploration against the real protocol classes.
- `VERIFICATION.md` states the invariants and trusted computing base explicitly.
- GitHub Actions runs both pytest and the bounded invariant checker across each supported Python version.

## Deliberate scope limits

- Logical intervals model time; there is no clock-synchronization protocol.
- There is no network transport, PKI, certificate handling, or remote provisioning.
- Receiver replay state is in memory unless the caller separately persists the receiver HSM state.
- This implementation does not attempt to reproduce the complete TESLA or Galileo OSNMA specifications.
