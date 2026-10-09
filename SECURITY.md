# Security design notes

This is a single-process, single-threaded technical-challenge simulation of
Mini-TESLA. It is not a physical HSM, complete TESLA, or Galileo OSNMA.

## Threat and trust model

Packets and disclosed keys are untrusted. An attacker may modify, inject, copy,
reorder, replay, delay, or drop them, and may compute valid tags once a key becomes
public. Trusted inputs are the public chain commitment, session configuration,
and time bound. SHA-256 preimage/collision resistance, HMAC-SHA256 unforgeability
before disclosure, AES-GCM integrity/confidentiality, CSPRNG output, the Python
runtime, and the cryptography package are assumptions. The attacker cannot read
or modify process memory, the master-key environment, or private Python fields.
Python private attributes model an HSM boundary; they do not enforce isolation.

## Time is a security precondition

The sender's logical clock and the receiver's logical clock must be advanced by
a trusted host. Let S be sender time, R receiver time, B the configured
`max_sender_ahead`, i the packet interval, and d the disclosure delay. The host
must ensure **S <= R + B at every receive**. Default B=0 assumes synchronized
logical intervals (or a receiver clock that does not trail the sender).

Admission requires `i <= R` and **`R + B < i + d`**, as well as an undisclosed
interval, valid metadata, and available capacity. Hence S < i+d at admission:
the key must still be secret. A cached-key check alone is insufficient because
an attacker can suppress local delivery of a key that is already public.
A receiver that lags beyond B can accept a known-key forgery. This project does
not discover or enforce synchronization over a network; an unknown skew bound
is unsupported. B >= d makes the admission window empty. Clock/policy properties
are read-only and `advance()` accepts strictly positive integer steps.

The sender releases K[i] only at S >= i+d. The receiver waits until R >= i+d
before processing its disclosure; with lag this can delay authentication further.
Do not reuse a chain with a restarted clock or sender sequence counter. A fresh
session needs a fresh commitment, or a separately designed trusted recovery
mechanism. That mechanism is outside this challenge.

## Key and packet validation

K[i-1] = SHA256(K[i]); the commitment is K[0]. Disclosed K[i] must hash i times
to the commitment before any candidate batch is removed. Comparisons of chain
values use constant-time comparison. The HSM holds no more than 4096 interval
keys; receiver caches contain only validated keys within that chain.

The MAC covers a domain separator and fixed-width network-order version uint8,
interval uint32, sequence uint64, delay uint32, payload length uint32, and payload.
Integers must be exact Python integers, excluding bools, floats, NaN, and numeric
strings. Intervals, sequences, and delays must be positive; packets must use the
supported version and configured delay. Payloads are bytes, at most 1 MiB, and
tags are exactly 32 bytes. Validation and serialization finish before state
mutation. The receiver stores a private packet snapshot and canonical bytes,
so a later change to the caller's packet cannot corrupt batch processing.

## Bounded candidates and replay handling

Unauthenticated identity claims are not treated as proof. An exact duplicate
candidate is rejected, but distinct candidates for `(interval, sequence)` may
coexist until verification. A bad first candidate therefore does not necessarily
exclude a later genuine packet. Only the first valid candidate for an identity
is accepted in its batch. Validating the interval key permanently closes that
interval to new arrivals; a batch-local accepted-identity set is then discarded.
There is no unbounded database of accepted message IDs.

Receiver defaults, configurable at construction:

| Policy | Default |
| --- | ---: |
| `max_buffered_packets` | 1024 |
| `max_packets_per_interval` | 256 |
| `max_candidates_per_identity` | 4 |
| `max_buffered_bytes` | 8,388,608 |
| `disclosure_grace` | 8 local intervals |
| `max_sender_ahead` | 0 |

The byte budget counts canonical authenticated bytes plus tags, not total Python
heap usage. Payload snapshots, encoded copies, and object overhead also use
memory; the packet cap bounds their number. On `advance()`, interval i expires
when R >= i+d+grace, releasing its candidates even if disclosure never arrives.
Late packets still fail the deadline check. A valid late disclosure may be cached
but cannot recover expired messages. Invalid disclosures leave unexpired batches
intact. Accepted packets and returned results become the caller's responsibility.

Flooding can fill any cap, including all candidate slots for a genuine identity.
Expiry can discard genuine messages during prolonged loss. These are explicit
bounded-memory tradeoffs, not availability or denial-of-service prevention claims.

## Encrypted HSM persistence

AES-256-GCM encrypts the HSM key store with a fresh random 96-bit nonce, using
file magic/version as associated data. `MINITESLA_MASTER_KEY` must hold a base64
32-byte AES key; it is never included in the output. Provision it securely.
Nonce collisions are probabilistic; this is not a nonce-management service.

Import reads at most 1 MiB plus one overflow-detection byte. It rejects unknown,
missing, or duplicate JSON fields, noncanonical/out-of-range indices, invalid
roles/types/key lengths, incomplete or inconsistent satellite chains, receiver
secret-key material, and disclosed keys that do not match the commitment. An
AEAD-valid file from a faulty writer must still pass these invariants. Rejection
uses `PersistenceError`. Encryption alone does not prevent rollback to an old,
valid state or compromise by someone holding the master key.

Export creates a temporary file in the destination directory with POSIX mode
0600 before writing, flushes and fsyncs it, then atomically replaces the target.
A failed replacement preserves the old file; the temporary file is cleaned up.
Replacing a target symlink does not write through it. This assumes ordinary local
filesystem semantics and a trusted containing directory. Windows ACLs and
power-loss durability of directory metadata are not guaranteed.

**This API saves only the HSM.** It does not save or restore endpoint clocks,
sequence counters, buffers, admission policy, or complete session replay state.
Restoring an HSM is not a protocol-session restart procedure.

## Verification and automation

`tests/` exercises the implementation, file failures, and real Git lease races.
`verification/check_invariants.py` runs two finite input grids and three fixed
adversarial traces. It is not exhaustive protocol-state exploration.
`verification/model/` contains a separate finite TLA+ model, positive checks,
attack counterexamples, and non-vacuity witnesses. No refinement proof connects
that abstraction to all Python executions. See `VERIFICATION.md` for exact limits.

CI exercises Python 3.11, 3.12, and 3.13; the package's `>=3.11` metadata is broader
than this tested matrix. CI dependencies have exact versions and SHA-256 hashes,
and actions have full commit pins. Runner images, Python patch releases, installer
and OS components remain platform dependencies, not hermetically locked inputs.

Branch cleanup runs only on a same-repository merged-PR event into main. It checks
fresh PR metadata, default/protected-branch guards, the exact unchanged head, and
integration of the merge commit. Deletion uses Git's atomic expected-SHA lease.
It never scans historical PRs to delete branches by reused names.
