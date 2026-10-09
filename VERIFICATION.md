# Verification argument and reproducible evidence

The evidence comprises implementation tests, finite input grids, a mathematical
safety argument under stated assumptions, and an independent finite TLA+ model.
There is **no machine-checked proof of the Python implementation**, no refinement
proof from Python to TLA+, and no proof of the cryptographic primitives.

## Invariants and implementation evidence

| ID | Property | Evidence |
| --- | --- | --- |
| V1 | Accepted K[i] hashes i times to trusted K[0] | HSM validation; invalid-key tests; import chain tests |
| V2 | Sender disclosure requires integer S >= i+d | HSM guard; early/NaN/type tests; 84 timing inputs |
| V3 | Admission requires i <= R and R+B < i+d | Receiver guard; 252 timing inputs; skew-bound attack regression |
| V4 | Acceptance follows key validation and successful HMAC verification | Positive/tampered-tag tests; invalid disclosure preserves batch |
| V5 | Each `(interval, sequence)` is accepted at most once within a session | Distinct-candidate tests; batch-local identity set; permanently closed interval |
| V6 | Public-key forgeries cannot be newly admitted under the time assumption | Real HMAC forgery traces; finite model negative controls |
| V7 | Metadata has an unambiguous, type/range-checked MAC representation | Invalid bool/float/NaN/overwide tests; maximum uint64; private snapshot |
| V8 | HSM import is authenticated and structurally/cryptographically valid | Wrong key, ciphertext corruption, authentic malformed-schema/chain tests |
| V9 | Unauthenticated receiver state is bounded and expires | Total/per-interval/candidate/byte limits; expiry and capacity reuse tests |
| V10 | Interrupted publication preserves the previous encrypted file | Injected replacement failure, temporary mode/cleanup, symlink test |
| V11 | Branch cleanup cannot delete a changed head using stale approval | Fresh metadata decision tests; real bare-Git concurrent-update lease test |

### Conditional source-authentication argument

Assume a trusted commitment and fixed delay d; correct key generation; no earlier
leak of interval keys; unforgeable HMAC before key release; and a trusted bound
S <= R+B at admission. The receiver admits only if R+B < i+d. By transitivity,
S < i+d, so K[i] was not public when the packet entered the buffer. Subsequent
key validation and a correct MAC then authenticate that previously buffered
message, subject to the cryptographic assumptions. Waiting until disclosure
without this admission inequality is insufficient.

This argument does not hold if the actual sender lead exceeds B. B=0 is the
synchronized logical-clock simulation default. A positive B supports bounded
lag conservatively; it does not establish the bound itself. With B >= d no
packet can satisfy both i <= R and R+B < i+d. Availability is not asserted.

### Replay and bounded-state argument

Candidates for each identity are limited; exact duplicates are rejected. During
batch verification the first valid candidate adds its identity to a batch-local
set, so no later candidate in that batch can be accepted again. Successful key
validation closes the interval before the batch is processed; monotonic time and
the stored key prevent any later admission for it. No lifetime per-message replay
set is needed. This argument assumes a single thread and an uninterrupted session;
HSM import alone cannot reconstruct endpoint/session state.

## Reproduce implementation checks

```bash
python -m pip install --require-hashes -r requirements-ci.txt
python -m pip install --no-deps --no-build-isolation -e .
pytest
python verification/check_invariants.py
python demo.py
```

CI runs these tests/checks on Python 3.11, 3.12, and 3.13. The finite Python checker
uses delays 1..3, key/packet intervals 1..4, receiver times 1..(5+delay), and
sender-ahead bounds 0..2. It performs 252 receive timing inputs, 84 sender
disclosure inputs, and six replay/forgery checks in three fixed traces: **342
cases/checks**. These are not 342 exhaustive protocol states. Keys are freshly
sampled, and trace interleavings, payload space, persistence, and concurrency
are not exhaustively explored. Pytest provides separate regressions for those
specified implementation cases.

## Independent finite TLA+ checking

See [model documentation](verification/model/README.md) for download, hash,
configuration, and execution instructions. The model uses two key intervals,
delays 1/2, two packet copies, capacity two, bounded clocks, idealized keys/MACs,
and arbitrary adversarial scheduling without fairness. The positive safety
properties are TypeOK, KeyValidation, SourceAuthentication, ArrivalWhileSecret,
CorrectAuthentication, NoEarlyAcceptance, and NoReplay.

| Configuration | Expected result | Distinct states in reference run |
| --- | --- | ---: |
| Synchronized, delay 1 | Complete; no violation | 5,688 |
| Synchronized, delay 2 | Complete; no violation | 22,186 |
| Lag 1, margin 0, delay 1 | SourceAuthentication counterexample | 1,031 before stopping |
| Lag 1, margin 1, delay 1 | Complete; no violation, empty admission window | 153 |
| Lag 1, margin 1, delay 2 | Complete; no violation | 18,856 |
| Delivery-only guard | SourceAuthentication counterexample | 398 before stopping |
| Honest-acceptance witness | Deliberately false NoHonestAcceptance fails | 476 before stopping |
| Replay-suppression witness | Deliberately false NoReplaySuppression fails | 1,892 before stopping |
| Lag-bound honest witness, delay 2 | Deliberately false NoHonestAcceptance fails | 1,764 before stopping |

The runner verifies the exact expected invariant and exit code, not merely that
TLC terminated. Negative controls expose broken assumptions/guards; witnesses
show that useful behaviors are reachable. They are intentionally expected
counterexamples, not unresolved failures of the intended positive configurations.
Finite exploration does not establish unbounded safety or liveness; TLC uses
fingerprints, with collision estimates in its output.

## Abstraction boundaries and trusted computing base

The model separates disclosure from per-packet verification, whereas Python
processes a batch. It derives lower keys from a disclosure while Python stores
only the supplied interval. Model honest/attacker identities are disjoint;
competing candidates with the same identity are checked in Python tests instead.
The finite model has no byte budget, expiry, serialization, file persistence,
Python object types, automation, or concurrent execution. Its symbolic-key
assumptions replace computational cryptographic analysis. Buffer bounds aid
finiteness; their exact Python policy values are not modeled.

The argument trusts Python, cryptography, SHA-256/HMAC/AES-GCM, CSPRNG entropy,
secure master-key provisioning, trusted time/commitment/session configuration,
and the relevant filesystem/Git/GitHub semantics. The CI lock file does not pin
all OS/runner/interpreter inputs. No crash-recovery protocol, full restart replay
protection, hardware isolation, network clock synchronization, or adversarial
availability guarantee is included. See `SECURITY.md` for operational constraints.
