# Verification argument and reproducible evidence

The evidence comprises implementation tests, finite input grids, a mathematical
safety argument under stated assumptions, and an independent finite TLA+ model.
There is **no machine-checked proof of the Python implementation**, no refinement
proof from Python to TLA+, and no proof of the cryptographic primitives.

## Signed-bootstrap assurance boundary

The new `setup.py` implementation adds an Ed25519 signature over a
domain-separated, canonical encoding of setup version, satellite identity,
fresh receiver challenge, K[0], chain length, and disclosure delay.
`ReceiverBootstrap.establish` checks pinned identity/public key, challenge,
field validity, and signature **before** constructing a receiver. Upon success
the receiver challenge is single-use. `tests/test_setup.py` covers a genuine
setup, substituted chain with attacker-owned signing key, tampered signed
metadata, malformed fields, stale signed bootstrap replay, wrong pinned public
key, same-challenge reuse, and a real delayed-authentication exchange.

**Conditional argument:** An accepted challenge-bound setup for pinned identity
must have a valid Ed25519 signature on the exact setup bytes. An adversary
without its signing private key cannot produce that signature for a substituted
commitment or fresh challenge, assuming Ed25519 existential unforgeability,
authentic initial public-key pinning, unpredictable challenge generation, and
trusted host execution. Replay of an old response fails because the new challenge
differs, absent an astronomically unlikely nonce collision. This reasoning does
not prove Ed25519, the Python code, or universal deployment security.

The original independent `MiniTesla.tla` checks symbolic TESLA safety.
The new independent `BootstrapTime.tla` composes symbolic signature/challenge
verification, adversarially delayed setup, live versus stale receiver clocks,
honest TESLA buffering and post-disclosure MAC forgeries. Its negative controls
reproduce the old delayed-setup attack and violations caused by invalid
signature, challenge and clock-bound assumptions. These models are finite,
idealized checks, not a machine-checked proof of Python or Ed25519.

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
| V12 | Challenge-bound Ed25519 verification and pinned sender identity precede K[0] acceptance | Signature/tamper/nonce regressions; symbolic bootstrap negative controls |
| V13 | Genuinely signed setup must be installed while K[1] is guaranteed secret | Establishment gate R+B<1+d; delayed setup attack regression; `bootstrap_stale_legacy` counterexample |
| V14 | Signed receiver checks monotonic trusted interval for each admission/disclosure | Receiver clock refresh, invalid/rollback/forgery tests; 54-case timing grid; symbolic live-time model |

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
python verification/check_bootstrap.py
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

## Signed setup timing proof obligation and new finite model

Let S be the actual satellite interval, R the trusted receiver interval,
B the independently justified maximum sender lead, i the claimed packet
interval, and d the signed disclosure delay.

Assume S <= R+B continuously, including at bootstrap and at each packet
admission; uncompromised Ed25519 keys and correct pre-provisioned public
identity key; fresh challenges; cryptographic resistance of SHA-256/HMAC;
one new, not-previously-used satellite chain per signed bootstrap; and a
monotonic, session-relative trusted receiver clock.

At bootstrap, enforce R+B < 1+d. Since S <= R+B, this implies S < 1+d:
K[1] is not public when receiver installs the signed K[0]. This rejects
the specific valid-signature/late-delivery attack even though signature
verification itself correctly succeeds.

Later, admit packet i only if R+B < i+d. Then S < i+d at admission,
so K[i] cannot be publicly disclosed yet. A forgery computed *from the
disclosed key* cannot enter the trusted receiver buffer after disclosure.
The receiver refreshes R before admission; restarting at R=1 after
a delayed setup violates the premise. If B underestimates actual lead,
or R is attacker-controlled or frozen, neither result follows.

The independent finite module `BootstrapTime.tla` models both bootstrap
and TESLA delayed-message admission. Pinned signatures/challenges are
symbolic idealizations; it includes genuine and attacker-controlled
setups, replay attempts, adversarial delivery delays, trustworthy
clock/live receiver checks, key-release-driven forgeries, and honest
message buffering/disclosure. CI runs two passing safety cases
(synchronous delay 1 and lag 1/bound 1/delay 2) and five
*expected* counterexamples/nonvacuity checks:

| Model configuration | Expected result |
| --- | --- |
| bootstrap_sync_d1 | Safety holds; 23 distinct states |
| bootstrap_lag_d2 | Safety holds; 52 distinct states |
| bootstrap_stale_legacy | NoReleasedForgery violation, old delayed relay |
| bootstrap_unsafe_bound | NoReleasedForgery violation with B < actual lag |
| bootstrap_broken_signature | AuthenticatedAnchor violation |
| bootstrap_broken_challenge | ChallengeFreshness violation |
| bootstrap_honest_witness | NoHonestAuthentication deliberately fails, genuine acceptance is reachable |

The new Python checker exhausts a **finite grid of 54 time-parameter
combinations**, with 10 safe admissible and 44 rejected. Pytest covers
real Ed25519 signatures, malformed values, late signed setups and the
live post-disclosure HMAC attack; the previous tests, finite TESLA grids
and original model run unchanged. These are **not** universal or
computational proofs, no Python-to-TLA+ refinement has been established,
and clock provisioning/synchronization remains out of scope.

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
