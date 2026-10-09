# Independent finite-state Mini-TESLA model

This audit model was constructed separately from `verification/check_invariants.py`.
It is a finite symbolic protocol model, not a translation or formal refinement of
the Python implementation. It was integrated with the audit repairs as an independently specified protocol abstraction.

## Tool provenance and reproduction

- Official release: https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4
- Download: https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
- TLC banner: `TLC2 Version 2.19 of 08 August 2024 (rev: 5a47802)`.
- Published and observed JAR SHA-1: `bee4a54f3ee3d4afc347c3240ec2d9e93b075104`.
- Observed SHA-256: `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
- Runtime: OpenJDK 17.0.20, one TLC worker, seed 1, fingerprint polynomial 0.

Download the official JAR to this directory (it is ignored by Git), then run
`python3 verification/model/run_models.py` from the repository root. Alternatively,
set `TLA2TOOLS_JAR` to its path. The runner checks the SHA-256 before execution
and records logs and commands in `verification/model/results/` (or
`TLA_RESULTS_DIR`). CI downloads and hash-checks this exact tool automatically.
The runner requires the exact expected invariant violation for each negative
control or witness; an unrelated failure does not count as success.
Exit 12 is expected for attack counterexamples and deliberately false witness
invariants. Exit 0 means completion without a violation in that finite graph.
Logs are the final execution of the delivered model. TLC fingerprint collision
estimates are retained in each log; finite model checking is not an unbounded proof.

## Model and assumptions

The configuration uses two key intervals, delays 1 or 2, two packet copies, and
buffer capacity two. Time runs from 0 through N+Delay. Events include sender
advance, receiver catch-up, genuine send, adversarial arrival, disclosure delivery,
and verification. The attacker may indefinitely withhold delivery of keys that
are already public. Genuine, invalid-tag, and valid-tag forged packets differ.
The latter become available only after their interval key is public.

Keys are symbolic indices. Learning key i permits deriving lower-index keys.
Anchor validation uses symbolic equality. This assumes ideal one-wayness,
collision separation, valid-key linkage, and unforgeable pre-disclosure MACs;
it does not establish those properties computationally. No AES-GCM, persistence,
Python types, integer overflow, file system, concurrency, or availability model
is included. There is no fairness or eventual-delivery guarantee.

`Lag` is a bound on how far the receiver can trail sender time. `Bound` is the
trusted margin used in admission. `GuardMode="delivery"` deliberately disables
deadline protection as a negative control. It is not the actual Python behavior.

## Final results

| Configuration | Distinct states | Result |
| --- | ---: | --- |
| sync_d1 | 5,688 | Safety invariants hold, complete exploration |
| sync_d2 | 22,186 | Safety invariants hold, complete exploration |
| lag_unsafe_d1 | 1,031 before stopping | Forged packet accepted; SourceAuthentication fails |
| lag_bounded_d1 | 153 | Safety holds but admission window is empty; no availability claim |
| lag_bounded_d2 | 18,856 | Safety holds; separate witness confirms genuine acceptance is reachable |
| delivery_guard_d1 | 398 before stopping | Forgery accepted when public disclosure is withheld locally |
| witness_honest | 476 before stopping | Genuine acceptance is reachable; false diagnostic invariant fails |
| witness_replay | 1,892 before stopping | Buffered duplicate is suppressed; false diagnostic invariant fails |
| witness_honest_lag_d2 | 1,764 before stopping | Genuine acceptance remains reachable with the lag margin and delay 2 |

The positive configurations check TypeOK, KeyValidation, SourceAuthentication,
ArrivalWhileSecret, CorrectAuthentication, NoEarlyAcceptance and NoReplay.
The three witness configurations deliberately falsify an additional diagnostic
predicate; these are successful non-vacuity checks, not defects in the intended
safety rules. The two attack configurations stop at the first counterexample,
so their counts are partial traversals, not full reachable-state counts.

## Connection to Python, and limits

Manual correspondences are `Receive` to `Receiver.receive`, `DeliverKey` to
key validation within `process_disclosure`, `Verify` to MAC acceptance, and
the monotonic clock actions to `advance`. The Python code actually combines
key validation and batch verification; the model separates them. The root audit
reproduced the lagging-receiver forgery using the real Python implementation.

The model permits multiple buffered copies. Repaired Python permits bounded
distinct candidates per identity; exact duplicate candidates are rejected. Model
honest and attacker identities are distinct, so same-identity candidate attacks
are covered by Python regressions, not by this model. Python now has packet,
byte, per-interval, and candidate limits plus expiry; the model has only a finite
packet capacity and no expiry. On disclosure the model
derives lower keys, whereas Python stores only the supplied interval. These are
explicit abstraction differences. The model does not prove Python refines it.

The run script's expected outcomes also serve as a check that every configuration
actually changes the intended model behavior. No claim of formal verification of
the submitted Python program or of its cryptographic primitives follows.
