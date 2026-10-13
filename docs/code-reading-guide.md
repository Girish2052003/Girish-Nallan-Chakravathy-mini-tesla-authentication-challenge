# Read the code in easy English

The comments beside the code explain what each meaningful step does and why it is there. Start with the story in `demo.py`, then follow the sender, receiver, and key operations. You do not need to learn all the testing and model-checking tools first.

This pass covers **41 existing files**: 15 Python files, 2 TLA+ models, 16 model configurations, 2 GitHub workflows, 4 package/dependency files, the sample environment file, and the Git ignore rules. The original challenge README and existing program statements remain unchanged. The dependency lock file explains repeated download-hash lines as groups; a closing bracket simply closes the group explained above it.

## Suggested reading order

1. **`demo.py`: the story.** Watch the real sender prove its identity, send messages, reveal keys later, and trigger rejection examples.
2. **`src/mini_tesla/protocol.py`: the message rules.** See what a packet contains, when the receiver may store it, and when it may trust it.
3. **`src/mini_tesla/hsm.py`: the key operations.** Follow key-chain creation, HMAC checks, delayed key release, and encrypted save/load.
4. **`src/mini_tesla/setup.py`: the first trust decision.** See why a signed setup needs an already trusted public key, a fresh challenge, and live trusted time.
5. **The tests:** see concrete examples of good inputs and attacks, with comments explaining each expected result.
6. **Verification and automation:** see what the finite models check and how GitHub reruns the evidence.

## Small Python vocabulary

| What you see | Read it this way |
| --- | --- |
| `# explanation` | A comment for people. Python skips it. |
| `"""description"""` | A documentation string, often describing a file, function, or class. |
| `import ...` | Make another file or library's tools available here. |
| `name = value` | Remember this value under this name. |
| `left == right` | Ask whether these values are equal. |
| `x is None` | Ask whether x is the special “no value” object. |
| `True`, `False` | Yes and no answers used by conditions. |
| `def name(...):` | Define a reusable group of steps called a function. |
| `return value` | Finish this function and give the value back to its caller. |
| `class Name:` | Define a kind of object that groups data and related operations. |
| `self` | This particular object, such as this receiver rather than another receiver. |
| `object.field` | Get one named part of an object. |
| `object.method(...)` | Run an operation belonging to that object. |
| `if ...`, `elif ...`, `else:` | Choose which indented steps run according to a condition. |
| `for item in collection:` | Repeat the indented steps for each item. |
| `while condition:` | Repeat while this condition stays true. |
| `and`, `or`, `not` | Require both; allow either; reverse a yes/no answer. |
| `try`, `except` | Try steps and handle a specified kind of failure. |
| `raise Error(...)` | Stop normal processing and report this failure to the caller. |
| `with ...:` | Use something temporarily, then run its cleanup/exit steps. |
| `assert condition` | Fail this check if the condition is false; tests use this to state expected results. |
| `@decorator` | Apply a helper to the function or class immediately below. |
| `name: int`, `-> bool` | Type hints: expected input/output kinds, not automatic runtime validation. |
| `b"text"` | Bytes: the exact data representation used by cryptographic operations here. |
| `"text"` | Human text; converting it to bytes needs an encoding such as UTF-8. |
| `[a, b]` | An ordered list. Index 0 is the first item. |
| `(a, b)` | A tuple: an ordered group whose entries cannot be replaced in place. |
| `{"name": value}` | A dictionary: values stored under lookup names called keys. These are not necessarily cryptographic keys. |
| `{a, b}` | A set: distinct values without a meaningful positional order. |
| `*args`, `**kwargs` | Collect or unpack positional arguments and named arguments. |
| `lambda: expression` | A tiny function that evaluates the expression when called. |
| `f"value={x}"` | Build text with x's value inserted at the marked place. |

Indented lines belong to the block above them. Parentheses allow one statement to span several physical lines. A comma separates entries; a closing `)`, `]`, or `}` ends a group rather than performing a new security operation.

## Security words used in the comments

| Word | Meaning in this project |
| --- | --- |
| Payload | The actual message bytes, such as telemetry. |
| Interval | A numbered time slot. The demo advances slots explicitly. |
| Sequence | A message number used with the interval to identify a logical message. |
| Hash | A fixed-size result calculated from data. Here SHA-256 links the keys. |
| Commitment | The trusted public anchor `K[0]` at the end of the key chain. |
| Key chain | Keys linked so `SHA256(K[i]) = K[i-1]`. Hashing a disclosed key reaches older indices; getting the next secret key requires reversing the hash. |
| HMAC/tag | A key-based check value covering the message and its encoded metadata. Once a key is public, anyone can make tags with it, so timing matters. |
| Disclosure | Making an interval key public after its waiting period. |
| Buffer | Temporary storage for packets awaiting their key; buffered does not mean authenticated. |
| Replay | Reusing an old packet or setup exchange as though it were new. |
| Digital signature | A private-key operation checked with its matching public key. The public key must already be trusted to establish identity. |
| Challenge | A fresh random request value the receiver requires inside the signed setup. It does not replace a trusted clock. |
| Nonce | A value used for an encryption operation. The save operation draws a random 12-byte nonce; randomness is not a proof that repeats are impossible. |
| AAD | Additional data checked by authenticated encryption but left unencrypted. The HSM file-format label uses this protection. |
| HSM | Here, a software object grouping key operations. Python private-name conventions do not provide hardware isolation. |
| Invariant | A condition expected to remain true throughout a modeled execution. |
| Counterexample | A sequence of allowed steps showing that a claimed condition fails. Some model configurations deliberately look for one. |
| Finite model | A simplified mathematical system explored within chosen bounds and assumptions, not a proof of all Python behavior. |

## Complete file map

All links below point to the actual annotated files. Configuration files control programs even though they are not Python, so they are included too.

| File | What its comments explain |
| --- | --- |
| [demo.py](../demo.py) | End-to-end setup, genuine messages, tampering, disclosure, and replay. |
| [src/mini_tesla/__init__.py](../src/mini_tesla/__init__.py) | The package's public import names and each exported component. |
| [src/mini_tesla/hsm.py](../src/mini_tesla/hsm.py) | Random keys, chain direction, role checks, HMAC, and encrypted persistence. |
| [src/mini_tesla/protocol.py](../src/mini_tesla/protocol.py) | Packet encoding, sender actions, trusted time, bounded buffering, and receiver decisions. |
| [src/mini_tesla/setup.py](../src/mini_tesla/setup.py) | Signed setup data, identity, fresh challenges, and live-time initialization. |
| [scripts/cleanup_merged_branch.py](../scripts/cleanup_merged_branch.py) | Checking a merged PR and deleting only its unchanged branch head. |
| [tests/test_protocol.py](../tests/test_protocol.py) | Original scenarios and their expected acceptance/rejection decisions. |
| [tests/test_receiver_hardening.py](../tests/test_receiver_hardening.py) | Bad types, extreme values, storage limits, candidate conflicts, and clock margins. |
| [tests/test_persistence_hardening.py](../tests/test_persistence_hardening.py) | Malformed saved state and safe handling of file-operation failures. |
| [tests/test_setup.py](../tests/test_setup.py) | Fake identities, copied challenges, signed-data tampering, and delayed setups. |
| [tests/test_branch_cleanup.py](../tests/test_branch_cleanup.py) | Branch-selection checks and a real Git race showing that new work survives. |
| [verification/check_invariants.py](../verification/check_invariants.py) | Finite timing grids and replay/forgery examples against Python. |
| [verification/check_bootstrap.py](../verification/check_bootstrap.py) | Finite combinations of signed setup and trusted receiver time. |
| [verification/model/MiniTesla.tla](../verification/model/MiniTesla.tla) | Symbolic protocol states, permitted steps, and safety conditions. |
| [verification/model/BootstrapTime.tla](../verification/model/BootstrapTime.tla) | Symbolic setup authentication combined with key-disclosure timing. |
| [verification/model/run_models.py](../verification/model/run_models.py) | Verified TLC tool hash and nine exact expected model outcomes. |
| [verification/model/run_bootstrap_models.py](../verification/model/run_bootstrap_models.py) | Seven exact expected setup-model outcomes. |
| [verification/model/sync_d1.cfg](../verification/model/sync_d1.cfg) | Synchronized clocks, one-slot disclosure delay. |
| [verification/model/sync_d2.cfg](../verification/model/sync_d2.cfg) | Synchronized clocks, two-slot disclosure delay. |
| [verification/model/lag_unsafe_d1.cfg](../verification/model/lag_unsafe_d1.cfg) | Intentionally inadequate time margin, exposing a forgery. |
| [verification/model/lag_bounded_d1.cfg](../verification/model/lag_bounded_d1.cfg) | Safe time margin with a one-slot delay and no useful admission window. |
| [verification/model/lag_bounded_d2.cfg](../verification/model/lag_bounded_d2.cfg) | Safe time margin with a two-slot delay. |
| [verification/model/delivery_guard_d1.cfg](../verification/model/delivery_guard_d1.cfg) | Deliberately unsafe reliance on local key delivery instead of the public deadline. |
| [verification/model/witness_honest.cfg](../verification/model/witness_honest.cfg) | A deliberate diagnostic failure showing genuine acceptance is reachable. |
| [verification/model/witness_honest_lag_d2.cfg](../verification/model/witness_honest_lag_d2.cfg) | Genuine acceptance remains reachable with a safe lag margin. |
| [verification/model/witness_replay.cfg](../verification/model/witness_replay.cfg) | A deliberate diagnostic failure showing replay suppression is reachable. |
| [verification/model/bootstrap_sync_d1.cfg](../verification/model/bootstrap_sync_d1.cfg) | Signed setup with synchronized live time. |
| [verification/model/bootstrap_lag_d2.cfg](../verification/model/bootstrap_lag_d2.cfg) | Signed setup with bounded clock lag. |
| [verification/model/bootstrap_stale_legacy.cfg](../verification/model/bootstrap_stale_legacy.cfg) | A delayed signed setup with intentionally stale receiver time. |
| [verification/model/bootstrap_unsafe_bound.cfg](../verification/model/bootstrap_unsafe_bound.cfg) | An intentionally underestimated clock bound. |
| [verification/model/bootstrap_broken_signature.cfg](../verification/model/bootstrap_broken_signature.cfg) | Signature checking deliberately disabled to reveal a fake anchor. |
| [verification/model/bootstrap_broken_challenge.cfg](../verification/model/bootstrap_broken_challenge.cfg) | Challenge checking deliberately disabled to reveal stale setup reuse. |
| [verification/model/bootstrap_honest_witness.cfg](../verification/model/bootstrap_honest_witness.cfg) | A deliberate diagnostic failure showing honest authentication is reachable. |
| [.github/workflows/tests.yml](../.github/workflows/tests.yml) | Three Python CI jobs and the finite-model checks. |
| [.github/workflows/cleanup-merged-branches.yml](../.github/workflows/cleanup-merged-branches.yml) | Merge event, permissions, trusted checkout, and guarded cleanup. |
| [pyproject.toml](../pyproject.toml) | Installation metadata, Python version, dependencies, and test discovery. |
| [requirements.txt](../requirements.txt) | Ordinary development dependency version ranges. |
| [requirements-ci.in](../requirements-ci.in) | Exact direct dependencies used to generate the CI lock file. |
| [requirements-ci.txt](../requirements-ci.txt) | Locked versions, approved download hashes, and dependency provenance. |
| [.env.example](../.env.example) | Placeholder master-key environment setting; no real secret. |
| [.gitignore](../.gitignore) | Generated files and local secret/runtime files that Git should ignore. |

For existing design detail, read [authenticated bootstrap](authenticated-bootstrap.md), [security assumptions](../SECURITY.md), and [verification scope](../VERIFICATION.md). Comments help explain the code; executed tests and model results remain the evidence for its checked behavior.
