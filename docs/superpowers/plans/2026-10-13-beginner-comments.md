# Beginner Code Comments Implementation Plan

> **For agentic workers:** Use the parallel-agent skill for disjoint annotation tasks; the coordinator verifies the complete change.

**Goal:** Let a reader with no Python knowledge explain every meaningful code step by reading nearby plain-English comments.

**Architecture:** Keep every executable statement, string, dependency version, workflow command, and model formula unchanged. Add comments explaining purpose, inputs, outputs, syntax, and security reasons beside the code.

**Tech Stack:** Python, pytest, TLA+/TLC, YAML, TOML, pip requirements.

**Spec:** Girish's request on 2026-10-13: identify all code files and explain every step, including tests, in ultra-easy English.

## Global Constraints

- Start from main commit `62f59c46ec6fbc09c3a5a5ac3d2c2d956bdb1507`.
- Add comments only to existing code/configuration; retain original docstrings too.
- Explain technical words where introduced. Use real behavior, including trust and availability limits.
- Cover all tracked Python, TLA+, TLC configuration, workflow and package/dependency configuration files, plus example environment and ignore rules.
- Leave the original challenge README intact. Provide a separate reading map.
- Reuse existing tests; a documentation-only change does not need new behavior tests.

## Review Focus

- No changed executable Python tokens or abstract syntax trees.
- No changed model formulas, configuration values, or shell commands.
- Comments do not overclaim HSM isolation, cryptographic proof, clock trust, nonce uniqueness, or flood resistance.
- Tests explain setup, attempted behavior, and expected result, including deliberate failures.
- Multi-line expressions and uncommon syntax remain understandable without generic filler.

## Tasks

- [x] Inventory all tracked code/configuration; run the existing baseline checks.
- [x] Annotate the HSM and protocol code, bootstrap code, tests, and formal models in disjoint file groups.
- [x] Annotate automation/configuration and create a complete file reading map.
- [x] Compare code tokens/AST and configuration/model semantics against the starting commit; review comment coverage and accuracy.
- [x] Run existing pytest and verification/model commands; obtain a fresh review.
- Publish the verified change through a PR, verify main CI, and retain main-only remote branch state. The associated PR and Actions records track this final publication step; this file records the pre-publication work.

## Verification commands

Run locally with the available Python 3.12 runtime and cached test dependencies,
using `PYTHONPATH=src` (plus the cached dependency path when needed). The existing
GitHub workflow supplies clean Python 3.11, 3.12, and 3.13 jobs:

- `python -m pytest`: all existing collected tests pass.
- `python verification/check_invariants.py`: all checks pass.
- `python verification/check_bootstrap.py`: all checks pass.
- `TLA2TOOLS_JAR=<existing verified jar> python verification/model/run_models.py`: every configured expected outcome matches.
- `TLA2TOOLS_JAR=<existing verified jar> python verification/model/run_bootstrap_models.py`: every configured expected outcome matches.
- `git diff --check`: no whitespace errors.

Comment-only Python token/AST comparison and parsing of YAML/TOML/model configuration provide the direct no-behavior-change evidence.

## Recorded progress

- All 41 existing code/configuration files are annotated; the reading map links every one.
- All 15 Python files retain identical non-comment tokens and abstract syntax trees, including every original string and docstring.
- Both TLA+ models and all 16 model configurations retain identical non-comment content.
- YAML/TOML values, embedded workflow commands, dependency hashes, environment values, and ignore patterns are unchanged.
- Every Python statement has an adjacent explanatory comment (syntax/docstring boundary lines are not separate operations).
- Local verification: 224 pytest cases, 342 protocol checks, 54 bootstrap cases, the executable demo, and all 16 expected TLC outcomes pass.
- Original README, security/verification documents, and bootstrap design document are unchanged.
- Fresh read-only review covered all 41 annotated files and both new documents: ready to merge within the annotation-review scope, with no outstanding actionable findings.
- Three review wording corrections were applied: random nonce draws do not guarantee uniqueness; network-operation timeout is not a total workflow deadline; finite models check properties under assumptions rather than proving those assumptions true in reality.
- The final local test rerun and executable-content comparisons pass after those corrections. GitHub publication and merged-main checks are recorded with the associated PR and Actions runs.
