# Approved audit repairs

Baseline: `2d961237332c5dea42bdf1e94543566f6f7ce7d8`. Authority: original
challenge README (preserve its first 5667 bytes), independent audit F01–F10,
and the user's instruction to complete all repairs, merge, and restore main-only.

1. Reproduce malformed packet admission, identity preclaim, unbounded state,
   and lagging-clock failures. Enforce exact integer wire domains, immutable
   public clock/policy, bounded distinct candidates, total/per-interval/byte
   caps, expiry, and a conservative sender-ahead bound. Verify red then green.
2. Reproduce malformed authenticated persistence and NaN disclosure bypasses.
   Validate complete state schemas and chain invariants, bound imports and
   chain size, normalize persistence errors, and replace files atomically
   using a restrictive temporary file. Verify red then green.
3. Replace the historical branch sweep with a merged-event-only cleanup that
   checks repository, PR, protected/default branch, current head and integrated
   merge commit, then deletes with an atomic expected-SHA lease. Test against
   a real bare Git remote, including a concurrent update. Pin CI actions and
   dependency versions/hashes. Preserve the challenge specification.
4. Describe the exact assurance boundaries; include the independent finite TLA+
   model and its expected negative controls. Run tests and the deterministic
   Python checker on Python 3.11, 3.12 and 3.13; run TLC. Obtain a fresh whole-
   branch review, repair material findings with regression tests, and run CI.
5. Merge the verified repair PR, verify the main commit and main-only branches,
   and deliver a closure report and reproducible evidence.

Interface decisions: HSM persistence remains HSM-only; it cannot restore sender
or receiver clocks, counters, buffers, or session replay state. A new process
must establish trusted current time and retain its public commitment/session
policy. Synchronization is a stated simulation assumption; a configured maximum
sender lead provides conservative admission when that bound is trustworthy.
Unbounded or unknown skew is unsupported. Resource limits can drop legitimate
traffic during a flood; they do not promise availability against an adversary.

Review focus: bool/float/NaN and overwide values; invalid encrypted but authentic
JSON; missing/duplicate/noncanonical fields; invalid chain links; duplicate
candidates around disclosure and expiry; skew-bound off-by-one errors; source
packet mutation; branch-name reuse and lease races; preservation of the README.
