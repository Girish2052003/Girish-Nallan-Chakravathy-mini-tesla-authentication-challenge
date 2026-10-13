# Bootstrap is the first signed setup that establishes trust in a sender.
# This runner checks its small TLA+ state model with TLC, an explorer of all
# reachable states in the configured finite model. A deliberate counterexample
# is a passing control only when it violates the exact expected invariant (state rule).
# # starts a Python comment; the quoted line below is a stored documentation string.
"""Require expected outcomes for independent signed-bootstrap timing model."""
# Load Path for constructing and resolving file and directory names.
from pathlib import Path
# Reuse the model folder and audited tool digest; importing run_models does not run its main.
from run_models import BASE, JAR_SHA256
# Load SHA-256 to check that the Java tool bytes match the audited archive.
import hashlib
# Load JSON encoding for structured evidence records.
import json
# Load access to optional environment settings for file locations.
import os
# Load regular expressions, which find violation names in the checker's text output.
import re
# Load the helper that launches TLC in an external Java process.
import subprocess

# Pair each configuration filename stem with its required failing rule.
# None means full exploration must finish without violating any selected rule.
CASES = [
    # Synchronized live clocks with delay 1 must satisfy every configured safety rule.
    ("bootstrap_sync_d1", None),
    # One interval of lag, a matching margin, and delay 2 must also satisfy safety.
    ("bootstrap_lag_d2", None),
    # A stale clock fixed at 1 must expose acceptance of a forgery after key release.
    ("bootstrap_stale_legacy", "NoReleasedForgery"),
    # A margin smaller than actual clock lag must expose the same forgery condition.
    ("bootstrap_unsafe_bound", "NoReleasedForgery"),
    # Bypassing signature checks must permit an attacker-owned anchor to be installed.
    ("bootstrap_broken_signature", "AuthenticatedAnchor"),
    # Bypassing the fresh challenge check must permit an old signed setup to be reused.
    ("bootstrap_broken_challenge", "ChallengeFreshness"),
    # The deliberately false no-honest-acceptance rule must fail. Its witness shows
    # a genuine message can authenticate, not merely that all messages can be rejected.
    ("bootstrap_honest_witness", "NoHonestAuthentication"),
]

# Define the function that verifies the tool and checks all bootstrap configurations.
def main():
    # Take an optional TLA2TOOLS_JAR path or use the JAR beside this script; resolve it absolutely.
    # A JAR is a Java program archive containing the model checker.
    jar = Path(os.environ.get("TLA2TOOLS_JAR", BASE / "tla2tools.jar")).resolve()
    # Hash the actual archive bytes and compare the hexadecimal digest with the fixed audited value.
    if hashlib.sha256(jar.read_bytes()).hexdigest() != JAR_SHA256:
        # Stop if the tool differs; an untrusted or missing tool is not an expected model counterexample.
        raise RuntimeError("TLC JAR hash mismatch")
    # Choose TLA_RESULTS_DIR if provided, otherwise the model folder's results subdirectory.
    directory = Path(os.environ.get("TLA_RESULTS_DIR", BASE / "results")).resolve()
    # Create missing result folders; exist_ok allows the directory to already be present.
    directory.mkdir(parents=True, exist_ok=True)
    # Start an empty list of completed, checked model results.
    evidence = []
    # Loop over each configuration name and the violation expected for that case.
    for name, expected in CASES:
        # Build a Java argument list using parallel memory cleanup, a 1 GiB heap limit,
        # and the verified archive on the class path (where Java finds program classes).
        cmd = ["java", "-XX:+UseParallelGC", "-Xmx1g", "-cp", str(jar),
               # Launch TLC with one worker, seed 1, and fingerprint choice 0. These settings
               # make exploration repeatable; fingerprints are compact identifiers for visited states.
               "tlc2.TLC", "-workers", "1", "-seed", "1", "-fp", "0",
               # Give each configuration a separate location for TLC's temporary state files.
               "-metadir", str(directory / "states" / name),
               # Select this case's constants and rules from its .cfg file and the BootstrapTime model.
               "-config", name + ".cfg", "BootstrapTime.tla"]
        # Run from the model directory and collect both text streams; a 60-second timeout
        # raises an error rather than being accepted as a successful finite exploration.
        run = subprocess.run(cmd, cwd=BASE, capture_output=True, text=True, timeout=60)
        # Combine normal and error text so the log and outcome checks see both.
        out = run.stdout + run.stderr
        # Write the raw output to this case's log, replacing a previous log with the same name.
        (directory / (name + ".log")).write_text(out)
        # Capture every invariant name in TLC's violation messages. r preserves the
        # backslashes, \w+ captures a word, and \. matches the final literal period.
        errors = re.findall(r"Error: Invariant (\w+) is violated\.", out)
        # Require exit 12 for the expected rule failure, or exit 0 for a safe complete run.
        # An invariant violation here can be intentional; another error code is a runner failure.
        if (run.returncode != (12 if expected else 0)
            # Require exactly the one expected rule name, or an empty list for a safe case.
            or errors != ([expected] if expected else [])
            # Also require the explicit no-error completion text when no violation is expected.
            or (expected is None and "No error has been found" not in out)):
            # Fail with the case name and final 3500 output characters if any required outcome differs.
            raise RuntimeError(f"Unexpected model result for {name}:\\n{out[-3500:]}")
        # Split output into lines and keep those containing any selected summary marker.
        # This list expression gathers only the useful report lines without changing the raw log.
        summary = [line for line in out.splitlines() if any(k in line for k in
                   # Retain state counts, search depth, and error lines.
                   ("states generated", "distinct states", "depth of", "Error:",
                    # Retain successful completion, elapsed-time, and model-checker version lines too.
                    "No error has been found", "Finished in", "TLC2 Version"))]
        # Create a dictionary recording the configuration and actual process exit code.
        row = {"configuration": name, "exit_code": run.returncode,
               # Add the expected violation, selected summary text, and command needed to reproduce the run.
               "expected_violation": expected, "summary": summary, "command": cmd}
        # Keep the checked record in the final evidence list.
        evidence.append(row)
        # Print this record as JSON; flush emits it immediately for progress monitoring.
        print(json.dumps(row), flush=True)
    # Write a combined report only after every configuration matched its expected result.
    (directory / "bootstrap_model_results.json").write_text(
        # Include the verified tool digest and all case records, using two-space JSON indentation.
        json.dumps({"jar_sha256": JAR_SHA256, "models": evidence}, indent=2)
    )

# Run checks when this file is executed directly, but not when imported by another module.
if __name__ == "__main__":
    # Invoke the function that runs and reports the full bootstrap suite.
    main()
