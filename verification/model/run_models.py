# TLA+ describes possible protocol states and steps; TLC is the program that
# explores their finite graph. An invariant is a rule checked in every reached state.
# Some cases deliberately break a rule to show that TLC can detect the intended
# attack or reach a useful event. Only that exact expected violation is a passing case.
# A # line is a Python comment; the quoted line below is a kept documentation string.
"""Run the pinned independent TLA+ model and require exact control outcomes."""
# Import Path for building filesystem paths without hand-written separators.
from pathlib import Path
# Import SHA-256 to compare the model checker's bytes with a fixed trusted digest.
import hashlib
# Import JSON output support so both people and programs can read the result records.
import json
# Import environment access for optional tool and results locations.
import os
# Import regular expressions, text patterns used to extract violated rule names.
import re
# Import process launching to run the external Java model checker.
import subprocess

# __file__ is this script's path; resolve makes it absolute and parent selects its folder.
BASE = Path(__file__).resolve().parent
# Pin the exact audited JAR bytes. A JAR is a Java program archive; the digest
# checks tool identity, not whether the model or cryptography is correct.
JAR_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
# Each tuple pairs a .cfg filename stem with the required violated invariant.
# None means no violation is expected; a named violation must match exactly.
CASES = [
    # With synchronized clocks and delays 1 or 2, every selected safety rule must hold.
    ("sync_d1", None), ("sync_d2", None),
    # An understated sender-ahead margin must expose a forged acceptance.
    ("lag_unsafe_d1", "SourceAuthentication"),
    # A sufficient margin must preserve safety at both delays; delay 1 can admit nothing.
    ("lag_bounded_d1", None), ("lag_bounded_d2", None),
    # Waiting for local key delivery instead of its public deadline must expose a forgery.
    ("delivery_guard_d1", "SourceAuthentication"),
    # Break the deliberately false claim that no genuine packet can ever authenticate.
    # This witness (a concrete reachable example) shows safety is not just rejecting everything.
    ("witness_honest", "NoHonestAcceptance"),
    # Break the false claim that replay is never suppressed, showing duplicate handling is reachable.
    ("witness_replay", "NoReplaySuppression"),
    # Require a genuine-acceptance witness even with one interval of lag and delay 2.
    ("witness_honest_lag_d2", "NoHonestAcceptance"),
]


# Define the function that checks the tool and runs each configured model case.
def main():
    # Use TLA2TOOLS_JAR when provided; otherwise look beside this script. Resolve the
    # chosen file to an absolute path so changing the child process directory cannot alter it.
    jar = Path(os.environ.get("TLA2TOOLS_JAR", BASE / "tla2tools.jar")).resolve()
    # Read the full JAR, hash its bytes, and compare its hexadecimal digest with the pinned value.
    if hashlib.sha256(jar.read_bytes()).hexdigest() != JAR_SHA256:
        # Stop before running an unexpected tool; this is a runner failure, never an expected counterexample.
        raise RuntimeError("TLC JAR hash does not match the audited tool")
    # Use TLA_RESULTS_DIR when set, or the model folder's results directory otherwise.
    output_dir = Path(os.environ.get("TLA_RESULTS_DIR", BASE / "results")).resolve()
    # Create the results directory and any missing parents; accept an already existing directory.
    output_dir.mkdir(parents=True, exist_ok=True)
    # Start the list of checked case records for the final JSON report.
    rows = []
    # Repeat for every configured case, unpacking its filename and expected violation.
    for config, expected_violation in CASES:
        # Build Java's argument list: use parallel garbage collection for memory cleanup,
        # cap the Java heap at 1 GiB, and load TLC from the verified JAR using -cp (class path).
        command = ["java", "-XX:+UseParallelGC", "-Xmx1g", "-cp", str(jar), "tlc2.TLC",
                   # Use one worker, random seed 1, and fingerprint choice 0 for repeatable exploration.
                   # A fingerprint is a compact state identifier; -metadir names temporary state storage.
                   "-workers", "1", "-seed", "1", "-fp", "0", "-metadir",
                   # Keep each case's states separate and select its configuration and MiniTesla model file.
                   str(output_dir / "states" / config), "-config", config + ".cfg", "MiniTesla.tla"]
        # Run in the model folder, capture both output streams as text, and allow at most
        # 60 seconds per case. A timeout raises an error instead of counting as success.
        run = subprocess.run(command, cwd=BASE, capture_output=True, text=True, timeout=60)
        # Join normal output and error output so checks and logs include both streams.
        output = run.stdout + run.stderr
        # Save this case's raw checker output, replacing an older log with the same name.
        (output_dir / (config + ".log")).write_text(output)
        # Extract each violated invariant name. The r string preserves pattern backslashes;
        # \w+ captures the name, and \. matches a literal period rather than any character.
        violations = re.findall(r"Error: Invariant (\w+) is violated\.", output)
        # TLC exit 12 means an invariant violation; successful safe exploration must exit 0.
        expected_exit = 12 if expected_violation else 0
        # Reject an exit status different from the one required for this specific case.
        if (run.returncode != expected_exit
                # Also reject missing, extra, or wrong violation names, even when exit status matches.
                or violations != ([expected_violation] if expected_violation else [])
                # For safe cases, additionally require TLC's successful-completion message; None
                # means there was no expected violation, so an incomplete run cannot silently pass.
                or (expected_violation is None and "No error has been found" not in output)):
            # Raise a runner failure with the case name and final 3000 output characters for diagnosis.
            raise RuntimeError(f"Unexpected model result for {config}:\n{output[-3000:]}")
        # Build a dictionary (named fields) recording the case and observed process status.
        row = {"configuration": config, "exit_code": run.returncode,
               # Keep the expected rule failure and exact command for later reproduction.
               "expected_violation": expected_violation, "command": command,
               # Build a short summary by splitting output into lines and keeping any line with
               # at least one selected marker; the nested for expressions filter this list.
               "summary": [line for line in output.splitlines() if any(marker in line for marker in
                            # Retain explored-state counts, distinct-state counts, search depth, and error information.
                            ("states generated", "distinct states", "depth of", "Error:",
                             # Also retain completion, elapsed-time, and TLC-version lines to make results assessable.
                             "No error has been found", "Finished in", "TLC2 Version"))]}
        # Add this verified case record to the overall report list.
        rows.append(row)
        # Print one JSON record now; flush sends it immediately instead of waiting in an output buffer.
        print(json.dumps(row), flush=True)
    # Save the pinned tool digest and all checked cases as indented JSON. Reaching
    # this line means every case had precisely its required outcome, including controls.
    (output_dir / "model_results.json").write_text(json.dumps({"jar_sha256": JAR_SHA256, "models": rows}, indent=2))


# Call main only when executing this script directly; imports can reuse BASE and the digest.
if __name__ == "__main__":
    # Perform all model runs and write their checked evidence.
    main()
