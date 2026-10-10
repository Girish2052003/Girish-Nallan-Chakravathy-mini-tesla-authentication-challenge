"""Require expected outcomes for independent signed-bootstrap timing model."""
from pathlib import Path
from run_models import BASE, JAR_SHA256
import hashlib
import json
import os
import re
import subprocess

CASES = [
    ("bootstrap_sync_d1", None),
    ("bootstrap_lag_d2", None),
    ("bootstrap_stale_legacy", "NoReleasedForgery"),
    ("bootstrap_unsafe_bound", "NoReleasedForgery"),
    ("bootstrap_broken_signature", "AuthenticatedAnchor"),
    ("bootstrap_broken_challenge", "ChallengeFreshness"),
    ("bootstrap_honest_witness", "NoHonestAuthentication"),
]

def main():
    jar = Path(os.environ.get("TLA2TOOLS_JAR", BASE / "tla2tools.jar")).resolve()
    if hashlib.sha256(jar.read_bytes()).hexdigest() != JAR_SHA256:
        raise RuntimeError("TLC JAR hash mismatch")
    directory = Path(os.environ.get("TLA_RESULTS_DIR", BASE / "results")).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    evidence = []
    for name, expected in CASES:
        cmd = ["java", "-XX:+UseParallelGC", "-Xmx1g", "-cp", str(jar),
               "tlc2.TLC", "-workers", "1", "-seed", "1", "-fp", "0",
               "-metadir", str(directory / "states" / name),
               "-config", name + ".cfg", "BootstrapTime.tla"]
        run = subprocess.run(cmd, cwd=BASE, capture_output=True, text=True, timeout=60)
        out = run.stdout + run.stderr
        (directory / (name + ".log")).write_text(out)
        errors = re.findall(r"Error: Invariant (\\w+) is violated\\.", out)
        if (run.returncode != (12 if expected else 0)
            or errors != ([expected] if expected else [])
            or (expected is None and "No error has been found" not in out)):
            raise RuntimeError(f"Unexpected model result for {name}:\\n{out[-3500:]}")
        summary = [line for line in out.splitlines() if any(k in line for k in
                   ("states generated", "distinct states", "depth of", "Error:",
                    "No error has been found", "Finished in", "TLC2 Version"))]
        row = {"configuration": name, "exit_code": run.returncode,
               "expected_violation": expected, "summary": summary, "command": cmd}
        evidence.append(row)
        print(json.dumps(row), flush=True)
    (directory / "bootstrap_model_results.json").write_text(
        json.dumps({"jar_sha256": JAR_SHA256, "models": evidence}, indent=2)
    )

if __name__ == "__main__":
    main()
