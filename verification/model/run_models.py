"""Run the pinned independent TLA+ model and require exact control outcomes."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess

BASE = Path(__file__).resolve().parent
JAR_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
CASES = [
    ("sync_d1", None), ("sync_d2", None),
    ("lag_unsafe_d1", "SourceAuthentication"),
    ("lag_bounded_d1", None), ("lag_bounded_d2", None),
    ("delivery_guard_d1", "SourceAuthentication"),
    ("witness_honest", "NoHonestAcceptance"),
    ("witness_replay", "NoReplaySuppression"),
    ("witness_honest_lag_d2", "NoHonestAcceptance"),
]


def main():
    jar = Path(os.environ.get("TLA2TOOLS_JAR", BASE / "tla2tools.jar")).resolve()
    if hashlib.sha256(jar.read_bytes()).hexdigest() != JAR_SHA256:
        raise RuntimeError("TLC JAR hash does not match the audited tool")
    output_dir = Path(os.environ.get("TLA_RESULTS_DIR", BASE / "results")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for config, expected_violation in CASES:
        command = ["java", "-XX:+UseParallelGC", "-Xmx1g", "-cp", str(jar), "tlc2.TLC",
                   "-workers", "1", "-seed", "1", "-fp", "0", "-metadir",
                   str(output_dir / "states" / config), "-config", config + ".cfg", "MiniTesla.tla"]
        run = subprocess.run(command, cwd=BASE, capture_output=True, text=True, timeout=60)
        output = run.stdout + run.stderr
        (output_dir / (config + ".log")).write_text(output)
        violations = re.findall(r"Error: Invariant (\w+) is violated\.", output)
        expected_exit = 12 if expected_violation else 0
        if (run.returncode != expected_exit
                or violations != ([expected_violation] if expected_violation else [])
                or (expected_violation is None and "No error has been found" not in output)):
            raise RuntimeError(f"Unexpected model result for {config}:\n{output[-3000:]}")
        row = {"configuration": config, "exit_code": run.returncode,
               "expected_violation": expected_violation, "command": command,
               "summary": [line for line in output.splitlines() if any(marker in line for marker in
                            ("states generated", "distinct states", "depth of", "Error:",
                             "No error has been found", "Finished in", "TLC2 Version"))]}
        rows.append(row)
        print(json.dumps(row), flush=True)
    (output_dir / "model_results.json").write_text(json.dumps({"jar_sha256": JAR_SHA256, "models": rows}, indent=2))


if __name__ == "__main__":
    main()
