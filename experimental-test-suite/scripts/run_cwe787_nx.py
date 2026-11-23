import csv
import resource
import subprocess
from pathlib import Path

EXECUTABLE = "./build/cwe787_nx_overflow"
TRIALS = 20
results = []

def disable_core_dumps():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

for mode in ("nx", "exec"):
    for trial in range(1, TRIALS + 1):
        try:
            process = subprocess.run(
                [EXECUTABLE, mode],
                capture_output=True,
                text=True,
                timeout=5,
                preexec_fn=disable_core_dumps
            )

            output = process.stdout

            success = (
                process.returncode == 0
                and "UNAUTHORIZED_EXECUTION" in output
            )

            if success:
                outcome = "unauthorized_execution"
            elif process.returncode == -11:
                outcome = "sigsegv"
            elif process.returncode < 0:
                outcome = "other_signal"
            else:
                outcome = "other"

            results.append({
                "mode": mode,
                "trial": trial,
                "exit_code": process.returncode,
                "callback_stage_reached": int(
                    "CALLBACK_OVERWRITTEN" in output
                ),
                "success": int(success),
                "outcome": outcome
            })

        except subprocess.TimeoutExpired:
            results.append({
                "mode": mode,
                "trial": trial,
                "exit_code": "",
                "callback_stage_reached": 0,
                "success": 0,
                "outcome": "timeout"
            })

path = Path("results/security/cwe787_nx_trials.csv")
path.parent.mkdir(parents=True, exist_ok=True)

with path.open("w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

print(f"Saved {len(results)} trials to {path}\n")

for mode in ("nx", "exec"):
    subset = [r for r in results if r["mode"] == mode]
    successes = sum(r["success"] for r in subset)

    print(f"{mode}: {successes}/{len(subset)} successful")

    counts = {}
    for row in subset:
        outcome = row["outcome"]
        counts[outcome] = counts.get(outcome, 0) + 1

    print(f"  Outcomes: {counts}")
