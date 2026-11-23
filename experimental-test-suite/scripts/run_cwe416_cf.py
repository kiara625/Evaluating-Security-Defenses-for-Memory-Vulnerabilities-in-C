import csv
import subprocess
from collections import Counter
from pathlib import Path

PROGRAMS = {
    "baseline": "build/cwe416_cf_baseline",
    "canary": "build/cwe416_cf_canary",
    "pie": "build/cwe416_cf_pie",
    "canary_pie": "build/cwe416_cf_canary_pie",
}

TRIALS = 20
results = []

for config, executable in PROGRAMS.items():
    for trial in range(1, TRIALS + 1):
        try:
            process = subprocess.run(
                [f"./{executable}"],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = process.stdout
            reused = "ADDRESS_REUSED" in output
            success = (
                reused
                and "UNAUTHORIZED_ACTION" in output
                and process.returncode == 0
            )

            if success:
                outcome = "unauthorized_action"
            elif "NO_REUSE" in output:
                outcome = "no_reuse"
            elif process.returncode < 0:
                outcome = "signal_termination"
            elif process.returncode != 0:
                outcome = "nonzero_exit"
            else:
                outcome = "other"

            results.append({
                "configuration": config,
                "trial": trial,
                "exit_code": process.returncode,
                "address_reused": int(reused),
                "success": int(success),
                "outcome": outcome
            })

        except subprocess.TimeoutExpired:
            results.append({
                "configuration": config,
                "trial": trial,
                "exit_code": "",
                "address_reused": 0,
                "success": 0,
                "outcome": "timeout"
            })

path = Path("results/security/cwe416_cf_trials.csv")
path.parent.mkdir(parents=True, exist_ok=True)

with path.open("w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

print(f"Saved {len(results)} trials to {path}\n")

for config in PROGRAMS:
    subset = [
        row for row in results
        if row["configuration"] == config
    ]

    successes = sum(row["success"] for row in subset)
    reuse_count = sum(row["address_reused"] for row in subset)
    outcomes = Counter(row["outcome"] for row in subset)

    print(
        f"{config}: {successes}/{len(subset)} successful, "
        f"{reuse_count}/{len(subset)} address reused"
    )
    print(f"  Outcomes: {dict(outcomes)}")
