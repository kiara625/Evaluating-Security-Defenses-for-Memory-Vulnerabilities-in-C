import csv
import subprocess
from collections import Counter
from pathlib import Path

PROGRAMS = {
    "baseline": "build/cwe121_cf_baseline",
    "canary": "build/cwe121_cf_canary",
    "pie": "build/cwe121_cf_pie",
    "canary_pie": "build/cwe121_cf_canary_pie",
}

TRIALS = 20
results = []

for config, executable in PROGRAMS.items():
    process = subprocess.run(
        [f"./{executable}", "normal"],
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert process.returncode == 0, (
        f"{config}: normal execution exited with "
        f"{process.returncode}"
    )
    assert "NORMAL_ACTION" in process.stdout, (
        f"{config}: normal action was not observed"
    )

print("Normal execution verified for all four configurations.\n")

for config, executable in PROGRAMS.items():
    for trial in range(1, TRIALS + 1):
        try:
            process = subprocess.run(
                [f"./{executable}", "overflow"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            output = process.stdout + process.stderr

            unauthorized = "UNAUTHORIZED_ACTION" in output
            canary_detected = "stack smashing detected" in output

            success = (
                unauthorized and process.returncode == 0
            )

            if success:
                outcome = "unauthorized_action"
            elif unauthorized:
                outcome = "unauthorized_then_abnormal_exit"
            elif canary_detected:
                outcome = "canary_detection"
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
                "unauthorized_action_observed": int(unauthorized),
                "canary_detected": int(canary_detected),
                "success": int(success),
                "outcome": outcome,
            })

        except subprocess.TimeoutExpired:
            results.append({
                "configuration": config,
                "trial": trial,
                "exit_code": "",
                "unauthorized_action_observed": 0,
                "canary_detected": 0,
                "success": 0,
                "outcome": "timeout",
            })

path = Path("results/security/cwe121_cf_trials.csv")
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
    unauthorized = sum(
        row["unauthorized_action_observed"] for row in subset
    )
    detections = sum(row["canary_detected"] for row in subset)
    outcomes = Counter(row["outcome"] for row in subset)

    print(
        f"{config}: {successes}/{TRIALS} successful, "
        f"{unauthorized}/{TRIALS} unauthorized actions, "
        f"{detections}/{TRIALS} canary detections"
    )
    print(f"  Outcomes: {dict(outcomes)}")
