
import csv
import subprocess
from pathlib import Path

PROGRAMS = {
    "baseline": "build/cwe787_baseline",
    "canary": "build/cwe787_canary",
    "pie": "build/cwe787_pie",
    "canary_pie": "build/cwe787_canary_pie"
}

INDICES = [0, 5, 15, 16, 17, 19]
TRIALS = 10

results = []

for configuration, executable in PROGRAMS.items():
    for index in INDICES:
        for trial in range(1, TRIALS + 1):
            try:
                result = subprocess.run(
                    [f"./{executable}", str(index)],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                unauthorized_access = (
                    "ACCESS_GRANTED" in result.stdout
                )

                canary_detected = (
                    "stack smashing detected"
                    in result.stderr
                )

                if unauthorized_access:
                    outcome = "unauthorized_access"
                elif canary_detected:
                    outcome = "canary_detected"
                elif result.returncode == 0:
                    outcome = "access_denied"
                else:
                    outcome = "abnormal_termination"

                results.append({
                    "configuration": configuration,
                    "index": index,
                    "trial": trial,
                    "exit_code": result.returncode,
                    "unauthorized_access": int(unauthorized_access),
                    "canary_detected": int(canary_detected),
                    "outcome": outcome
                })

            except subprocess.TimeoutExpired:
                results.append({
                    "configuration": configuration,
                    "index": index,
                    "trial": trial,
                    "exit_code": "",
                    "unauthorized_access": 0,
                    "canary_detected": 0,
                    "outcome": "timeout"
                })

output_path = Path(
    "results/security/cwe787_trials.csv"
)

output_path.parent.mkdir(parents=True, exist_ok=True)

with output_path.open("w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "configuration",
            "index",
            "trial",
            "exit_code",
            "unauthorized_access",
            "canary_detected",
            "outcome"
        ]
    )
    writer.writeheader()
    writer.writerows(results)

print(f"Completed {len(results)} trials.")
print(f"Results saved to {output_path}")
