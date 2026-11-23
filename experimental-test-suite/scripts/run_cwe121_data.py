import subprocess
import csv
from pathlib import Path

PROGRAMS = {
    "baseline": "build/cwe121_data_baseline",
    "canary": "build/cwe121_data_canary",
    "pie": "build/cwe121_data_pie",
    "canary_pie": "build/cwe121_data_canary_pie",
}

INPUT_LENGTHS = [5, 15, 16, 17, 18, 20]
TRIALS = 10

results = []

for configuration, executable in PROGRAMS.items():
    for length in INPUT_LENGTHS:
        for trial in range(1, TRIALS + 1):
            input_string = "A" * length

            try:
                result = subprocess.run(
                    [f"./{executable}", input_string],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                output = result.stdout + result.stderr

                unauthorized_access = (
                    "ACCESS_GRANTED" in result.stdout
                )

                canary_detected = (
                    "stack smashing detected" in output
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
                    "input_length": length,
                    "trial": trial,
                    "exit_code": result.returncode,
                    "unauthorized_access": int(unauthorized_access),
                    "canary_detected": int(canary_detected),
                    "outcome": outcome
                })

            except subprocess.TimeoutExpired:
                results.append({
                    "configuration": configuration,
                    "input_length": length,
                    "trial": trial,
                    "exit_code": "",
                    "unauthorized_access": 0,
                    "canary_detected": 0,
                    "outcome": "timeout"
                })

output_path = Path(
    "results/security/cwe121_data_trials.csv"
)

output_path.parent.mkdir(parents=True, exist_ok=True)

with output_path.open("w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "configuration",
            "input_length",
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
