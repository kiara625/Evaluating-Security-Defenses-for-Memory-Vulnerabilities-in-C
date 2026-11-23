import csv
import subprocess
from pathlib import Path

PROGRAMS = {
    "baseline": "build/cwe416_baseline",
    "canary": "build/cwe416_canary",
    "pie": "build/cwe416_pie",
    "canary_pie": "build/cwe416_canary_pie"
}

TRIALS = 20
results = []

for configuration, executable in PROGRAMS.items():
    for trial in range(1, TRIALS + 1):
        try:
            result = subprocess.run(
                [f"./{executable}"],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = result.stdout

            if result.returncode == 0 and "ACCESS_GRANTED" in output:
                outcome = "unauthorized_access"
            elif "NO_REUSE" in output:
                outcome = "no_reuse"
            elif result.returncode == 0 and "ACCESS_DENIED" in output:
                outcome = "access_denied"
            else:
                outcome = "abnormal_termination"

            results.append({
                "configuration": configuration,
                "trial": trial,
                "exit_code": result.returncode,
                "outcome": outcome,
                "unauthorized_access": int(
                    outcome == "unauthorized_access"
                )
            })

        except subprocess.TimeoutExpired:
            results.append({
                "configuration": configuration,
                "trial": trial,
                "exit_code": "",
                "outcome": "timeout",
                "unauthorized_access": 0
            })

output_path = Path("results/security/cwe416_trials.csv")
output_path.parent.mkdir(parents=True, exist_ok=True)

with output_path.open("w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "configuration",
            "trial",
            "exit_code",
            "outcome",
            "unauthorized_access"
        ]
    )
    writer.writeheader()
    writer.writerows(results)

print(f"Completed {len(results)} trials.")
print(f"Results saved to {output_path}")

print()
print(f"{'Configuration':<15} {'Success':<10} {'No reuse':<10} {'Other'}")

for configuration in PROGRAMS:
    subset = [
        r for r in results
        if r["configuration"] == configuration
    ]

    successes = sum(
        r["outcome"] == "unauthorized_access"
        for r in subset
    )

    no_reuse = sum(
        r["outcome"] == "no_reuse"
        for r in subset
    )

    other = len(subset) - successes - no_reuse

    print(
        f"{configuration:<15} "
        f"{successes}/{len(subset):<7} "
        f"{no_reuse:<10} "
        f"{other}"
    )
