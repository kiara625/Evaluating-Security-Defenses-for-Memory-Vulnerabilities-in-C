import csv
import subprocess
import resource
from pathlib import Path

EXECUTABLE = "./build/nx_test"
TRIALS = 20

def disable_core_dumps():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

results = []

for mode in ["nx", "exec"]:
    for trial in range(1, TRIALS + 1):
        try:
            result = subprocess.run(
                [EXECUTABLE, mode],
                capture_output=True,
                text=True,
                timeout=5,
                preexec_fn=disable_core_dumps
            )

            if (result.returncode == 0
                    and "EXECUTION_SUCCEEDED" in result.stdout):
                outcome = "execution_succeeded"
            elif result.returncode < 0:
                outcome = "signal_termination"
            else:
                outcome = "other"

            results.append({
                "mode": mode,
                "trial": trial,
                "exit_code": result.returncode,
                "execution_succeeded": int(
                    outcome == "execution_succeeded"
                ),
                "outcome": outcome
            })

        except subprocess.TimeoutExpired:
            results.append({
                "mode": mode,
                "trial": trial,
                "exit_code": "",
                "execution_succeeded": 0,
                "outcome": "timeout"
            })

path = Path("results/security/dep_nx_trials.csv")
path.parent.mkdir(parents=True, exist_ok=True)

with path.open("w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "mode",
            "trial",
            "exit_code",
            "execution_succeeded",
            "outcome"
        ]
    )
    writer.writeheader()
    writer.writerows(results)

print(f"Completed {len(results)} trials.")
print(f"Results saved to {path}\n")

for mode in ["nx", "exec"]:
    subset = [r for r in results if r["mode"] == mode]
    successes = sum(r["execution_succeeded"] for r in subset)
    outcomes = {}
    for r in subset:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1

    print(
        f"{mode}: {successes}/{len(subset)} "
        f"executions succeeded"
    )
    print(f"  Outcomes: {outcomes}")
