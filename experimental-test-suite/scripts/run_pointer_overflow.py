import csv
import resource
import subprocess
from pathlib import Path

PROGRAMS = {
    "non_pie": "build/pointer_no_pie",
    "pie_aslr": "build/pointer_pie",
}

TRIALS = 30
results = []


def disable_core_dumps():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_program(args):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=5,
        preexec_fn=disable_core_dumps
    )


for configuration, executable in PROGRAMS.items():
    for trial in range(1, TRIALS + 1):
        address = ""
        exit_code = ""

        try:
            # Learn the target address in a separate process.
            probe = run_program([f"./{executable}", "--probe"])

            if probe.returncode != 0:
                outcome = "probe_failed"
            else:
                addresses = [
                    line.split("=", 1)[1]
                    for line in probe.stdout.splitlines()
                    if line.startswith("TARGET_ADDR=")
                ]

                if len(addresses) != 1:
                    outcome = "probe_failed"
                else:
                    address = addresses[0]

                    # Attempt to reuse that address in a new process.
                    attack = run_program([
                        f"./{executable}",
                        "--attack",
                        address
                    ])

                    exit_code = attack.returncode

                    if (
                        attack.returncode == 0
                        and "UNAUTHORIZED_ACTION" in attack.stdout
                    ):
                        outcome = "success"
                    elif attack.returncode < 0:
                        outcome = "signal_termination"
                    elif attack.returncode != 0:
                        outcome = "nonzero_exit"
                    else:
                        outcome = "no_unauthorized_action"

        except subprocess.TimeoutExpired:
            outcome = "timeout"

        results.append({
            "configuration": configuration,
            "trial": trial,
            "captured_address": address,
            "exit_code": exit_code,
            "outcome": outcome,
            "success": int(outcome == "success")
        })


output_path = Path("results/security/aslr_pie_trials.csv")
output_path.parent.mkdir(parents=True, exist_ok=True)

with output_path.open("w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "configuration",
            "trial",
            "captured_address",
            "exit_code",
            "outcome",
            "success"
        ]
    )
    writer.writeheader()
    writer.writerows(results)

print(f"Completed {len(results)} trials.")
print(f"Results saved to {output_path}\n")

for configuration in PROGRAMS:
    subset = [
        row for row in results
        if row["configuration"] == configuration
    ]

    successes = sum(row["success"] for row in subset)

    print(
        f"{configuration}: "
        f"{successes}/{len(subset)} successful "
        f"({100 * successes / len(subset):.1f}%)"
    )

    counts = {}
    for row in subset:
        outcome = row["outcome"]
        counts[outcome] = counts.get(outcome, 0) + 1

    print("  Outcomes:", counts)
