import csv
import subprocess
from pathlib import Path

PROGRAMS = {
    "baseline": "build/cwe125_baseline",
    "canary": "build/cwe125_canary",
    "pie": "build/cwe125_pie",
    "canary_pie": "build/cwe125_canary_pie"
}

INDICES = [0, 5, 15, 16, 17, 18, 19, 21]
MARKER = "SECRET"
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

                expected_byte = (
                    ord(MARKER[index - 16])
                    if 16 <= index < 16 + len(MARKER)
                    else None
                )

                expected_output = (
                    f"READ_VALUE: 0x{expected_byte:02X}"
                    if expected_byte is not None
                    else None
                )

                disclosure = (
                    expected_output is not None
                    and expected_output in result.stdout
                    and result.returncode == 0
                )

                results.append({
                    "configuration": configuration,
                    "index": index,
                    "trial": trial,
                    "exit_code": result.returncode,
                    "disclosure": int(disclosure),
                    "expected_byte": (
                        f"0x{expected_byte:02X}"
                        if expected_byte is not None
                        else ""
                    ),
                    "outcome": (
                        "marker_disclosed"
                        if disclosure
                        else "no_marker_disclosure"
                        if result.returncode == 0
                        else "abnormal_termination"
                    )
                })

            except subprocess.TimeoutExpired:
                results.append({
                    "configuration": configuration,
                    "index": index,
                    "trial": trial,
                    "exit_code": "",
                    "disclosure": 0,
                    "expected_byte": "",
                    "outcome": "timeout"
                })

output_path = Path("results/security/cwe125_trials.csv")
output_path.parent.mkdir(parents=True, exist_ok=True)

with output_path.open("w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "configuration",
            "index",
            "trial",
            "exit_code",
            "disclosure",
            "expected_byte",
            "outcome"
        ]
    )
    writer.writeheader()
    writer.writerows(results)

print(f"Completed {len(results)} trials.")
print(f"Results saved to {output_path}")
