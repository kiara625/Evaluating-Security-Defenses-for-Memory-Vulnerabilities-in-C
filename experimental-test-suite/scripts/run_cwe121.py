import subprocess
import csv
from pathlib import Path

programs = {
	"baseline" : "build/cwe121_baseline",
	"canary": "build/cwe121_canary"
}

input_lengths = list(range(15,26))

results = []

for configuration, executable in programs.items():
	for length in input_lengths:
		input_string = "A" * length
	
		result =  subprocess.run(
			[f"./{executable}", input_string],
			capture_output=True,
			text=True,
			timeout=5
		)

		output = result.stdout + result.stderr

		if "stack smashing detected" in output:
			outcome = "canary_detected"
		elif result.returncode == 0:
			outcome = "normal_completion"
		elif result.returncode < 0:
			outcome = "signal termination"
		else:
			outcome = "nonzero outcome"

		results.append({
			"configuration": configuration,
			"input_length": length,
			"return_code": result.returncode,
			"outcome": outcome
		})

		print(configuration, length, result.returncode, outcome)

output_path = Path("results/security/cwe121_trials.csv")
output_path.parent.mkdir(parents=True, exist_ok=True)

with output_path.open("w", newline="") as file:
	writer = csv.DictWriter(
		file,
		fieldnames=[
			"configuration",
			"input_length",
			"return_code",
			"outcome"
		]
	)

	writer.writeheader()
	writer.writerows(results)

print(f"\nResults saved to {output_path}")
