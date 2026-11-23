import csv
import random
import statistics
import subprocess
from pathlib import Path

PROGRAMS = {
    "baseline": "build/perf_baseline",
    "canary": "build/perf_canary",
    "pie": "build/perf_pie",
    "canary_pie": "build/perf_canary_pie"
}

ITERATIONS = 500_000_000
TRIALS = 30
WARMUP_ROUNDS = 2

OUTPUT = Path("results/performance/benchmark_trials.csv")
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

rng = random.Random(42)
results = []
expected_checksum = None


def run_benchmark(executable):
    result = subprocess.run(
        [f"./{executable}", str(ITERATIONS)],
        capture_output=True,
        text=True,
        timeout=30,
        check=True
    )

    metrics = {}

    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            metrics[key] = value

    return {
        "runtime_seconds": float(
            metrics["RUNTIME_SECONDS"]
        ),
        "max_rss_kb": int(metrics["MAX_RSS_KB"]),
        "checksum": metrics["CHECKSUM"]
    }


print("Running warm-up rounds...")

for _ in range(WARMUP_ROUNDS):
    configurations = list(PROGRAMS.keys())
    rng.shuffle(configurations)

    for config in configurations:
        run_benchmark(PROGRAMS[config])


print("Collecting measured trials...")

for trial in range(1, TRIALS + 1):
    configurations = list(PROGRAMS.keys())
    rng.shuffle(configurations)

    for config in configurations:
        metrics = run_benchmark(PROGRAMS[config])

        if expected_checksum is None:
            expected_checksum = metrics["checksum"]

        if metrics["checksum"] != expected_checksum:
            raise RuntimeError(
                f"Checksum mismatch: {config}, trial {trial}"
            )

        results.append({
            "trial": trial,
            "configuration": config,
            "runtime_seconds": metrics["runtime_seconds"],
            "max_rss_kb": metrics["max_rss_kb"],
            "checksum": metrics["checksum"]
        })

    if trial % 5 == 0:
        print(f"Completed {trial}/{TRIALS} rounds")


with OUTPUT.open("w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "trial",
            "configuration",
            "runtime_seconds",
            "max_rss_kb",
            "checksum"
        ]
    )
    writer.writeheader()
    writer.writerows(results)


print(f"\nSaved {len(results)} measurements to {OUTPUT}")
print(f"Verified checksum: {expected_checksum}\n")

baseline_times = [
    r["runtime_seconds"]
    for r in results
    if r["configuration"] == "baseline"
]

baseline_median = statistics.median(baseline_times)

print(
    f"{'Configuration':<15} "
    f"{'Median (s)':>11} "
    f"{'Std dev':>10} "
    f"{'Overhead':>11} "
    f"{'RSS (KB)':>11}"
)

for config in PROGRAMS:
    subset = [
        r for r in results
        if r["configuration"] == config
    ]

    times = [r["runtime_seconds"] for r in subset]
    memory = [r["max_rss_kb"] for r in subset]

    median_time = statistics.median(times)
    std_dev = statistics.stdev(times)

    overhead = (
        (median_time / baseline_median) - 1
    ) * 100

    median_rss = statistics.median(memory)

    print(
        f"{config:<15} "
        f"{median_time:>11.4f} "
        f"{std_dev:>10.4f} "
        f"{overhead:>+10.2f}% "
        f"{median_rss:>11.0f}"
    )
