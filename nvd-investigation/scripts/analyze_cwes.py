import pandas as pd
from pathlib import Path

MEMORY_CWES = {
    "CWE-119": "Improper Memory Buffer Bounds",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-416": "Use After Free",
    "CWE-787": "Out-of-bounds Write",
    "CWE-476": "NULL Pointer Dereference",
}

df = pd.read_csv("data/processed/cve_cwe_records.csv")

memory_df = df[df["cwe_id"].isin(MEMORY_CWES)].copy()

# A CVE counts once for each distinct CWE to which it is mapped.
counts = (
    memory_df.groupby("cwe_id")["cve_id"]
    .nunique()
    .sort_values(ascending=False)
    .reset_index(name="cve_count")
)

counts["weakness"] = counts["cwe_id"].map(MEMORY_CWES)

counts = counts[["cwe_id", "weakness", "cve_count"]]

Path("results").mkdir(exist_ok=True)
counts.to_csv("results/cwe_frequency.csv", index=False)

print(counts.to_string(index=False))

# Year-by-year trends
trends = (
    memory_df.groupby(["year", "cwe_id"])["cve_id"]
    .nunique()
    .unstack(fill_value=0)
)

trends.to_csv("results/cwe_yearly_trends.csv")

print("\nUnique CVEs with at least one selected memory CWE:")
print(memory_df["cve_id"].nunique())
