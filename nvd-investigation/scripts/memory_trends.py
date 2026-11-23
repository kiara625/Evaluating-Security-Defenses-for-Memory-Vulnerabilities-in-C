import pandas as pd

df = pd.read_csv("data/processed/cve_cwe_records.csv")

memory_cwes = {
    "CWE-119", "CWE-120", "CWE-121",
    "CWE-122", "CWE-125", "CWE-416",
    "CWE-787", "CWE-476",
}

all_by_year = df.groupby("year")["cve_id"].nunique()

memory_by_year = (
    df[df["cwe_id"].isin(memory_cwes)]
    .groupby("year")["cve_id"]
    .nunique()
)

results = pd.DataFrame({
    "all_classified_cves": all_by_year,
    "selected_memory_cves": memory_by_year
}).fillna(0)

results["percentage"] = (
    results["selected_memory_cves"]
    / results["all_classified_cves"]
    * 100
).round(2)

print(results)

results.to_csv("results/memory_safety_trends.csv")
