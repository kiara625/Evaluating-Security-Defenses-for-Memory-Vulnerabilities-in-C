import json
import zipfile
from pathlib import Path
import pandas as pd

RAW_DIR = Path("data/raw")
OUTPUT = Path("data/processed/cve_cwe_records.csv")

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

rows = []
missing_cwe = 0
processed_cves = 0

for path in sorted(RAW_DIR.glob("nvdcve-2.0-*.json.zip")):
    print(f"Processing {path.name}")

    with zipfile.ZipFile(path) as archive:
        with archive.open(archive.namelist()[0]) as file:
            data = json.load(file)

    for item in data["vulnerabilities"]:
        cve = item["cve"]

        # Publication period
        published = cve.get("published", "")
        if not ("2016-01-01" <= published[:10] <= "2025-12-31"):
            continue

        # Exclude rejected CVE records
        if cve.get("vulnStatus", "").lower() == "rejected":
            continue

        processed_cves += 1

        weaknesses = cve.get("weaknesses", [])

        # Prefer NVD's mapping when available.
        nvd_weaknesses = [
            w for w in weaknesses
            if w.get("source") == "nvd@nist.gov"
        ]

        selected = nvd_weaknesses or weaknesses
        cwe_ids = set()

        for weakness in selected:
            for description in weakness.get("description", []):
                value = description.get("value", "")

                if description.get("lang") == "en" and value.startswith("CWE-"):
                    cwe_ids.add(value)

        if not cwe_ids:
            missing_cwe += 1

        for cwe_id in sorted(cwe_ids):
            rows.append({
                "cve_id": cve["id"],
                "year": int(published[:4]),
                "cwe_id": cwe_id
            })

df = pd.DataFrame(rows)
df = df.drop_duplicates()

df.to_csv(OUTPUT, index=False)

print(f"CVEs in scope: {processed_cves}")
print(f"CVEs without a usable CWE: {missing_cwe}")
print(f"CVE-CWE associations: {len(df)}")
print(f"Saved to {OUTPUT}")
