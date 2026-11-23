import json
import zipfile
from pathlib import Path

path = Path("data/raw/nvdcve-2.0-2025.json.zip")

with zipfile.ZipFile(path) as archive:
    filename = archive.namelist()[0]

    with archive.open(filename) as file:
        data = json.load(file)

print("Top-level keys:", data.keys())
print("Number of records:", len(data["vulnerabilities"]))

first_record = data["vulnerabilities"][0]["cve"]

print(json.dumps({
    "id": first_record.get("id"),
    "published": first_record.get("published"),
    "vulnStatus": first_record.get("vulnStatus"),
    "weaknesses": first_record.get("weaknesses", [])
}, indent=2))
