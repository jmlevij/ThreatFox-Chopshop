'''
threatfox_chopshop.py

Author: James Levija
Date: 2025-02-13
License: MIT

Description:
    This script takes the threatfox.json file and converts it to a master csv
    file in memory. It then parses based on IOC type and saves them into their
    own csv files.
    
Usage:
    python threatfox_chopshop.py

Requirements:
    - Python 3.x
    - Threatfox json file is found here https://threatfox.abuse.ch/export/json/full/
'''

import json
import csv
import os
from collections import defaultdict

INPUT_JSON_FILE = "threatfox.json"
OUTPUT_DIR = "split_by_type"

CSV_COLUMNS = [
    "ioc_value", 
    "ioc_type", 
    "threat_type", 
    "malware", 
    "malware_alias", 
    "malware_printable", 
    "first_seen_utc", 
    "last_seen_utc", 
    "confidence_level", 
    "reference", 
    "tags", 
    "anonymous", 
    "reporter"
]

def split_directly():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Read JSON
    with open(INPUT_JSON_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Organize IOCs into a dict grouped by ioc_type
    iocs_by_type = defaultdict(list)
    for key, ioc_list in data.items():
        for ioc in ioc_list:
            ioc_type = ioc.get("ioc_type", "")
            iocs_by_type[ioc_type].append(ioc)

    # For each ioc_type, write a CSV
    for ioc_type, iocs in iocs_by_type.items():
        safe_type = ioc_type.replace(":", "_").replace("/", "_")
        out_csv = os.path.join(OUTPUT_DIR, f"{safe_type}.csv")
        with open(out_csv, "w", newline="", encoding="utf-8") as f_out:
            writer = csv.DictWriter(f_out, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            for ioc in iocs:
                writer.writerow(ioc)

        print(f"[+] Wrote {len(iocs)} rows of type '{ioc_type}' to {out_csv}")

if __name__ == "__main__":
    split_directly()
