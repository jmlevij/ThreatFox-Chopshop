# ThreatFox-Chopshop
This repository contains a single Python script that loads ThreatFox JSON data and automatically splits it into multiple CSV files based on the IOC (Indicator of Compromise) type.

Overview

Reads the threatfox.json file (exported from threatfox.abuse.ch).
Parses the JSON into memory.
Groups IOCs by their ioc_type field (e.g., url, ip:port, sha256_hash, etc.).
Writes each type of IOC to a separate CSV file in the split_by_type directory.

Usage
Ensure you have Python 3.x installed.
Obtain the ThreatFox JSON file from https://threatfox.abuse.ch/export/json/full/
Unzip and place the JSON file in the same directory as threatfox_chopshop.py

Run:
python threatfox_chopshop.py
Check the split_by_type folder. There will be a CSV for each ioc_type encountered in the ThreatFox data. For example, url.csv, ip_port.csv, sha256_hash.csv, etc.

Columns in Each CSV
Each CSV file includes the following columns taken directly from the ThreatFox JSON:
ioc_value
ioc_type
threat_type
malware
malware_alias
malware_printable
first_seen_utc
last_seen_utc
confidence_level
reference
tags
anonymous
reporter

License
This project is licensed under the MIT License.
