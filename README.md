# IOC Collector – Mini CTI Tool

A Python-based command-line tool developed during Week 3 internship tasks to extract Indicators of Compromise (IOCs) from text files and export them in structured formats.

---

## Features
- Regex-based IOC extraction (IP, domain, URL, email, hash, CVE, MITRE techniques)
- Refang support
- Unique IOC filtering
- CSV export
- Markdown report export

---

## Project Structure
proje-week3/
├── ioc_collector/
│   ├── extractors/
│   ├── formatters/
│   ├── parsers/
│   ├── utils/
│   └── cli.py
├── tests/
│   └── sample_data/
├── ioc_export.csv
├── report.md
├── requirements.txt
└── README.md

## How to Run
```bash
python3 -m ioc_collector.cli -f tests/sample_data/test_iocs.txt --refang --unique \
--export-csv ioc_export.csv --export-md report.md

---

```md
## Outputs
- `ioc_export.csv` – Extracted IOC list (CSV format)
- `report.md` – Markdown threat intelligence report

## Requirements
- Python 3.10+
