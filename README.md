![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Status](https://img.shields.io/badge/Status-Working-success)

# IOC Collector – Mini CTI Tool

This Python-powered command-line interface (CLI) tool is designed to automate the extraction of Indicators of Compromise (IOCs) from unstructured text files. It streamlines the transition from raw data to actionable intelligence, making it an essential utility for Cyber Threat Intelligence (CTI) and Security Operations Center (SOC) workflows.

---

## Features
- Regex-based IOC extraction (IP, domain, URL, email, hash, CVE, MITRE techniques)
- Refang support
- Unique IOC filtering
- CSV export
- Markdown threat intelligence report export

---

## Project Structure
```text
proje-week3/
├── ioc_collector/
│   ├── extractors/
│   ├── formatters/
│   ├── parsers/
│   ├── utils/
│   └── cli.py
├── tests/
│   └── sample_data/
│       └── test_iocs.txt
├── ioc_export.csv
├── report.md
├── requirements.txt
└── README.md
```

## How to Run

### Create virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```


### Install dependencies
```bash
pip install -r requirements.txt
```

### Run the tool
```bash
python3 -m ioc_collector.cli \
  -f tests/sample_data/test_iocs.txt \
  --refang \
  --unique \
  --export-csv ioc_export.csv \
  --export-md report.md
```

## Example Output (CSV)
```csv
type,value,confidence,source,note
ip,188.190.10.10,High,OSINT,RedLine Stealer C2 server
domain,promo-usa.info,High,OSINT,Malicious domain
domain,api.ip.sb,Medium,OSINT,Legitimate service abused
```
