# Threat Intelligence Report – RedLine Stealer IOC Analysis

## Overview
Source: `tests/sample_data/test_iocs.txt`
Total extracted IOCs: **9**

## High-Priority IOCs (sample)
- 188.190.10.10
- promo-usa.info
- api.ip.sb

## Usage Notes
These IOCs can be used by SOC/CTI teams for detection, enrichment, and blocking purposes.

## References (TR-CERT / USOM)
- USOM (TR-CERT) resources were consulted for Turkey-focused threat intelligence context and IOC handling best practices.

## How to Run
```bash
python3 -m ioc_collector.cli -f tests/sample_data/test_iocs.txt --refang --unique \
--export-csv ioc_export.csv --export-md report.md

