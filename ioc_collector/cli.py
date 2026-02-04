import argparse
from .parsers.file_parser import read_file
from .extractors.regex_extractor import extract_iocs
from .formatters.json_formatter import format_json


def create_parser():
    p = argparse.ArgumentParser(prog="ioc-collector", description="IOC Collector Tool")
    p.add_argument("-f", "--file", required=True, help="Input file path")
    p.add_argument("--refang", action="store_true", help="Refang defanged IOCs")
    p.add_argument("--unique", action="store_true", help="Remove duplicates")
    p.add_argument("--export-csv", help="CSV output path (e.g., ioc_export.csv)")
    p.add_argument("--export-md", help="Markdown report output path (e.g., report.md)")
    p.add_argument("--source-label", default="GitHub", help="Source label for exports")
    p.add_argument("--confidence", default="High", choices=["Low", "Medium", "High"], help="Default confidence")  
    return p

def flatten_for_export(iocs: dict, source: str, confidence: str):
    rows = []

    def add_many(t, values, note):
        for v in values:
            rows.append({
                "type": t,
                "value": v,
                "confidence": confidence,
                "source": source,
                "note": note
            })

    add_many("ip", iocs.get("ipv4", []), "Extracted IPv4 indicator")
    add_many("domain", iocs.get("domains", []), "Extracted domain indicator")
    add_many("url", iocs.get("urls", []), "Extracted URL indicator")
    add_many("email", iocs.get("emails", []), "Extracted email indicator")
    add_many("cve", iocs.get("cves", []), "Extracted CVE indicator")
    add_many("mitre", iocs.get("mitre_techniques", []), "Extracted MITRE technique ID")
    add_many("hash_md5", iocs.get("hash_md5", []), "Extracted MD5 hash")
    add_many("hash_sha1", iocs.get("hash_sha1", []), "Extracted SHA1 hash")
    add_many("hash_sha256", iocs.get("hash_sha256", []), "Extracted SHA256 hash")

    return rows

def main():
    args = create_parser().parse_args()
    text = read_file(args.file)

    iocs = extract_iocs(text, do_refang=args.refang, unique=args.unique)

    flat_rows = flatten_for_export(iocs, args.source_label, args.confidence)

    if args.export_csv:
        from .formatters.csv_formatter import format_csv
        csv_out = format_csv(flat_rows)
        with open(args.export_csv, "w", encoding="utf-8") as f:
            f.write(csv_out)

    if args.export_md:
        from .formatters.md_report import format_markdown_report
        total = len(flat_rows)
        highlights = []
        highlights.extend(iocs.get("ipv4", [])[:2])
        highlights.extend(iocs.get("domains", [])[:2])
        md_out = format_markdown_report(args.file, total, highlights)
        with open(args.export_md, "w", encoding="utf-8") as f:
            f.write(md_out)

    result = {
        "metadata": {
            "source": args.file,
        },
        "iocs": iocs
    }

    print(format_json(result))


if __name__ == "__main__":
    main()