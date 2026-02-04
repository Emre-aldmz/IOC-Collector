def format_markdown_report(source: str, total: int, highlights: list[str]) -> str:
    lines = []
    lines.append("# Threat Intelligence Report — IOC Export")
    lines.append("")
    lines.append("## Overview")
    lines.append(f"Source: `{source}`")
    lines.append(f"Total extracted IOCs: **{total}**")
    lines.append("")
    lines.append("## High-Priority IOCs (sample)")
    if not highlights:
        lines.append("- (none)")
    else:
        for h in highlights[:5]:
            lines.append(f"- {h}")
    lines.append("")
    lines.append("## Usage Notes")
    lines.append("These IOCs can be used by SOC/CTI teams for detection, enrichment, and blocking purposes.")
    lines.append("")
    return "\n".join(lines)