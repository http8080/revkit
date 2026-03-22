#!/usr/bin/env python3
"""Generate markdown or JSON reports from analysis result JSON files.

Usage:
    python report_generator.py --input result.json --output report.md
    python report_generator.py --input result.json --template security
    python report_generator.py --input result.json --format json --output out.json
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import argparse
import json
from datetime import datetime


def template_analysis(data: dict) -> str:
    """General analysis report template."""
    lines = [
        f"# Analysis Report: {data.get('file', 'unknown')}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Engine: {data.get('engine', 'unknown')}",
        "",
        "## Summary",
    ]
    summary = data.get("summary") or data.get("analysis", {}).get("summary", {})
    if isinstance(summary, dict):
        for k, v in summary.items():
            if k != "raw":
                lines.append(f"- **{k}**: {v}")
    elif summary:
        lines.append(str(summary))
    lines.append("")

    if "analysis" in data:
        lines.append("## Detailed Analysis")
        for section, content in data["analysis"].items():
            if section == "summary":
                continue
            lines.append(f"### {section.replace('_', ' ').title()}")
            if isinstance(content, (list, dict)):
                lines.append(f"```json\n{json.dumps(content, indent=2, default=str)}\n```")
            else:
                lines.append(str(content))
            lines.append("")
    return "\n".join(lines)


def template_security(data: dict) -> str:
    """Security-focused report template."""
    lines = [
        f"# Security Report: {data.get('file', 'unknown')}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    # Risk / protection level
    if "risk_score" in data:
        lines.append(f"## Risk Assessment")
        lines.append(f"- Score: **{data['risk_score']}/100** ({data.get('risk_level', '')})")
        lines.append("")
    if "protection_level" in data:
        lines.append(f"## MASVS Protection Level: **L{data['protection_level']}**")
        lines.append("")

    # Vulnerabilities
    vulns = data.get("vulnerabilities", [])
    if vulns:
        lines.append("## Vulnerabilities")
        lines.append("| # | Type | Name | Severity |")
        lines.append("|---|------|------|----------|")
        for i, v in enumerate(vulns, 1):
            lines.append(f"| {i} | {v.get('type', '')} | {v.get('name', '')} "
                         f"| {v.get('severity', '')} |")
        lines.append("")

    # MASVS results
    masvs = data.get("masvs_results", {})
    if masvs:
        lines.append("## MASVS Findings")
        for category, checks in masvs.items():
            found = [c for c in checks if c.get("found")]
            lines.append(f"### {category} ({len(found)}/{len(checks)} issues)")
            for c in found:
                lines.append(f"- [{c.get('severity', '')}] {c.get('id', '')}: "
                             f"{c.get('description', '')}")
            lines.append("")

    # Findings
    findings = data.get("findings", {})
    if findings:
        lines.append("## Findings")
        for k, v in findings.items():
            lines.append(f"### {k.replace('_', ' ').title()}")
            if isinstance(v, list):
                for item in v:
                    lines.append(f"- {item}")
            elif isinstance(v, dict):
                lines.append(f"```json\n{json.dumps(v, indent=2, default=str)}\n```")
            else:
                lines.append(str(v))
            lines.append("")

    return "\n".join(lines)


def template_comparison(data: dict) -> str:
    """Comparison report template."""
    lines = [
        f"# Comparison Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Targets",
    ]
    for key in ("file1", "file2", "file"):
        if key in data:
            lines.append(f"- {key}: {data[key]}")
    lines.append("")

    if "diff" in data or "analysis" in data:
        content = data.get("analysis", data)
        lines.append("## Differences")
        lines.append(f"```json\n{json.dumps(content, indent=2, default=str)}\n```")

    return "\n".join(lines)


def template_batch(data: dict) -> str:
    """Batch results report template."""
    lines = [
        f"# Batch Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    items = data if isinstance(data, list) else data.get("results", [data])
    lines.append(f"Total items: {len(items)}")
    lines.append("")

    for i, item in enumerate(items, 1):
        name = item.get("file", item.get("name", f"Item {i}"))
        lines.append(f"## {i}. {name}")
        for k, v in item.items():
            if k in ("file", "name"):
                continue
            if isinstance(v, (dict, list)):
                lines.append(f"- **{k}**: {json.dumps(v, default=str)}")
            else:
                lines.append(f"- **{k}**: {v}")
        lines.append("")

    return "\n".join(lines)


TEMPLATES = {
    "analysis": template_analysis,
    "security": template_security,
    "comparison": template_comparison,
    "batch": template_batch,
}


def auto_detect_template(data: dict) -> str:
    """Auto-detect best template from data keys."""
    if "risk_score" in data or "vulnerabilities" in data or "masvs_results" in data:
        return "security"
    if "diff" in data or "code_diff" in data:
        return "comparison"
    if isinstance(data, list):
        return "batch"
    return "analysis"


def main():
    parser = argparse.ArgumentParser(description="Generate reports from JSON results")
    parser.add_argument("--input", "-i", required=True, help="Input JSON file")
    parser.add_argument("--output", "-o", default=None, help="Output file path")
    parser.add_argument("--template", "-t", choices=list(TEMPLATES.keys()),
                        default=None, help="Report template (auto-detected if omitted)")
    parser.add_argument("--format", "-f", choices=["markdown", "json"],
                        default="markdown", help="Output format (default: markdown)")
    parser.add_argument("--remote", default=None,
                        help="Gateway URL (unused, for CLI consistency)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    data = json.loads(input_path.read_text(encoding="utf-8"))

    if args.format == "json":
        output = json.dumps(data, indent=2, default=str)
    else:
        tmpl_name = args.template or auto_detect_template(data)
        renderer = TEMPLATES[tmpl_name]
        output = renderer(data)
        print(f"[*] Using template: {tmpl_name}")

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"[+] Report saved to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
