#!/usr/bin/env python3
"""revkit full analysis pipeline.

Usage:
    python full_analysis.py sample.exe
    python full_analysis.py app.apk
    python full_analysis.py sample.exe --remote http://server:8080

Supported: .exe .dll .so .elf .bin .apk .dex
Output: tmp/reports/{filename}_analysis.md
"""

import argparse
import os
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from _helpers import detect_engine, run_rk, start_and_wait, stop_all, setup_cleanup


def analyze_ida(path, remote=None):
    """IDA binary analysis workflow."""
    report = {"engine": "ida", "binary": os.path.basename(path), "sections": {}}

    out, _ = run_rk("ida", "summary", remote=remote)
    report["sections"]["summary"] = out

    out, _ = run_rk("ida", "find-func", "main", remote=remote)
    report["sections"]["main_search"] = out

    out, _ = run_rk("ida", "segments", remote=remote)
    report["sections"]["segments"] = out

    out, _ = run_rk("ida", "strings-xrefs", remote=remote, timeout=30)
    report["sections"]["strings_xrefs"] = out

    out, _ = run_rk("ida", "profile", "--action", "run", "vuln", remote=remote)
    report["sections"]["vuln_profile"] = out

    return report


def analyze_jeb(path, remote=None):
    """JEB APK/DEX analysis workflow."""
    report = {"engine": "jeb", "binary": os.path.basename(path), "sections": {}}

    for cmd, key in [
        (["jeb", "info"], "info"),
        (["jeb", "permissions"], "permissions"),
        (["jeb", "components"], "components"),
        (["jeb", "summary"], "summary"),
        (["jeb", "native-methods"], "native_methods"),
        (["jeb", "security-scan"], "security_scan"),
        (["jeb", "entry-points"], "entry_points"),
    ]:
        out, _ = run_rk(*cmd, remote=remote)
        report["sections"][key] = out

    return report


def generate_report(report, output_path):
    """Generate markdown report."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# Analysis Report: {report['binary']}\n\n")
        f.write(f"- **Engine**: {report['engine']}\n")
        f.write(f"- **Date**: {datetime.now().isoformat()}\n\n")
        f.write("---\n\n")
        for key, value in report["sections"].items():
            title = key.replace("_", " ").title()
            f.write(f"## {title}\n\n```\n{value}\n```\n\n")
    print(f"[+] Report saved: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="revkit full analysis")
    parser.add_argument("path", help="File to analyze")
    parser.add_argument("--remote", default=None, help="Gateway URL")
    args = parser.parse_args()

    path = args.path
    if not os.path.isfile(path):
        print(f"[-] File not found: {path}")
        sys.exit(1)

    engine = detect_engine(path)
    setup_cleanup(args.remote)

    print(f"[*] Analyzing: {os.path.basename(path)} ({engine})")
    iid = start_and_wait(engine, path, fresh=(engine == "jeb"), remote=args.remote)
    print(f"[*] Instance: {iid}")

    try:
        if engine == "ida":
            report = analyze_ida(path, args.remote)
        else:
            report = analyze_jeb(path, args.remote)
    finally:
        stop_all(engine, args.remote)
        print("[*] Instance stopped")

    name = Path(path).stem
    output = f"tmp/reports/{name}_analysis.md"
    generate_report(report, output)


if __name__ == "__main__":
    main()
