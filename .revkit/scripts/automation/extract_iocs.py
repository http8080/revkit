#!/usr/bin/env python3
"""Extract Indicators of Compromise (IOCs) from binary strings.

Usage:
    python extract_iocs.py sample.exe
    python extract_iocs.py sample.apk --remote http://server:8080
    python extract_iocs.py sample.exe --output iocs.json
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import argparse
import json
import re
from _helpers import detect_engine, run_rk, start_and_wait, stop_all, setup_cleanup

PATTERNS = {
    "urls": re.compile(r'https?://[^\s"\'<>]{4,200}'),
    "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "emails": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "file_paths_win": re.compile(r'[A-Z]:\\[\w\\. -]+'),
    "file_paths_unix": re.compile(r'/(?:etc|tmp|usr|var|bin|home|opt)/[\w/.+-]+'),
}


def extract_iocs(strings_output: str) -> dict:
    """Match IOC patterns against string data."""
    iocs: dict[str, list[str]] = {k: [] for k in PATTERNS}
    for line in strings_output.splitlines():
        for category, regex in PATTERNS.items():
            for m in regex.findall(line):
                if m not in iocs[category]:
                    iocs[category].append(m)
    # Filter out false-positive IPs (e.g., version numbers like 1.0.0.0)
    iocs["ipv4"] = [
        ip for ip in iocs["ipv4"]
        if all(0 <= int(o) <= 255 for o in ip.split("."))
        and ip not in ("0.0.0.0", "255.255.255.255")
    ]
    return {k: v for k, v in iocs.items() if v}


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from binary strings")
    parser.add_argument("path", help="Binary or APK file path")
    parser.add_argument("--remote", default=None, help="Gateway URL for remote mode")
    parser.add_argument("--output", "-o", default=None, help="Output JSON file")
    args = parser.parse_args()

    setup_cleanup(args.remote)

    engine = detect_engine(args.path)
    print(f"[*] Engine: {engine} | File: {args.path}")

    iid = start_and_wait(engine, args.path, remote=args.remote)
    print(f"[*] Instance {iid} ready, extracting strings ...")

    out, _ = run_rk(engine, "strings-xrefs", "-i", iid, "--json",
                     timeout=120, remote=args.remote)
    iocs = extract_iocs(out)

    result = {
        "file": args.path,
        "engine": engine,
        "ioc_counts": {k: len(v) for k, v in iocs.items()},
        "iocs": iocs,
    }

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"[+] IOCs saved to {args.output}")
    else:
        print(json.dumps(result, indent=2))

    stop_all(engine, args.remote)
    print("[+] Done.")


if __name__ == "__main__":
    main()
