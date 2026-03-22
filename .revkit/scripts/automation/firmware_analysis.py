#!/usr/bin/env python3
"""Firmware binary analysis using IDA engine.

Usage:
    python firmware_analysis.py firmware.bin
    python firmware_analysis.py firmware.elf --remote http://server:8080
    python firmware_analysis.py firmware.bin --output fw_report.json
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import argparse
import json
from _helpers import run_rk, start_and_wait, stop_all, setup_cleanup

PERIPHERAL_KEYWORDS = {
    "uart": ["uart", "serial", "baud", "tx_buf", "rx_buf"],
    "spi": ["spi", "spi_transfer", "spi_init"],
    "i2c": ["i2c", "i2c_read", "i2c_write", "twi"],
    "gpio": ["gpio", "pin_set", "pin_get", "digital_write"],
    "timer": ["timer", "systick", "watchdog", "wdt"],
    "dma": ["dma", "dma_channel", "dma_transfer"],
}

CREDENTIAL_KEYWORDS = ["password", "passwd", "login", "admin", "root",
                         "secret", "key", "token", "shell", "telnet",
                         "backdoor", "debug"]


def analyze_firmware(iid: str, remote=None) -> dict:
    """Run firmware-specific analysis."""
    results: dict[str, object] = {}

    # Memory map via segments
    out, _ = run_rk("ida", "segments", "-i", iid, "--json",
                     timeout=120, remote=remote)
    try:
        results["memory_map"] = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        results["memory_map"] = {"raw": out}

    # Image base
    out, _ = run_rk("ida", "imagebase", "-i", iid, "--json", remote=remote)
    results["imagebase"] = out.strip() if out else "unknown"

    # Peripheral interfaces
    peripherals: dict[str, list[str]] = {}
    for category, keywords in PERIPHERAL_KEYWORDS.items():
        for kw in keywords:
            out, _ = run_rk("ida", "find-func", kw, "-i", iid,
                             "--json", remote=remote)
            if out and "no " not in out.lower():
                peripherals.setdefault(category, []).append(kw)
    results["peripherals"] = peripherals

    # Credential / backdoor strings
    out, _ = run_rk("ida", "strings-xrefs", "-i", iid, "--json",
                     timeout=120, remote=remote)
    strings_text = (out or "").lower()
    found_creds = [kw for kw in CREDENTIAL_KEYWORDS if kw in strings_text]
    results["credential_strings"] = found_creds

    # Profile
    out, _ = run_rk("ida", "profile", "-i", iid, "--json",
                     timeout=120, remote=remote)
    try:
        results["profile"] = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        results["profile"] = {"raw": out}

    # Summary
    out, _ = run_rk("ida", "summary", "-i", iid, "--json", remote=remote)
    try:
        results["summary"] = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        results["summary"] = {"raw": out}

    return results


def main():
    parser = argparse.ArgumentParser(description="Firmware analysis (IDA only)")
    parser.add_argument("path", help="Firmware binary file path")
    parser.add_argument("--remote", default=None, help="Gateway URL for remote mode")
    parser.add_argument("--output", "-o", default=None, help="Output JSON file")
    args = parser.parse_args()

    setup_cleanup(args.remote)

    print(f"[*] Firmware: {args.path}")
    iid = start_and_wait("ida", args.path, remote=args.remote)
    print(f"[*] Instance {iid} ready, analyzing firmware ...")

    results = analyze_firmware(iid, args.remote)

    report = {
        "file": args.path,
        "engine": "ida",
        "imagebase": results.get("imagebase"),
        "peripherals_found": list(results.get("peripherals", {}).keys()),
        "credential_strings": results.get("credential_strings", []),
        "analysis": results,
    }

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))

    stop_all("ida", args.remote)
    print("[+] Done.")


if __name__ == "__main__":
    main()
