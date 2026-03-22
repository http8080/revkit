#!/usr/bin/env python3
"""revkit security audit automation.

Usage:
    python security_audit.py app.apk
    python security_audit.py sample.exe
    python security_audit.py app.apk --remote http://server:8080

Output: tmp/reports/{filename}_security.md + {filename}_security.json
"""

import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from _helpers import detect_engine, run_rk, start_and_wait, stop_all, setup_cleanup


class SecurityAuditor:
    def __init__(self, path, remote=None):
        self.path = path
        self.engine = detect_engine(path)
        self.remote = remote
        self.findings = []

    def run(self):
        setup_cleanup(self.remote)
        iid = start_and_wait(
            self.engine, self.path,
            fresh=(self.engine == "jeb"), remote=self.remote,
        )
        print(f"[*] Auditing: {os.path.basename(self.path)} ({self.engine})")
        try:
            if self.engine == "jeb":
                self._audit_apk()
            else:
                self._audit_binary()
        finally:
            stop_all(self.engine, self.remote)
        return self.findings

    def _audit_apk(self):
        # Manifest checks
        out, _ = run_rk("jeb", "manifest", remote=self.remote)
        if 'allowBackup="true"' in out:
            self._add("HIGH", "manifest", "allowBackup=true — data extractable via adb backup")
        if 'debuggable="true"' in out:
            self._add("CRITICAL", "manifest", "debuggable=true — app can be debugged")

        # Permissions
        out, _ = run_rk("jeb", "permissions", remote=self.remote)
        dangerous = ["READ_SMS", "READ_CONTACTS", "CAMERA", "RECORD_AUDIO",
                      "ACCESS_FINE_LOCATION", "READ_CALL_LOG"]
        for perm in dangerous:
            if perm in out:
                self._add("MEDIUM", "permissions", f"Dangerous permission: {perm}")

        # Exported components
        out, _ = run_rk("jeb", "entry-points", remote=self.remote)
        if "exported" in out.lower():
            self._add("MEDIUM", "components", "Exported components found (attack surface)")

        # Security scan
        out, _ = run_rk("jeb", "security-scan", remote=self.remote)
        if out:
            self._add("INFO", "security-scan", out[:300])

        # Hardcoded secrets
        out, _ = run_rk("jeb", "strings", "--regex",
                         "password|secret|api.key|token|private.key", remote=self.remote)
        if out and "Total: 0" not in out:
            self._add("HIGH", "secrets", "Potential hardcoded secrets in strings")

        # Native methods
        out, _ = run_rk("jeb", "native-methods", remote=self.remote)
        if "Native Methods" in out and "(0)" not in out:
            self._add("INFO", "native", "Native methods found (JNI interface)")

    def _audit_binary(self):
        # Vulnerability profile
        out, _ = run_rk("ida", "profile", "--action", "run", "vuln", remote=self.remote)
        if out:
            self._add("INFO", "vuln-profile", out[:300])

        # Dangerous imports
        out, _ = run_rk("ida", "strings-xrefs", remote=self.remote, timeout=30)
        if out:
            for keyword in ["http://", "password", "secret"]:
                if keyword in out.lower():
                    self._add("MEDIUM", "strings", f"Suspicious string pattern: {keyword}")

    def _add(self, severity, category, finding):
        self.findings.append({
            "severity": severity,
            "category": category,
            "finding": finding,
        })

    def generate_report(self, output_dir="tmp/reports"):
        os.makedirs(output_dir, exist_ok=True)
        name = Path(self.path).stem

        # JSON
        json_path = f"{output_dir}/{name}_security.json"
        with open(json_path, "w") as f:
            json.dump({"file": self.path, "findings": self.findings,
                        "date": datetime.now().isoformat()}, f, indent=2)

        # Markdown
        md_path = f"{output_dir}/{name}_security.md"
        with open(md_path, "w") as f:
            f.write(f"# Security Audit: {os.path.basename(self.path)}\n\n")
            f.write(f"Date: {datetime.now().isoformat()}\n\n")
            by_sev = {}
            for finding in self.findings:
                sev = finding["severity"]
                by_sev.setdefault(sev, []).append(finding)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                items = by_sev.get(sev, [])
                if items:
                    f.write(f"## {sev} ({len(items)})\n\n")
                    for item in items:
                        f.write(f"- **[{item['category']}]** {item['finding']}\n")
                    f.write("\n")

        print(f"[+] JSON: {json_path}")
        print(f"[+] Report: {md_path}")
        print(f"[*] Total findings: {len(self.findings)}")


def main():
    parser = argparse.ArgumentParser(description="revkit security audit")
    parser.add_argument("path", help="File to audit")
    parser.add_argument("--remote", default=None, help="Gateway URL")
    args = parser.parse_args()

    auditor = SecurityAuditor(args.path, args.remote)
    auditor.run()
    auditor.generate_report()


if __name__ == "__main__":
    main()
