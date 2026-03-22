#!/usr/bin/env python3
"""ida-cli -- legacy wrapper for revkit ida."""
import os
import subprocess
import sys

if not os.environ.get("REVKIT_NO_DEPRECATION_WARN"):
    print("[DEPRECATED] Use 'revkit ida ...' instead", file=sys.stderr)

sys.exit(subprocess.call(
    [sys.executable, "-m", "revkit.tools.cli.main", "ida"] + sys.argv[1:]
))
