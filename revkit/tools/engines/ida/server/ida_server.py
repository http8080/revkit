#!/usr/bin/env python3
"""ida_server.py — idalib-based HTTP JSON-RPC server

Usage:
    python ida_server.py <binary> --id <instance_id> --idb <idb_path>
                         --log <log_path> --config <config_path> [--fresh]

This is a thin entry point. Implementation is in server/ package.
"""

import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# server/ → ida/ → engines/ → tools/
_TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.dirname(_SCRIPT_DIR)))
# ida/ (parent of server/) — needed for ``from server import main``
_IDA_DIR = os.path.dirname(_SCRIPT_DIR)

for _p in (_IDA_DIR, _TOOLS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from server import main

if __name__ == "__main__":
    main()
