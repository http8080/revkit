# -*- coding: utf-8 -*-
"""Shared constants for the JEB server package.

Both framework.py and handlers.py import from here to avoid
circular import issues and keep constants in a single location.
"""

SERVER_VERSION = "1.0"

MAX_BATCH_DECOMPILE = 20
MAX_SEARCH_RESULTS = 500
MAX_REQUEST_BODY = 1024 * 1024  # 1 MB
