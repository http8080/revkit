# -*- coding: utf-8 -*-
"""JEB Headless Server package -- Jython-based HTTP JSON-RPC server."""
# Note: server/ runs under Jython 2.7. Import structure differs from CLI.
# main(ctx) is called from jeb_server.py IScript entry point.

def main(ctx):
    from .framework import run_server
    run_server(ctx)
