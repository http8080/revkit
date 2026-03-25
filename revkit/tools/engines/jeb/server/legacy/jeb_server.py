# -*- coding: utf-8 -*-
"""jeb_server.py -- JEB Jython-based HTTP JSON-RPC server

Usage:
    Launched by jeb_cli.py via:
      jeb_wincon.bat -c --script=jeb_server.py -- <args>  (Method B)
      java -cp ... JebScriptRunner jeb_server.py -- <args> (Method A)

This is a thin entry point. Implementation is in server/ package.
Note: This file runs under Jython 2.7 (Python 2 syntax).
"""
#?description=JEB Headless HTTP JSON-RPC Server
from com.pnfsoftware.jeb.client.api import IScript

class jeb_server(IScript):
    def run(self, ctx):
        import os, sys, traceback
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(script_dir)
            if parent_dir not in sys.path:
                sys.path.insert(0, parent_dir)
            from server import main
            main(ctx)
        except Exception as e:
            sys.stderr.write("[jeb_server] ERROR: %s\n" % e)
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
