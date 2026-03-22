# -*- coding: utf-8 -*-
"""Shared exception classes for JEB server.

Jython 2.7 compatible -- no f-strings, no type hints.
"""


class RpcError(Exception):
    def __init__(self, code, message, suggestion=None):
        self.code = code
        self.message = message
        self.suggestion = suggestion
        super(RpcError, self).__init__(message)
