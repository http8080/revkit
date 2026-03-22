class RpcError(Exception):
    def __init__(self, code, message, suggestion=None):
        self.code = code
        self.message = message
        self.suggestion = suggestion
        super().__init__(message)
