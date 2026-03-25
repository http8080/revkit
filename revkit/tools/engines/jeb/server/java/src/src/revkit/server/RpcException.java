package revkit.server;

/**
 * RPC error with code, message, and optional suggestion.
 * Maps to: {"error": {"code": "...", "message": "...", "suggestion": "..."}}
 */
public class RpcException extends RuntimeException {
    private final String code;
    private final String suggestion;

    public RpcException(String code, String message) {
        this(code, message, null);
    }

    public RpcException(String code, String message, String suggestion) {
        super(message);
        this.code = code;
        this.suggestion = suggestion;
    }

    public String getCode() { return code; }
    public String getSuggestion() { return suggestion; }
}
