package revkit.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * HTTP handler for JSON-RPC requests.
 * Host validation, Bearer auth, size limit, JSON parse, dispatch.
 */
public class RpcHandler implements HttpHandler {

    private static final int MAX_REQUEST_BODY = 1_048_576;  // 1 MB

    private final ServerState state;
    private final RpcDispatcher dispatcher;

    public RpcHandler(ServerState state) {
        this.state = state;
        this.dispatcher = new RpcDispatcher(state);
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            // 1. Host validation (DNS rebinding defense)
            String host = exchange.getRequestHeaders().getFirst("Host");
            if (host == null) host = "";
            int port = state.getActualPort();
            // Allow 127.0.0.1, localhost, and 0.0.0.0 (CLI may use config server.host)
            if (!host.equals("127.0.0.1:" + port)
                    && !host.equals("localhost:" + port)
                    && !host.equals("0.0.0.0:" + port)) {
                sendError(exchange, null, "FORBIDDEN_HOST",
                    "Invalid Host header: " + host, null);
                return;
            }

            // 2. Bearer auth (timing-safe comparison)
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth == null) auth = "";
            String expected = "Bearer " + state.getAuthToken();
            if (!MessageDigest.isEqual(
                    auth.getBytes(StandardCharsets.UTF_8),
                    expected.getBytes(StandardCharsets.UTF_8))) {
                sendError(exchange, null, "AUTH_FAILED", "Invalid or missing auth token", null);
                return;
            }

            // 3. Content-Length pre-check
            String contentLen = exchange.getRequestHeaders().getFirst("Content-Length");
            if (contentLen != null) {
                try {
                    if (Long.parseLong(contentLen) > MAX_REQUEST_BODY) {
                        sendError(exchange, null, "INVALID_PARAMS",
                            "Content-Length exceeds limit (" + MAX_REQUEST_BODY + " bytes)", null);
                        return;
                    }
                } catch (NumberFormatException ignored) {}
            }

            // 4. Read and parse body
            byte[] bodyBytes = readWithLimit(exchange.getRequestBody(), MAX_REQUEST_BODY);
            String body = new String(bodyBytes, StandardCharsets.UTF_8);
            JSONParser parser = new JSONParser();
            JSONObject request = (JSONObject) parser.parse(body.trim());

            String method = (String) request.get("method");
            if (method == null || method.isEmpty()) {
                sendError(exchange, request.get("id"), "INVALID_PARAMS", "Missing 'method'", null);
                return;
            }
            JSONObject params = (JSONObject) request.get("params");
            if (params == null) params = new JSONObject();
            Object reqId = request.getOrDefault("id", 1L);

            // 5. Dispatch
            JSONObject result = dispatcher.dispatch(method, params);

            // 6. Success response
            JSONObject response = new JSONObject();
            response.put("result", result);
            response.put("id", reqId);
            sendJson(exchange, response);

        } catch (RpcException e) {
            sendError(exchange, null, e.getCode(), e.getMessage(), e.getSuggestion());
        } catch (Exception e) {
            sendError(exchange, null, "INTERNAL",
                e.getClass().getName() + ": " + e.getMessage(), null);
        }
    }

    private void sendJson(HttpExchange exchange, JSONObject obj) throws IOException {
        byte[] resp = obj.toJSONString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, resp.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(resp);
        }
    }

    @SuppressWarnings("unchecked")
    private void sendError(HttpExchange ex, Object id, String code, String msg, String suggestion)
            throws IOException {
        JSONObject error = new JSONObject();
        error.put("code", code);
        error.put("message", msg);
        if (suggestion != null) error.put("suggestion", suggestion);
        JSONObject resp = new JSONObject();
        resp.put("error", error);
        resp.put("id", id);
        sendJson(ex, resp);
    }

    private byte[] readWithLimit(InputStream is, int limit) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0, n;
        while ((n = is.read(buf)) != -1) {
            total += n;
            if (total > limit) {
                throw new RpcException("INVALID_PARAMS",
                    "Request body too large (" + total + " bytes, max " + limit + ")");
            }
            baos.write(buf, 0, n);
        }
        return baos.toByteArray();
    }
}
