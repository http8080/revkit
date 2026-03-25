package revkit.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import revkit.server.util.JsonUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.GZIPOutputStream;

/**
 * HTTP handler for JSON-RPC requests.
 * Host validation, Bearer auth, size limit, JSON parse, dispatch.
 */
public class RpcHandler implements HttpHandler {

    private static final int MAX_REQUEST_BODY = 1_048_576;  // 1 MB

    private final ServerState state;
    private final RpcDispatcher dispatcher;
    private final Set<String> allowedHosts;

    public RpcHandler(ServerState state) {
        this.state = state;
        this.dispatcher = new RpcDispatcher(state);
        // Pre-compute allowed Host header values (Optimization: configurable host validation)
        int port = state.getActualPort();
        this.allowedHosts = new HashSet<>();
        allowedHosts.add("127.0.0.1:" + port);
        allowedHosts.add("localhost:" + port);
        allowedHosts.add("0.0.0.0:" + port);
        // Add custom host from config (e.g. server.host = "10.0.0.1")
        String configHost = JsonUtil.getString(
            JsonUtil.getMap(state.getConfig(), "server"), "host", "");
        if (!configHost.isEmpty()
                && !"127.0.0.1".equals(configHost)
                && !"localhost".equals(configHost)
                && !"0.0.0.0".equals(configHost)) {
            allowedHosts.add(configHost + ":" + port);
        }
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            // 1. Host validation (DNS rebinding defense)
            String host = exchange.getRequestHeaders().getFirst("Host");
            if (host == null) host = "";
            // Pre-computed allowed hosts set (includes config server.host)
            if (!allowedHosts.contains(host)) {
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

    /** Minimum response size to consider gzip compression (4 KB). */
    private static final int GZIP_THRESHOLD = 4096;

    private void sendJson(HttpExchange exchange, JSONObject obj) throws IOException {
        byte[] resp = obj.toJSONString().getBytes(StandardCharsets.UTF_8);

        // Optimization #9: gzip large responses if client accepts it
        String acceptEncoding = exchange.getRequestHeaders().getFirst("Accept-Encoding");
        if (acceptEncoding != null && acceptEncoding.contains("gzip") && resp.length > GZIP_THRESHOLD) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(resp.length / 2);
            try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
                gzip.write(resp);
            }
            byte[] compressed = baos.toByteArray();
            exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
            exchange.getResponseHeaders().add("Content-Encoding", "gzip");
            exchange.sendResponseHeaders(200, compressed.length);
            try (OutputStream os = exchange.getResponseBody()) {
                // Optimization #7: stream in chunks for large responses
                if (compressed.length > 1_048_576) {
                    int offset = 0;
                    while (offset < compressed.length) {
                        int len = Math.min(65536, compressed.length - offset);
                        os.write(compressed, offset, len);
                        offset += len;
                    }
                    os.flush();
                } else {
                    os.write(compressed);
                }
            }
        } else {
            exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                // Optimization #7: stream in chunks for responses > 1 MB
                if (resp.length > 1_048_576) {
                    int offset = 0;
                    while (offset < resp.length) {
                        int len = Math.min(65536, resp.length - offset);
                        os.write(resp, offset, len);
                        offset += len;
                    }
                    os.flush();
                } else {
                    os.write(resp);
                }
            }
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
