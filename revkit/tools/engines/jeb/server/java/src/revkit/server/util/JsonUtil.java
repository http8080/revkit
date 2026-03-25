package revkit.server.util;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import revkit.server.RpcException;

/**
 * json-simple utility methods. Equivalent to Jython helpers.py _to_str() etc.
 */
public final class JsonUtil {

    private JsonUtil() {}

    /** Jython _to_str() equivalent: null -> "", else toString(). */
    public static String toStr(Object obj) {
        if (obj == null) return "";
        return obj.toString();
    }

    /** Null-safe string extraction. */
    public static String getString(JSONObject obj, String key) {
        if (obj == null) return null;
        Object v = obj.get(key);
        return v == null ? null : v.toString();
    }

    /** Null-safe string with default. */
    public static String getString(JSONObject obj, String key, String def) {
        String v = getString(obj, key);
        return v == null ? def : v;
    }

    /** Null-safe int extraction. json-simple stores numbers as Long. */
    public static int getInt(JSONObject obj, String key, int def) {
        if (obj == null) return def;
        Object v = obj.get(key);
        if (v instanceof Number) return ((Number) v).intValue();
        if (v instanceof String) {
            try { return Integer.parseInt((String) v); }
            catch (NumberFormatException e) { return def; }
        }
        return def;
    }

    /** Null-safe long extraction. */
    public static long getLong(JSONObject obj, String key, long def) {
        if (obj == null) return def;
        Object v = obj.get(key);
        if (v instanceof Number) return ((Number) v).longValue();
        return def;
    }

    /** Null-safe boolean extraction. */
    public static boolean getBool(JSONObject obj, String key, boolean def) {
        if (obj == null) return def;
        Object v = obj.get(key);
        if (v instanceof Boolean) return (Boolean) v;
        return def;
    }

    /** Get nested JSONObject safely. */
    @SuppressWarnings("unchecked")
    public static JSONObject getMap(JSONObject obj, String key) {
        if (obj == null) return new JSONObject();
        Object v = obj.get(key);
        if (v instanceof JSONObject) return (JSONObject) v;
        return new JSONObject();
    }

    /** Require a string parameter or throw RpcException. */
    public static String requireParam(JSONObject params, String key) {
        Object v = params.get(key);
        if (v == null || v.toString().isEmpty()) {
            throw new RpcException("MISSING_PARAM",
                "Required parameter '" + key + "' is missing",
                "Provide '" + key + "' in params");
        }
        return v.toString();
    }

    /** Parse JSON string, return JSONObject. */
    public static JSONObject parseJson(String s) {
        try {
            Object parsed = new JSONParser().parse(s.trim());
            if (parsed instanceof JSONObject) return (JSONObject) parsed;
            throw new RpcException("INVALID_PARAMS", "Expected JSON object");
        } catch (org.json.simple.parser.ParseException e) {
            throw new RpcException("INVALID_PARAMS", "Invalid JSON: " + e.getMessage());
        }
    }

    /** Expand ~ to user home. */
    public static String expandPath(String path) {
        if (path == null || path.isEmpty()) return path;
        if (path.startsWith("~")) {
            return System.getProperty("user.home") + path.substring(1);
        }
        return path;
    }

    /** Parse a JSON file and return JSONObject. */
    public static JSONObject parseJsonFile(String path) {
        try {
            byte[] bytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path));
            String content = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
            return parseJson(content);
        } catch (java.io.IOException e) {
            // Return empty config on file read failure
            return new JSONObject();
        }
    }
}
