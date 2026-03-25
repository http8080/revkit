package revkit.server.util;

import org.json.simple.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * JSONL structured logger. Writes to ~/.revkit/logs/jeb/instances/{iid}.jsonl
 */
public class JsonLogger {
    private PrintWriter writer;
    private final String logPath;

    public JsonLogger(String logPath) {
        this.logPath = logPath;
        try {
            File parent = new File(logPath).getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            this.writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(logPath, true), StandardCharsets.UTF_8), true);
        } catch (IOException e) {
            System.err.println("[revkit] Failed to open log: " + logPath + " — " + e.getMessage());
            this.writer = null;
        }
    }

    @SuppressWarnings("unchecked")
    public synchronized void log(String level, String message, JSONObject data) {
        if (writer == null) return;
        JSONObject entry = new JSONObject();
        entry.put("ts", Instant.now().toString());
        entry.put("level", level);
        entry.put("message", message);
        if (data != null) entry.putAll(data);
        writer.println(entry.toJSONString());
    }

    public void info(String msg)  { log("INFO", msg, null); }
    public void warn(String msg)  { log("WARNING", msg, null); }
    public void error(String msg) { log("ERROR", msg, null); }

    @SuppressWarnings("unchecked")
    public void info(String msg, String key, Object val) {
        JSONObject d = new JSONObject();
        d.put(key, val);
        log("INFO", msg, d);
    }

    public void close() {
        if (writer != null) writer.close();
    }

    public String getLogPath() { return logPath; }
}
