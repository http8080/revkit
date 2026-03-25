package revkit.server.util;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Registry and auth token file management.
 * Compatible with Python CLI core/registry.py format.
 *
 * Registry: dict format {iid: entry} — Python CLI auto-converts to list.
 * Auth tokens: plain text, one per line: "iid:port:token\n"
 */
public final class RegistryManager {

    private static final long LOCK_TIMEOUT_MS = 2000;

    private RegistryManager() {}

    // ── Registry ──

    /** Load registry as dict {iid: entry}. Handles both dict and list input. */
    @SuppressWarnings("unchecked")
    public static JSONObject loadRegistry(String path) {
        File f = new File(path);
        if (!f.exists()) return new JSONObject();
        try (InputStreamReader r = new InputStreamReader(
                new FileInputStream(f), StandardCharsets.UTF_8)) {
            Object parsed = new JSONParser().parse(r);
            if (parsed instanceof JSONObject) return (JSONObject) parsed;
            if (parsed instanceof JSONArray) {
                JSONObject dict = new JSONObject();
                for (Object item : (JSONArray) parsed) {
                    if (item instanceof JSONObject) {
                        JSONObject entry = (JSONObject) item;
                        String id = (String) entry.get("id");
                        if (id != null) dict.put(id, entry);
                    }
                }
                return dict;
            }
        } catch (Exception e) {
            // Corrupted file — treat as empty
        }
        return new JSONObject();
    }

    /** Save registry in dict format. */
    public static void saveRegistry(String path, JSONObject data) throws IOException {
        File parent = new File(path).getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();
        try (OutputStreamWriter w = new OutputStreamWriter(
                new FileOutputStream(path), StandardCharsets.UTF_8)) {
            w.write(data.toJSONString());
        }
    }

    /** Update or create a registry entry (locked). */
    @SuppressWarnings("unchecked")
    public static void updateRegistry(String regPath, String iid, JSONObject updates) {
        String lockPath = regPath + ".lock";
        try {
            withLock(lockPath, () -> {
                JSONObject reg = loadRegistry(regPath);
                JSONObject entry = (JSONObject) reg.get(iid);
                if (entry == null) {
                    entry = new JSONObject();
                    entry.put("id", iid);
                }
                entry.putAll(updates);
                reg.put(iid, entry);
                saveRegistry(regPath, reg);
            });
        } catch (Exception e) {
            System.err.println("[revkit] Registry update failed: " + e.getMessage());
        }
    }

    /** Remove an entry from the registry (locked). */
    public static void removeFromRegistry(String regPath, String iid) {
        String lockPath = regPath + ".lock";
        try {
            withLock(lockPath, () -> {
                JSONObject reg = loadRegistry(regPath);
                reg.remove(iid);
                saveRegistry(regPath, reg);
            });
        } catch (Exception e) {
            System.err.println("[revkit] Registry remove failed: " + e.getMessage());
        }
    }

    // ── Auth Tokens ──

    /** Save auth token: append "iid:port:token\n" (locked). */
    public static void saveAuthToken(String tokenPath, String iid, int port, String token) {
        String lockPath = tokenPath + ".lock";
        try {
            withLock(lockPath, () -> {
                List<String> lines = readTokenLines(tokenPath);
                // Remove existing entries for this iid
                lines = lines.stream()
                    .filter(l -> !l.startsWith(iid + ":"))
                    .collect(Collectors.toCollection(ArrayList::new));
                lines.add(String.format("%s:%d:%s", iid, port, token));

                File parent = new File(tokenPath).getParentFile();
                if (parent != null && !parent.exists()) parent.mkdirs();
                Files.write(new File(tokenPath).toPath(), lines, StandardCharsets.UTF_8);
            });
        } catch (Exception e) {
            System.err.println("[revkit] Token save failed: " + e.getMessage());
        }
    }

    /** Remove auth token entries for this iid (locked). */
    public static void removeAuthToken(String tokenPath, String iid) {
        String lockPath = tokenPath + ".lock";
        try {
            withLock(lockPath, () -> {
                List<String> lines = readTokenLines(tokenPath);
                lines = lines.stream()
                    .filter(l -> !l.startsWith(iid + ":"))
                    .collect(Collectors.toCollection(ArrayList::new));
                Files.write(new File(tokenPath).toPath(), lines, StandardCharsets.UTF_8);
            });
        } catch (Exception e) {
            // Ignore — cleanup best-effort
        }
    }

    private static List<String> readTokenLines(String path) {
        File f = new File(path);
        if (!f.exists()) return new ArrayList<>();
        try {
            return Files.readAllLines(f.toPath(), StandardCharsets.UTF_8).stream()
                .filter(l -> !l.trim().isEmpty())
                .collect(Collectors.toCollection(ArrayList::new));
        } catch (IOException e) {
            return new ArrayList<>();
        }
    }

    // ── File Locking ──

    @FunctionalInterface
    interface LockAction {
        void run() throws Exception;
    }

    /**
     * File-based mutex compatible with Python CLI's os.open(O_CREAT|O_EXCL) pattern.
     *
     * Uses java.nio.file.Files.createFile() which is atomic (throws
     * FileAlreadyExistsException if file exists) — equivalent to
     * Python's os.open(path, O_CREAT|O_EXCL|O_WRONLY).
     *
     * Stale lock timeout: 10 seconds (must match Python STALE_LOCK_TIMEOUT).
     * Poll interval: 100ms (must match Python LOCK_POLL_INTERVAL).
     */
    private static final long STALE_LOCK_MS = 10_000;  // Python: STALE_LOCK_TIMEOUT = 10.0
    private static final long LOCK_POLL_MS = 100;       // Python: LOCK_POLL_INTERVAL = 0.1

    private static void withLock(String lockPath, LockAction action) throws Exception {
        Path lock = Path.of(lockPath);
        Path parent = lock.getParent();
        if (parent != null) Files.createDirectories(parent);

        boolean acquired = false;
        long deadline = System.currentTimeMillis() + LOCK_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            try {
                // Atomic create — equivalent to Python os.open(O_CREAT|O_EXCL)
                Files.createFile(lock);
                acquired = true;
                break;
            } catch (FileAlreadyExistsException e) {
                // Lock file exists — check if stale
                try {
                    long age = System.currentTimeMillis()
                             - Files.getLastModifiedTime(lock).toMillis();
                    if (age > STALE_LOCK_MS) {
                        System.err.println("[revkit] Removing stale lock (age="
                            + (age / 1000.0) + "s): " + lockPath);
                        Files.deleteIfExists(lock);
                        continue;
                    }
                } catch (IOException ignored) {
                    // File may have been deleted between check and getLastModifiedTime
                }
            } catch (IOException e) {
                // Retry on other I/O errors
            }
            try { Thread.sleep(LOCK_POLL_MS); } catch (InterruptedException e) { break; }
        }

        try {
            if (!acquired) {
                System.err.println("[revkit] Lock timeout (" + LOCK_TIMEOUT_MS + "ms): " + lockPath);
            }
            action.run();
        } finally {
            if (acquired) {
                try { Files.deleteIfExists(lock); } catch (IOException ignored) {}
            }
        }
    }
}
