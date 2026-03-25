package revkit.server;

import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.IRuntimeProject;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.IApkUnit;
import com.sun.net.httpserver.HttpServer;
import org.json.simple.JSONObject;
import revkit.server.util.JsonLogger;
import revkit.server.util.JsonUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Immutable server state holder. Set once during init, read by all handlers.
 */
public class ServerState {
    // JEB context
    private IEnginesContext engctx;
    private IRuntimeProject project;
    private List<IDexUnit> dexUnits;
    private IApkUnit apkUnit;
    private Object runner;  // AbstractClientContext (JM) — kept as Object to avoid import

    // Server
    private HttpServer httpServer;
    private int actualPort;
    private String authToken;
    private final CountDownLatch shutdownLatch = new CountDownLatch(1);
    private final AtomicBoolean projectSaved = new AtomicBoolean(false);

    // Config
    private JSONObject config;
    private String binaryPath;
    private String instanceId;
    private String projectPath;
    private String logPath;
    private String registryPath;
    private String authTokenPath;
    private long startTime;
    private boolean loadedFromJdb2;
    private DecompilerCache decompilerCache;
    private JsonLogger logger;

    // Output settings
    private int defaultCount = 50;
    private int maxCount = 500;
    private boolean autoSave = true;

    // Cached counts
    private int totalClassCount = -1;
    private int totalMethodCount = -1;

    // ── Getters ──
    public IEnginesContext getEngctx() { return engctx; }
    public IRuntimeProject getProject() { return project; }
    public List<IDexUnit> getDexUnits() { return dexUnits; }
    public IApkUnit getApkUnit() { return apkUnit; }
    public Object getRunner() { return runner; }
    public HttpServer getHttpServer() { return httpServer; }
    public int getActualPort() { return actualPort; }
    public String getAuthToken() { return authToken; }
    public CountDownLatch getShutdownLatch() { return shutdownLatch; }
    public AtomicBoolean getProjectSaved() { return projectSaved; }
    public JSONObject getConfig() { return config; }
    public String getBinaryPath() { return binaryPath; }
    public String getInstanceId() { return instanceId; }
    public String getProjectPath() { return projectPath; }
    public String getLogPath() { return logPath; }
    public String getRegistryPath() { return registryPath; }
    public String getAuthTokenPath() { return authTokenPath; }
    public long getStartTime() { return startTime; }
    public boolean isLoadedFromJdb2() { return loadedFromJdb2; }
    public DecompilerCache getDecompilerCache() { return decompilerCache; }
    public JsonLogger getLogger() { return logger; }
    public int getDefaultCount() { return defaultCount; }
    public int getMaxCount() { return maxCount; }
    public boolean isAutoSave() { return autoSave; }

    // ── Setters (called once during init) ──
    public void setEngctx(IEnginesContext v) { this.engctx = v; }
    public void setProject(IRuntimeProject v) { this.project = v; }
    public void setDexUnits(List<IDexUnit> v) { this.dexUnits = v; }
    public void setApkUnit(IApkUnit v) { this.apkUnit = v; }
    public void setRunner(Object v) { this.runner = v; }
    public void setHttpServer(HttpServer v) { this.httpServer = v; }
    public void setActualPort(int v) { this.actualPort = v; }
    public void setAuthToken(String v) { this.authToken = v; }
    public void setConfig(JSONObject v) {
        this.config = v;
        JSONObject output = JsonUtil.getMap(v, "output");
        this.defaultCount = JsonUtil.getInt(output, "default_count", 50);
        this.maxCount = JsonUtil.getInt(output, "max_count", 500);
        JSONObject analysis = JsonUtil.getMap(v, "analysis");
        this.autoSave = JsonUtil.getBool(analysis, "auto_save", true);
    }
    public void setBinaryPath(String v) { this.binaryPath = v; }
    public void setInstanceId(String v) { this.instanceId = v; }
    public void setProjectPath(String v) { this.projectPath = v; }
    public void setLogPath(String v) { this.logPath = v; }
    public void setRegistryPath(String v) { this.registryPath = v; }
    public void setAuthTokenPath(String v) { this.authTokenPath = v; }
    public void setStartTime(long v) { this.startTime = v; }
    public void setLoadedFromJdb2(boolean v) { this.loadedFromJdb2 = v; }
    public void setDecompilerCache(DecompilerCache v) { this.decompilerCache = v; }
    public void setLogger(JsonLogger v) { this.logger = v; }

    // ── Utility ──

    /** Find IDexUnit containing a class signature. */
    public IDexUnit findDexForClass(String sig) {
        if (dexUnits == null) return null;
        for (IDexUnit dex : dexUnits) {
            try {
                if (dex.getClass(sig) != null) return dex;
            } catch (Exception e) { /* skip */ }
        }
        return null;
    }

    /** Get total class count (cached). */
    public int getTotalClassCount() {
        if (totalClassCount < 0) {
            int count = 0;
            if (dexUnits != null) {
                for (IDexUnit dex : dexUnits) {
                    try { count += dex.getClasses().size(); }
                    catch (Exception e) { /* skip */ }
                }
            }
            totalClassCount = count;
        }
        return totalClassCount;
    }

    /** Get total method count (cached). */
    public int getTotalMethodCount() {
        if (totalMethodCount < 0) {
            int count = 0;
            if (dexUnits != null) {
                for (IDexUnit dex : dexUnits) {
                    try {
                        for (Object cls : dex.getClasses()) {
                            count += ((IDexClass) cls).getMethods().size();
                        }
                    } catch (Exception e) { /* skip */ }
                }
            }
            totalMethodCount = count;
        }
        return totalMethodCount;
    }

    /** Compute MD5 of a file. */
    public static String fileMd5(String path) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            try (InputStream is = new FileInputStream(path)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) md.update(buf, 0, n);
            }
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
