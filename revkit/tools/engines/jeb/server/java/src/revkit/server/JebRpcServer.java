package revkit.server;

import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.IRuntimeProject;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.IApkUnit;
import com.sun.net.httpserver.HttpServer;
import org.json.simple.JSONObject;
import revkit.server.util.JsonLogger;
import revkit.server.util.JsonUtil;
import revkit.server.util.RegistryManager;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * JEB Java RPC Server — main entry point.
 * Phase 0.5: 7 methods (ping, status, stop, methods, save, get_classes, get_class_source).
 *
 * Usage: java revkit.server.JebRpcServer -- binary_path instance_id project_path log_path config_path [--fresh]
 */
public class JebRpcServer {

    private final ServerState state = new ServerState();

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: JebRpcServer -- <binary> <iid> <project> <log> <config> [--fresh]");
            System.exit(1);
        }
        String[] extraArgs = extractExtraArgs(args);
        if (extraArgs.length < 5) {
            System.err.println("Usage: JebRpcServer -- <binary> <iid> <project> <log> <config> [--fresh]");
            System.exit(1);
        }
        new JebRpcServer().run(extraArgs);
    }

    @SuppressWarnings("unchecked")
    private void run(String[] args) throws Exception {
        state.setStartTime(System.currentTimeMillis());
        state.setBinaryPath(args[0]);
        state.setInstanceId(args[1]);
        state.setProjectPath(args[2]);
        String logPath = args[3];
        String configPath = args[4];
        boolean fresh = args.length > 5 && "--fresh".equals(args[5]);

        // 1. Load config
        JSONObject config = JsonUtil.parseJsonFile(configPath);
        state.setConfig(config);

        // 2. Logger
        state.setLogPath(logPath);
        state.setLogger(new JsonLogger(logPath));
        state.getLogger().info("JEB Java server starting");

        // 3. Resolve paths
        JSONObject jebCfg = JsonUtil.getMap(config, "jeb");
        String regPath = JsonUtil.getString(jebCfg, "registry");
        state.setRegistryPath(regPath != null && !regPath.isEmpty()
            ? JsonUtil.expandPath(regPath)
            : System.getProperty("user.home") + "/.revkit/jeb/registry.json");

        JSONObject secCfg = JsonUtil.getMap(config, "security");
        state.setAuthTokenPath(JsonUtil.expandPath(
            JsonUtil.getString(secCfg, "auth_token_file", "~/.revkit/auth_tokens.json")));

        // 4. Fresh — delete existing project
        if (fresh) {
            Path prjPath = Paths.get(state.getProjectPath());
            if (Files.exists(prjPath)) {
                if (Files.isDirectory(prjPath)) {
                    Files.walk(prjPath)
                        .sorted(Comparator.reverseOrder())
                        .map(Path::toFile)
                        .forEach(File::delete);
                } else {
                    Files.deleteIfExists(prjPath);
                }
            }
        }

        // 5. Update registry (state: analyzing)
        JSONObject regUpdates = new JSONObject();
        regUpdates.put("state", "analyzing");
        regUpdates.put("pid", ProcessHandle.current().pid());
        regUpdates.put("binary", new File(state.getBinaryPath()).getName());
        regUpdates.put("path", state.getBinaryPath());
        regUpdates.put("project_path", state.getProjectPath());
        regUpdates.put("started", System.currentTimeMillis() / 1000.0);
        RegistryManager.updateRegistry(state.getRegistryPath(), state.getInstanceId(), regUpdates);

        // 6. JEB initialization
        Object runner = initJeb();
        state.setRunner(runner);

        IEnginesContext engctx = (IEnginesContext) runner.getClass()
            .getMethod("getEnginesContext").invoke(runner);
        state.setEngctx(engctx);

        // 7. Open project
        boolean loadedFromJdb2 = false;
        IRuntimeProject prj = null;

        if (!fresh && new File(state.getProjectPath()).exists()) {
            try {
                prj = engctx.loadProject(state.getProjectPath());
                if (prj != null) loadedFromJdb2 = true;
            } catch (Exception e) {
                System.err.println("[revkit] loadProject failed: " + e.getMessage());
                state.getLogger().warn("loadProject failed: " + e.getMessage());
            }
        }

        if (!loadedFromJdb2) {
            runner.getClass().getMethod("open", String.class).invoke(runner, state.getBinaryPath());
            prj = (IRuntimeProject) runner.getClass().getMethod("getOpenedProject").invoke(runner);
        }

        if (prj == null) {
            JSONObject errUpdate = new JSONObject();
            errUpdate.put("state", "error");
            RegistryManager.updateRegistry(state.getRegistryPath(), state.getInstanceId(), errUpdate);
            throw new RuntimeException("Failed to open project: " + state.getBinaryPath());
        }

        state.setProject(prj);
        state.setLoadedFromJdb2(loadedFromJdb2);

        // 8. Cache units
        List<IDexUnit> dexUnits = (List<IDexUnit>) prj.getClass()
            .getMethod("findUnits", Class.class).invoke(prj, IDexUnit.class);
        state.setDexUnits(dexUnits != null ? dexUnits : Collections.emptyList());

        try {
            IApkUnit apk = (IApkUnit) prj.getClass()
                .getMethod("findUnit", Class.class).invoke(prj, IApkUnit.class);
            state.setApkUnit(apk);
        } catch (Exception e) {
            // APK unit may not be present (e.g., raw DEX)
        }

        // 9. Decompiler cache
        state.setDecompilerCache(new DecompilerCache());

        // 10. Auth token
        String authToken = UUID.randomUUID().toString().replace("-", "");
        state.setAuthToken(authToken);

        // 11. HTTP server
        HttpServer httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        httpServer.createContext("/", new RpcHandler(state));
        AtomicInteger threadCounter = new AtomicInteger(0);
        httpServer.setExecutor(Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "revkit-rpc-" + threadCounter.getAndIncrement());
            t.setDaemon(true);
            return t;
        }));
        httpServer.start();
        state.setHttpServer(httpServer);
        state.setActualPort(httpServer.getAddress().getPort());

        // 12. Save auth token
        RegistryManager.saveAuthToken(state.getAuthTokenPath(),
            state.getInstanceId(), state.getActualPort(), authToken);

        // 13. Start heartbeat
        startHeartbeat();

        // 14. Update registry (state: ready)
        JSONObject readyUpdate = new JSONObject();
        readyUpdate.put("state", "ready");
        readyUpdate.put("port", (long) state.getActualPort());
        readyUpdate.put("last_heartbeat", System.currentTimeMillis() / 1000.0);
        RegistryManager.updateRegistry(state.getRegistryPath(), state.getInstanceId(), readyUpdate);

        // 15. Shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                if (!state.getProjectSaved().get()) {
                    state.getEngctx().saveProject(
                        state.getProject().getKey(),
                        state.getProjectPath(), null, null);
                }
            } catch (Exception ignored) {}
            try {
                RegistryManager.removeFromRegistry(state.getRegistryPath(), state.getInstanceId());
            } catch (Exception ignored) {}
            try {
                RegistryManager.removeAuthToken(state.getAuthTokenPath(), state.getInstanceId());
            } catch (Exception ignored) {}
        }, "revkit-shutdown"));

        state.getLogger().info("JEB Java server ready", "port", state.getActualPort());

        System.out.printf("[revkit] JEB Java server ready on port %d (iid=%s)%n",
            state.getActualPort(), state.getInstanceId());
        System.out.flush();

        // 16. Block until stop
        state.getShutdownLatch().await();
        httpServer.stop(0);
        System.exit(0);
    }

    /**
     * Initialize JEB using the obfuscated HeadlessClientContext (JM class).
     */
    private Object initJeb() throws Exception {
        String[] candidates = {"com.pnfsoftware.jeb.JM"};
        for (String className : candidates) {
            try {
                Class<?> cls = Class.forName(className);
                // JM(boolean devMode, String scriptPath, String libDir, String[] extraArgs)
                Object runner = cls.getConstructor(boolean.class, String.class, String.class, String[].class)
                    .newInstance(false, null, null, new String[]{});
                // HeadlessClientContext.initialize() — sets up JEB core context
                // Note: start() requires a script path, so we skip it.
                // initialize() alone is sufficient for API access.
                cls.getMethod("initialize", String[].class).invoke(runner, (Object) new String[]{});
                return runner;
            } catch (ClassNotFoundException e) {
                // Try next candidate
            }
        }
        throw new RuntimeException("Cannot find JEB HeadlessClientContext class. "
            + "Ensure JEB classpath is correct.");
    }

    /**
     * Heartbeat: update registry every 30 seconds.
     */
    @SuppressWarnings("unchecked")
    private void startHeartbeat() {
        JSONObject analysisCfg = JsonUtil.getMap(state.getConfig(), "analysis");
        long intervalMs = JsonUtil.getInt(analysisCfg, "heartbeat_interval", 30) * 1000L;

        Thread heartbeat = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(intervalMs);
                    JSONObject hb = new JSONObject();
                    hb.put("last_heartbeat", System.currentTimeMillis() / 1000.0);
                    RegistryManager.updateRegistry(
                        state.getRegistryPath(), state.getInstanceId(), hb);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    try { state.getLogger().warn("heartbeat error: " + e.getMessage()); }
                    catch (Exception ignored) {}
                }
            }
        }, "revkit-heartbeat");
        heartbeat.setDaemon(true);
        heartbeat.start();
    }

    /**
     * Extract args after "--" (engine.py passes actual args after --).
     */
    private static String[] extractExtraArgs(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if ("--".equals(args[i])) {
                if (i + 1 < args.length) {
                    return Arrays.copyOfRange(args, i + 1, args.length);
                }
                return new String[0];
            }
        }
        return args;
    }
}
