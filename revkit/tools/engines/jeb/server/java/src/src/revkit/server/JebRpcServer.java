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
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * JEB Java RPC Server — main entry point.
 * Phase 0.5: 7 methods (ping, status, stop, methods, save, get_classes, get_class_source).
 *
 * Usage: java revkit.server.JebRpcServer -- binary_path instance_id project_path log_path config_path [--fresh]
 */
public class JebRpcServer {

    /** Set by handleStop to cancel in-progress cache warmup early. */
    public static volatile boolean warmupCancelled = false;

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

        // 5. Update registry (state: analyzing) — async (#2)
        JSONObject regUpdates = new JSONObject();
        regUpdates.put("state", "analyzing");
        regUpdates.put("pid", ProcessHandle.current().pid());
        regUpdates.put("binary", new File(state.getBinaryPath()).getName());
        regUpdates.put("path", state.getBinaryPath());
        regUpdates.put("project_path", state.getProjectPath());
        regUpdates.put("started", System.currentTimeMillis() / 1000.0);
        CompletableFuture.runAsync(() ->
            RegistryManager.updateRegistry(state.getRegistryPath(), state.getInstanceId(), regUpdates)
        );

        // 6. JEB initialization (bridge script sets state.engctx)
        Object runner = initJeb();
        state.setRunner(runner);
        IEnginesContext engctx = state.getEngctx();  // set by bridge

        // 7. Auth token + HTTP server (lazy start — serve ping/status BEFORE project opens)
        String authToken = UUID.randomUUID().toString().replace("-", "");
        state.setAuthToken(authToken);

        state.setDecompilerCache(DecompilerCache.createFromConfig(config));

        HttpServer httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        httpServer.createContext("/", new RpcHandler(state));
        int poolSize = JsonUtil.getInt(jebCfg, "thread_pool_size", 4);
        AtomicInteger threadCounter = new AtomicInteger(0);
        httpServer.setExecutor(Executors.newFixedThreadPool(poolSize, r -> {
            Thread t = new Thread(r, "revkit-rpc-" + threadCounter.getAndIncrement());
            t.setDaemon(true);
            return t;
        }));
        httpServer.start();
        state.setHttpServer(httpServer);
        state.setActualPort(httpServer.getAddress().getPort());

        // Save auth token
        RegistryManager.saveAuthToken(state.getAuthTokenPath(),
            state.getInstanceId(), state.getActualPort(), authToken);

        // Start heartbeat
        startHeartbeat();

        state.getLogger().info("HTTP server started (analyzing)", "port", state.getActualPort());

        // 8. Open project (HTTP server already serving ping/status with "analyzing" state)
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

        // 9. Cache units
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

        // 10. Build class index (Optimization #22 — cache dex.getClasses())
        state.buildClassIndex();

        // 10b. Build string cache (Optimization #8 — cache dex.getStrings())
        state.buildStringCache();

        // 11. Mark server as fully ready (data methods now allowed via RpcDispatcher guard)
        state.setServerReady(true);

        // 12. Update registry (state: ready) — async (#2)
        JSONObject readyUpdate = new JSONObject();
        readyUpdate.put("state", "ready");
        readyUpdate.put("port", (long) state.getActualPort());
        readyUpdate.put("last_heartbeat", System.currentTimeMillis() / 1000.0);
        CompletableFuture.runAsync(() ->
            RegistryManager.updateRegistry(state.getRegistryPath(), state.getInstanceId(), readyUpdate)
        );

        // 13. Shutdown hook
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

        // 14. Background cache warmup (Phase 2 — parallel decompile)
        //     Optimization #2: warmup config + framework class filter
        Thread warmup = new Thread(() -> {
            try {
                // Read warmup config
                JSONObject warmupCfg = JsonUtil.getMap(jebCfg, "warmup");
                boolean warmupEnabled = JsonUtil.getBool(warmupCfg, "enabled", true);
                int warmupMaxClasses = JsonUtil.getInt(warmupCfg, "max_classes", 5000);
                boolean skipFramework = JsonUtil.getBool(warmupCfg, "skip_framework", true);

                if (!warmupEnabled) {
                    state.getLogger().info("Cache warmup disabled by config");
                    return;
                }

                // Use cached classes from buildClassIndex() (#22)
                List<String> allClasses = new ArrayList<>();
                if (state.getCachedClasses() != null) {
                    for (com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass cls : state.getCachedClasses()) {
                        allClasses.add(cls.getSignature(false));
                    }
                }

                if (allClasses.isEmpty()) return;
                if (warmupCancelled) {
                    state.getLogger().info("Cache warmup cancelled by stop signal");
                    return;
                }

                // Filter framework classes if configured (#2)
                List<String> warmupClasses = allClasses;
                if (skipFramework) {
                    warmupClasses = allClasses.stream()
                        .filter(s -> !s.startsWith("Landroid/") && !s.startsWith("Ljava/")
                                  && !s.startsWith("Lkotlin/") && !s.startsWith("Landroidx/"))
                        .collect(Collectors.toList());
                }
                if (warmupMaxClasses > 0 && warmupClasses.size() > warmupMaxClasses) {
                    warmupClasses = warmupClasses.subList(0, warmupMaxClasses);
                }

                if (warmupCancelled) {
                    state.getLogger().info("Cache warmup cancelled by stop signal");
                    return;
                }

                state.getLogger().info(String.format(
                    "Cache warmup started: total=%d, warmup=%d, skip_framework=%s",
                    allClasses.size(), warmupClasses.size(), skipFramework));
                long t0 = System.currentTimeMillis();
                IDexUnit firstDex = state.getDexUnits().get(0);
                int ok = state.getDecompilerCache().warmupAll(firstDex, warmupClasses, 0, null);
                long elapsed = System.currentTimeMillis() - t0;
                state.getLogger().info(String.format(
                    "Cache warmup complete: %d/%d classes in %dms",
                    ok, warmupClasses.size(), elapsed));
            } catch (Exception e) {
                state.getLogger().warn("Cache warmup failed: " + e.getMessage());
            }
        }, "revkit-cache-warmup");
        warmup.setDaemon(true);
        warmup.start();

        // 15. Block until stop signal (from handleStop -> countDown)
        state.getShutdownLatch().await();
        httpServer.stop(1);  // 1-second grace for in-flight responses
        state.getLogger().info("Server shutdown complete", "iid", state.getInstanceId());
        System.exit(0);
    }

    /**
     * Initialize JEB using a Jython bridge script.
     *
     * Strategy: Create a Jython script that:
     * 1. Gets engctx from the JEB script context (ctx.getEnginesContext())
     * 2. Stores it in a shared static field on JebRpcServer
     * 3. Signals readiness via CountDownLatch
     * 4. Blocks until shutdown (keeps JEB alive)
     *
     * This is clean because engctx is obtained naturally through JEB's
     * script lifecycle — no polling or reflection needed.
     */
    private Object initJeb() throws Exception {
        // Strategy: JM.start() blocks while running a Jython script.
        // We use a minimal "keeper" script that blocks forever, then
        // poll getEnginesContext() from Java side until it's ready.
        //
        // This is the simplest reliable approach — JM sets up engctx
        // during start() before running the script, so polling catches
        // it within a few hundred milliseconds.
        Path keeperScript = Files.createTempFile("revkit_jeb_keeper_", ".py");
        Files.write(keeperScript, java.util.Arrays.asList(
            "# revkit — keeper script (blocks to keep JEB alive)",
            "from java.util.concurrent import CountDownLatch",
            "latch = CountDownLatch(1)",
            "latch.await()  # blocks forever until JVM exits"
        ));
        keeperScript.toFile().deleteOnExit();

        String[] candidates = {"com.pnfsoftware.jeb.JM"};
        for (String className : candidates) {
            try {
                Class<?> cls = Class.forName(className);
                Object runner = cls.getConstructor(boolean.class, String.class, String.class, String[].class)
                    .newInstance(false, keeperScript.toString(), null, new String[]{});
                cls.getMethod("initialize", String[].class).invoke(runner, (Object) new String[]{});

                // start() in background (blocks running keeper script)
                Thread jebThread = new Thread(() -> {
                    try {
                        cls.getMethod("start").invoke(runner);
                    } catch (Exception e) {
                        System.err.println("[revkit] JM.start() exited: " + e.getMessage());
                    }
                }, "jeb-core");
                jebThread.setDaemon(true);
                jebThread.start();

                // Poll until engctx is available (max 60s)
                Method getEngCtx = cls.getMethod("getEnginesContext");
                long deadline = System.currentTimeMillis() + 60_000;
                while (System.currentTimeMillis() < deadline) {
                    Object ctx = getEngCtx.invoke(runner);
                    if (ctx != null) {
                        state.setEngctx((IEnginesContext) ctx);
                        return runner;
                    }
                    Thread.sleep(200);
                }
                throw new RuntimeException("JEB enginesContext not available after 60s");
            } catch (ClassNotFoundException e) {
                // Try next candidate
            }
        }
        throw new RuntimeException("Cannot find JEB HeadlessClientContext class");
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
