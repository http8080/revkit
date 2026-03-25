package revkit.server.handlers;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;
import revkit.server.util.RegistryManager;

/**
 * System RPC handlers: ping, status, stop, methods, save.
 */
public final class SystemHandlers {

    private SystemHandlers() {}

    @SuppressWarnings("unchecked")
    public static JSONObject handlePing(JSONObject params, ServerState state) {
        JSONObject r = new JSONObject();
        r.put("ok", true);
        r.put("state", "ready");
        return r;
    }

    @SuppressWarnings("unchecked")
    public static JSONObject handleStatus(JSONObject params, ServerState state) {
        JSONObject r = new JSONObject();
        r.put("state", "ready");
        r.put("binary", new java.io.File(state.getBinaryPath()).getName());
        r.put("project_path", state.getProjectPath());
        r.put("binary_md5", ServerState.fileMd5(state.getBinaryPath()));
        r.put("class_count", (long) state.getTotalClassCount());
        r.put("method_count", (long) state.getTotalMethodCount());
        r.put("dex_count", (long) (state.getDexUnits() != null ? state.getDexUnits().size() : 0));
        r.put("jeb_version", getJebVersion(state));
        r.put("server_version", "1.0-java");
        r.put("uptime", (System.currentTimeMillis() - state.getStartTime()) / 1000.0);
        r.put("spawn_method", "java");
        r.put("loaded_from_jdb2", state.isLoadedFromJdb2());

        // JVM info
        JSONObject jebCfg = JsonUtil.getMap(state.getConfig(), "jeb");
        r.put("java_home", JsonUtil.getString(jebCfg, "java_home", System.getProperty("java.home")));
        Object jvmOpts = jebCfg.get("jvm_opts");
        r.put("jvm_opts", jvmOpts != null ? jvmOpts : new JSONArray());

        return r;
    }

    @SuppressWarnings("unchecked")
    public static JSONObject handleStop(JSONObject params, ServerState state) {
        // Save project first
        JSONObject r = new JSONObject();
        try {
            state.getEngctx().saveProject(
                state.getProject().getKey(),
                state.getProjectPath(), null, null);
            state.getProjectSaved().set(true);
            r.put("ok", true);
        } catch (Exception e) {
            r.put("ok", false);
            r.put("save_error", e.getMessage());
        }

        // Clean up registry and auth token BEFORE shutdown
        // (Don't rely on shutdown hook — CLI checks registry to confirm stop)
        try {
            RegistryManager.removeFromRegistry(state.getRegistryPath(), state.getInstanceId());
        } catch (Exception ignored) {}
        try {
            RegistryManager.removeAuthToken(state.getAuthTokenPath(), state.getInstanceId());
        } catch (Exception ignored) {}

        // Schedule shutdown after HTTP response is flushed
        // countDown() wakes main thread → httpServer.stop(1) → System.exit(0)
        Thread stopThread = new Thread(() -> {
            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
            state.getShutdownLatch().countDown();
        }, "revkit-stop");
        stopThread.setDaemon(true);
        stopThread.start();

        return r;
    }

    @SuppressWarnings("unchecked")
    public static JSONObject handleMethods(JSONObject params, ServerState state) {
        // Full method list — must match Jython server's _METHODS for CLI compatibility
        String[][] methods = {
            {"ping", "Check server connectivity."},
            {"status", "Server status and binary info."},
            {"stop", "Save project and stop server."},
            {"methods", "List available RPC methods."},
            {"save", "Save project to disk."},
            {"get_classes", "List classes (paginated)."},
            {"get_class_source", "Decompile a class to Java source."},
            {"decompile", "Alias for get_class_source."},
            {"get_class_source_with_xrefs", "Decompile with cross-references."},
            {"decompile_with_xrefs", "Alias for get_class_source_with_xrefs."},
            {"get_method_by_name", "Get a method's decompiled code."},
            {"decompile_batch", "Batch decompile multiple classes."},
            {"decompile_all", "Decompile all classes."},
            {"get_smali", "Get Smali/bytecode for a class."},
            {"get_manifest", "Get AndroidManifest.xml content."},
            {"decompile_diff", "Compare two decompiled versions."},
            {"get_method_info", "Get method details."},
            {"get_methods_of_class", "List methods of a class."},
            {"get_fields_of_class", "List fields of a class."},
            {"get_imports", "List imports."},
            {"get_exports", "List exports."},
            {"native_methods", "List native methods."},
            {"get_strings", "List strings (paginated)."},
            {"get_strings_xrefs", "Strings with cross-references."},
            {"get_resources_list", "List APK resources."},
            {"get_resources", "Alias for get_resources_list."},
            {"get_resource", "Get a specific resource content."},
            {"search_classes", "Search classes by name."},
            {"search_methods", "Search methods by name."},
            {"search_code", "Search in decompiled code."},
            {"get_xrefs", "Get cross-references for an item."},
            {"get_xrefs_to", "Alias for get_xrefs (direction=to)."},
            {"get_xrefs_from", "Alias for get_xrefs (direction=from)."},
            {"callgraph", "Build call graph for a class."},
            {"cross_refs", "Get cross-references summary."},
            {"rename", "Rename a DEX item."},
            {"rename_class", "Rename a class."},
            {"rename_method", "Rename a method."},
            {"rename_field", "Rename a field."},
            {"rename_batch", "Batch rename from JSON."},
            {"rename_preview", "Preview rename effect."},
            {"set_comment", "Set an inline comment."},
            {"get_comments", "Get all comments."},
            {"undo", "Undo last rename."},
            {"export_annotations", "Export annotations to JSON."},
            {"import_annotations", "Import annotations from JSON."},
            {"snapshot_save", "Save project snapshot."},
            {"snapshot_list", "List saved snapshots."},
            {"snapshot_restore", "Restore a snapshot."},
            {"auto_rename", "Heuristic auto-rename based on string references."},
            {"info", "Get binary/APK info."},
            {"summary", "Generate analysis summary."},
            {"exec", "Execute Python code via Jython."},
            {"strings_xrefs", "Alias for get_strings_xrefs."},
            {"get_main_activity", "Get main activity class."},
            {"get_app_classes", "Get application classes."},
            {"get_app_class", "Alias for get_app_classes."},
            {"report", "Generate analysis report."},
            {"entry_points", "Identify entry points."},
            {"security_scan", "Run security pattern scan."},
            {"save_project", "Alias for save."},
        };

        JSONArray list = new JSONArray();
        for (String[] m : methods) {
            JSONObject item = new JSONObject();
            item.put("name", m[0]);
            item.put("description", m[1]);
            list.add(item);
        }

        JSONObject r = new JSONObject();
        r.put("methods", list);
        return r;
    }

    @SuppressWarnings("unchecked")
    public static JSONObject handleSave(JSONObject params, ServerState state) {
        JSONObject r = new JSONObject();
        try {
            state.getEngctx().saveProject(
                state.getProject().getKey(),
                state.getProjectPath(), null, null);
            r.put("ok", true);
            r.put("project_path", state.getProjectPath());
        } catch (Exception e) {
            r.put("ok", false);
            r.put("error", e.getMessage());
        }
        return r;
    }

    /** Get JEB version from CoreContext if available. */
    private static String getJebVersion(ServerState state) {
        try {
            // ICoreContext.getSoftwareVersion() → IVersion
            Object ctx = state.getEngctx().getClass()
                .getMethod("getCoreContext").invoke(state.getEngctx());
            if (ctx != null) {
                Object ver = ctx.getClass().getMethod("getSoftwareVersion").invoke(ctx);
                if (ver != null) return ver.toString();
            }
        } catch (Exception e) {
            // Reflection failed — fallback
        }
        return "5.38";  // Hardcoded fallback for Phase 0.5
    }
}
