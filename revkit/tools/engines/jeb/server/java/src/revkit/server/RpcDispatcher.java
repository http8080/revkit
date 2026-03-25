package revkit.server;

import org.json.simple.JSONObject;
import revkit.server.handlers.*;
import revkit.server.util.JsonUtil;

import java.util.*;

/**
 * RPC method dispatcher. Routes method names to handler functions.
 * Phase 1: Full handler coverage — 60+ methods.
 */
public class RpcDispatcher {

    @FunctionalInterface
    public interface RpcMethod {
        JSONObject handle(JSONObject params, ServerState state);
    }

    private final ServerState state;
    private final Map<String, RpcMethod> handlers = new HashMap<>();

    // Parameter aliases: Jython _PARAM_ALIASES porting
    private static final Map<String, List<String>> PARAM_ALIASES = new HashMap<>();
    static {
        PARAM_ALIASES.put("sig", Arrays.asList("class_sig", "item_sig", "method_sig", "field_sig"));
        PARAM_ALIASES.put("class", Arrays.asList("class_sig"));
        PARAM_ALIASES.put("target", Arrays.asList("item_sig", "class_sig"));
        PARAM_ALIASES.put("method", Arrays.asList("method_sig"));
        PARAM_ALIASES.put("field", Arrays.asList("field_sig"));
        PARAM_ALIASES.put("name", Arrays.asList("new_name"));
    }

    // Method aliases: alternative names mapping to canonical name
    private static final Map<String, String> METHOD_ALIASES = new HashMap<>();
    static {
        METHOD_ALIASES.put("decompile", "get_class_source");
        METHOD_ALIASES.put("save_project", "save");
        METHOD_ALIASES.put("save_db", "save");
        METHOD_ALIASES.put("get_resources", "get_resources_list");
        METHOD_ALIASES.put("get_xrefs_to", "get_xrefs");
        METHOD_ALIASES.put("get_xrefs_from", "get_xrefs");
        METHOD_ALIASES.put("strings_xrefs", "get_strings_xrefs");
        METHOD_ALIASES.put("get_app_class", "get_app_classes");
    }

    public RpcDispatcher(ServerState state) {
        this.state = state;
        registerHandlers();
    }

    private void registerHandlers() {
        // ── System (5) ──
        handlers.put("ping", SystemHandlers::handlePing);
        handlers.put("status", SystemHandlers::handleStatus);
        handlers.put("stop", SystemHandlers::handleStop);
        handlers.put("methods", SystemHandlers::handleMethods);
        handlers.put("save", SystemHandlers::handleSave);

        // ── Listing (8) ──
        handlers.put("get_classes", ListingHandlers::handleGetClasses);
        handlers.put("get_methods_of_class", ListingHandlers::handleGetMethodsOfClass);
        handlers.put("get_fields_of_class", ListingHandlers::handleGetFieldsOfClass);
        handlers.put("get_method_info", ListingHandlers::handleGetMethodInfo);
        handlers.put("get_imports", ListingHandlers::handleGetImports);
        handlers.put("get_exports", ListingHandlers::handleGetExports);
        handlers.put("get_strings", ListingHandlers::handleGetStrings);
        handlers.put("native_methods", ListingHandlers::handleNativeMethods);

        // ── Analysis (7) ──
        handlers.put("get_class_source", AnalysisHandlers::handleGetClassSource);
        handlers.put("get_class_source_with_xrefs", AnalysisHandlers::handleGetClassSourceWithXrefs);
        handlers.put("decompile_with_xrefs", AnalysisHandlers::handleGetClassSourceWithXrefs);
        handlers.put("get_method_by_name", AnalysisHandlers::handleGetMethodByName);
        handlers.put("decompile_batch", AnalysisHandlers::handleDecompileBatch);
        handlers.put("decompile_all", AnalysisHandlers::handleDecompileAll);
        handlers.put("get_smali", AnalysisHandlers::handleGetSmali);
        handlers.put("get_manifest", AnalysisHandlers::handleGetManifest);

        // ── Search (3) ──
        handlers.put("search_classes", SearchHandlers::handleSearchClasses);
        handlers.put("search_methods", SearchHandlers::handleSearchMethods);
        handlers.put("search_code", SearchHandlers::handleSearchCode);

        // ── Xrefs (3) ──
        handlers.put("get_xrefs", XrefHandlers::handleGetXrefs);
        handlers.put("callgraph", XrefHandlers::handleCallgraph);
        handlers.put("cross_refs", XrefHandlers::handleCrossRefs);

        // ── Modification (9) ──
        handlers.put("rename", ModificationHandlers::handleRename);
        handlers.put("rename_class", ModificationHandlers::handleRenameClass);
        handlers.put("rename_method", ModificationHandlers::handleRenameMethod);
        handlers.put("rename_field", ModificationHandlers::handleRenameField);
        handlers.put("rename_batch", ModificationHandlers::handleRenameBatch);
        handlers.put("set_comment", ModificationHandlers::handleSetComment);
        handlers.put("get_comments", ModificationHandlers::handleGetComments);
        handlers.put("undo", ModificationHandlers::handleUndo);
        handlers.put("rename_preview", ModificationHandlers::handleRenamePreview);

        // ── Security (2) ──
        handlers.put("entry_points", SecurityHandlers::handleEntryPoints);
        handlers.put("security_scan", SecurityHandlers::handleSecurityScan);

        // ── Snapshot (3) ──
        handlers.put("snapshot_save", SnapshotHandlers::handleSnapshotSave);
        handlers.put("snapshot_list", SnapshotHandlers::handleSnapshotList);
        handlers.put("snapshot_restore", SnapshotHandlers::handleSnapshotRestore);

        // ── Annotations (2) ──
        handlers.put("export_annotations", AnnotationHandlers::handleExportAnnotations);
        handlers.put("import_annotations", AnnotationHandlers::handleImportAnnotations);

        // ── Advanced (6) ──
        handlers.put("auto_rename", AdvancedHandlers::handleAutoRename);
        handlers.put("exec", AdvancedHandlers::handleExec);
        handlers.put("get_strings_xrefs", AdvancedHandlers::handleStringsXrefs);
        handlers.put("report", AdvancedHandlers::handleReport);
        handlers.put("decompile_diff", AdvancedHandlers::handleDecompileDiff);

        // ── Android/Resource (5) ──
        handlers.put("info", AnalysisHandlers::handleInfo);
        handlers.put("summary", AnalysisHandlers::handleSummary);
        handlers.put("get_main_activity", AnalysisHandlers::handleGetMainActivity);
        handlers.put("get_app_classes", AnalysisHandlers::handleGetAppClasses);
        handlers.put("get_resources_list", AnalysisHandlers::handleGetResourcesList);
        handlers.put("get_resource", AnalysisHandlers::handleGetResource);
    }

    /**
     * Dispatch an RPC method call.
     * Resolves aliases, normalizes params, invokes handler.
     */
    @SuppressWarnings("unchecked")
    public JSONObject dispatch(String method, JSONObject params) {
        // Resolve method alias
        String resolved = METHOD_ALIASES.getOrDefault(method, method);

        RpcMethod handler = handlers.get(resolved);
        if (handler != null) {
            normalizeParams(params);
            return handler.handle(params, state);
        }

        // Unknown method
        throw new RpcException("UNKNOWN_METHOD",
            "Unknown method: " + method,
            "Use 'methods' to list available methods.");
    }

    /**
     * Expand parameter aliases so handlers can use canonical names.
     */
    @SuppressWarnings("unchecked")
    private void normalizeParams(JSONObject params) {
        for (Map.Entry<String, List<String>> entry : PARAM_ALIASES.entrySet()) {
            if (params.containsKey(entry.getKey())) {
                for (String alias : entry.getValue()) {
                    if (!params.containsKey(alias)) {
                        params.put(alias, params.get(entry.getKey()));
                    }
                }
            }
        }
    }
}
