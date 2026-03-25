package revkit.server.handlers;

import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import org.json.simple.JSONObject;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

/**
 * Analysis RPC handlers. Phase 0.5: get_class_source (+ decompile alias).
 */
public final class AnalysisHandlers {

    private AnalysisHandlers() {}

    /**
     * Decompile a class to Java source code.
     * Response: {class_sig, code, saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetClassSource(JSONObject params, ServerState state) {
        String classSig = JsonUtil.requireParam(params, "class_sig");

        // Find the DEX unit containing this class
        IDexUnit dex = state.findDexForClass(classSig);
        if (dex == null) {
            throw new RpcException("CLASS_NOT_FOUND",
                "Class not found: " + classSig,
                "Use 'search_classes' or 'get_classes' to find valid signatures");
        }

        // Decompile via cache (cache miss triggers actual decompile)
        String code = state.getDecompilerCache().getOrDecompile(dex, classSig);

        JSONObject r = new JSONObject();
        r.put("class_sig", classSig);
        r.put("code", code != null ? code : "");
        r.put("saved_to", null);  // Phase 0.5: no server-side file save
        return r;
    }
}
