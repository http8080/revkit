package revkit.server.handlers;

import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexField;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Annotation RPC handlers: export_annotations, import_annotations.
 */
public final class AnnotationHandlers {

    private AnnotationHandlers() {}

    /**
     * Export all renames and comments to JSON.
     * Response: {binary, exported_at, names: [...], comments: {...}, saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleExportAnnotations(JSONObject params, ServerState state) {
        JSONArray names = new JSONArray();
        JSONObject commentsObj = new JSONObject();

        for (IDexUnit dex : state.getDexUnits()) {
            // Collect renames
            for (Object obj : dex.getClasses()) {
                IDexClass cls = (IDexClass) obj;
                if (cls.isRenamed()) {
                    JSONObject entry = new JSONObject();
                    entry.put("sig", cls.getSignature(false));
                    entry.put("original_name", cls.getName(false));
                    entry.put("current_name", cls.getName(true));
                    entry.put("type", "class");
                    names.add(entry);
                }
                for (Object mObj : cls.getMethods()) {
                    IDexMethod m = (IDexMethod) mObj;
                    if (m.isRenamed()) {
                        JSONObject entry = new JSONObject();
                        entry.put("sig", m.getSignature(false));
                        entry.put("original_name", m.getName(false));
                        entry.put("current_name", m.getName(true));
                        entry.put("type", "method");
                        names.add(entry);
                    }
                }
                for (Object fObj : cls.getFields()) {
                    IDexField f = (IDexField) fObj;
                    if (f.isRenamed()) {
                        JSONObject entry = new JSONObject();
                        entry.put("sig", f.getSignature(false));
                        entry.put("original_name", f.getName(false));
                        entry.put("current_name", f.getName(true));
                        entry.put("type", "field");
                        names.add(entry);
                    }
                }
            }

            // Collect inline comments
            try {
                Map<?, ?> allComments = dex.getInlineComments();
                if (allComments != null) {
                    for (Map.Entry<?, ?> e : allComments.entrySet()) {
                        commentsObj.put(
                            JsonUtil.toStr(e.getKey()),
                            JsonUtil.toStr(e.getValue()));
                    }
                }
            } catch (Exception e) {
                // skip comment collection failure
            }
        }

        String binaryName = "";
        if (state.getApkUnit() != null) {
            try {
                binaryName = JsonUtil.toStr(state.getApkUnit().getName());
            } catch (Exception e) {
                // ignore
            }
        }

        String exportedAt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").format(new Date());

        JSONObject r = new JSONObject();
        r.put("binary", binaryName);
        r.put("exported_at", exportedAt);
        r.put("names", names);
        r.put("comments", commentsObj);
        r.put("saved_to", null);
        return r;
    }

    /**
     * Import renames and comments from JSON data.
     * Params: {data: {names: [...], comments: {...}}}
     * Response: {names, comments, errors}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleImportAnnotations(JSONObject params, ServerState state) {
        Object dataRaw = params.get("data");
        if (dataRaw == null) {
            throw new RpcException("MISSING_PARAM", "data is required",
                "Include 'data' in the request params");
        }

        // data can be a JSONObject or a JSON string
        JSONObject data;
        if (dataRaw instanceof JSONObject) {
            data = (JSONObject) dataRaw;
        } else {
            try {
                Object parsed = new JSONParser().parse(dataRaw.toString());
                if (parsed instanceof JSONObject) {
                    data = (JSONObject) parsed;
                } else {
                    throw new RpcException("INVALID_PARAMS",
                        "data must be a JSON object");
                }
            } catch (org.json.simple.parser.ParseException e) {
                throw new RpcException("INVALID_PARAMS",
                    "Invalid JSON in data: " + e.getMessage());
            }
        }

        int namesApplied = 0;
        int commentsApplied = 0;
        JSONArray errors = new JSONArray();

        // Apply renames
        Object namesRaw = data.get("names");
        if (namesRaw instanceof JSONArray) {
            for (Object item : (JSONArray) namesRaw) {
                if (!(item instanceof JSONObject)) continue;
                JSONObject entry = (JSONObject) item;
                String sig = JsonUtil.getString(entry, "sig");
                String newName = JsonUtil.getString(entry, "current_name");
                if (sig == null || sig.isEmpty() || newName == null || newName.isEmpty()) continue;

                try {
                    String itemType = JsonUtil.getString(entry, "type", "");
                    boolean found = false;

                    for (IDexUnit dex : state.getDexUnits()) {
                        Object resolved = null;
                        if ("class".equals(itemType)) {
                            resolved = dex.getClass(sig);
                        } else if ("method".equals(itemType)) {
                            resolved = dex.getMethod(sig);
                        } else if ("field".equals(itemType)) {
                            resolved = dex.getField(sig);
                        } else {
                            // Try method -> class -> field
                            resolved = dex.getMethod(sig);
                            if (resolved == null) resolved = dex.getClass(sig);
                            if (resolved == null) resolved = dex.getField(sig);
                        }

                        if (resolved != null) {
                            // All dex items implement IDexItem which has setName
                            if (resolved instanceof IDexClass) {
                                ((IDexClass) resolved).setName(newName);
                            } else if (resolved instanceof IDexMethod) {
                                ((IDexMethod) resolved).setName(newName);
                            } else if (resolved instanceof IDexField) {
                                ((IDexField) resolved).setName(newName);
                            }
                            dex.notifyGenericChange();
                            namesApplied++;
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        errors.add("Item not found: " + sig);
                    }
                } catch (Exception e) {
                    errors.add("Error renaming " + sig + ": " + e.getMessage());
                }
            }
        }

        // Apply comments (dict {addr: text})
        Object commentsRaw = data.get("comments");
        if (commentsRaw instanceof JSONObject) {
            JSONObject commentsMap = (JSONObject) commentsRaw;
            for (Object key : commentsMap.keySet()) {
                String addr = key.toString();
                String text = JsonUtil.toStr(commentsMap.get(key));
                try {
                    // Try to find the right dex unit, fallback to first
                    IDexUnit targetDex = null;
                    for (IDexUnit dex : state.getDexUnits()) {
                        // Attempt to use the first dex that doesn't throw
                        targetDex = dex;
                        break;
                    }
                    if (targetDex != null) {
                        targetDex.setInlineComment(addr, text);
                        commentsApplied++;
                    }
                } catch (Exception e) {
                    errors.add("Error setting comment at " + addr + ": " + e.getMessage());
                }
            }
        }
        // If comments is a list, skip it (as in Jython: list -> empty dict)

        JSONObject r = new JSONObject();
        r.put("names", (long) namesApplied);
        r.put("comments", (long) commentsApplied);
        r.put("errors", errors);
        return r;
    }
}
