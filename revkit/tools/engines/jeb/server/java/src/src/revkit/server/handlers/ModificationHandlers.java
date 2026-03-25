package revkit.server.handlers;

import com.pnfsoftware.jeb.core.units.code.android.dex.*;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Modification RPC handlers: rename, set_comment, get_comments, undo, rename_preview.
 *
 * Maintains a server-side undo history stack for rename/comment operations.
 */
public final class ModificationHandlers {

    private ModificationHandlers() {}

    /**
     * Undo history stack. Each entry is a map with:
     *   type="rename": sig, old_name, new_name, item_type
     *   type="comment": addr, old_comment
     * Thread-safe via ConcurrentLinkedDeque.
     */
    private static final Deque<Map<String, String>> undoHistory = new ConcurrentLinkedDeque<>();

    // ── rename (auto-detect type) ──

    /**
     * Unified rename: auto-detect class/method/field from sig format.
     * Params: sig, name (or new_name)
     * Response: {ok, old_name, new_name}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleRename(JSONObject params, ServerState state) {
        String sig = JsonUtil.getString(params, "sig", "");
        String name = JsonUtil.getString(params, "name",
                       JsonUtil.getString(params, "new_name", ""));

        if (sig == null || sig.isEmpty()) {
            throw new RpcException("MISSING_PARAM", "sig is required");
        }
        if (name == null || name.isEmpty()) {
            throw new RpcException("MISSING_PARAM", "name (new name) is required");
        }

        // Auto-detect type from signature format
        String itemType;
        if (sig.contains("->")) {
            String afterArrow = sig.substring(sig.indexOf("->") + 2);
            if (afterArrow.contains("(")) {
                itemType = "method";
            } else if (afterArrow.contains(":")) {
                itemType = "field";
            } else {
                itemType = "method";  // fallback
            }
        } else {
            itemType = "class";
        }

        return renameItem(state, sig, name, itemType);
    }

    // ── rename_class ──

    /**
     * Rename a class.
     * Params: class_sig, new_name
     * Response: {ok, old_name, new_name}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleRenameClass(JSONObject params, ServerState state) {
        String sig = JsonUtil.getString(params, "class_sig", "");
        String newName = JsonUtil.getString(params, "new_name", "");
        return renameItem(state, sig, newName, "class");
    }

    // ── rename_method ──

    /**
     * Rename a method.
     * Params: method_sig, new_name
     * Response: {ok, old_name, new_name}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleRenameMethod(JSONObject params, ServerState state) {
        String sig = JsonUtil.getString(params, "method_sig", "");
        String newName = JsonUtil.getString(params, "new_name", "");
        return renameItem(state, sig, newName, "method");
    }

    // ── rename_field ──

    /**
     * Rename a field.
     * Params: field_sig, new_name
     * Response: {ok, old_name, new_name}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleRenameField(JSONObject params, ServerState state) {
        String sig = JsonUtil.getString(params, "field_sig", "");
        String newName = JsonUtil.getString(params, "new_name", "");
        return renameItem(state, sig, newName, "field");
    }

    // ── rename_batch ──

    /**
     * Batch rename classes/methods/fields.
     * Params: entries (array of {sig, new_name})
     * Response: {total, success, failed, results: [{sig, ok, old_name?, new_name?, error?}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleRenameBatch(JSONObject params, ServerState state) {
        Object entriesObj = params.get("entries");
        if (!(entriesObj instanceof JSONArray)) {
            throw new RpcException("MISSING_PARAM",
                "entries (array of {sig, new_name}) is required");
        }
        JSONArray entries = (JSONArray) entriesObj;

        JSONArray results = new JSONArray();
        int success = 0, failed = 0;

        for (Object entryObj : entries) {
            if (!(entryObj instanceof JSONObject)) {
                JSONObject err = new JSONObject();
                err.put("ok", false);
                err.put("error", "Invalid entry format");
                results.add(err);
                failed++;
                continue;
            }
            JSONObject entry = (JSONObject) entryObj;
            String sig = JsonUtil.getString(entry, "sig", "");
            String newName = JsonUtil.getString(entry, "new_name", "");

            try {
                IDexUnit dex = findDexForAny(state, sig);
                if (dex == null) {
                    JSONObject err = new JSONObject();
                    err.put("sig", sig);
                    err.put("ok", false);
                    err.put("error", "ITEM_NOT_FOUND");
                    results.add(err);
                    failed++;
                    continue;
                }

                ResolvedItem resolved = resolveDexItem(dex, sig);
                if (resolved == null) {
                    JSONObject err = new JSONObject();
                    err.put("sig", sig);
                    err.put("ok", false);
                    err.put("error", "CANNOT_RESOLVE");
                    results.add(err);
                    failed++;
                    continue;
                }

                String oldName = resolved.item.getName(true);
                resolved.item.setName(newName);
                dex.notifyGenericChange();

                JSONObject res = new JSONObject();
                res.put("sig", sig);
                res.put("ok", true);
                res.put("old_name", oldName);
                res.put("new_name", newName);
                results.add(res);
                success++;
            } catch (Exception e) {
                JSONObject err = new JSONObject();
                err.put("sig", sig);
                err.put("ok", false);
                err.put("error", e.getMessage());
                results.add(err);
                failed++;
            }
        }

        JSONObject r = new JSONObject();
        r.put("total", (long) entries.size());
        r.put("success", (long) success);
        r.put("failed", (long) failed);
        r.put("results", results);
        return r;
    }

    // ── set_comment ──

    /**
     * Set an inline comment at an address/sig.
     * Params: addr (or address), comment
     * Response: {ok, addr}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleSetComment(JSONObject params, ServerState state) {
        // Accept addr, address, sig, or item_sig (CLI compatibility)
        String addr = JsonUtil.getString(params, "addr", null);
        if (addr == null) addr = JsonUtil.getString(params, "address", null);
        if (addr == null) addr = JsonUtil.getString(params, "sig", null);
        if (addr == null) addr = JsonUtil.getString(params, "item_sig", null);
        if (addr == null || addr.isEmpty()) {
            throw new RpcException("MISSING_PARAM",
                "addr, sig, or address is required",
                "Provide a method/field signature or hex address");
        }
        String comment = JsonUtil.getString(params, "comment", "");

        IDexUnit dex = findDexForAny(state, addr);
        if (dex == null) {
            // Fallback to first DEX unit
            List<IDexUnit> units = state.getDexUnits();
            if (units == null || units.isEmpty()) {
                throw new RpcException("NO_DEX_UNITS", "No DEX units available");
            }
            dex = units.get(0);
        }

        // Save old comment for undo
        String oldComment = "";
        try {
            oldComment = dex.getInlineComment(addr);
            if (oldComment == null) oldComment = "";
        } catch (Exception e) { /* skip */ }

        dex.setInlineComment(addr, comment);

        // Push undo entry
        Map<String, String> undoEntry = new HashMap<>();
        undoEntry.put("type", "comment");
        undoEntry.put("addr", addr);
        undoEntry.put("old_comment", oldComment);
        undoHistory.push(undoEntry);

        JSONObject r = new JSONObject();
        r.put("ok", true);
        r.put("addr", addr);
        return r;
    }

    // ── get_comments ──

    /**
     * Get comments. If addr specified, single lookup; else all comments.
     * Params: addr (optional)
     * Response: {addr, comment} or {comments: {addr: comment, ...}}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetComments(JSONObject params, ServerState state) {
        String addr = JsonUtil.getString(params, "addr");

        if (addr != null && !addr.isEmpty()) {
            // Single comment lookup
            IDexUnit dex = findDexForAny(state, addr);
            if (dex == null) {
                List<IDexUnit> units = state.getDexUnits();
                dex = (units != null && !units.isEmpty()) ? units.get(0) : null;
            }
            String comment = "";
            if (dex != null) {
                try {
                    comment = dex.getInlineComment(addr);
                    if (comment == null) comment = "";
                } catch (Exception e) { /* skip */ }
            }
            JSONObject r = new JSONObject();
            r.put("addr", addr);
            r.put("comment", comment);
            return r;
        }

        // Get all comments across all DEX units
        JSONObject comments = new JSONObject();
        if (state.getDexUnits() != null) {
            for (IDexUnit dex : state.getDexUnits()) {
                try {
                    Map<String, String> allComments = dex.getInlineComments();
                    if (allComments != null) {
                        for (Map.Entry<String, String> e : allComments.entrySet()) {
                            comments.put(
                                e.getKey() != null ? e.getKey().toString() : "",
                                e.getValue() != null ? e.getValue().toString() : "");
                        }
                    }
                } catch (Exception e) { /* skip */ }
            }
        }

        JSONObject r = new JSONObject();
        r.put("comments", comments);
        return r;
    }

    // ── undo ──

    /**
     * Undo the last rename/comment via server-side history.
     * Response: {ok, action, reverted?} or {ok: false, message}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleUndo(JSONObject params, ServerState state) {
        if (undoHistory.isEmpty()) {
            JSONObject r = new JSONObject();
            r.put("ok", false);
            r.put("message", "No undo history");
            return r;
        }

        Map<String, String> entry = undoHistory.pop();
        String action = entry.getOrDefault("type", "");

        if ("rename".equals(action)) {
            String sig = entry.getOrDefault("sig", "");
            String oldName = entry.getOrDefault("old_name", "");
            String itemType = entry.getOrDefault("item_type", "class");
            try {
                // Rename back to old name (don't push to undo stack)
                renameItemNoUndo(state, sig, oldName, itemType);
                JSONObject r = new JSONObject();
                r.put("ok", true);
                r.put("action", "undo_rename");
                r.put("reverted", entry.getOrDefault("new_name", "") + " -> " + oldName);
                return r;
            } catch (Exception e) {
                JSONObject r = new JSONObject();
                r.put("ok", false);
                r.put("message", "Undo rename failed: " + e.getMessage());
                return r;
            }
        } else if ("comment".equals(action)) {
            String addr = entry.getOrDefault("addr", "");
            String oldComment = entry.getOrDefault("old_comment", "");
            try {
                IDexUnit dex = findDexForAny(state, addr);
                if (dex == null) {
                    List<IDexUnit> units = state.getDexUnits();
                    dex = (units != null && !units.isEmpty()) ? units.get(0) : null;
                }
                if (dex != null) {
                    dex.setInlineComment(addr, oldComment);
                }
                JSONObject r = new JSONObject();
                r.put("ok", true);
                r.put("action", "undo_comment");
                r.put("addr", addr);
                return r;
            } catch (Exception e) {
                JSONObject r = new JSONObject();
                r.put("ok", false);
                r.put("message", "Undo comment failed: " + e.getMessage());
                return r;
            }
        }

        JSONObject r = new JSONObject();
        r.put("ok", false);
        r.put("message", "Unknown undo type: " + action);
        return r;
    }

    // ── rename_preview ──

    /**
     * Preview what a rename would do without applying it.
     * Params: sig (or class_sig), name (or new_name)
     * Response: {ok, preview, sig, old_name, new_name, would_rename, applied}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleRenamePreview(JSONObject params, ServerState state) {
        String sig = JsonUtil.getString(params, "sig",
                      JsonUtil.getString(params, "class_sig", ""));
        String newName = JsonUtil.getString(params, "name",
                          JsonUtil.getString(params, "new_name", ""));

        if (sig == null || sig.isEmpty() || newName == null || newName.isEmpty()) {
            JSONObject r = new JSONObject();
            r.put("ok", false);
            r.put("error", "sig and name required");
            return r;
        }

        // Resolve item to get old name (without modifying anything)
        String oldName = sig;
        try {
            IDexUnit dex = findDexForAny(state, sig);
            if (dex != null) {
                ResolvedItem resolved = resolveDexItem(dex, sig);
                if (resolved != null) {
                    String n = resolved.item.getName(true);
                    if (n != null) oldName = n;
                }
            }
        } catch (Exception e) {
            // Use sig as fallback for old_name
            int semiPos = sig.indexOf(';');
            int slashPos = sig.lastIndexOf('/');
            if (slashPos >= 0 && semiPos > slashPos) {
                oldName = sig.substring(slashPos + 1, semiPos);
            }
        }

        JSONObject r = new JSONObject();
        r.put("ok", true);
        r.put("preview", true);
        r.put("sig", sig);
        r.put("old_name", oldName);
        r.put("new_name", newName);
        r.put("would_rename", true);
        r.put("applied", false);
        return r;
    }

    // ── internal helpers ──

    /** Rename an item and push to undo history. */
    @SuppressWarnings("unchecked")
    private static JSONObject renameItem(ServerState state, String sig, String newName, String itemType) {
        if (sig == null || sig.isEmpty()) {
            throw new RpcException("MISSING_PARAM", itemType + " signature is required");
        }
        if (newName == null || newName.isEmpty()) {
            throw new RpcException("MISSING_PARAM", "new_name is required");
        }

        IDexUnit dex = findDexForAny(state, sig);
        if (dex == null) {
            throw new RpcException(itemType.toUpperCase() + "_NOT_FOUND",
                itemType.substring(0, 1).toUpperCase() + itemType.substring(1) + " not found: " + sig,
                "Use 'search_" + itemType + "s' to find valid signatures");
        }

        IDexItem item = getItemByType(dex, sig, itemType);
        if (item == null) {
            throw new RpcException(itemType.toUpperCase() + "_NOT_FOUND",
                itemType.substring(0, 1).toUpperCase() + itemType.substring(1) + " not found: " + sig,
                "Use 'search_" + itemType + "s' to find valid signatures");
        }

        String oldName = item.getName(true);
        item.setName(newName);
        dex.notifyGenericChange();

        // Push undo entry
        Map<String, String> undoEntry = new HashMap<>();
        undoEntry.put("type", "rename");
        undoEntry.put("sig", sig);
        undoEntry.put("old_name", oldName);
        undoEntry.put("new_name", newName);
        undoEntry.put("item_type", itemType);
        undoHistory.push(undoEntry);

        JSONObject r = new JSONObject();
        r.put("ok", true);
        r.put("old_name", oldName);
        r.put("new_name", newName);
        return r;
    }

    /** Rename without pushing to undo stack (used by undo itself). */
    private static void renameItemNoUndo(ServerState state, String sig, String name, String itemType) {
        IDexUnit dex = findDexForAny(state, sig);
        if (dex == null) {
            throw new RpcException(itemType.toUpperCase() + "_NOT_FOUND",
                itemType + " not found: " + sig);
        }
        IDexItem item = getItemByType(dex, sig, itemType);
        if (item == null) {
            throw new RpcException(itemType.toUpperCase() + "_NOT_FOUND",
                itemType + " not found: " + sig);
        }
        item.setName(name);
        dex.notifyGenericChange();
    }

    /** Get a DEX item by type (class/method/field). */
    private static IDexItem getItemByType(IDexUnit dex, String sig, String itemType) {
        switch (itemType) {
            case "class": return dex.getClass(sig);
            case "method": return dex.getMethod(sig);
            case "field": return dex.getField(sig);
            default: return null;
        }
    }

    /** Find a DEX unit containing any item matching sig. */
    private static IDexUnit findDexForAny(ServerState state, String sig) {
        if (state.getDexUnits() == null) return null;
        for (IDexUnit dex : state.getDexUnits()) {
            try {
                if (dex.getMethod(sig) != null) return dex;
                if (dex.getClass(sig) != null) return dex;
                if (dex.getField(sig) != null) return dex;
            } catch (Exception e) { /* skip */ }
        }
        return null;
    }

    /** Resolve a signature to item + pool type. */
    private static ResolvedItem resolveDexItem(IDexUnit dex, String sig) {
        IDexMethod m = dex.getMethod(sig);
        if (m != null) return new ResolvedItem(m, "method");
        IDexClass c = dex.getClass(sig);
        if (c != null) return new ResolvedItem(c, "class");
        IDexField f = dex.getField(sig);
        if (f != null) return new ResolvedItem(f, "field");
        return null;
    }

    /** Holder for resolved item + type string. */
    private static class ResolvedItem {
        final IDexItem item;
        final String type;
        ResolvedItem(IDexItem item, String type) {
            this.item = item;
            this.type = type;
        }
    }
}
