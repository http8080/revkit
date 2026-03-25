package revkit.server.handlers;

import com.pnfsoftware.jeb.core.units.code.android.dex.*;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

import java.util.regex.Pattern;

/**
 * Listing RPC handlers: classes, methods, fields, strings, imports, exports, natives.
 */
public final class ListingHandlers {

    private ListingHandlers() {}

    /**
     * Paginated class listing. Streaming -- no full collection built.
     * Response: {total, offset, count, data: [{sig, name, current_name, access}], saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetClasses(JSONObject params, ServerState state) {
        int offset = JsonUtil.getInt(params, "offset", 0);
        int count = Math.min(
            JsonUtil.getInt(params, "count", state.getDefaultCount()),
            state.getMaxCount());
        String filter = JsonUtil.getString(params, "filter");
        Pattern filterPattern = filter != null && !filter.isEmpty()
            ? Pattern.compile(Pattern.quote(filter), Pattern.CASE_INSENSITIVE) : null;

        JSONArray data = new JSONArray();
        int collected = 0, total = 0;

        for (IDexUnit dex : state.getDexUnits()) {
            for (Object obj : dex.getClasses()) {
                IDexClass cls = (IDexClass) obj;
                // Cache key = getSignature(false) -- immutable original signature
                String sig = cls.getSignature(false);
                String currentName = cls.getName(true);

                // Filter: case-insensitive substring on sig or current name
                if (filterPattern != null) {
                    if (!filterPattern.matcher(sig).find()
                        && !filterPattern.matcher(currentName).find()) {
                        continue;
                    }
                }

                total++;
                if (total - 1 >= offset && collected < count) {
                    JSONObject item = new JSONObject();
                    item.put("sig", sig);
                    item.put("name", cls.getName(false));
                    item.put("current_name", currentName);
                    item.put("access", (long) cls.getAccessFlags());
                    data.add(item);
                    collected++;
                }
            }
        }

        JSONObject r = new JSONObject();
        r.put("total", (long) total);
        r.put("offset", (long) offset);
        r.put("count", (long) collected);
        r.put("data", data);
        r.put("saved_to", null);  // Phase 0.5: no server-side file save
        return r;
    }

    /**
     * List methods of a class.
     * Params: class_sig (required)
     * Response: {class_sig, methods: [{sig, name, access, return_type, is_internal}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetMethodsOfClass(JSONObject params, ServerState state) {
        String classSig = JsonUtil.requireParam(params, "class_sig");

        // Optimization #15: O(1) class index lookup instead of O(n) linear search
        IDexClass found = state.getClassBySig(classSig);
        if (found == null) {
            throw new RpcException("CLASS_NOT_FOUND",
                "Class not found: " + classSig,
                "Use 'get_classes' to list available classes");
        }

        JSONArray methods = new JSONArray();
        for (Object mObj : found.getMethods()) {
            IDexMethod m = (IDexMethod) mObj;
            IDexType rt = m.getReturnType();
            boolean internal = m.isInternal();
            long access = 0;
            if (internal) {
                IDexMethodData mdata = m.getData();
                if (mdata != null) {
                    access = mdata.getAccessFlags();
                }
            }
            JSONObject item = new JSONObject();
            item.put("sig", m.getSignature(true));
            item.put("name", m.getName(true));
            item.put("access", access);
            item.put("return_type", rt != null ? rt.getSignature(true, false) : "?");
            item.put("is_internal", internal);
            methods.add(item);
        }

        JSONObject r = new JSONObject();
        r.put("class_sig", classSig);
        r.put("methods", methods);
        return r;
    }

    /**
     * List fields of a class.
     * Params: class_sig (required)
     * Response: {class_sig, fields: [{sig, name, type, access}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetFieldsOfClass(JSONObject params, ServerState state) {
        String classSig = JsonUtil.requireParam(params, "class_sig");

        // Optimization #15: O(1) class index lookup instead of O(n) linear search
        IDexClass found = state.getClassBySig(classSig);
        if (found == null) {
            throw new RpcException("CLASS_NOT_FOUND",
                "Class not found: " + classSig,
                "Use 'get_classes' to list available classes");
        }

        JSONArray fields = new JSONArray();
        for (Object fObj : found.getFields()) {
            IDexField f = (IDexField) fObj;
            IDexType ftype = f.getFieldType();
            JSONObject item = new JSONObject();
            item.put("sig", f.getSignature(true));
            item.put("name", f.getName(true));
            item.put("type", ftype != null ? ftype.getSignature(true, false) : "?");
            item.put("access", (long) f.getGenericFlags());
            fields.add(item);
        }

        JSONObject r = new JSONObject();
        r.put("class_sig", classSig);
        r.put("fields", fields);
        return r;
    }

    /**
     * Detailed method information.
     * Params: method_sig (required)
     * Response: {method_sig, name, class_sig, return_type, params, access_flags, is_internal, is_renamed}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetMethodInfo(JSONObject params, ServerState state) {
        String methodSig = JsonUtil.requireParam(params, "method_sig");

        IDexMethod found = null;
        for (IDexUnit dex : state.getDexUnits()) {
            found = dex.getMethod(methodSig);
            if (found != null) break;
        }
        if (found == null) {
            throw new RpcException("METHOD_NOT_FOUND",
                "Method not found: " + methodSig,
                "Use 'get_methods_of_class' to list available methods");
        }

        // Parameter types
        JSONArray paramList = new JSONArray();
        java.util.List<? extends IDexType> paramTypes = found.getParameterTypes();
        if (paramTypes != null) {
            int idx = 0;
            for (IDexType pt : paramTypes) {
                JSONObject p = new JSONObject();
                p.put("index", (long) idx);
                p.put("type", pt.getSignature(true, false));
                paramList.add(p);
                idx++;
            }
        }

        // Cache isInternal() result to avoid duplicate JNI call
        boolean internal = found.isInternal();

        // Access flags
        long accessFlags = 0;
        if (internal) {
            IDexMethodData mdata = found.getData();
            if (mdata != null) {
                accessFlags = mdata.getAccessFlags();
            }
        }

        IDexType rt = found.getReturnType();
        IDexType ct = found.getClassType();

        JSONObject r = new JSONObject();
        r.put("method_sig", methodSig);
        r.put("name", found.getName(true));
        r.put("class_sig", ct != null ? ct.getSignature(true, false) : "?");
        r.put("return_type", rt != null ? rt.getSignature(true, false) : "?");
        r.put("params", paramList);
        r.put("access_flags", accessFlags);
        r.put("is_internal", internal);
        r.put("is_renamed", found.isRenamed());
        return r;
    }

    /**
     * List external class references (imports). Methods where isInternal()==false.
     * Paginated with offset/count.
     * Response: {total, offset, count, data: [{sig, name, class_sig}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetImports(JSONObject params, ServerState state) {
        int offset = JsonUtil.getInt(params, "offset", 0);
        int count = Math.min(
            JsonUtil.getInt(params, "count", state.getDefaultCount()),
            state.getMaxCount());
        String filter = JsonUtil.getString(params, "filter");
        Pattern filterPattern = filter != null && !filter.isEmpty()
            ? Pattern.compile(Pattern.quote(filter), Pattern.CASE_INSENSITIVE) : null;

        JSONArray data = new JSONArray();
        int collected = 0, total = 0;

        for (IDexUnit dex : state.getDexUnits()) {
            for (Object mObj : dex.getMethods()) {
                IDexMethod m = (IDexMethod) mObj;
                if (m.isInternal()) continue;

                String sig = m.getSignature(true);
                String name = m.getName(true);
                IDexType ct = m.getClassType();
                String cSig = ct != null ? ct.getSignature(true, false) : "?";

                if (filterPattern != null) {
                    if (!filterPattern.matcher(sig).find()
                        && !filterPattern.matcher(name).find()
                        && !filterPattern.matcher(cSig).find()) {
                        continue;
                    }
                }

                total++;
                if (total - 1 >= offset && collected < count) {
                    JSONObject item = new JSONObject();
                    item.put("sig", sig);
                    item.put("name", name);
                    item.put("class_sig", cSig);
                    data.add(item);
                    collected++;
                }
            }
        }

        JSONObject r = new JSONObject();
        r.put("total", (long) total);
        r.put("offset", (long) offset);
        r.put("count", (long) collected);
        r.put("data", data);
        return r;
    }

    /**
     * List public classes (exports). Classes with ACC_PUBLIC (0x0001) flag.
     * Paginated with offset/count.
     * Response: {total, offset, count, data: [{sig, name, access}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetExports(JSONObject params, ServerState state) {
        int offset = JsonUtil.getInt(params, "offset", 0);
        int count = Math.min(
            JsonUtil.getInt(params, "count", state.getDefaultCount()),
            state.getMaxCount());
        String filter = JsonUtil.getString(params, "filter");
        Pattern filterPattern = filter != null && !filter.isEmpty()
            ? Pattern.compile(Pattern.quote(filter), Pattern.CASE_INSENSITIVE) : null;

        JSONArray data = new JSONArray();
        int collected = 0, total = 0;

        for (IDexUnit dex : state.getDexUnits()) {
            for (Object obj : dex.getClasses()) {
                IDexClass cls = (IDexClass) obj;
                int flags = cls.getAccessFlags();
                if ((flags & 0x0001) == 0) continue;  // ACC_PUBLIC

                String sig = cls.getSignature(true);
                String name = cls.getName(true);

                if (filterPattern != null) {
                    if (!filterPattern.matcher(sig).find()
                        && !filterPattern.matcher(name).find()) {
                        continue;
                    }
                }

                total++;
                if (total - 1 >= offset && collected < count) {
                    JSONObject item = new JSONObject();
                    item.put("sig", sig);
                    item.put("name", name);
                    item.put("access", (long) flags);
                    data.add(item);
                    collected++;
                }
            }
        }

        JSONObject r = new JSONObject();
        r.put("total", (long) total);
        r.put("offset", (long) offset);
        r.put("count", (long) collected);
        r.put("data", data);
        return r;
    }

    /**
     * DEX string pool entries with optional filters.
     * Params: filter (substring), min_len (minimum length), offset, count
     * Response: {total, offset, count, data: [{value, index}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetStrings(JSONObject params, ServerState state) {
        int offset = JsonUtil.getInt(params, "offset", 0);
        int count = Math.min(
            JsonUtil.getInt(params, "count", state.getDefaultCount()),
            state.getMaxCount());
        String filter = JsonUtil.getString(params, "filter");
        Pattern filterPattern = filter != null && !filter.isEmpty()
            ? Pattern.compile(Pattern.quote(filter), Pattern.CASE_INSENSITIVE) : null;
        int minLen = JsonUtil.getInt(params, "min_len", 0);

        JSONArray data = new JSONArray();
        int collected = 0, total = 0;

        // Use cached strings if available (Optimization #8)
        java.util.List<String> cached = state.getCachedStrings();
        if (cached != null) {
            for (int i = 0; i < cached.size(); i++) {
                String val = cached.get(i);
                if (minLen > 0 && val.length() < minLen) continue;
                if (filterPattern != null && !filterPattern.matcher(val).find()) continue;

                total++;
                if (total - 1 >= offset && collected < count) {
                    JSONObject item = new JSONObject();
                    item.put("value", val);
                    item.put("index", (long) i);
                    data.add(item);
                    collected++;
                }
            }
        } else {
            // Fallback: iterate dex units directly
            for (IDexUnit dex : state.getDexUnits()) {
                for (Object sObj : dex.getStrings()) {
                    IDexString s = (IDexString) sObj;
                    String val = s.getValue();
                    if (val == null) continue;
                    if (minLen > 0 && val.length() < minLen) continue;
                    if (filterPattern != null && !filterPattern.matcher(val).find()) continue;

                    total++;
                    if (total - 1 >= offset && collected < count) {
                        JSONObject item = new JSONObject();
                        item.put("value", val);
                        item.put("index", (long) s.getIndex());
                        data.add(item);
                        collected++;
                    }
                }
            }
        }

        JSONObject r = new JSONObject();
        r.put("total", (long) total);
        r.put("offset", (long) offset);
        r.put("count", (long) collected);
        r.put("data", data);
        return r;
    }

    /**
     * List native methods (ACC_NATIVE 0x0100).
     * Params: filter (optional substring on sig or name)
     * Response: {total, offset, count, data: [{sig, class_sig, name, return_type, params, access}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleNativeMethods(JSONObject params, ServerState state) {
        int offset = JsonUtil.getInt(params, "offset", 0);
        int count = Math.min(
            JsonUtil.getInt(params, "count", state.getDefaultCount()),
            state.getMaxCount());
        String filter = JsonUtil.getString(params, "filter");
        Pattern filterPattern = filter != null && !filter.isEmpty()
            ? Pattern.compile(Pattern.quote(filter), Pattern.CASE_INSENSITIVE) : null;

        final int ACC_NATIVE = 0x0100;
        JSONArray data = new JSONArray();
        int collected = 0, total = 0;

        for (IDexUnit dex : state.getDexUnits()) {
            for (Object obj : dex.getClasses()) {
                IDexClass cls = (IDexClass) obj;
                String clsSig = cls.getSignature(true);

                for (Object mObj : cls.getMethods()) {
                    IDexMethod m = (IDexMethod) mObj;
                    if (!m.isInternal()) continue;
                    IDexMethodData mdata = m.getData();
                    if (mdata == null) continue;
                    if ((mdata.getAccessFlags() & ACC_NATIVE) == 0) continue;

                    String sig = m.getSignature(true);
                    String name = m.getName(true);
                    IDexType rt = m.getReturnType();

                    // Build params string
                    StringBuilder paramsBuf = new StringBuilder();
                    java.util.List<? extends IDexType> paramTypes = m.getParameterTypes();
                    if (paramTypes != null) {
                        boolean first = true;
                        for (IDexType pt : paramTypes) {
                            if (!first) paramsBuf.append(", ");
                            paramsBuf.append(pt.getSignature(true, false));
                            first = false;
                        }
                    }

                    if (filterPattern != null) {
                        if (!filterPattern.matcher(sig).find()
                            && !filterPattern.matcher(name).find()
                            && !filterPattern.matcher(clsSig).find()) {
                            continue;
                        }
                    }

                    total++;
                    if (total - 1 >= offset && collected < count) {
                        JSONObject item = new JSONObject();
                        item.put("sig", sig);
                        item.put("class_sig", clsSig);
                        item.put("name", name);
                        item.put("return_type", rt != null ? rt.getSignature(true, false) : "void");
                        item.put("params", paramsBuf.toString());
                        item.put("access", (long) mdata.getAccessFlags());
                        data.add(item);
                        collected++;
                    }
                }
            }
        }

        JSONObject r = new JSONObject();
        r.put("total", (long) total);
        r.put("offset", (long) offset);
        r.put("count", (long) collected);
        r.put("data", data);
        return r;
    }
}
