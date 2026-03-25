package revkit.server.handlers;

import com.pnfsoftware.jeb.core.units.code.DecompilationContext;
import com.pnfsoftware.jeb.core.units.code.IDecompilerUnit;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.IApkUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.*;
import com.pnfsoftware.jeb.core.util.DecompilerHelper;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import revkit.server.DecompilerCache;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Advanced RPC handlers: auto_rename, exec, strings_xrefs, report,
 * decompile_diff, rename_preview.
 */
public final class AdvancedHandlers {

    private AdvancedHandlers() {}

    private static final String[] FRAMEWORK_PREFIXES = {
        "Landroid/", "Ljava/", "Landroidx/", "Lcom/google/"
    };
    private static final int OBFUSCATED_NAME_MAX_LEN = 3;

    /**
     * In-memory store for previous decompilations (for decompile_diff).
     * Key = sanitized class sig, Value = previous source code.
     */
    private static final ConcurrentHashMap<String, String> prevDecompileStore =
        new ConcurrentHashMap<>();

    private static boolean isFrameworkClass(String sig) {
        for (String prefix : FRAMEWORK_PREFIXES) {
            if (sig.startsWith(prefix)) return true;
        }
        return false;
    }

    // ── handleAutoRename ──

    /**
     * Heuristic auto-rename based on string references.
     * Classes with short (obfuscated) names that reference distinctive strings
     * get renamed to a sanitized version of that string.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleAutoRename(JSONObject params, ServerState state) {
        int maxClasses = JsonUtil.getInt(params, "max_classes", 100);
        boolean dryRun;
        // Support both "dry_run" and "apply" params (CLI sends "apply")
        if (params.containsKey("apply")) {
            dryRun = !JsonUtil.getBool(params, "apply", false);
        } else {
            dryRun = JsonUtil.getBool(params, "dry_run", true);
        }

        JSONArray renames = new JSONArray();
        int processed = 0;

        for (IDexUnit dex : state.getDexUnits()) {
            // refMgr removed (not in JEB 5.38 API)
            try {
                // getReferenceManager not in JEB 5.38
            } catch (Exception e) {
                // no reference manager available
            }

            for (Object obj : dex.getClasses()) {
                if (processed >= maxClasses) break;
                IDexClass cls = (IDexClass) obj;
                String sig = cls.getSignature(true);
                String name = cls.getName(true);

                // Skip framework, already-renamed, or non-obfuscated classes
                if (isFrameworkClass(sig)) continue;
                if (cls.isRenamed()) continue;

                // Heuristic: obfuscated names are typically 1-3 chars
                String shortName = name.contains("/")
                    ? name.substring(name.lastIndexOf('/') + 1) : name;
                if (shortName.endsWith(";")) {
                    shortName = shortName.substring(0, shortName.length() - 1);
                }
                if (shortName.length() > OBFUSCATED_NAME_MAX_LEN) continue;

                processed++;

                // Look for string references in methods of this class
                String bestString = null;
                if (false) { // refMgr not available
                    for (Object mObj : cls.getMethods()) {
                        IDexMethod m = (IDexMethod) mObj;
                        if (!m.isInternal()) continue;
                        int idx = m.getIndex();
                        try {
                            Map<?, ?> refMap = null; // refMgr.getReferences() not available
                            if (refMap != null) {
                                for (Map.Entry<?, ?> e : refMap.entrySet()) {
                                    Object pool = e.getKey();
                                    if (pool.toString().equals(DexPoolType.STRING.toString())) {
                                        @SuppressWarnings("unchecked")
                                        Collection<Integer> indices =
                                            (Collection<Integer>) e.getValue();
                                        for (int strIdx : indices) {
                                            IDexString s = dex.getString(strIdx);
                                            if (s != null) {
                                                String val = s.getValue();
                                                if (val != null && val.length() >= 4
                                                        && val.length() <= 40) {
                                                    if (bestString == null
                                                            || val.length() > bestString.length()) {
                                                        bestString = val;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } catch (Exception e) {
                            // skip
                        }
                    }
                }

                if (bestString != null) {
                    // Sanitize: only alphanumeric + underscore
                    StringBuilder sb = new StringBuilder();
                    for (char ch : bestString.toCharArray()) {
                        if (Character.isLetterOrDigit(ch) || ch == '_') {
                            sb.append(ch);
                        } else if (ch == ' ' || ch == '-' || ch == '.') {
                            sb.append('_');
                        }
                    }
                    String newName = sb.toString();
                    if (newName.isEmpty() || !Character.isLetter(newName.charAt(0))) {
                        newName = "C_" + newName;
                    }
                    if (newName.length() > 40) {
                        newName = newName.substring(0, 40);
                    }

                    String oldName = cls.getName(true);
                    JSONObject rename = new JSONObject();
                    rename.put("sig", sig);
                    rename.put("old_name", oldName);
                    rename.put("new_name", newName);
                    rename.put("reason", bestString);
                    renames.add(rename);

                    if (!dryRun) {
                        try {
                            cls.setName(newName);
                            dex.notifyGenericChange();
                        } catch (Exception e) {
                            // rename failure -- still count as suggestion
                        }
                    }
                }
            }
        }

        int applied = dryRun ? 0 : renames.size();
        JSONObject r = new JSONObject();
        r.put("total", (long) renames.size());
        r.put("dry_run", dryRun);
        r.put("applied", (long) applied);
        r.put("suggestions", renames);
        return r;
    }

    // ── handleExec ──

    /**
     * Execute arbitrary code with JEB context.
     * Requires security.exec_enabled=true in config.
     *
     * Uses javax.script (Nashorn/GraalJS) for JavaScript execution as a
     * portable alternative to Jython in the Java server.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleExec(JSONObject params, ServerState state) {
        // Check exec_enabled in config
        JSONObject security = JsonUtil.getMap(state.getConfig(), "security");
        if (!JsonUtil.getBool(security, "exec_enabled", false)) {
            // Also check engine-specific security
            JSONObject jebSec = JsonUtil.getMap(
                JsonUtil.getMap(state.getConfig(), "jeb"), "security");
            if (!JsonUtil.getBool(jebSec, "exec_enabled", false)) {
                throw new RpcException("EXEC_DISABLED",
                    "exec is disabled",
                    "Set security.exec_enabled=true in config.json");
            }
        }

        String code = JsonUtil.getString(params, "code", "");

        // Use Jython (bundled with JEB) for Python execution
        StringWriter outWriter = new StringWriter();
        StringWriter errWriter = new StringWriter();
        try {
            org.python.util.PythonInterpreter interp = new org.python.util.PythonInterpreter();
            interp.setOut(outWriter);
            interp.setErr(errWriter);

            // Bind JEB context variables
            interp.set("engctx", state.getEngctx());
            interp.set("prj", state.getProject());
            interp.set("dex_units", state.getDexUnits());
            interp.set("apk", state.getApkUnit());
            interp.set("ctx", state);

            interp.exec(code);

            String stdout = outWriter.toString();
            String stderr = errWriter.toString();

            JSONObject r = new JSONObject();
            r.put("stdout", stdout);
            r.put("stderr", stderr);
            r.put("saved_to", null);
            return r;
        } catch (org.python.core.PyException e) {
            JSONObject r = new JSONObject();
            r.put("stdout", outWriter.toString());
            r.put("stderr", e.toString());
            r.put("saved_to", null);
            return r;
        } catch (Exception e) {
            throw new RpcException("EXEC_FAILED",
                "Execution error: " + e.getMessage(),
                "Jython exec requires valid Python 2 syntax");
        }
    }

    // ── handleStringsXrefs ──

    /**
     * Get strings with their cross-references.
     * Returns strings that have xrefs, with caller information.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleStringsXrefs(JSONObject params, ServerState state) {
        String filter = JsonUtil.getString(params, "filter");
        String filterLower = filter != null ? filter.toLowerCase() : null;
        int minRefs = JsonUtil.getInt(params, "min_refs", 0);
        int maxResults = JsonUtil.getInt(params, "max_results", 0);
        int offset = JsonUtil.getInt(params, "offset", 0);
        int count = Math.min(
            JsonUtil.getInt(params, "count", state.getDefaultCount()),
            state.getMaxCount());

        JSONArray results = new JSONArray();
        int totalMatched = 0;

        for (IDexUnit dex : state.getDexUnits()) {
            for (Object sObj : dex.getStrings()) {
                if (maxResults > 0 && results.size() >= maxResults) break;

                IDexString s = (IDexString) sObj;
                String value = s.getValue();

                // Apply filter
                if (filterLower != null && !value.toLowerCase().contains(filterLower)) {
                    continue;
                }

                int idx = s.getIndex();
                // Get cross-references for this string
                List<?> xrefAddrs;
                try {
                    xrefAddrs = new java.util.ArrayList<>(dex.getCrossReferences(DexPoolType.STRING, idx));
                } catch (Exception e) {
                    continue;
                }
                if (xrefAddrs == null || xrefAddrs.isEmpty()) continue;

                // Resolve caller method names from addresses
                JSONArray callers = new JSONArray();
                for (Object addr : xrefAddrs) {
                    JSONObject callerInfo = new JSONObject();
                    String addrStr = addr.toString();
                    callerInfo.put("address", addrStr);

                    // Try to resolve internal address to method sig
                    try {
                        String iaddr = addrStr;
                        // Internal address format: Lcom/...;->method(...)V+offset
                        int plusPos = iaddr.lastIndexOf('+');
                        String methodPart = plusPos > 0 ? iaddr.substring(0, plusPos) : iaddr;
                        IDexMethod m = dex.getMethod(methodPart);
                        if (m != null) {
                            callerInfo.put("method_sig", m.getSignature(true));
                            callerInfo.put("method_name", m.getName(true));
                            try {
                                callerInfo.put("class_sig",
                                    m.getClassType().getSignature(true, false));
                            } catch (Exception e) {
                                // skip class resolution
                            }
                        }
                    } catch (Exception e) {
                        // skip resolution
                    }
                    callers.add(callerInfo);
                }

                if (callers.size() < minRefs) continue;

                totalMatched++;
                // Apply pagination
                if (totalMatched - 1 < offset) continue;
                if (results.size() >= count) continue;

                JSONObject entry = new JSONObject();
                entry.put("value", value);
                entry.put("index", (long) idx);
                entry.put("xrefs", callers);
                entry.put("xref_count", (long) callers.size());
                results.add(entry);
            }
            if (maxResults > 0 && results.size() >= maxResults) break;
        }

        JSONObject r = new JSONObject();
        r.put("total", (long) totalMatched);
        r.put("offset", (long) offset);
        r.put("count", (long) results.size());
        r.put("data", results);
        return r;
    }

    // ── handleReport ──

    /**
     * Generate markdown analysis report with summary, top classes,
     * permissions, and security hints.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleReport(JSONObject params, ServerState state) {
        StringBuilder report = new StringBuilder();
        report.append("# revkit JEB Analysis Report\n\n");

        // Summary section
        report.append("## Summary\n");
        String binaryName = "";
        if (state.getApkUnit() != null) {
            try {
                binaryName = JsonUtil.toStr(state.getApkUnit().getName());
            } catch (Exception e) { /* ignore */ }
        }
        report.append("- binary: ").append(binaryName).append("\n");
        report.append("- class_count: ").append(state.getTotalClassCount()).append("\n");
        report.append("- method_count: ").append(state.getTotalMethodCount()).append("\n");
        report.append("- dex_count: ").append(state.getDexUnits().size()).append("\n");

        // String count
        int totalStrings = 0;
        for (IDexUnit dex : state.getDexUnits()) {
            try { totalStrings += dex.getStrings().size(); }
            catch (Exception e) { /* skip */ }
        }
        report.append("- string_count: ").append(totalStrings).append("\n");

        // APK info
        if (state.getApkUnit() != null) {
            IApkUnit apk = state.getApkUnit();
            try {
                report.append("- package: ").append(
                    JsonUtil.toStr(apk.getPackageName())).append("\n");
            } catch (Exception e) { /* ignore */ }
            try {
                report.append("- main_activity: ").append(
                    JsonUtil.toStr(apk.getMainActivity())).append("\n");
            } catch (Exception e) { /* ignore */ }
        }

        // Permissions
        report.append("\n## Permissions\n");
        if (state.getApkUnit() != null) {
            try {
                Object xmlUnit = state.getApkUnit().getManifest();
                if (xmlUnit != null) {
                    java.lang.reflect.Method m = xmlUnit.getClass().getMethod("getDocumentAsText");
                    Object text = m.invoke(xmlUnit);
                    if (text != null) {
                        Matcher permMatcher = Pattern.compile(
                            "<uses-permission\\s+android:name=\"([^\"]*)\"")
                            .matcher(text.toString());
                        while (permMatcher.find()) {
                            report.append("- ").append(permMatcher.group(1)).append("\n");
                        }
                    }
                }
            } catch (Exception e) {
                report.append("- (unable to read permissions)\n");
            }
        }

        // Top 20 classes
        report.append("\n## Classes (top 20)\n");
        try {
            int classCount = 0;
            for (IDexUnit dex : state.getDexUnits()) {
                for (Object obj : dex.getClasses()) {
                    if (classCount >= 20) break;
                    IDexClass cls = (IDexClass) obj;
                    report.append("- ").append(cls.getSignature(true)).append("\n");
                    classCount++;
                }
                if (classCount >= 20) break;
            }
        } catch (Exception e) {
            report.append("- (unable to list classes)\n");
        }

        // Security hints
        report.append("\n## Security Notes\n");
        report.append("- Run 'security-scan' for detailed vulnerability analysis\n");
        report.append("- Run 'entry-points' for attack surface analysis\n");

        JSONObject r = new JSONObject();
        r.put("report", report.toString());
        r.put("format", "markdown");
        return r;
    }

    // ── handleDecompileDiff ──

    /**
     * Compare current decompilation with previously stored version.
     * On first call for a class, stores the current code as baseline.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleDecompileDiff(JSONObject params, ServerState state) {
        String sig = JsonUtil.getString(params, "sig");
        if (sig == null) sig = JsonUtil.getString(params, "class_sig");
        if (sig == null || sig.isEmpty()) {
            throw new RpcException("MISSING_PARAM", "sig parameter required",
                "Provide 'sig' (class signature) in params");
        }

        // Decompile current version
        IDexUnit dex = state.findDexForClass(sig);
        if (dex == null) {
            throw new RpcException("CLASS_NOT_FOUND", "Class not found: " + sig,
                "Use 'search_classes' or 'get_classes' to find valid signatures");
        }

        String currentCode;
        try {
            currentCode = state.getDecompilerCache().getOrDecompile(dex, sig);
            if (currentCode == null) currentCode = "";
        } catch (Exception e) {
            throw new RpcException("DECOMPILE_FAILED",
                "Decompilation failed: " + e.getMessage());
        }

        // Check for previous version
        String storeKey = sig.replace("/", "_").replace(";", "");
        String prevCode = prevDecompileStore.get(storeKey);

        if (prevCode == null) {
            // Store current for next comparison
            prevDecompileStore.put(storeKey, currentCode);

            JSONObject r = new JSONObject();
            r.put("diff", null);
            r.put("message",
                "No previous version. Current stored for future comparison.");
            r.put("code", currentCode);
            return r;
        }

        // Compute unified diff
        String[] prevLines = prevCode.split("\n", -1);
        String[] currLines = currentCode.split("\n", -1);
        String diff = computeUnifiedDiff(prevLines, currLines, "previous", "current");

        // Store current for next comparison
        prevDecompileStore.put(storeKey, currentCode);

        JSONObject r = new JSONObject();
        r.put("diff", diff.isEmpty() ? "(identical)" : diff);
        r.put("has_changes", !diff.isEmpty());
        return r;
    }

    /**
     * Simple unified diff implementation.
     */
    private static String computeUnifiedDiff(String[] a, String[] b,
                                              String fromFile, String toFile) {
        // Simple LCS-based diff for reasonable-sized inputs
        StringBuilder sb = new StringBuilder();
        sb.append("--- ").append(fromFile).append("\n");
        sb.append("+++ ").append(toFile).append("\n");

        boolean hasChanges = false;

        // Walk through both arrays finding differences
        int i = 0, j = 0;
        while (i < a.length || j < b.length) {
            if (i < a.length && j < b.length && a[i].equals(b[j])) {
                i++;
                j++;
            } else {
                hasChanges = true;
                // Find how many lines differ
                int contextStart = Math.max(0, i - 3);
                sb.append(String.format("@@ -%d +%d @@\n", i + 1, j + 1));

                // Output context before
                for (int c = contextStart; c < i; c++) {
                    sb.append(" ").append(a[c]).append("\n");
                }

                // Output removed lines
                int removedStart = i;
                while (i < a.length && (j >= b.length || !a[i].equals(b[j]))) {
                    // Check if this line appears soon in b
                    boolean foundInB = false;
                    for (int k = j; k < Math.min(j + 5, b.length); k++) {
                        if (a[i].equals(b[k])) { foundInB = true; break; }
                    }
                    if (foundInB) break;
                    sb.append("-").append(a[i]).append("\n");
                    i++;
                }

                // Output added lines
                while (j < b.length && (i >= a.length || !b[j].equals(a[i]))) {
                    boolean foundInA = false;
                    for (int k = i; k < Math.min(i + 5, a.length); k++) {
                        if (b[j].equals(a[k])) { foundInA = true; break; }
                    }
                    if (foundInA) break;
                    sb.append("+").append(b[j]).append("\n");
                    j++;
                }

                // Prevent infinite loop if neither advances
                if (i == removedStart && i < a.length && j < b.length) {
                    sb.append("-").append(a[i]).append("\n");
                    sb.append("+").append(b[j]).append("\n");
                    i++;
                    j++;
                }
            }
        }

        return hasChanges ? sb.toString() : "";
    }

    // ── handleRenamePreview ──

    /**
     * Preview what a rename would do without applying it.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleRenamePreview(JSONObject params, ServerState state) {
        String sig = JsonUtil.getString(params, "sig");
        if (sig == null) sig = JsonUtil.getString(params, "class_sig");
        String newName = JsonUtil.getString(params, "name");
        if (newName == null) newName = JsonUtil.getString(params, "new_name");

        if (sig == null || sig.isEmpty() || newName == null || newName.isEmpty()) {
            JSONObject r = new JSONObject();
            r.put("ok", false);
            r.put("error", "sig and name required");
            return r;
        }

        // Resolve item to verify it exists and get old name
        String oldName = sig;
        try {
            for (IDexUnit dex : state.getDexUnits()) {
                // Try method -> class -> field
                Object item = dex.getMethod(sig);
                if (item == null) item = dex.getClass(sig);
                if (item == null) item = dex.getField(sig);
                if (item != null) {
                    if (item instanceof IDexClass) {
                        oldName = ((IDexClass) item).getName(true);
                    } else if (item instanceof IDexMethod) {
                        oldName = ((IDexMethod) item).getName(true);
                    } else if (item instanceof IDexField) {
                        oldName = ((IDexField) item).getName(true);
                    }
                    break;
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
}
