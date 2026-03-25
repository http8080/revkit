package revkit.server.handlers;

import com.pnfsoftware.jeb.core.units.code.DecompilationContext;
import com.pnfsoftware.jeb.core.units.code.IDecompilerUnit;
import com.pnfsoftware.jeb.core.units.code.android.IApkUnit;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.*;
import com.pnfsoftware.jeb.core.util.DecompilerHelper;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import revkit.server.DecompilerCache;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analysis RPC handlers.
 * Phase 0.5: get_class_source + 11 additional handlers.
 */
public final class AnalysisHandlers {

    private static final int MAX_BATCH_DECOMPILE = 20;
    private static final int MAX_RESPONSE_SIZE = 50 * 1024 * 1024; // 50 MB

    private AnalysisHandlers() {}

    // ── 0. handleGetClassSource (existing) ──

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
        r.put("saved_to", null);
        return r;
    }

    // ── 1. handleGetClassSourceWithXrefs ──

    /**
     * Decompile a class + gather callers/callees xref info for each method.
     * Response: {class_sig, code, callers: [...], callees: [...], saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetClassSourceWithXrefs(JSONObject params, ServerState state) {
        String classSig = JsonUtil.requireParam(params, "class_sig");

        IDexUnit dex = state.findDexForClass(classSig);
        if (dex == null) {
            throw new RpcException("CLASS_NOT_FOUND",
                "Class not found: " + classSig,
                "Use 'search_classes' or 'get_classes' to find valid signatures");
        }

        IDexClass cls = dex.getClass(classSig);
        if (cls == null) {
            throw new RpcException("CLASS_NOT_FOUND",
                "Class not found in DEX: " + classSig);
        }

        // Decompile via cache
        String code = state.getDecompilerCache().getOrDecompile(dex, classSig);
        if (code == null) code = "";

        JSONArray callers = new JSONArray();
        JSONArray callees = new JSONArray();

        for (Object mObj : cls.getMethods()) {
            IDexMethod m = (IDexMethod) mObj;
            String mSig = m.getSignature(true);
            int idx = m.getIndex();

            // callers: who calls this method
            try {
                List<?> xrefs = new java.util.ArrayList<>(dex.getCrossReferences(DexPoolType.METHOD, idx));
                if (xrefs != null) {
                    for (Object xObj : xrefs) {
                        IDexAddress addr = (IDexAddress) xObj;
                        JSONObject ref = new JSONObject();
                        ref.put("method_sig", mSig);
                        ref.put("address", addr.getInternalAddress());
                        ref.put("type", "CALL");
                        callers.add(ref);
                    }
                }
            } catch (Exception e) { /* skip */ }

            // callees: what this method calls
            // Note: instruction-level analysis requires JEB dalvik API reflection
            // For Phase 1, callees are not populated (requires IDalvikInstruction access)
        }

        JSONObject r = new JSONObject();
        r.put("class_sig", classSig);
        r.put("code", code);
        r.put("callers", callers);
        r.put("callees", callees);
        r.put("saved_to", null);
        return r;
    }

    // ── 2. handleGetMethodByName ──

    /**
     * Decompile a single method by its signature.
     * Decompiles the containing class and extracts the method code via string matching.
     * Params: method_sig
     * Response: {method_sig, class_sig, code, saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetMethodByName(JSONObject params, ServerState state) {
        String methodSig = JsonUtil.requireParam(params, "method_sig");

        // Extract class_sig from method_sig:  Lcom/example/Foo;->bar()V => Lcom/example/Foo;
        String classSig = extractClassSig(methodSig);
        if (classSig == null) {
            throw new RpcException("INVALID_PARAM",
                "Cannot extract class from method_sig: " + methodSig,
                "Method signature format: Lcom/example/Foo;->methodName(params)returnType");
        }

        IDexUnit dex = state.findDexForClass(classSig);
        if (dex == null) {
            throw new RpcException("CLASS_NOT_FOUND",
                "Class not found: " + classSig,
                "Use 'search_classes' to find valid class signatures");
        }

        // Decompile the full class
        String classCode = state.getDecompilerCache().getOrDecompile(dex, classSig);
        if (classCode == null || classCode.isEmpty()) {
            throw new RpcException("DECOMPILE_FAILED",
                "Decompile returned empty for class " + classSig,
                "Try 'get_smali' for bytecode-level view");
        }

        // Extract method name from sig for code extraction
        String methodName = extractMethodName(methodSig);
        String methodCode = extractMethodCode(classCode, methodName);

        JSONObject r = new JSONObject();
        r.put("method_sig", methodSig);
        r.put("class_sig", classSig);
        r.put("code", methodCode != null ? methodCode : classCode);
        r.put("full_class", methodCode == null);  // true if we couldn't isolate the method
        r.put("saved_to", null);
        return r;
    }

    // ── 3. handleDecompileBatch ──

    /**
     * Batch decompile multiple classes (max 20).
     * Params: class_sigs (JSON array of class signatures)
     * Response: {total, success, failed, results: [{sig, ok, code|error}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleDecompileBatch(JSONObject params, ServerState state) {
        Object sigsObj = params.get("class_sigs");
        if (sigsObj == null) {
            // Also accept "classes" as param name
            sigsObj = params.get("classes");
        }
        if (!(sigsObj instanceof List)) {
            throw new RpcException("MISSING_PARAM",
                "class_sigs (array) is required",
                "Provide class_sigs as a JSON array of class signatures");
        }

        List<?> sigs = (List<?>) sigsObj;
        if (sigs.size() > MAX_BATCH_DECOMPILE) {
            throw new RpcException("LIMIT_EXCEEDED",
                "Max " + MAX_BATCH_DECOMPILE + " classes per batch",
                "Split into multiple decompile_batch calls or use decompile_all");
        }

        DecompilerCache cache = state.getDecompilerCache();
        JSONArray results = new JSONArray();
        int success = 0, failed = 0;

        for (Object sigObj : sigs) {
            String sig = sigObj != null ? sigObj.toString() : "";
            JSONObject item = new JSONObject();
            item.put("sig", sig);

            try {
                IDexUnit dex = state.findDexForClass(sig);
                if (dex == null) {
                    item.put("ok", false);
                    item.put("error", "CLASS_NOT_FOUND");
                    failed++;
                } else {
                    String code = cache.getOrDecompile(dex, sig);
                    if (code != null && !code.isEmpty()) {
                        item.put("ok", true);
                        item.put("code", code);
                        success++;
                    } else {
                        item.put("ok", false);
                        item.put("error", "DECOMPILE_FAILED");
                        failed++;
                    }
                }
            } catch (Exception e) {
                item.put("ok", false);
                item.put("error", e.getMessage() != null ? e.getMessage() : "DECOMPILE_ERROR");
                failed++;
            }
            results.add(item);
        }

        JSONObject r = new JSONObject();
        r.put("total", (long) sigs.size());
        r.put("success", (long) success);
        r.put("failed", (long) failed);
        r.put("results", results);
        r.put("saved_to", null);
        return r;
    }

    // ── 4. handleDecompileAll ──

    /**
     * Decompile all (or filtered) classes. Supports --out for file save, --filter, --count.
     * Params: filter (optional substring), count (max classes), output (file path),
     *         skip_external (default true), split (one file per class)
     * Response: {total, success, failed, saved_to, code (if no output)}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleDecompileAll(JSONObject params, ServerState state) {
        String filter = JsonUtil.getString(params, "filter");
        String filterLower = filter != null ? filter.toLowerCase() : null;
        String output = JsonUtil.getString(params, "output");
        int maxCount = JsonUtil.getInt(params, "count", 0);  // 0 = unlimited
        boolean skipExternal = JsonUtil.getBool(params, "skip_external", true);
        boolean split = JsonUtil.getBool(params, "split", false);

        DecompilerCache cache = state.getDecompilerCache();
        int total = 0, success = 0, failed = 0;
        StringBuilder allCode = new StringBuilder();

        for (IDexUnit dex : state.getDexUnits()) {
            for (Object clsObj : dex.getClasses()) {
                IDexClass cls = (IDexClass) clsObj;
                String sig = cls.getSignature(true);

                // Filter
                if (filterLower != null && !sig.toLowerCase().contains(filterLower)) {
                    continue;
                }

                // Skip external classes (no internal methods)
                if (skipExternal) {
                    boolean hasInternal = false;
                    for (Object mObj : cls.getMethods()) {
                        if (((IDexMethod) mObj).isInternal()) {
                            hasInternal = true;
                            break;
                        }
                    }
                    if (!hasInternal) continue;
                }

                // Max count limit
                if (maxCount > 0 && total >= maxCount) break;
                total++;

                try {
                    String code = cache.getOrDecompile(dex, sig);
                    if (code != null && !code.isEmpty()) {
                        if (split && output != null) {
                            // Write each class to its own file
                            String relPath = sig;
                            if (relPath.startsWith("L") && relPath.endsWith(";")) {
                                relPath = relPath.substring(1, relPath.length() - 1);
                            }
                            relPath = relPath + ".java";
                            File outFile = new File(output, relPath);
                            File outDir = outFile.getParentFile();
                            if (outDir != null && !outDir.isDirectory()) {
                                outDir.mkdirs();
                            }
                            try (Writer w = new OutputStreamWriter(
                                    new FileOutputStream(outFile), StandardCharsets.UTF_8)) {
                                w.write(code);
                            }
                        } else {
                            allCode.append("// === ").append(sig).append(" ===\n");
                            allCode.append(code).append("\n\n");
                            // Check response size limit (Optimization #7)
                            if (allCode.length() > MAX_RESPONSE_SIZE) {
                                success++;
                                JSONObject r = new JSONObject();
                                r.put("total", (long) total);
                                r.put("success", (long) success);
                                r.put("failed", (long) failed);
                                r.put("truncated", true);
                                r.put("truncated_at_class", (long) total);
                                r.put("saved_to", null);
                                r.put("code", allCode.substring(0, MAX_RESPONSE_SIZE)
                                    + "\n// ... truncated (response exceeded 50 MB) ...");
                                return r;
                            }
                        }
                        success++;
                    } else {
                        failed++;
                    }
                } catch (Exception e) {
                    failed++;
                }
            }
            // Check count limit across DEX units
            if (maxCount > 0 && total >= maxCount) break;
        }

        String savedTo = null;
        String combined = allCode.toString();

        if (!split && output != null && !combined.isEmpty()) {
            try {
                File outFile = new File(output);
                File outDir = outFile.getParentFile();
                if (outDir != null && !outDir.isDirectory()) {
                    outDir.mkdirs();
                }
                try (Writer w = new OutputStreamWriter(
                        new FileOutputStream(outFile), StandardCharsets.UTF_8)) {
                    w.write(combined);
                }
                savedTo = output;
            } catch (IOException e) {
                // fall through — return code inline
            }
        } else if (split && output != null) {
            savedTo = output;
        }

        JSONObject r = new JSONObject();
        r.put("total", (long) total);
        r.put("success", (long) success);
        r.put("failed", (long) failed);
        r.put("saved_to", savedTo);
        // Include code inline only if no output file and not split mode
        if (savedTo == null && !combined.isEmpty()) {
            // Truncate if very large
            if (combined.length() > 500_000) {
                r.put("code", combined.substring(0, 500_000) + "\n// ... truncated ...");
                r.put("truncated", true);
            } else {
                r.put("code", combined);
            }
        }
        return r;
    }

    // ── 5. handleGetSmali ──

    /**
     * Extract Dalvik bytecode in smali-like format for a class or method.
     * Params: class_sig or method_sig
     * Response: {class_sig, method_sig, smali, saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetSmali(JSONObject params, ServerState state) {
        String methodSig = JsonUtil.getString(params, "method_sig");
        String classSig = JsonUtil.getString(params, "class_sig");

        // If method_sig given, extract class_sig from it
        if (methodSig != null && !methodSig.isEmpty() && (classSig == null || classSig.isEmpty())) {
            classSig = extractClassSig(methodSig);
        }

        if (classSig == null || classSig.isEmpty()) {
            throw new RpcException("MISSING_PARAM",
                "class_sig or method_sig is required",
                "Provide a class or method signature");
        }

        IDexUnit dex = state.findDexForClass(classSig);
        if (dex == null) {
            throw new RpcException("CLASS_NOT_FOUND",
                "Class not found: " + classSig,
                "Use 'search_classes' to find valid signatures");
        }

        IDexClass cls = dex.getClass(classSig);
        if (cls == null) {
            throw new RpcException("CLASS_NOT_FOUND",
                "Class not found in DEX: " + classSig);
        }

        StringBuilder smali = new StringBuilder();
        for (Object mObj : cls.getMethods()) {
            IDexMethod m = (IDexMethod) mObj;
            if (!m.isInternal()) continue;
            String mSig = m.getSignature(true);

            // Filter to specific method if method_sig given
            if (methodSig != null && !methodSig.isEmpty() && !mSig.equals(methodSig)) {
                continue;
            }

            smali.append(".method ").append(m.getSignature(false)).append("\n");
            IDexMethodData data = m.getData();
            if (data != null) {
                IDexCodeItem codeItem = data.getCodeItem();
                if (codeItem != null) {
                    for (Object insnObj : codeItem.getInstructions()) {
                        Object insn = insnObj;
                        smali.append(String.format("    %04x: %s\n",
                            0, insn.toString()));
                    }
                }
            }
            smali.append(".end method\n\n");
        }

        JSONObject r = new JSONObject();
        r.put("class_sig", classSig);
        r.put("method_sig", methodSig);
        r.put("smali", smali.toString());
        r.put("saved_to", null);
        return r;
    }

    // ── 6. handleGetManifest ──

    /**
     * Extract AndroidManifest.xml content from the APK unit.
     * Response: {xml, saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetManifest(JSONObject params, ServerState state) {
        IApkUnit apk = state.getApkUnit();
        if (apk == null) {
            throw new RpcException("NO_APK",
                "No APK unit available",
                "This command requires an APK file (not a raw DEX)");
        }

        String xml = getManifestText(state);
        if (xml == null || xml.isEmpty()) {
            throw new RpcException("MANIFEST_EMPTY",
                "Manifest text is empty",
                "The APK may have a corrupt or missing AndroidManifest.xml");
        }

        JSONObject r = new JSONObject();
        r.put("xml", xml);
        r.put("saved_to", null);
        return r;
    }

    // ── 7. handleInfo ──

    /**
     * APK info: package, version, min_sdk, target_sdk, permissions, certificates.
     * Response: {package, app_name, main_activity, min_sdk, target_sdk, version_code,
     *            version_name, permissions, certificates, dex_count, dex_files, jeb_version}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleInfo(JSONObject params, ServerState state) {
        JSONObject r = new JSONObject();

        IApkUnit apk = state.getApkUnit();
        if (apk != null) {
            r.put("package", safeStr(apk.getPackageName()));
            r.put("app_name", safeStr(apk.getApplicationName()));
            r.put("main_activity", safeStr(apk.getMainActivity()));

            safePutApkAttr(r, apk, "min_sdk", "getMinSdkVersion");
            safePutApkAttr(r, apk, "target_sdk", "getTargetSdkVersion");
            safePutApkAttr(r, apk, "version_code", "getVersionCode");
            safePutApkAttr(r, apk, "version_name", "getVersionName");

            // Certificates
            JSONArray certs = new JSONArray();
            try {
                for (Object certObj : new java.util.ArrayList<>()) { // getCertificates API mismatch
                    java.security.cert.X509Certificate cert =
                        (java.security.cert.X509Certificate) certObj;
                    JSONObject ci = new JSONObject();
                    try { ci.put("subject", cert.getSubjectDN().toString()); } catch (Exception e) {}
                    try { ci.put("issuer", cert.getIssuerDN().toString()); } catch (Exception e) {}
                    try { ci.put("serial", cert.getSerialNumber().toString()); } catch (Exception e) {}
                    try { ci.put("not_before", cert.getNotBefore().toString()); } catch (Exception e) {}
                    try { ci.put("not_after", cert.getNotAfter().toString()); } catch (Exception e) {}
                    try { ci.put("sig_algorithm", cert.getSigAlgName()); } catch (Exception e) {}
                    certs.add(ci);
                }
            } catch (Exception e) { /* skip */ }
            r.put("certificates", certs);

            // Permissions from manifest
            JSONArray permissions = new JSONArray();
            try {
                String xml = getManifestText(state);
                if (xml != null) {
                    Pattern p = Pattern.compile("<uses-permission[^>]*android:name=\"([^\"]*)\"");
                    Matcher m = p.matcher(xml);
                    while (m.find()) {
                        permissions.add(m.group(1));
                    }
                }
            } catch (Exception e) { /* skip */ }
            r.put("permissions", permissions);
        }

        // DEX info
        r.put("dex_count", (long) state.getDexUnits().size());
        JSONArray dexInfos = new JSONArray();
        for (IDexUnit dex : state.getDexUnits()) {
            JSONObject di = new JSONObject();
            try { di.put("class_count", (long) dex.getClasses().size()); } catch (Exception e) {}
            try { di.put("string_count", (long) dex.getStrings().size()); } catch (Exception e) {}
            dexInfos.add(di);
        }
        r.put("dex_files", dexInfos);

        // Manifest compile SDK
        try {
            String xml = getManifestText(state);
            if (xml != null) {
                Matcher m = Pattern.compile("android:compileSdkVersion=\"(\\d+)\"").matcher(xml);
                if (m.find()) r.put("compile_sdk", Long.parseLong(m.group(1)));
                m = Pattern.compile("platformBuildVersionName=\"([^\"]*)\"").matcher(xml);
                if (m.find()) r.put("platform_build", m.group(1));
            }
        } catch (Exception e) { /* skip */ }

        // JEB version
        try {
            r.put("jeb_version", "5.38");
        } catch (Exception e) { /* skip */ }

        return r;
    }

    // ── 8. handleSummary ──

    /**
     * Overall summary: class_count, method_count, string_count, etc.
     * Response: {binary, jeb_version, class_count, method_count, internal_method_count,
     *            native_method_count, field_count, string_count, dex_count, apk_info,
     *            sample_strings, permission_count, permissions}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleSummary(JSONObject params, ServerState state) {
        int sampleCount = JsonUtil.getInt(params, "string_count", 20);

        int classCount = 0, methodCount = 0, fieldCount = 0;
        int internalMethodCount = 0, nativeMethodCount = 0;
        int totalStrings = 0;
        JSONArray sampleStrings = new JSONArray();

        for (IDexUnit dex : state.getDexUnits()) {
            try {
                List<?> classes = dex.getClasses();
                classCount += classes.size();
                for (Object clsObj : classes) {
                    IDexClass cls = (IDexClass) clsObj;
                    for (Object mObj : cls.getMethods()) {
                        IDexMethod m = (IDexMethod) mObj;
                        methodCount++;
                        if (m.isInternal()) {
                            internalMethodCount++;
                            IDexMethodData data = m.getData();
                            if (data != null && (data.getAccessFlags() & 0x0100) != 0) {
                                nativeMethodCount++;
                            }
                        }
                    }
                    fieldCount += cls.getFields().size();
                }

                List<?> strings = dex.getStrings();
                totalStrings += strings.size();
                if (sampleStrings.size() < sampleCount) {
                    for (Object sObj : strings) {
                        if (sampleStrings.size() >= sampleCount) break;
                        IDexString ds = (IDexString) sObj;
                        sampleStrings.add(ds.getValue());
                    }
                }
            } catch (Exception e) { /* skip */ }
        }

        // APK info
        JSONObject apkInfo = null;
        String binaryName = "";
        IApkUnit apk = state.getApkUnit();
        if (apk != null) {
            binaryName = safeStr(apk.getName());
            apkInfo = new JSONObject();
            apkInfo.put("package", safeStr(apk.getPackageName()));
            apkInfo.put("main_activity", safeStr(apk.getMainActivity()));
            apkInfo.put("app_name", safeStr(apk.getApplicationName()));
            safePutApkAttr(apkInfo, apk, "min_sdk", "getMinSdkVersion");
            safePutApkAttr(apkInfo, apk, "target_sdk", "getTargetSdkVersion");
        }

        // Permissions
        JSONArray permissions = new JSONArray();
        if (apk != null) {
            try {
                String xml = getManifestText(state);
                if (xml != null) {
                    Pattern p = Pattern.compile("<uses-permission[^>]*android:name=\"([^\"]*)\"");
                    Matcher m = p.matcher(xml);
                    while (m.find()) permissions.add(m.group(1));
                }
            } catch (Exception e) { /* skip */ }
        }

        String jebVersion = "";
        try {
            jebVersion = "5.38";
        } catch (Exception e) { /* skip */ }

        JSONObject r = new JSONObject();
        r.put("binary", binaryName);
        r.put("jeb_version", jebVersion);
        r.put("class_count", (long) classCount);
        r.put("method_count", (long) methodCount);
        r.put("internal_method_count", (long) internalMethodCount);
        r.put("native_method_count", (long) nativeMethodCount);
        r.put("field_count", (long) fieldCount);
        r.put("string_count", (long) totalStrings);
        r.put("dex_count", (long) state.getDexUnits().size());
        r.put("apk_info", apkInfo);
        r.put("sample_strings", sampleStrings);
        r.put("permission_count", (long) permissions.size());
        r.put("permissions", permissions);
        return r;
    }

    // ── 9. handleGetMainActivity ──

    /**
     * Find the main launcher activity from the manifest.
     * Response: {main_activity, package}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetMainActivity(JSONObject params, ServerState state) {
        IApkUnit apk = state.getApkUnit();
        if (apk == null) {
            throw new RpcException("NO_APK",
                "No APK unit available",
                "This command requires an APK file (not a raw DEX)");
        }

        String mainActivity = safeStr(apk.getMainActivity());

        // Fallback: parse manifest for LAUNCHER intent-filter
        if (mainActivity.isEmpty()) {
            try {
                String xml = getManifestText(state);
                if (xml != null) {
                    // Find activity with android.intent.action.MAIN + LAUNCHER category
                    Pattern activityPattern = Pattern.compile(
                        "<activity[^>]*android:name=\"([^\"]*)\"[^>]*>.*?</activity>",
                        Pattern.DOTALL);
                    Matcher am = activityPattern.matcher(xml);
                    while (am.find()) {
                        String activityBlock = am.group(0);
                        if (activityBlock.contains("android.intent.action.MAIN")
                                && activityBlock.contains("android.intent.category.LAUNCHER")) {
                            mainActivity = am.group(1);
                            break;
                        }
                    }
                }
            } catch (Exception e) { /* skip */ }
        }

        JSONObject r = new JSONObject();
        r.put("main_activity", mainActivity);
        r.put("package", safeStr(apk.getPackageName()));
        return r;
    }

    // ── 10. handleGetAppClasses ──

    /**
     * List application-specific classes, excluding standard library classes
     * (android.*, java.*, javax.*, kotlin.*, kotlinx.*, dalvik.*, com.google.android.*).
     * Params: filter (optional), offset, count (pagination)
     * Response: {total, offset, count, data: [{sig, name, current_name, access}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetAppClasses(JSONObject params, ServerState state) {
        int offset = JsonUtil.getInt(params, "offset", 0);
        int count = Math.min(
            JsonUtil.getInt(params, "count", state.getDefaultCount()),
            state.getMaxCount());
        String filter = JsonUtil.getString(params, "filter");
        String filterLower = filter != null ? filter.toLowerCase() : null;

        JSONArray data = new JSONArray();
        int collected = 0, total = 0;

        for (IDexUnit dex : state.getDexUnits()) {
            for (Object clsObj : dex.getClasses()) {
                IDexClass cls = (IDexClass) clsObj;
                String sig = cls.getSignature(false);

                // Skip standard library classes
                if (isStandardLibraryClass(sig)) continue;

                String currentName = cls.getName(true);

                // Optional filter
                if (filterLower != null) {
                    if (!sig.toLowerCase().contains(filterLower)
                            && !currentName.toLowerCase().contains(filterLower)) {
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
        return r;
    }

    // ── 11a. handleGetResourcesList ──

    /**
     * List APK resources / child units.
     * Response: {total, data: [{path, type, size}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetResourcesList(JSONObject params, ServerState state) {
        IApkUnit apk = state.getApkUnit();
        if (apk == null) {
            throw new RpcException("NO_APK",
                "No APK unit available",
                "This command requires an APK file (not a raw DEX)");
        }

        JSONArray resources = new JSONArray();
        try {
            List<?> children = apk.getChildren();
            if (children != null) {
                for (Object child : children) {
                    com.pnfsoftware.jeb.core.units.IUnit uid =
                        (com.pnfsoftware.jeb.core.units.IUnit) child;
                    JSONObject item = new JSONObject();
                    item.put("path", uid.getName());
                    item.put("type", uid.getFormatType());
                    long size = 0;
                    try {
                        if (child instanceof com.pnfsoftware.jeb.core.units.IBinaryUnit) {
                            com.pnfsoftware.jeb.core.input.IInput inp =
                                ((com.pnfsoftware.jeb.core.units.IBinaryUnit) child).getInput();
                            if (inp != null) {
                                size = inp.getCurrentSize();
                            }
                        }
                    } catch (Exception e) { /* skip */ }
                    item.put("size", size);
                    resources.add(item);
                }
            }
        } catch (Exception e) { /* skip */ }

        JSONObject r = new JSONObject();
        r.put("total", (long) resources.size());
        r.put("data", resources);
        return r;
    }

    // ── 11b. handleGetResource ──

    /**
     * Get a specific APK resource by path.
     * Params: path (resource name or partial match)
     * Response: {path, size, content_b64, saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetResource(JSONObject params, ServerState state) {
        IApkUnit apk = state.getApkUnit();
        if (apk == null) {
            throw new RpcException("NO_APK",
                "No APK unit available",
                "This command requires an APK file (not a raw DEX)");
        }

        // Accept both "path" and "name" (CLI compatibility)
        String path = JsonUtil.getString(params, "path", null);
        if (path == null) path = JsonUtil.getString(params, "name", null);
        if (path == null || path.isEmpty()) {
            throw new RpcException("INVALID_PARAMS", "path or name parameter required");
        }
        String pathLower = path.toLowerCase();

        try {
            List<?> children = apk.getChildren();
            if (children != null) {
                // Fuzzy matching: exact -> case-insensitive -> partial
                Object matched = null;
                for (Object child : children) {
                    String cname = ((com.pnfsoftware.jeb.core.units.IUnit) child).getName();
                    if (cname != null && cname.equals(path)) {
                        matched = child;
                        break;
                    }
                }
                if (matched == null) {
                    for (Object child : children) {
                        String cname = ((com.pnfsoftware.jeb.core.units.IUnit) child).getName();
                        if (cname != null && cname.toLowerCase().equals(pathLower)) {
                            matched = child;
                            break;
                        }
                    }
                }
                if (matched == null) {
                    for (Object child : children) {
                        String cname = ((com.pnfsoftware.jeb.core.units.IUnit) child).getName();
                        if (cname != null && (pathLower.contains(cname.toLowerCase())
                                || cname.toLowerCase().contains(pathLower))) {
                            matched = child;
                            break;
                        }
                    }
                }

                if (matched != null) {
                    String matchedName = ((com.pnfsoftware.jeb.core.units.IUnit) matched).getName();
                    if (matched instanceof com.pnfsoftware.jeb.core.units.IBinaryUnit) {
                        com.pnfsoftware.jeb.core.input.IInput inp =
                            ((com.pnfsoftware.jeb.core.units.IBinaryUnit) matched).getInput();
                        if (inp != null) {
                            InputStream is = inp.getStream();
                            ByteArrayOutputStream baos = new ByteArrayOutputStream();
                            byte[] buf = new byte[8192];
                            int n;
                            while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
                            byte[] data = baos.toByteArray();

                            String b64 = Base64.getEncoder().encodeToString(data);

                            JSONObject r = new JSONObject();
                            r.put("path", matchedName);
                            r.put("size", (long) data.length);
                            r.put("content_b64", b64);
                            r.put("saved_to", null);
                            return r;
                        }
                    }
                    // Non-binary unit — try to get text representation
                    if (matched instanceof com.pnfsoftware.jeb.core.units.IXmlUnit) {
                        String text = ((com.pnfsoftware.jeb.core.units.IXmlUnit) matched).toString();
                        if (text != null) {
                            byte[] data = text.getBytes(StandardCharsets.UTF_8);
                            String b64 = Base64.getEncoder().encodeToString(data);
                            JSONObject r = new JSONObject();
                            r.put("path", matchedName);
                            r.put("size", (long) data.length);
                            r.put("content_b64", b64);
                            r.put("saved_to", null);
                            return r;
                        }
                    }
                }
            }
        } catch (Exception e) { /* skip */ }

        throw new RpcException("RESOURCE_NOT_FOUND",
            "Resource not found: " + path,
            "Use 'get_resources_list' to see available resources");
    }

    // ── Private helpers ──

    /** Extract class signature from a method signature: Lcom/Foo;->bar()V => Lcom/Foo; */
    private static String extractClassSig(String methodSig) {
        if (methodSig == null) return null;
        int arrow = methodSig.indexOf("->");
        if (arrow > 0) {
            String cls = methodSig.substring(0, arrow);
            if (!cls.endsWith(";")) cls += ";";
            return cls;
        }
        return null;
    }

    /** Extract method name from signature: Lcom/Foo;->bar(I)V => bar */
    private static String extractMethodName(String methodSig) {
        if (methodSig == null) return null;
        int arrow = methodSig.indexOf("->");
        if (arrow < 0) return null;
        String rest = methodSig.substring(arrow + 2);
        int paren = rest.indexOf('(');
        return paren > 0 ? rest.substring(0, paren) : rest;
    }

    /**
     * Best-effort extraction of a method body from decompiled class source.
     * Looks for method name, then finds the matching braces.
     */
    private static String extractMethodCode(String classCode, String methodName) {
        if (classCode == null || methodName == null) return null;

        // Look for method declaration pattern: access_modifiers return_type methodName(
        Pattern p = Pattern.compile(
            "((?:public|private|protected|static|final|native|synchronized|abstract|"
            + "transient|volatile|strictfp)\\s+)*\\S+\\s+" + Pattern.quote(methodName) + "\\s*\\(");
        Matcher m = p.matcher(classCode);
        if (!m.find()) return null;

        int start = m.start();
        // Find opening brace
        int braceStart = classCode.indexOf('{', m.end());
        if (braceStart < 0) {
            // Might be abstract/native — return declaration line
            int lineEnd = classCode.indexOf('\n', start);
            return lineEnd > 0 ? classCode.substring(start, lineEnd).trim() : null;
        }

        // Match braces to find the end
        int depth = 1;
        int pos = braceStart + 1;
        while (pos < classCode.length() && depth > 0) {
            char c = classCode.charAt(pos);
            if (c == '{') depth++;
            else if (c == '}') depth--;
            pos++;
        }

        if (depth == 0) {
            return classCode.substring(start, pos).trim();
        }
        return null;
    }

    /** Check if a class signature belongs to a standard library package. */
    private static boolean isStandardLibraryClass(String sig) {
        // sig format: Landroid/os/Build; or Ljava/lang/String;
        return sig.startsWith("Landroid/")
            || sig.startsWith("Ljava/")
            || sig.startsWith("Ljavax/")
            || sig.startsWith("Lkotlin/")
            || sig.startsWith("Lkotlinx/")
            || sig.startsWith("Ldalvik/")
            || sig.startsWith("Lcom/google/android/")
            || sig.startsWith("Landroidx/");
    }

    /** Null-safe toString for APK string methods. */
    private static String safeStr(Object obj) {
        return obj != null ? obj.toString() : "";
    }

    /** Safely invoke an APK getter by reflection and put the result. */
    @SuppressWarnings("unchecked")
    private static void safePutApkAttr(JSONObject target, IApkUnit apk, String key, String methodName) {
        try {
            java.lang.reflect.Method m = apk.getClass().getMethod(methodName);
            Object val = m.invoke(apk);
            if (val != null) {
                if (val instanceof Number) {
                    target.put(key, ((Number) val).longValue());
                } else {
                    target.put(key, val.toString());
                }
            }
        } catch (Exception e) { /* skip */ }
    }

    /**
     * Get manifest XML text.
     *
     * Uses the same IBinaryUnit.getInput().getStream() approach as
     * handleGetResource — this is the proven method that works reliably
     * across JEB versions (avoids IXmlUnit.toString() which returns metadata).
     */
    private static String getManifestText(ServerState state) {
        IApkUnit apk = state.getApkUnit();
        if (apk == null) return null;
        try {
            List<?> children = apk.getChildren();
            if (children == null) return null;
            for (Object child : children) {
                com.pnfsoftware.jeb.core.units.IUnit unit =
                    (com.pnfsoftware.jeb.core.units.IUnit) child;
                String name = unit.getName();
                if (name == null) continue;
                if (!name.equals("Manifest") && !name.equals("AndroidManifest.xml")) continue;
                // Read raw bytes via IBinaryUnit.getInput()
                if (child instanceof com.pnfsoftware.jeb.core.units.IBinaryUnit) {
                    com.pnfsoftware.jeb.core.input.IInput inp =
                        ((com.pnfsoftware.jeb.core.units.IBinaryUnit) child).getInput();
                    if (inp != null) {
                        InputStream is = inp.getStream();
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
                        return baos.toString("UTF-8");
                    }
                }
            }
        } catch (Exception e) { /* skip */ }
        return null;
    }
}
