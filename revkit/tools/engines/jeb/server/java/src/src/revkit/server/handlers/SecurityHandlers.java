package revkit.server.handlers;

import com.pnfsoftware.jeb.core.units.code.IDecompilerUnit;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.IApkUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.util.DecompilerHelper;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Security RPC handlers: entry_points, security_scan.
 */
public final class SecurityHandlers {

    private SecurityHandlers() {}

    // Framework prefixes to skip during code scanning
    private static final String[] FRAMEWORK_PREFIXES = {
        "Landroid/", "Ljava/", "Landroidx/", "Lcom/google/"
    };

    // Dangerous Android permissions
    private static final Set<String> DANGEROUS_PERMS = new HashSet<>(Arrays.asList(
        "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
        "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS", "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.MANAGE_EXTERNAL_STORAGE"
    ));

    // Crypto weakness patterns: description, literal to search
    private static final String[][] CRYPTO_PATTERNS = {
        {"ECB mode", "ECB"},
        {"DES (weak)", "/DES/"},
        {"MD5 (weak hash)", "MD5"},
        {"SHA1 (weak hash)", "\"SHA-1\""},
        {"Static IV", "IvParameterSpec"},
        {"Hardcoded key", "SecretKeySpec"},
    };

    // Secret patterns: description, regex
    private static final String[][] SECRET_PATTERNS = {
        {"API key", "(?:api[_\\-]?key|apikey)\\s*[:=]\\s*[\"'][A-Za-z0-9+/=]{16,}"},
        {"AWS key", "AKIA[0-9A-Z]{16}"},
        {"Private key", "-----BEGIN (?:RSA )?PRIVATE KEY-----"},
        {"Password", "(?:password|passwd|pwd)\\s*[:=]\\s*[\"'][^\"']{4,}"},
        {"Token", "(?:token|secret|auth)\\s*[:=]\\s*[\"'][A-Za-z0-9+/=_\\-]{16,}"},
    };

    // Pre-compiled secret patterns (avoid recompiling per-class)
    private static final Pattern[] SECRET_COMPILED;
    static {
        SECRET_COMPILED = new Pattern[SECRET_PATTERNS.length];
        for (int i = 0; i < SECRET_PATTERNS.length; i++) {
            SECRET_COMPILED[i] = Pattern.compile(SECRET_PATTERNS[i][1], Pattern.CASE_INSENSITIVE);
        }
    }

    private static boolean isFrameworkClass(String sig) {
        for (String prefix : FRAMEWORK_PREFIXES) {
            if (sig.startsWith(prefix)) return true;
        }
        return false;
    }

    /**
     * Read manifest XML text from APK unit. Returns null if unavailable.
     */
    private static String readManifestText(ServerState state) {
        IApkUnit apk = state.getApkUnit();
        if (apk == null) return null;
        try {
            Object xmlUnit = apk.getManifest();
            if (xmlUnit == null) return null;
            // IXmlUnit.getDocumentAsText()
            java.lang.reflect.Method m = xmlUnit.getClass().getMethod("getDocumentAsText");
            Object text = m.invoke(xmlUnit);
            if (text != null) {
                String s = text.toString();
                if (s.trim().startsWith("<?xml") || s.trim().startsWith("<manifest")) {
                    return s;
                }
            }
        } catch (Exception e) {
            // fall through
        }
        // Fallback: try toString on manifest
        try {
            Object xmlUnit = apk.getManifest();
            if (xmlUnit != null) {
                String s = xmlUnit.toString();
                if (s != null && (s.trim().startsWith("<?xml") || s.trim().startsWith("<manifest"))) {
                    return s;
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    private static void requireApk(ServerState state) {
        if (state.getApkUnit() == null) {
            throw new RpcException("NOT_APK", "No APK unit found",
                "This binary is a DEX file; manifest/resources require an APK");
        }
    }

    /**
     * Decompile a single class, returning source code or null.
     */
    private static String decompileClass(IDexUnit dex, String classSig, ServerState state) {
        // Try the decompiler cache first
        String cached = state.getDecompilerCache().getOrDecompile(dex, classSig);
        return cached;
    }

    // ── handleEntryPoints ──

    /**
     * Analyze attack surface: exported activities, services, receivers, providers,
     * deeplinks, JS interfaces, dynamic receivers.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleEntryPoints(JSONObject params, ServerState state) {
        requireApk(state);
        String text = readManifestText(state);
        if (text == null) {
            throw new RpcException("MANIFEST_NOT_FOUND", "Cannot read manifest");
        }

        JSONArray exported = new JSONArray();
        JSONArray deeplinks = new JSONArray();
        JSONArray providers = new JSONArray();

        String[] componentTags = {"activity", "service", "receiver", "provider"};
        for (String tag : componentTags) {
            Pattern tagPattern = Pattern.compile(
                "<" + tag + "\\b([^>]*)(/?>)", Pattern.DOTALL);
            Matcher tagMatcher = tagPattern.matcher(text);
            while (tagMatcher.find()) {
                String attrs = tagMatcher.group(1);
                String closeType = tagMatcher.group(2);

                Matcher nameMatcher = Pattern.compile("android:name=\"([^\"]*)\"").matcher(attrs);
                if (!nameMatcher.find()) continue;
                String name = nameMatcher.group(1);

                boolean isExported = attrs.contains("android:exported=\"true\"");

                // Determine full tag content for intent filter parsing
                String fullContent;
                if ("/>".equals(closeType)) {
                    fullContent = tagMatcher.group(0);
                } else {
                    String endTag = "</" + tag + ">";
                    int endPos = text.indexOf(endTag, tagMatcher.start());
                    if (endPos > 0) {
                        fullContent = text.substring(tagMatcher.start(), endPos + endTag.length());
                    } else {
                        fullContent = tagMatcher.group(0);
                    }
                    // Implicit export: has intent-filter
                    if (fullContent.contains("intent-filter")) {
                        isExported = true;
                    }
                }

                if (isExported) {
                    JSONObject comp = new JSONObject();
                    comp.put("type", tag);
                    comp.put("name", name);
                    JSONArray intentFilters = new JSONArray();

                    Pattern ifPattern = Pattern.compile(
                        "<intent-filter[^>]*>(.*?)</intent-filter>", Pattern.DOTALL);
                    Matcher ifMatcher = ifPattern.matcher(fullContent);
                    while (ifMatcher.find()) {
                        String ifContent = ifMatcher.group(1);
                        JSONObject intent = new JSONObject();

                        // Find action names
                        Matcher actionMatcher = Pattern.compile(
                            "android:name=\"([^\"]*)\"").matcher(ifContent);
                        while (actionMatcher.find()) {
                            String a = actionMatcher.group(1);
                            if (a.toLowerCase().contains("action") || a.contains(".")) {
                                intent.put("action", a);
                            }
                        }

                        // Deeplink data
                        Pattern dataPattern = Pattern.compile("<data\\s+([^/]*)/>");
                        Matcher dataMatcher = dataPattern.matcher(ifContent);
                        while (dataMatcher.find()) {
                            String d = dataMatcher.group(1);
                            Matcher schemeMatcher = Pattern.compile(
                                "android:scheme=\"([^\"]*)\"").matcher(d);
                            Matcher hostMatcher = Pattern.compile(
                                "android:host=\"([^\"]*)\"").matcher(d);
                            Matcher pathMatcher = Pattern.compile(
                                "android:path(?:Prefix|Pattern)?\"([^\"]*)\"").matcher(d);
                            if (schemeMatcher.find()) {
                                String scheme = schemeMatcher.group(1);
                                String host = hostMatcher.find() ? hostMatcher.group(1) : "";
                                String path = pathMatcher.find() ? pathMatcher.group(1) : "";

                                JSONObject dl = new JSONObject();
                                dl.put("scheme", scheme);
                                dl.put("host", host);
                                dl.put("path", path);
                                dl.put("activity", name);
                                deeplinks.add(dl);

                                intent.put("data", scheme + "://" + host + path);
                            }
                        }

                        if (!intent.isEmpty()) {
                            intentFilters.add(intent);
                        }
                    }
                    comp.put("intent_filters", intentFilters);
                    exported.add(comp);
                }

                if ("provider".equals(tag) && isExported) {
                    Matcher authMatcher = Pattern.compile(
                        "android:authorities=\"([^\"]*)\"").matcher(attrs);
                    JSONObject prov = new JSONObject();
                    prov.put("name", name);
                    prov.put("exported", true);
                    prov.put("authorities", authMatcher.find() ? authMatcher.group(1) : "");
                    providers.add(prov);
                }
            }
        }

        // Optimization #14: Use cached class list pre-filtered by app package
        List<IDexClass> appClasses = state.getCachedClasses();
        if (appClasses == null) {
            appClasses = new ArrayList<>();
            for (IDexUnit dex : state.getDexUnits()) {
                for (Object obj : dex.getClasses()) {
                    appClasses.add((IDexClass) obj);
                }
            }
        }
        // Pre-filter: skip framework classes once
        List<IDexClass> nonFramework = new ArrayList<>();
        for (IDexClass cls : appClasses) {
            if (!isFrameworkClass(cls.getSignature(true))) {
                nonFramework.add(cls);
            }
        }

        // Search for JS interfaces in decompiled code
        JSONArray jsInterfaces = new JSONArray();
        IDexUnit firstDex = state.getDexUnits().isEmpty() ? null : state.getDexUnits().get(0);
        for (IDexClass cls : nonFramework) {
            if (jsInterfaces.size() >= 20) break;
            String sig = cls.getSignature(true);
            try {
                String code = decompileClass(firstDex, sig, state);
                if (code == null || !code.contains("addJavascriptInterface")) continue;
                for (String line : code.split("\n")) {
                    if (line.contains("addJavascriptInterface")) {
                        JSONObject jsi = new JSONObject();
                        jsi.put("class", sig);
                        String trimmed = line.trim();
                        jsi.put("method", trimmed.length() > 100
                            ? trimmed.substring(0, 100) : trimmed);
                        jsInterfaces.add(jsi);
                    }
                }
            } catch (Exception e) {
                // skip
            }
        }

        // Search for dynamic receivers (registerReceiver calls)
        JSONArray dynReceivers = new JSONArray();
        for (IDexClass cls : nonFramework) {
            if (dynReceivers.size() >= 20) break;
            String sig = cls.getSignature(true);
            try {
                String code = decompileClass(firstDex, sig, state);
                if (code == null || !code.contains("registerReceiver")) continue;
                for (String line : code.split("\n")) {
                    if (line.contains("registerReceiver")) {
                        JSONObject dr = new JSONObject();
                        dr.put("class", sig);
                        String trimmed = line.trim();
                        dr.put("caller", trimmed.length() > 100
                            ? trimmed.substring(0, 100) : trimmed);
                        dynReceivers.add(dr);
                    }
                }
            } catch (Exception e) {
                // skip
            }
        }

        JSONObject r = new JSONObject();
        r.put("exported_components", exported);
        r.put("deeplinks", deeplinks);
        r.put("js_interfaces", jsInterfaces);
        r.put("content_providers", providers);
        r.put("dynamic_receivers", dynReceivers);
        return r;
    }

    // ── handleSecurityScan ──

    /**
     * Automated security issue detection: crypto, secrets, permissions,
     * storage, network, WebView.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleSecurityScan(JSONObject params, ServerState state) {
        JSONArray cryptoIssues = new JSONArray();
        JSONArray hardcodedSecrets = new JSONArray();
        JSONArray dangerousPermissions = new JSONArray();
        JSONArray insecureStorage = new JSONArray();
        JSONArray networkIssues = new JSONArray();
        JSONArray webviewIssues = new JSONArray();

        // 1. Check manifest for dangerous permissions and insecure settings
        try {
            String text = readManifestText(state);
            if (text != null) {
                // Dangerous permissions
                Matcher permMatcher = Pattern.compile(
                    "<uses-permission\\s+android:name=\"([^\"]*)\"").matcher(text);
                while (permMatcher.find()) {
                    String p = permMatcher.group(1);
                    if (DANGEROUS_PERMS.contains(p)) {
                        JSONObject issue = new JSONObject();
                        issue.put("severity", "MEDIUM");
                        issue.put("description", "Dangerous permission: " + p);
                        issue.put("location", "AndroidManifest.xml");
                        dangerousPermissions.add(issue);
                    }
                }
                // Debuggable
                if (text.contains("android:debuggable=\"true\"")) {
                    JSONObject issue = new JSONObject();
                    issue.put("severity", "HIGH");
                    issue.put("description", "Application is debuggable");
                    issue.put("location", "AndroidManifest.xml");
                    insecureStorage.add(issue);
                }
                // allowBackup
                if (text.contains("android:allowBackup=\"true\"")) {
                    JSONObject issue = new JSONObject();
                    issue.put("severity", "MEDIUM");
                    issue.put("description",
                        "allowBackup=true (data can be extracted via adb backup)");
                    issue.put("location", "AndroidManifest.xml");
                    insecureStorage.add(issue);
                }
                // Cleartext traffic
                if (text.contains("android:usesCleartextTraffic=\"true\"")) {
                    JSONObject issue = new JSONObject();
                    issue.put("severity", "MEDIUM");
                    issue.put("description", "Cleartext traffic allowed");
                    issue.put("location", "AndroidManifest.xml");
                    networkIssues.add(issue);
                }
            }
        } catch (Exception e) {
            // ignore manifest parsing failures
        }

        // 2. Scan decompiled code for crypto/secrets/network/WebView issues
        // Optimization #24: read max_classes from config (default 200)
        JSONObject jebCfg = JsonUtil.getMap(state.getConfig(), "jeb");
        JSONObject scanCfg = JsonUtil.getMap(jebCfg, "security_scan");
        int maxClasses = JsonUtil.getInt(scanCfg, "max_classes", 200);

        // Optimization #14: use cached class list, pre-filter framework classes
        List<IDexClass> scanClasses;
        List<IDexClass> cached = state.getCachedClasses();
        if (cached != null) {
            scanClasses = new ArrayList<>(cached.size());
            for (IDexClass cls : cached) {
                if (!isFrameworkClass(cls.getSignature(true))) {
                    scanClasses.add(cls);
                }
            }
        } else {
            scanClasses = new ArrayList<>();
            for (IDexUnit dex : state.getDexUnits()) {
                for (Object obj : dex.getClasses()) {
                    IDexClass cls = (IDexClass) obj;
                    if (!isFrameworkClass(cls.getSignature(true))) {
                        scanClasses.add(cls);
                    }
                }
            }
        }
        // Limit to maxClasses
        if (scanClasses.size() > maxClasses) {
            scanClasses = scanClasses.subList(0, maxClasses);
        }

        // Optimization #13: parallel pattern matching via parallelStream
        IDexUnit scanDex = state.getDexUnits().isEmpty() ? null : state.getDexUnits().get(0);
        final IDexUnit dexForLambda = scanDex;

        // Thread-safe issue collectors
        ConcurrentLinkedQueue<JSONObject> cryptoQ = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<JSONObject> secretsQ = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<JSONObject> networkQ = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<JSONObject> webviewQ = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<JSONObject> storageQ = new ConcurrentLinkedQueue<>();

        scanClasses.parallelStream().forEach(cls -> {
            String sig = cls.getSignature(true);
            String code;
            try {
                code = decompileClass(dexForLambda, sig, state);
                if (code == null || code.isEmpty()) return;
            } catch (Exception e) {
                return;
            }

            // Crypto issues
            for (String[] cp : CRYPTO_PATTERNS) {
                String desc = cp[0];
                String pattern = cp[1];
                if (code.contains(pattern)) {
                    JSONObject issue = new JSONObject();
                    issue.put("severity",
                        (desc.contains("DES") || desc.contains("ECB")) ? "HIGH" : "MEDIUM");
                    issue.put("description", desc);
                    issue.put("location", sig);
                    cryptoQ.add(issue);
                }
            }

            // Hardcoded secrets (use pre-compiled patterns)
            for (int i = 0; i < SECRET_PATTERNS.length; i++) {
                try {
                    if (SECRET_COMPILED[i].matcher(code).find()) {
                        JSONObject issue = new JSONObject();
                        issue.put("severity", "HIGH");
                        issue.put("description", SECRET_PATTERNS[i][0] + " found");
                        issue.put("location", sig);
                        secretsQ.add(issue);
                    }
                } catch (Exception e) {
                    // skip
                }
            }

            // Network issues
            if (code.contains("http://") && !code.contains("https://")) {
                JSONObject issue = new JSONObject();
                issue.put("severity", "MEDIUM");
                issue.put("description", "HTTP (non-HTTPS) URL found");
                issue.put("location", sig);
                networkQ.add(issue);
            }
            if ((code.contains("TrustAllCertificates") || code.contains("X509TrustManager"))
                    && code.contains("checkServerTrusted")) {
                JSONObject issue = new JSONObject();
                issue.put("severity", "HIGH");
                issue.put("description",
                    "Custom TrustManager (possible cert pinning bypass)");
                issue.put("location", sig);
                networkQ.add(issue);
            }
            if (code.contains("SSLContext") && !code.contains("TLS")) {
                JSONObject issue = new JSONObject();
                issue.put("severity", "MEDIUM");
                issue.put("description", "SSLContext without explicit TLS version");
                issue.put("location", sig);
                networkQ.add(issue);
            }

            // WebView issues
            if (code.contains("setJavaScriptEnabled")) {
                JSONObject issue = new JSONObject();
                issue.put("severity", "MEDIUM");
                issue.put("description", "WebView JavaScript enabled");
                issue.put("location", sig);
                webviewQ.add(issue);
            }
            if (code.contains("addJavascriptInterface")) {
                JSONObject issue = new JSONObject();
                issue.put("severity", "HIGH");
                issue.put("description",
                    "WebView JavaScript interface (potential RCE on API < 17)");
                issue.put("location", sig);
                webviewQ.add(issue);
            }

            // Insecure storage
            if (code.contains("getSharedPreferences")) {
                String lower = code.toLowerCase();
                if (lower.contains("password") || lower.contains("token")) {
                    JSONObject issue = new JSONObject();
                    issue.put("severity", "MEDIUM");
                    issue.put("description", "Sensitive data in SharedPreferences");
                    issue.put("location", sig);
                    storageQ.add(issue);
                }
            }
            if (code.contains("MODE_WORLD_READABLE") || code.contains("MODE_WORLD_WRITEABLE")) {
                JSONObject issue = new JSONObject();
                issue.put("severity", "HIGH");
                issue.put("description", "World-readable/writeable file mode");
                issue.put("location", sig);
                storageQ.add(issue);
            }
        });

        int classesScanned = scanClasses.size();
        // Collect parallel results into JSON arrays
        cryptoIssues.addAll(cryptoQ);
        hardcodedSecrets.addAll(secretsQ);
        networkIssues.addAll(networkQ);
        webviewIssues.addAll(webviewQ);
        insecureStorage.addAll(storageQ);

        JSONObject r = new JSONObject();
        r.put("crypto_issues", cryptoIssues);
        r.put("hardcoded_secrets", hardcodedSecrets);
        r.put("dangerous_permissions", dangerousPermissions);
        r.put("insecure_storage", insecureStorage);
        r.put("network_issues", networkIssues);
        r.put("webview_issues", webviewIssues);
        r.put("classes_scanned", (long) classesScanned);
        return r;
    }
}
