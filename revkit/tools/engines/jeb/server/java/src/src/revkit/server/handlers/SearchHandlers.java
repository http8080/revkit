package revkit.server.handlers;

import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import revkit.server.DecompilerCache;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Search RPC handlers: search_classes, search_methods, search_code.
 */
public final class SearchHandlers {

    private static final int MAX_SEARCH_RESULTS = 500;

    // Optimization #11: LRU regex pattern cache (synchronized, max 100 entries)
    private static final Map<String, Pattern> REGEX_CACHE =
        Collections.synchronizedMap(new LinkedHashMap<String, Pattern>(100, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Pattern> eldest) {
                return size() > 100;
            }
        });

    private SearchHandlers() {}

    // ── search_classes ──

    /**
     * Search classes by keyword (substring or regex match, case-insensitive).
     * Params: keyword, regex (bool), max_results
     * Response: {query, total, matches: [{sig, name}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleSearchClasses(JSONObject params, ServerState state) {
        String keyword = JsonUtil.getString(params, "keyword", "");
        boolean useRegex = JsonUtil.getBool(params, "regex", false);
        int maxResults = searchMax(params);

        Pattern pattern = null;
        if (useRegex) {
            pattern = compileRegex(keyword);
        }
        String kwLower = keyword.toLowerCase();

        JSONArray matches = new JSONArray();

        for (IDexUnit dex : state.getDexUnits()) {
            if (matches.size() >= maxResults) break;
            for (Object obj : dex.getClasses()) {
                if (matches.size() >= maxResults) break;
                IDexClass cls = (IDexClass) obj;
                String sig = cls.getSignature(true);
                String name = cls.getName(true);

                boolean matched;
                if (useRegex) {
                    matched = pattern.matcher(sig).find() || pattern.matcher(name).find();
                } else {
                    matched = sig.toLowerCase().contains(kwLower)
                           || name.toLowerCase().contains(kwLower);
                }

                if (matched) {
                    JSONObject item = new JSONObject();
                    item.put("sig", sig);
                    item.put("name", name);
                    matches.add(item);
                }
            }
        }

        JSONObject r = new JSONObject();
        r.put("query", keyword);
        r.put("total", (long) matches.size());
        r.put("matches", matches);
        return r;
    }

    // ── search_methods ──

    /**
     * Search methods by name (substring or regex match, case-insensitive).
     * Params: name, regex (bool), max_results
     * Response: {query, total, matches: [{sig, class_sig, name}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleSearchMethods(JSONObject params, ServerState state) {
        String nameQ = JsonUtil.getString(params, "name", "");
        boolean useRegex = JsonUtil.getBool(params, "regex", false);
        int maxResults = searchMax(params);

        Pattern pattern = null;
        if (useRegex) {
            pattern = compileRegex(nameQ);
        }
        String nqLower = nameQ.toLowerCase();

        JSONArray matches = new JSONArray();

        for (IDexUnit dex : state.getDexUnits()) {
            if (matches.size() >= maxResults) break;
            for (Object clsObj : dex.getClasses()) {
                if (matches.size() >= maxResults) break;
                IDexClass cls = (IDexClass) clsObj;
                String classSig = cls.getSignature(true);

                for (Object mObj : cls.getMethods()) {
                    if (matches.size() >= maxResults) break;
                    IDexMethod m = (IDexMethod) mObj;
                    String mName = m.getName(true);
                    String mSig = m.getSignature(true);

                    boolean matched;
                    if (useRegex) {
                        matched = pattern.matcher(mName).find()
                               || pattern.matcher(mSig).find();
                    } else {
                        matched = mName.toLowerCase().contains(nqLower);
                    }

                    if (matched) {
                        JSONObject item = new JSONObject();
                        item.put("sig", mSig);
                        item.put("class_sig", classSig);
                        item.put("name", mName);
                        matches.add(item);
                    }
                }
            }
        }

        JSONObject r = new JSONObject();
        r.put("query", nameQ);
        r.put("total", (long) matches.size());
        r.put("matches", matches);
        return r;
    }

    // ── search_code ──

    /**
     * Search within decompiled Java source code.
     * Decompiles classes on the fly and searches for the query string.
     * Params: query (required), case_sensitive, max_results, max_classes, context_lines, regex, package
     * Response: {query, total, classes_searched, matches: [{class_sig, line_no, line, context?}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleSearchCode(JSONObject params, ServerState state) {
        String query = JsonUtil.requireParam(params, "query");
        boolean caseSensitive = JsonUtil.getBool(params, "case_sensitive", false);
        int maxResults = searchMax(params);
        int maxClasses = JsonUtil.getInt(params, "max_classes", 0);  // 0 = no limit
        int contextLines = JsonUtil.getInt(params, "context_lines", 0);
        boolean useRegex = JsonUtil.getBool(params, "regex", false);
        String packageFilter = JsonUtil.getString(params, "package", "");

        Pattern regex = null;
        if (useRegex) {
            int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
            regex = compileRegex(query, flags);  // Optimization #11: cached
        }

        // Phase 2: Use parallel search if cache has entries (warm cache)
        DecompilerCache decompCache = state.getDecompilerCache();
        JSONArray matches = new JSONArray();
        int classesSearched = 0;

        if (decompCache.size() > 0) {
            // ── Fast path: parallel search across cached sources ──
            java.util.List<DecompilerCache.SearchMatch> results =
                decompCache.searchParallel(query, useRegex, caseSensitive,
                                           contextLines, maxResults);
            for (DecompilerCache.SearchMatch sm : results) {
                // Apply package filter
                if (packageFilter != null && !packageFilter.isEmpty()) {
                    if (!sm.classSig.toLowerCase().contains(packageFilter.toLowerCase())) {
                        continue;
                    }
                }
                JSONObject match = new JSONObject();
                match.put("class_sig", sm.classSig);
                match.put("line_no", (long) sm.lineNumber);
                match.put("line", sm.lineText);
                if (contextLines > 0 && sm.context != null) {
                    match.put("context_text", sm.context);
                }
                matches.add(match);
                if (matches.size() >= maxResults) break;
            }
            classesSearched = decompCache.size();
        } else {
            // ── Cold path: sequential decompile + search ──
            String queryCmp = caseSensitive ? query : query.toLowerCase();
            for (IDexUnit dex : state.getDexUnits()) {
                if (matches.size() >= maxResults) break;
                for (Object clsObj : dex.getClasses()) {
                    if (matches.size() >= maxResults) break;
                    if (maxClasses > 0 && classesSearched >= maxClasses) break;
                    IDexClass cls = (IDexClass) clsObj;
                    String sig = cls.getSignature(true);
                    if (packageFilter != null && !packageFilter.isEmpty()
                            && !sig.toLowerCase().contains(packageFilter.toLowerCase())) {
                        continue;
                    }
                    String code;
                    try {
                        code = decompCache.getOrDecompile(dex, sig);
                        if (code == null || code.isEmpty()) continue;
                    } catch (Exception e) { continue; }
                    classesSearched++;
                    String[] codeLines = code.split("\n");
                    for (int lineNo = 1; lineNo <= codeLines.length; lineNo++) {
                        if (matches.size() >= maxResults) break;
                        String line = codeLines[lineNo - 1];
                        boolean hit = useRegex
                            ? regex.matcher(line).find()
                            : (caseSensitive ? line : line.toLowerCase()).contains(queryCmp);
                        if (!hit) continue;
                        JSONObject match = new JSONObject();
                        match.put("class_sig", sig);
                        match.put("line_no", (long) lineNo);
                        match.put("line", line.trim());
                        matches.add(match);
                    }
                }
                if (maxClasses > 0 && classesSearched >= maxClasses) break;
            }
        }

        JSONObject r = new JSONObject();
        r.put("query", query);
        r.put("total", (long) matches.size());
        r.put("classes_searched", (long) classesSearched);
        r.put("matches", matches);
        r.put("saved_to", null);
        return r;
    }

    // ── helpers ──

    private static int searchMax(JSONObject params) {
        int v = JsonUtil.getInt(params, "max_results",
                JsonUtil.getInt(params, "max", 50));
        return Math.min(v, MAX_SEARCH_RESULTS);
    }

    private static Pattern compileRegex(String pattern) {
        return compileRegex(pattern, Pattern.CASE_INSENSITIVE);
    }

    /**
     * Compile regex with caching. Cache key includes flags for correctness.
     */
    private static Pattern compileRegex(String pattern, int flags) {
        String cacheKey = flags + ":" + pattern;
        Pattern cached = REGEX_CACHE.get(cacheKey);
        if (cached != null) return cached;
        try {
            Pattern compiled = Pattern.compile(pattern, flags);
            REGEX_CACHE.put(cacheKey, compiled);
            return compiled;
        } catch (PatternSyntaxException e) {
            throw new RpcException("INVALID_REGEX",
                "Bad regex: " + e.getMessage(),
                "Check your regex syntax");
        }
    }
}
