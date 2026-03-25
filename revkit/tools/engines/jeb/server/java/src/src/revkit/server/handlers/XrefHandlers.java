package revkit.server.handlers;

import com.pnfsoftware.jeb.core.units.code.android.dex.*;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

import java.util.*;

/**
 * Cross-reference / graph RPC handlers: get_xrefs, callgraph, cross_refs.
 */
public final class XrefHandlers {

    private static final Set<String> VALID_DIRECTIONS = new HashSet<>(
        Arrays.asList("to", "from", "both"));
    private static final Set<String> CALLGRAPH_DIRECTIONS = new HashSet<>(
        Arrays.asList("callers", "callees", "both"));

    private XrefHandlers() {}

    // ── get_xrefs ──

    /**
     * Cross-references for an item (class, method, or field).
     * direction="to" (default): who references this item.
     * direction="from": what this item references.
     * Params: item_sig, direction (to|from|both)
     * Response: {item_sig, direction, total, refs: [{address, type, ...}]}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetXrefs(JSONObject params, ServerState state) {
        String itemSig = JsonUtil.getString(params, "item_sig", "");
        String direction = JsonUtil.getString(params, "direction", "to");

        if (!VALID_DIRECTIONS.contains(direction)) {
            throw new RpcException("INVALID_PARAM",
                "direction must be one of: to, from, both",
                "Use --direction to|from|both");
        }

        IDexUnit dex = findDexForAny(state, itemSig);
        if (dex == null) {
            throw new RpcException("ITEM_NOT_FOUND",
                "Item not found: " + itemSig,
                "Use 'search_classes' or 'search_methods' to find valid signatures");
        }

        ResolvedItem resolved = resolveDexItem(dex, itemSig);
        if (resolved == null) {
            throw new RpcException("ITEM_NOT_FOUND",
                "Cannot resolve item: " + itemSig,
                "Use 'search_classes' or 'search_methods' to find valid signatures");
        }

        JSONArray refs = new JSONArray();

        if ("from".equals(direction) || "both".equals(direction)) {
            collectRefsFrom(dex, resolved, refs);
        }
        if ("to".equals(direction) || "both".equals(direction)) {
            collectRefsTo(dex, resolved, refs);
        }

        JSONObject r = new JSONObject();
        r.put("item_sig", itemSig);
        r.put("direction", direction);
        r.put("total", (long) refs.size());
        r.put("refs", refs);
        return r;
    }

    // ── callgraph ──

    /**
     * Call graph for a class (mermaid/DOT output).
     * Explores method-level call relationships starting from a class.
     * Params: class_sig, depth (max 5), direction (callers|callees|both), exclude
     * Response: {root, nodes, edges, mermaid, dot, saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleCallgraph(JSONObject params, ServerState state) {
        String classSig = JsonUtil.getString(params, "class_sig", "");
        int depth = Math.min(JsonUtil.getInt(params, "depth", 2), 5);
        String direction = JsonUtil.getString(params, "direction", "both");
        String excludeRaw = JsonUtil.getString(params, "exclude", "");

        // Parse exclude prefixes
        List<String> excludePrefixes = new ArrayList<>();
        if (excludeRaw != null && !excludeRaw.isEmpty()) {
            for (String e : excludeRaw.split(",")) {
                String trimmed = e.trim();
                if (!trimmed.isEmpty()) excludePrefixes.add(trimmed);
            }
        }

        // Require class
        IDexUnit dex = state.findDexForClass(classSig);
        if (dex == null) {
            throw new RpcException("CLASS_NOT_FOUND",
                "Class not found: " + classSig,
                "Use 'search_classes' to find valid signatures");
        }
        IDexClass cls = dex.getClass(classSig);
        if (cls == null) {
            throw new RpcException("CLASS_NOT_FOUND",
                "Class not found: " + classSig,
                "Use 'search_classes' to find valid signatures");
        }

        Set<String> nodes = new LinkedHashSet<>();
        EdgeCollector ec = new EdgeCollector();
        Set<String> visited = new HashSet<>();

        // Collect initial method sigs from the class
        List<String> currentSigs = new ArrayList<>();
        for (Object mObj : cls.getMethods()) {
            IDexMethod m = (IDexMethod) mObj;
            String sig = m.getSignature(true);
            currentSigs.add(sig);
            nodes.add(sig);
        }

        for (int level = 0; level < depth; level++) {
            if (currentSigs.isEmpty()) break;
            List<String> nextSigs = new ArrayList<>();

            for (String sig : currentSigs) {
                if (visited.contains(sig)) continue;
                visited.add(sig);

                IDexMethod item = dex.getMethod(sig);
                if (item == null) continue;
                int idx = item.getIndex();

                // Callees (from): look at instructions in the method body
                if ("callees".equals(direction) || "both".equals(direction)) {
                    if (item.isInternal()) {
                        try {
                            IDexMethodData data = item.getData();
                            IDexCodeItem codeItem = data != null ? data.getCodeItem() : null;
                            if (codeItem != null) {
                                for (Object insnObj : codeItem.getInstructions()) {
                                    // Use reflection-safe access to instruction parameters
                                    try {
                                        java.lang.reflect.Method getParams = insnObj.getClass().getMethod("getParameters");
                                        Object[] instrParams = (Object[]) getParams.invoke(insnObj);
                                        if (instrParams != null) {
                                            for (Object param : instrParams) {
                                                try {
                                                    java.lang.reflect.Method getValue = param.getClass().getMethod("getValue");
                                                    int paramIdx = ((Number) getValue.invoke(param)).intValue();
                                                    IDexMethod target = dex.getMethod(paramIdx);
                                                    if (target != null) {
                                                        String tSig = target.getSignature(true);
                                                        if (shouldExclude(tSig, excludePrefixes)) continue;
                                                        nodes.add(tSig);
                                                        ec.add(sig, tSig);
                                                        nextSigs.add(tSig);
                                                    }
                                                } catch (Exception e2) { /* not a method ref */ }
                                            }
                                        }
                                    } catch (Exception e2) { /* skip */ }
                                }
                            }
                        } catch (Exception e) {
                            // skip
                        }
                    }
                }

                // Callers (to)
                if ("callers".equals(direction) || "both".equals(direction)) {
                    Collection<? extends IDexAddress> xrefAddrs = dex.getCrossReferences(DexPoolType.METHOD, idx);
                    if (xrefAddrs != null) {
                        for (IDexAddress addr : xrefAddrs) {
                            String callerAddr = addr.getInternalAddress();
                            if (callerAddr == null) callerAddr = "";
                            if (shouldExclude(callerAddr, excludePrefixes)) continue;
                            nodes.add(callerAddr);
                            ec.add(callerAddr, sig);
                            nextSigs.add(callerAddr);
                        }
                    }
                }
            }
            currentSigs = nextSigs;
        }

        return buildGraphResult(classSig, nodes, ec, "callgraph");
    }

    // ── cross_refs ──

    /**
     * Multi-level xref chain tracing.
     * Starting from item_sig, follows xrefs up to 'depth' levels.
     * Params: item_sig, depth (max 5), direction (to|from|both)
     * Response: {root, nodes, edges, mermaid, dot, depth, chain, saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleCrossRefs(JSONObject params, ServerState state) {
        String itemSig = JsonUtil.getString(params, "item_sig", "");
        int depth = Math.min(JsonUtil.getInt(params, "depth", 2), 5);
        String direction = JsonUtil.getString(params, "direction", "to");

        if (!VALID_DIRECTIONS.contains(direction)) {
            throw new RpcException("INVALID_PARAM",
                "direction must be one of: to, from, both",
                "Use --direction to|from|both");
        }

        IDexUnit dex = findDexForAny(state, itemSig);
        if (dex == null) {
            throw new RpcException("ITEM_NOT_FOUND",
                "Item not found: " + itemSig,
                "Use 'search_classes' or 'search_methods' to find valid signatures");
        }

        Set<String> nodes = new LinkedHashSet<>();
        nodes.add(itemSig);
        EdgeCollector ec = new EdgeCollector();
        JSONArray chain = new JSONArray();
        Set<String> visited = new HashSet<>();
        List<String> currentSigs = new ArrayList<>();
        currentSigs.add(itemSig);

        for (int level = 0; level < depth; level++) {
            if (currentSigs.isEmpty()) break;
            List<String> nextSigs = new ArrayList<>();

            for (String sig : currentSigs) {
                if (visited.contains(sig)) continue;
                visited.add(sig);

                ResolvedItem resolved = resolveDexItem(dex, sig);
                if (resolved == null) continue;
                int idx = resolved.item.getIndex();

                // "to" direction: who references this item
                if ("to".equals(direction) || "both".equals(direction)) {
                    Collection<? extends IDexAddress> xrefAddrs =
                        dex.getCrossReferences(resolved.poolType, idx);
                    if (xrefAddrs != null) {
                        for (IDexAddress addr : xrefAddrs) {
                            String refAddr = addr.getInternalAddress();
                            // Resolve to full method signature
                            String resolvedAddr = refAddr != null ? refAddr : "";
                            int plusPos = resolvedAddr.lastIndexOf('+');
                            String methodPart = plusPos > 0 ? resolvedAddr.substring(0, plusPos) : resolvedAddr;
                            IDexMethod m = dex.getMethod(methodPart);
                            String displayAddr = m != null ? m.getSignature(true) : resolvedAddr;

                            nodes.add(displayAddr);
                            ec.add(displayAddr, sig);

                            JSONObject chainEntry = new JSONObject();
                            chainEntry.put("depth", (long) (level + 1));
                            chainEntry.put("from", displayAddr);
                            chainEntry.put("to", sig);
                            chainEntry.put("type", String.valueOf(addr.getReferenceType()));
                            chain.add(chainEntry);

                            nextSigs.add(m != null ? methodPart : resolvedAddr);
                        }
                    }
                }

                // "from" direction: what this item references
                // Only works for methods with internal code (inspect instructions)
                if ("from".equals(direction) || "both".equals(direction)) {
                    if (resolved.poolType == DexPoolType.METHOD) {
                        IDexMethod mItem = dex.getMethod(sig);
                        if (mItem != null && mItem.isInternal()) {
                            try {
                                IDexMethodData data = mItem.getData();
                                IDexCodeItem codeItem = data != null ? data.getCodeItem() : null;
                                if (codeItem != null) {
                                    for (Object insnObj : codeItem.getInstructions()) {
                                        try {
                                            java.lang.reflect.Method getParams = insnObj.getClass().getMethod("getParameters");
                                            Object[] instrParams = (Object[]) getParams.invoke(insnObj);
                                            if (instrParams != null) {
                                                for (Object param : instrParams) {
                                                    try {
                                                        java.lang.reflect.Method getValue = param.getClass().getMethod("getValue");
                                                        int refIdx = ((Number) getValue.invoke(param)).intValue();
                                                        IDexMethod target = dex.getMethod(refIdx);
                                                        if (target != null) {
                                                            String displayAddr = target.getSignature(true);
                                                            nodes.add(displayAddr);
                                                            ec.add(sig, displayAddr);

                                                            JSONObject chainEntry = new JSONObject();
                                                            chainEntry.put("depth", (long) (level + 1));
                                                            chainEntry.put("from", sig);
                                                            chainEntry.put("to", displayAddr);
                                                            chainEntry.put("type", "REFERENCE");
                                                            chain.add(chainEntry);

                                                            nextSigs.add(displayAddr);
                                                        }
                                                    } catch (Exception e3) { /* not a method ref */ }
                                                }
                                            }
                                        } catch (Exception e2) { /* skip */ }
                                    }
                                }
                            } catch (Exception e) {
                                // skip
                            }
                        }
                    }
                }
            }
            currentSigs = nextSigs;
        }

        JSONObject r = buildGraphResult(itemSig, nodes, ec, "cross_refs");
        r.put("depth", (long) depth);
        r.put("chain", chain);
        return r;
    }

    // ── internal helpers ──

    /** Find a DEX unit containing any item (method, class, or field) matching sig. */
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

    /** Resolve a signature to item + pool type. Tries method -> class -> field. */
    private static ResolvedItem resolveDexItem(IDexUnit dex, String sig) {
        IDexMethod m = dex.getMethod(sig);
        if (m != null) return new ResolvedItem(m, DexPoolType.METHOD);
        IDexClass c = dex.getClass(sig);
        if (c != null) return new ResolvedItem(c, DexPoolType.TYPE);
        IDexField f = dex.getField(sig);
        if (f != null) return new ResolvedItem(f, DexPoolType.FIELD);
        return null;
    }

    /** Holder for resolved DEX item + its pool type. */
    private static class ResolvedItem {
        final IDexItem item;
        final DexPoolType poolType;
        ResolvedItem(IDexItem item, DexPoolType poolType) {
            this.item = item;
            this.poolType = poolType;
        }
    }

    /**
     * Collect "from" references: what the resolved item references (outgoing).
     * For methods, inspects instructions for method call targets.
     */
    @SuppressWarnings("unchecked")
    private static void collectRefsFrom(IDexUnit dex, ResolvedItem resolved, JSONArray refs) {
        if (resolved.poolType != DexPoolType.METHOD) return;
        IDexMethod m = dex.getMethod(resolved.item.getSignature(true));
        if (m == null || !m.isInternal()) return;
        try {
            IDexMethodData data = m.getData();
            IDexCodeItem codeItem = data != null ? data.getCodeItem() : null;
            if (codeItem == null) return;
            for (Object insnObj : codeItem.getInstructions()) {
                try {
                    java.lang.reflect.Method getParams = insnObj.getClass().getMethod("getParameters");
                    Object[] instrParams = (Object[]) getParams.invoke(insnObj);
                    if (instrParams != null) {
                        for (Object param : instrParams) {
                            try {
                                java.lang.reflect.Method getValue = param.getClass().getMethod("getValue");
                                int paramIdx = ((Number) getValue.invoke(param)).intValue();
                                IDexMethod target = dex.getMethod(paramIdx);
                                if (target != null) {
                                    JSONObject ref = new JSONObject();
                                    ref.put("address", target.getSignature(true));
                                    ref.put("type", "REFERENCE");
                                    ref.put("direction", "from");
                                    refs.add(ref);
                                }
                            } catch (Exception e2) { /* not a method ref */ }
                        }
                    }
                } catch (Exception e2) { /* skip */ }
            }
        } catch (Exception e) { /* skip */ }
    }

    /**
     * Collect "to" references: who references this item (incoming xrefs).
     * Uses dex.getCrossReferences() directly.
     */
    @SuppressWarnings("unchecked")
    private static void collectRefsTo(IDexUnit dex, ResolvedItem resolved, JSONArray refs) {
        try {
            Collection<? extends IDexAddress> xrefAddrs =
                dex.getCrossReferences(resolved.poolType, resolved.item.getIndex());
            if (xrefAddrs == null) return;
            for (IDexAddress addr : xrefAddrs) {
                JSONObject ref = new JSONObject();
                ref.put("address", addr.getInternalAddress());
                ref.put("type", String.valueOf(addr.getReferenceType()));
                ref.put("direction", "to");
                refs.add(ref);
            }
        } catch (Exception e) { /* skip */ }
    }

    /** Check if a signature should be excluded by prefix list. */
    private static boolean shouldExclude(String sig, List<String> prefixes) {
        if (prefixes.isEmpty()) return false;
        for (String p : prefixes) {
            if (sig.startsWith("L" + p.replace('.', '/'))) return true;
        }
        return false;
    }

    /**
     * Deduplicating edge collector for graph traversals.
     */
    private static class EdgeCollector {
        final List<String[]> edges = new ArrayList<>();
        private final Set<String> seen = new HashSet<>();

        void add(String src, String dst) {
            String key = src + "\0" + dst;
            if (!seen.contains(key)) {
                seen.add(key);
                edges.add(new String[]{src, dst});
            }
        }

        @SuppressWarnings("unchecked")
        JSONArray toDicts() {
            JSONArray arr = new JSONArray();
            for (String[] e : edges) {
                JSONObject obj = new JSONObject();
                obj.put("from", e[0]);
                obj.put("to", e[1]);
                arr.add(obj);
            }
            return arr;
        }
    }

    /** Build standard graph result from nodes + edges. */
    @SuppressWarnings("unchecked")
    private static JSONObject buildGraphResult(String root, Set<String> nodes,
                                                EdgeCollector ec, String graphName) {
        String mermaid = edgesToGraph(ec.edges, "mermaid", graphName);
        String dot = edgesToGraph(ec.edges, "dot", graphName);

        JSONArray nodesArr = new JSONArray();
        nodesArr.addAll(nodes);

        JSONObject r = new JSONObject();
        r.put("root", root);
        r.put("nodes", nodesArr);
        r.put("edges", ec.toDicts());
        r.put("mermaid", mermaid);
        r.put("dot", dot);
        r.put("saved_to", null);
        return r;
    }

    /** Generate Mermaid or DOT graph text from edges. */
    private static String edgesToGraph(List<String[]> edges, String fmt, String graphName) {
        StringBuilder sb = new StringBuilder();
        if ("dot".equals(fmt)) {
            sb.append("digraph ").append(graphName).append(" {\n");
            for (String[] e : edges) {
                sb.append("  \"").append(escapeDot(e[0]))
                  .append("\" -> \"").append(escapeDot(e[1])).append("\";\n");
            }
            sb.append("}");
        } else {
            sb.append("graph LR\n");
            for (String[] e : edges) {
                sb.append("  \"").append(escapeMermaid(e[0]))
                  .append("\" --> \"").append(escapeMermaid(e[1])).append("\"\n");
            }
        }
        return sb.toString();
    }

    private static String escapeDot(String s) {
        return s == null ? "" : s.replace("\"", "\\\"");
    }

    private static String escapeMermaid(String s) {
        return s == null ? "" : s.replace("\"", "'");
    }
}
