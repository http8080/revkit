package revkit.server;

import com.pnfsoftware.jeb.core.units.code.DecompilationContext;
import com.pnfsoftware.jeb.core.units.code.DecompilationOptions;
import com.pnfsoftware.jeb.core.units.code.IDecompilerUnit;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.util.DecompilerHelper;

import org.json.simple.JSONObject;
import revkit.server.util.JsonUtil;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Decompiler cache with approximate LRU eviction.
 * ConcurrentHashMap for thread-safe reads, ConcurrentLinkedDeque for access order.
 */
public class DecompilerCache {

    private final int maxCacheEntries;

    /** Default max entries when no config provided. */
    private static final int DEFAULT_MAX_CACHE_ENTRIES = 5_000;

    /** Estimated memory per cache entry (30 KB) for auto-scaling from heap. */
    private static final long BYTES_PER_ENTRY_ESTIMATE = 30L * 1024;

    /** Default decompile timeout per method in milliseconds (#25). */
    private static final long DEFAULT_TIMEOUT_PER_METHOD_MS = 30_000L;

    private final long timeoutPerMethodMs;

    private final ConcurrentHashMap<String, String> cache = new ConcurrentHashMap<>();
    private final ConcurrentLinkedDeque<String> accessOrder = new ConcurrentLinkedDeque<>();

    // Per-thread decompiler instances (IDecompilerUnit may not be thread-safe)
    private final ThreadLocal<Map<Integer, IDecompilerUnit>> threadDecompilers =
        ThreadLocal.withInitial(HashMap::new);

    /** Construct with explicit max entries and decompile timeout. */
    public DecompilerCache(int maxEntries, long timeoutPerMethodMs) {
        this.maxCacheEntries = maxEntries > 0 ? maxEntries : DEFAULT_MAX_CACHE_ENTRIES;
        this.timeoutPerMethodMs = timeoutPerMethodMs > 0 ? timeoutPerMethodMs : DEFAULT_TIMEOUT_PER_METHOD_MS;
    }

    /** Construct with default settings. */
    public DecompilerCache() {
        this(DEFAULT_MAX_CACHE_ENTRIES, DEFAULT_TIMEOUT_PER_METHOD_MS);
    }

    /**
     * Factory: create from config (#3).
     * Reads jeb.cache.max_entries (default: auto-calculate from heap).
     * Reads jeb.decompile.timeout_per_method_ms (default: 30000) (#25).
     */
    public static DecompilerCache createFromConfig(JSONObject config) {
        JSONObject jebCfg = JsonUtil.getMap(config, "jeb");

        // Max entries: explicit config or auto-scale from heap
        JSONObject cacheCfg = JsonUtil.getMap(jebCfg, "cache");
        int maxEntries = JsonUtil.getInt(cacheCfg, "max_entries", -1);
        if (maxEntries <= 0) {
            long maxHeap = Runtime.getRuntime().maxMemory();
            maxEntries = (int) Math.min(maxHeap / BYTES_PER_ENTRY_ESTIMATE, Integer.MAX_VALUE);
            if (maxEntries < 500) maxEntries = 500;  // reasonable floor
        }

        // Decompile timeout
        JSONObject decompCfg = JsonUtil.getMap(jebCfg, "decompile");
        long timeout = JsonUtil.getLong(decompCfg, "timeout_per_method_ms", DEFAULT_TIMEOUT_PER_METHOD_MS);

        return new DecompilerCache(maxEntries, timeout);
    }

    /**
     * Get cached decompile result, or decompile on miss.
     * @param dex The DEX unit containing the class
     * @param classSig Class signature using getSignature(false) — immutable key
     */
    public String getOrDecompile(IDexUnit dex, String classSig) {
        String cached = cache.get(classSig);
        if (cached != null) {
            accessOrder.offer(classSig);
            return cached;
        }

        // Cache miss — decompile
        IDecompilerUnit decomp = getOrCreateDecompiler(dex);
        if (decomp == null) return "";

        String code = "";
        try {
            DecompilationContext dctx = makeDecompileContext();
            if (decomp.decompileClass(classSig, dctx)) {
                String text = decomp.getDecompiledClassText(classSig);
                if (text != null) code = text;
            }
        } catch (Exception e) {
            // Decompile failure — cache empty string to avoid retries
        }

        cache.putIfAbsent(classSig, code);
        accessOrder.offer(classSig);
        evictIfNeeded();
        return code;
    }

    public String get(String classSig) {
        String val = cache.get(classSig);
        if (val != null) accessOrder.offer(classSig);
        return val;
    }

    public void put(String classSig, String code) {
        cache.put(classSig, code);
        accessOrder.offer(classSig);
        evictIfNeeded();
    }

    public void invalidate(String classSig) { cache.remove(classSig); }
    public void invalidateAll() { cache.clear(); accessOrder.clear(); }
    public int size() { return cache.size(); }

    /** Direct view of cache entries — thread-safe for iteration (#5). */
    public Set<Map.Entry<String, String>> entrySet() {
        return cache.entrySet();
    }

    /** Snapshot copy of cache entries for callers that need a stable view. */
    public Set<Map.Entry<String, String>> entrySetSnapshot() {
        return new HashMap<>(cache).entrySet();
    }

    private void evictIfNeeded() {
        while (cache.size() > maxCacheEntries) {
            String oldest = accessOrder.poll();
            if (oldest == null) break;
            cache.remove(oldest);
        }
    }

    private IDecompilerUnit getOrCreateDecompiler(IDexUnit dex) {
        return threadDecompilers.get()
            .computeIfAbsent(System.identityHashCode(dex), k -> {
                try {
                    return DecompilerHelper.getDecompiler(dex);
                } catch (Exception e) {
                    return null;
                }
            });
    }

    /** Create decompilation context with configured timeout (#25). */
    public DecompilationContext makeDecompileContext() {
        return new DecompilationContext(
            DecompilationOptions.Builder.newInstance()
                .maxTimePerMethod(timeoutPerMethodMs)
                .build()
        );
    }

    /** Static convenience for callers without a cache instance. */
    public static DecompilationContext makeDefaultDecompileContext() {
        return new DecompilationContext(DecompilationOptions.DEFAULT);
    }

    // ── Phase 2: Parallel Decompilation ──────────────────────

    /**
     * Warm up cache by decompiling all classes in parallel.
     * Uses JEB native batch if available, falls back to manual parallelism.
     *
     * @param dex DEX unit to decompile
     * @param classes List of class signatures to decompile
     * @param maxWorkers Number of parallel workers (0 = CPU cores - 1)
     * @param progress Optional callback (decompiled, total) for progress tracking
     * @return Number of successfully decompiled classes
     */
    public int warmupAll(IDexUnit dex, List<String> classes, int maxWorkers,
                         BiConsumer<Integer, Integer> progress) {
        if (classes == null || classes.isEmpty()) return 0;
        int workers = maxWorkers > 0 ? maxWorkers
            : Math.max(1, Runtime.getRuntime().availableProcessors() - 1);

        // Strategy A: Try JEB native decompileAllClasses() first
        try {
            IDecompilerUnit decomp = DecompilerHelper.getDecompiler(dex);
            if (decomp != null) {
                DecompilationContext dctx = makeDecompileContext();  // uses configured timeout (#25)
                decomp.decompileAllClasses(dctx);
                // Collect results in batches of 100 (#6)
                AtomicInteger ok = new AtomicInteger(0);
                int batchSize = 100;
                for (int i = 0; i < classes.size(); i += batchSize) {
                    int end = Math.min(i + batchSize, classes.size());
                    List<String> batch = classes.subList(i, end);
                    for (String sig : batch) {
                        String code = decomp.getDecompiledClassText(sig);
                        if (code != null && !code.isEmpty()) {
                            put(sig, code);
                            ok.incrementAndGet();
                        }
                    }
                    if (progress != null) progress.accept(ok.get(), classes.size());
                }
                return ok.get();
            }
        } catch (Exception e) {
            // Native batch failed — fall through to Strategy B
        }

        // Strategy B: Manual parallel decompilation — process in batches of 100 (#6)
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        AtomicInteger success = new AtomicInteger(0);
        AtomicInteger done = new AtomicInteger(0);

        int batchSize = 100;
        for (int batchStart = 0; batchStart < classes.size(); batchStart += batchSize) {
            int batchEnd = Math.min(batchStart + batchSize, classes.size());
            List<String> batch = classes.subList(batchStart, batchEnd);

            List<Future<?>> futures = new ArrayList<>();
            for (String sig : batch) {
                if (cache.containsKey(sig)) {
                    done.incrementAndGet();
                    continue;
                }
                futures.add(pool.submit(() -> {
                    try {
                        String code = getOrDecompile(dex, sig);
                        if (code != null && !code.isEmpty()) success.incrementAndGet();
                    } catch (Exception e) {
                        // Individual class failure — continue
                    } finally {
                        int d = done.incrementAndGet();
                        if (progress != null) progress.accept(d, classes.size());
                    }
                }));
            }

            for (Future<?> f : futures) {
                try { f.get(60, TimeUnit.SECONDS); }
                catch (Exception e) { /* timeout or error — skip */ }
            }
        }

        pool.shutdown();
        return success.get();
    }

    // ── Phase 2: Parallel Search ─────────────────────────────

    /**
     * Search result holder for parallel search.
     */
    public static class SearchMatch {
        public final String classSig;
        public final int lineNumber;
        public final String lineText;
        public final String context;

        public SearchMatch(String classSig, int lineNumber, String lineText, String context) {
            this.classSig = classSig;
            this.lineNumber = lineNumber;
            this.lineText = lineText;
            this.context = context;
        }
    }

    /**
     * Parallel code search across cached decompiled sources.
     * Uses parallelStream for N-core speedup.
     *
     * @param query Search string
     * @param useRegex True for regex matching
     * @param caseSensitive Case-sensitive matching
     * @param contextLines Number of context lines around match
     * @param maxResults Maximum results to return
     * @return List of matches
     */
    public List<SearchMatch> searchParallel(String query, boolean useRegex,
                                            boolean caseSensitive, int contextLines,
                                            int maxResults) {
        Pattern regex = useRegex ? Pattern.compile(query,
            caseSensitive ? 0 : Pattern.CASE_INSENSITIVE) : null;
        String queryLower = caseSensitive ? query : query.toLowerCase();

        return cache.entrySet().parallelStream()
            .filter(e -> {
                String code = caseSensitive ? e.getValue() : e.getValue().toLowerCase();
                return useRegex ? regex.matcher(code).find() : code.contains(queryLower);
            })
            .flatMap(e -> {
                List<SearchMatch> matches = new ArrayList<>();
                String[] lines = e.getValue().split("\n");
                for (int i = 0; i < lines.length && matches.size() < maxResults; i++) {
                    boolean matched = useRegex
                        ? regex.matcher(lines[i]).find()
                        : (caseSensitive ? lines[i] : lines[i].toLowerCase()).contains(queryLower);
                    if (matched) {
                        // Build context
                        int start = Math.max(0, i - contextLines);
                        int end = Math.min(lines.length, i + contextLines + 1);
                        StringBuilder ctx = new StringBuilder();
                        for (int j = start; j < end; j++) {
                            if (j > start) ctx.append("\n");
                            ctx.append(j == i ? ">>> " : "    ").append(lines[j]);
                        }
                        matches.add(new SearchMatch(e.getKey(), i + 1, lines[i].trim(), ctx.toString()));
                    }
                }
                return matches.stream();
            })
            .limit(maxResults)
            .collect(Collectors.toList());
    }
}
