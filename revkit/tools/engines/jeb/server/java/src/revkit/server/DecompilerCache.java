package revkit.server;

import com.pnfsoftware.jeb.core.units.code.DecompilationContext;
import com.pnfsoftware.jeb.core.units.code.DecompilationOptions;
import com.pnfsoftware.jeb.core.units.code.IDecompilerUnit;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.util.DecompilerHelper;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Decompiler cache with approximate LRU eviction.
 * ConcurrentHashMap for thread-safe reads, ConcurrentLinkedDeque for access order.
 */
public class DecompilerCache {

    private static final int MAX_CACHE_ENTRIES = 5_000;  // Phase 0.5 scale

    private final ConcurrentHashMap<String, String> cache = new ConcurrentHashMap<>();
    private final ConcurrentLinkedDeque<String> accessOrder = new ConcurrentLinkedDeque<>();

    // Per-thread decompiler instances (IDecompilerUnit may not be thread-safe)
    private final ThreadLocal<Map<Integer, IDecompilerUnit>> threadDecompilers =
        ThreadLocal.withInitial(HashMap::new);

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

    public Set<Map.Entry<String, String>> entrySet() {
        return new HashMap<>(cache).entrySet();  // Snapshot copy
    }

    private void evictIfNeeded() {
        while (cache.size() > MAX_CACHE_ENTRIES) {
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

    public static DecompilationContext makeDecompileContext() {
        return new DecompilationContext(DecompilationOptions.DEFAULT);
    }
}
