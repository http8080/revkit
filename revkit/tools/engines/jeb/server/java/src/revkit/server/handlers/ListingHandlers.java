package revkit.server.handlers;

import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

/**
 * Listing RPC handlers. Phase 0.5: get_classes only.
 */
public final class ListingHandlers {

    private ListingHandlers() {}

    /**
     * Paginated class listing. Streaming — no full collection built.
     * Response: {total, offset, count, data: [{sig, name, current_name, access}], saved_to}
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleGetClasses(JSONObject params, ServerState state) {
        int offset = JsonUtil.getInt(params, "offset", 0);
        int count = Math.min(
            JsonUtil.getInt(params, "count", state.getDefaultCount()),
            state.getMaxCount());
        String filter = JsonUtil.getString(params, "filter");
        String filterLower = filter != null ? filter.toLowerCase() : null;

        JSONArray data = new JSONArray();
        int collected = 0, total = 0;

        for (IDexUnit dex : state.getDexUnits()) {
            for (Object obj : dex.getClasses()) {
                IDexClass cls = (IDexClass) obj;
                // Cache key = getSignature(false) — immutable original signature
                String sig = cls.getSignature(false);
                String currentName = cls.getName(true);

                // Filter: case-insensitive substring on sig or current name
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
        r.put("saved_to", null);  // Phase 0.5: no server-side file save
        return r;
    }
}
