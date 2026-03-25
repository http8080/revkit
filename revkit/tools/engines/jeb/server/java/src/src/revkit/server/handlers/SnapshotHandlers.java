package revkit.server.handlers;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import revkit.server.RpcException;
import revkit.server.ServerState;
import revkit.server.util.JsonUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Snapshot RPC handlers: snapshot_save, snapshot_list, snapshot_restore.
 */
public final class SnapshotHandlers {

    private SnapshotHandlers() {}

    /**
     * Return (projectPath, snapshotsDir). Throws if project path unknown.
     */
    private static Path[] getSnapshotPaths(ServerState state, boolean requireFile) {
        String prjPath = state.getProjectPath();
        if (prjPath == null || prjPath.isEmpty()) {
            throw new RpcException("SNAPSHOT_FAILED",
                "Cannot determine project file path",
                "Ensure the project was saved at least once with 'save'");
        }
        Path prj = Paths.get(prjPath);
        if (requireFile && !Files.isRegularFile(prj)) {
            throw new RpcException("SNAPSHOT_FAILED",
                "Project file not found: " + prjPath,
                "Ensure the project was saved at least once with 'save'");
        }
        Path snapDir = prj.getParent().resolve("snapshots");
        return new Path[]{prj, snapDir};
    }

    /**
     * Save a project snapshot (.jdb2 backup with optional description metadata).
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleSnapshotSave(JSONObject params, ServerState state) {
        String description = JsonUtil.getString(params, "description", "");

        // Try to save the project first (best effort)
        try {
            state.getEngctx().saveProject(state.getProject().getKey(), state.getProjectPath(), null, null);
        } catch (Exception e) {
            // ignore save failure -- we still snapshot whatever is on disk
        }

        Path[] paths = getSnapshotPaths(state, true);
        Path prjPath = paths[0];
        Path snapDir = paths[1];

        try {
            Files.createDirectories(snapDir);
        } catch (IOException e) {
            throw new RpcException("SNAPSHOT_FAILED",
                "Cannot create snapshots directory: " + e.getMessage());
        }

        String ts = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String baseName = prjPath.getFileName().toString();
        int dot = baseName.lastIndexOf('.');
        String stem = dot > 0 ? baseName.substring(0, dot) : baseName;
        String snapName = stem + "_" + ts + ".bak";
        Path snapPath = snapDir.resolve(snapName);

        try {
            Files.copy(prjPath, snapPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new RpcException("SNAPSHOT_FAILED",
                "Failed to copy project file: " + e.getMessage());
        }

        // Write metadata file if description provided
        if (description != null && !description.isEmpty()) {
            Path metaPath = Paths.get(snapPath.toString() + ".meta");
            JSONObject meta = new JSONObject();
            meta.put("description", description);
            meta.put("created", ts);
            meta.put("source", prjPath.toString());
            try {
                Files.write(metaPath, meta.toJSONString().getBytes(StandardCharsets.UTF_8));
            } catch (IOException e) {
                // metadata write failure is non-fatal
            }
        }

        JSONObject r = new JSONObject();
        r.put("ok", true);
        r.put("filename", snapName);
        r.put("description", description);
        return r;
    }

    /**
     * List available snapshots with metadata.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleSnapshotList(JSONObject params, ServerState state) {
        Path snapDir;
        try {
            Path[] paths = getSnapshotPaths(state, false);
            snapDir = paths[1];
        } catch (Exception e) {
            JSONObject r = new JSONObject();
            r.put("total", 0L);
            r.put("snapshots", new JSONArray());
            return r;
        }

        JSONArray snapshots = new JSONArray();
        if (Files.isDirectory(snapDir)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(snapDir, "*.bak")) {
                java.util.List<Path> sorted = new java.util.ArrayList<>();
                for (Path p : stream) sorted.add(p);
                sorted.sort(java.util.Comparator.comparing(p -> p.getFileName().toString()));

                for (Path fpath : sorted) {
                    JSONObject snap = new JSONObject();
                    snap.put("filename", fpath.getFileName().toString());
                    try {
                        long mtime = Files.getLastModifiedTime(fpath).toMillis();
                        snap.put("created",
                            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(mtime)));
                        snap.put("size", Files.size(fpath));
                    } catch (IOException e) {
                        snap.put("created", "");
                        snap.put("size", 0L);
                    }

                    // Read description from .meta file
                    String desc = "";
                    Path metaPath = Paths.get(fpath.toString() + ".meta");
                    if (Files.isRegularFile(metaPath)) {
                        try {
                            String metaContent = new String(
                                Files.readAllBytes(metaPath), StandardCharsets.UTF_8);
                            Object parsed = new JSONParser().parse(metaContent);
                            if (parsed instanceof JSONObject) {
                                Object d = ((JSONObject) parsed).get("description");
                                if (d != null) desc = d.toString();
                            }
                        } catch (Exception e) {
                            // ignore metadata read failure
                        }
                    }
                    snap.put("description", desc);
                    snapshots.add(snap);
                }
            } catch (IOException e) {
                // directory listing failure
            }
        }

        JSONObject r = new JSONObject();
        r.put("total", (long) snapshots.size());
        r.put("snapshots", snapshots);
        return r;
    }

    /**
     * Restore a project from a snapshot. Auto-backs up current state first.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject handleSnapshotRestore(JSONObject params, ServerState state) {
        String filename = JsonUtil.requireParam(params, "filename");

        Path[] paths = getSnapshotPaths(state, true);
        Path prjPath = paths[0];
        Path snapDir = paths[1];
        Path snapPath = snapDir.resolve(filename);

        if (!Files.isRegularFile(snapPath)) {
            throw new RpcException("SNAPSHOT_NOT_FOUND",
                "Snapshot not found: " + filename,
                "Use 'snapshot list' to see available snapshots");
        }

        // Auto-backup before restoring
        String ts = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String baseName = prjPath.getFileName().toString();
        int dot = baseName.lastIndexOf('.');
        String stem = dot > 0 ? baseName.substring(0, dot) : baseName;
        Path autoBackup = snapDir.resolve(stem + "_pre_restore_" + ts + ".bak");
        try {
            Files.copy(prjPath, autoBackup, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            // auto-backup failure is non-fatal
        }

        // Restore snapshot over project file
        try {
            Files.copy(snapPath, prjPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new RpcException("SNAPSHOT_FAILED",
                "Failed to restore snapshot: " + e.getMessage());
        }

        JSONObject r = new JSONObject();
        r.put("ok", true);
        r.put("filename", filename);
        return r;
    }
}
