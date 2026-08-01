package com.reconlens.analysis;

import com.reconlens.model.ResourceProfile;
import com.reconlens.model.TrafficEntry;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Groups traffic by *resource* to answer "what CAN you do here". Same host +
 * path shape across every HTTP method is grouped together as before, but a
 * path's own trailing id-like segment (the last {id}/{uuid}/{objectId}/{hash}
 * placeholder {@link EndpointGrouper} produces) is also stripped before
 * grouping -- so GET /orders (list), POST /orders (create), and
 * GET/PUT/DELETE /orders/{id} (read/update/delete) are all recognized as one
 * "Orders" resource, not two separate, half-complete rows. Without this,
 * "Create" would almost never register on a normal REST API, since create
 * nearly always lives on the collection path rather than the item path.
 */
public final class ResourceProfiler {

    private static final String[] ID_PLACEHOLDERS = {"{id}", "{uuid}", "{objectId}", "{hash}"};

    private ResourceProfiler() {}

    public static List<ResourceProfile> profile(List<TrafficEntry> entries) {
        Map<String, ResourceProfile> byKey = new LinkedHashMap<>();
        for (TrafficEntry e : entries) {
            String basePath = basePathOf(e.normalizedPath);
            String key = e.host + basePath;
            ResourceProfile p = byKey.computeIfAbsent(key, k -> new ResourceProfile(k, e.host, basePath));
            String m = e.method == null ? "" : e.method.toUpperCase(Locale.ROOT);
            if (!m.isEmpty()) p.methodsSeen.add(m);
            p.memberIds.add(e.id);
        }
        return new ArrayList<>(byKey.values());
    }

    /**
     * Strips a single trailing id-like placeholder segment so an item path
     * and its collection path fall under the same resource:
     * "/orders/{id}" -> "/orders"; "/orders" is returned unchanged (nothing
     * to strip). Package-visible so {@code EndpointGroupIndex} can use the
     * exact same rule to look up which entries belong to a given resource.
     */
    static String basePathOf(String normalizedPath) {
        if (normalizedPath == null || normalizedPath.isEmpty()) return normalizedPath;
        for (String placeholder : ID_PLACEHOLDERS) {
            String suffix = "/" + placeholder;
            if (normalizedPath.endsWith(suffix)) {
                String stripped = normalizedPath.substring(0, normalizedPath.length() - suffix.length());
                return stripped.isEmpty() ? "/" : stripped;
            }
        }
        return normalizedPath;
    }
}
