package com.reconlens.analysis;

import java.util.regex.Pattern;

/**
 * Collapses "same endpoint, different data" requests together, e.g.
 * {@code /api/v2/users/1042/orders/88f3} and {@code /api/v2/users/77/orders/12}
 * both normalize to {@code /api/v2/users/{id}/orders/{id}}. This is the
 * difference between staring at 4,000 rows of proxy history and staring at 60.
 */
public final class EndpointGrouper {

    private static final Pattern NUMERIC = Pattern.compile("^\\d+$");
    private static final Pattern UUID = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern MONGO_OBJECT_ID = Pattern.compile("(?i)^[0-9a-f]{24}$");
    private static final Pattern HEX_HASHISH = Pattern.compile("^[0-9a-fA-F]{16,}$");

    private EndpointGrouper() {}

    public static String normalize(String pathWithoutQuery) {
        if (pathWithoutQuery == null || pathWithoutQuery.isEmpty()) return "/";
        String[] segments = pathWithoutQuery.split("/", -1);
        for (int i = 0; i < segments.length; i++) {
            segments[i] = normalizeSegment(segments[i]);
        }
        return String.join("/", segments);
    }

    private static String normalizeSegment(String seg) {
        if (seg.isEmpty()) return seg;
        if (NUMERIC.matcher(seg).matches()) return "{id}";
        if (UUID.matcher(seg).matches()) return "{uuid}";
        if (MONGO_OBJECT_ID.matcher(seg).matches()) return "{objectId}";
        if (HEX_HASHISH.matcher(seg).matches()) return "{hash}";
        return seg;
    }
}
