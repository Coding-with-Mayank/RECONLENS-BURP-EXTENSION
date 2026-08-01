package com.reconlens.analysis;

import com.reconlens.model.Severity;
import com.reconlens.model.TrafficEntry;
import com.reconlens.model.VulnSuggestion;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Compares JSON response bodies *within* a single endpoint group (same method,
 * same normalized path -- so the same expected shape, different concrete
 * request). This is the "GET /users/5 vs GET /users/6" check: identical field
 * names but different values across requests is a strong signal the endpoint
 * returns per-object data keyed by whatever varied in the request; byte-
 * identical bodies for different requests is a different, also-useful signal.
 * Purely structural -- it never looks at what the values *mean*.
 */
public final class ResponseDiffAnalyzer {

    private static final int MAX_SAMPLES = 8; // keep this cheap even on a huge group

    private ResponseDiffAnalyzer() {}

    public static List<VulnSuggestion> analyze(List<TrafficEntry> members) {
        List<VulnSuggestion> out = new ArrayList<>();

        List<Object> parsed = new ArrayList<>();
        List<String> rawBodies = new ArrayList<>();
        for (TrafficEntry e : members) {
            if (parsed.size() >= MAX_SAMPLES) break;
            if (e.mimeType == null || !e.mimeType.toLowerCase(Locale.ROOT).contains("json")) continue;
            if (e.responseBody == null || e.responseBody.isBlank()) continue;
            Object tree = MiniJson.parseQuietly(e.responseBody);
            if (tree == null) continue;
            parsed.add(tree);
            rawBodies.add(e.responseBody);
        }

        if (parsed.size() < 2) return out;

        Set<String> firstShape = shapeOf(parsed.get(0));
        boolean sameShapeThroughout = true;
        boolean allBodiesIdentical = true;
        for (int i = 1; i < parsed.size(); i++) {
            if (!shapeOf(parsed.get(i)).equals(firstShape)) sameShapeThroughout = false;
            if (!rawBodies.get(i).equals(rawBodies.get(0))) allBodiesIdentical = false;
        }

        if (!firstShape.isEmpty() && sameShapeThroughout && !allBodiesIdentical) {
            out.add(new VulnSuggestion("IDOR / Data Enumeration", Severity.MEDIUM,
                "Compared " + parsed.size() + " responses on this endpoint shape: identical JSON field names " +
                "every time (" + String.join(", ", limit(firstShape, 6)) + "), but different values -- this " +
                "looks like a per-object endpoint returning different records for different requests.",
                "If the varying part of the request was an ID/identifier, confirm the server checks that the " +
                "requesting user actually owns that record, not just that it exists."));
        } else if (!firstShape.isEmpty() && allBodiesIdentical) {
            out.add(new VulnSuggestion("Possible Unused Identifier", Severity.LOW,
                "Compared " + parsed.size() + " responses on this endpoint shape and got byte-identical bodies " +
                "every time despite different requests.",
                "Check whether the varying parameter is actually consulted server-side at all, or whether " +
                "you're looking at a cached/default response regardless of input."));
        }

        return out;
    }

    /** Field-name signature, descending up to 2 levels into nested objects/arrays, ignoring values. */
    private static Set<String> shapeOf(Object tree) {
        Set<String> names = new TreeSet<>();
        collectShape(tree, "", names, 0);
        return names;
    }

    private static void collectShape(Object node, String prefix, Set<String> out, int depth) {
        if (depth > 2 || node == null) return;
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String name = prefix.isEmpty() ? String.valueOf(entry.getKey()) : prefix + "." + entry.getKey();
                out.add(name);
                collectShape(entry.getValue(), name, out, depth + 1);
            }
        } else if (node instanceof List<?> list && !list.isEmpty()) {
            collectShape(list.get(0), prefix + "[]", out, depth + 1);
        }
    }

    private static List<String> limit(Collection<String> in, int n) {
        List<String> out = new ArrayList<>();
        for (String s : in) {
            if (out.size() >= n) break;
            out.add(s);
        }
        return out;
    }
}
