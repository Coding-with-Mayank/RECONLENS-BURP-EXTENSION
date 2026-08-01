package com.reconlens.analysis;

import com.reconlens.model.ParamFinding;
import com.reconlens.model.RiskScore;
import com.reconlens.model.Severity;
import com.reconlens.model.VulnSuggestion;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Turns a pile of parameter findings + vulnerability leads into a single,
 * explainable 0-100 score. This is still a deterministic rubric, not a model
 * -- every point is attributable to a named reason on purpose, so a tester
 * can see exactly *why* one request outranks another instead of trusting a
 * black box. That's a design choice, not a limitation: an opaque score would
 * be worse than no score at all for triage.
 *
 * Contribution is capped *per distinct category / vuln class*, not per raw
 * finding -- ten boringly-similar parameters on one request shouldn't
 * outscore one genuinely dangerous one just by volume.
 */
public final class RiskScorer {

    private RiskScorer() {}

    public static RiskScore score(String method,
                                   List<ParamFinding> findings,
                                   List<VulnSuggestion> suggestions,
                                   boolean looksAuthenticated) {
        int total = 0;
        List<String> reasons = new ArrayList<>();

        Set<String> findingCategories = new LinkedHashSet<>();
        for (ParamFinding f : findings) findingCategories.add(f.category);

        for (String category : findingCategories) {
            Severity worst = worstSeverityFor(findings, category);
            int points = pointsFor(worst, 18, 10, 4);
            if (points == 0) continue;
            total += points;
            reasons.add("+" + points + "  " + category + " parameter present (" + worst + ")");
        }

        Set<String> vulnClasses = new LinkedHashSet<>();
        for (VulnSuggestion v : suggestions) vulnClasses.add(v.vulnClass);

        for (String vulnClass : vulnClasses) {
            Severity worst = worstConfidenceFor(suggestions, vulnClass);
            int points = pointsFor(worst, 20, 12, 5);
            if (points == 0) continue;
            total += points;
            reasons.add("+" + points + "  " + vulnClass + " lead (" + worst + " confidence)");
        }

        boolean stateChanging = isStateChanging(method);
        boolean hasObjectId = findingCategories.contains("Object Identifier");
        if (stateChanging && hasObjectId) {
            total += 10;
            reasons.add("+10  state-changing request (" + method + ") carries an object identifier");
        }

        boolean sensitiveCategory = findingCategories.contains("Object Identifier")
                || findingCategories.contains("Access Control");
        if (looksAuthenticated && sensitiveCategory) {
            total += 8;
            reasons.add("+8  occurs on what looks like an authenticated endpoint");
        }

        if (reasons.isEmpty()) {
            return RiskScore.none();
        }
        return new RiskScore(total, reasons);
    }

    private static boolean isStateChanging(String method) {
        if (method == null) return false;
        String m = method.toUpperCase(Locale.ROOT);
        return m.equals("POST") || m.equals("PUT") || m.equals("PATCH") || m.equals("DELETE");
    }

    private static Severity worstSeverityFor(List<ParamFinding> findings, String category) {
        Severity worst = Severity.INFO;
        for (ParamFinding f : findings) {
            if (f.category.equals(category) && f.severity.atLeast(worst)) worst = f.severity;
        }
        return worst;
    }

    private static Severity worstConfidenceFor(List<VulnSuggestion> suggestions, String vulnClass) {
        Severity worst = Severity.INFO;
        for (VulnSuggestion v : suggestions) {
            if (v.vulnClass.equals(vulnClass) && v.confidence.atLeast(worst)) worst = v.confidence;
        }
        return worst;
    }

    private static int pointsFor(Severity s, int high, int medium, int low) {
        switch (s) {
            case HIGH: return high;
            case MEDIUM: return medium;
            case LOW: return low;
            default: return 0;
        }
    }
}
