package com.reconlens.analysis;

import com.reconlens.model.ParamFinding;
import com.reconlens.model.Severity;
import com.reconlens.model.VulnSuggestion;

import java.util.List;

/**
 * Produces a plain-English, fully offline summary of a request/response pair.
 * This runs on every captured request. The optional Claude-powered explanation
 * (see {@code com.reconlens.ai.ClaudeClient}) is a richer, on-demand alternative
 * for the handful of requests a tester actually wants to think hard about.
 */
public final class RequestExplainer {

    private RequestExplainer() {}

    public static String explain(String method, String host, String path, int paramCount,
                                  Integer statusCode, String mimeType, int responseLength,
                                  List<ParamFinding> findings, List<VulnSuggestion> suggestions) {
        StringBuilder sb = new StringBuilder();

        sb.append("This is a ").append(method).append(" request to ").append(host).append(path);
        if (paramCount > 0) {
            sb.append(" carrying ").append(paramCount).append(paramCount == 1 ? " parameter" : " parameters");
        }
        sb.append(". ");

        if (statusCode != null) {
            sb.append("The server responded ").append(statusCode);
            if (mimeType != null && !mimeType.isEmpty() && !"null".equalsIgnoreCase(mimeType)) {
                sb.append(" with a ").append(mimeType).append(" body");
            }
            sb.append(" (").append(responseLength).append(" bytes). ");
        } else {
            sb.append("No response was captured for this request. ");
        }

        Severity worstParam = Severity.INFO;
        for (ParamFinding f : findings) if (f.severity.atLeast(worstParam)) worstParam = f.severity;

        if (!findings.isEmpty()) {
            sb.append("Parameter analysis flagged ").append(findings.size())
              .append(findings.size() == 1 ? " item" : " items")
              .append(" worth a look (highest severity: ").append(worstParam).append("). ");
        } else {
            sb.append("No notable parameters were flagged by name/shape heuristics. ");
        }

        if (!suggestions.isEmpty()) {
            sb.append("Candidate test areas: ");
            for (int i = 0; i < suggestions.size(); i++) {
                if (i > 0) sb.append(i == suggestions.size() - 1 ? "; and " : "; ");
                sb.append(suggestions.get(i).vulnClass);
            }
            sb.append(". These are heuristic leads, not confirmed findings -- verify each by hand.");
        } else {
            sb.append("No specific vulnerability class stood out from this pair alone.");
        }

        return sb.toString();
    }
}
