package com.reconlens.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Everything ReconLens knows about one captured request/response pair. */
public final class TrafficEntry {
    public final long id;
    public final Instant capturedAt;
    public final String toolSource;      // "PROXY", "REPEATER", "MANUAL", ...
    public final String method;
    public final String host;
    public final int port;
    public final boolean secure;
    public final String path;            // without query string
    public final String url;
    public final Integer statusCode;     // null if no response was captured
    public final String mimeType;
    public final int responseLength;
    public final String requestHead;     // request line + headers, for the detail view
    public final String requestBody;
    public final String responseHead;    // status line + headers
    public final String responseBody;

    public final String normalizedPath;  // e.g. /users/{id}/orders/{id}
    public final String groupKey;        // method + " " + host + normalizedPath

    public final List<HttpParam> params;
    public final List<ParamFinding> findings;
    public final List<VulnSuggestion> suggestions;

    /** True if the request carried an Authorization header or a non-empty Cookie header --
     *  a cheap but useful signal that a finding here has real access-control stakes. */
    public final boolean looksAuthenticated;

    /** Decoded JWTs found either as a parameter value or in the Authorization header. Usually
     *  empty; see {@code com.reconlens.analysis.JwtInspector} for how these get produced. */
    public final List<JwtInfo> jwtFindings;

    /** Explainable 0-100 score combining every signal above -- see RiskScorer for the rubric. */
    public final RiskScore riskScore;

    /** Filled in lazily, only when the user clicks "Explain with AI". Not thread-safe by
     *  design -- only ever written from the Swing EDT via ReconLensTab. */
    public volatile String aiExplanation;

    public TrafficEntry(long id, Instant capturedAt, String toolSource, String method, String host, int port,
                         boolean secure, String path, String url, Integer statusCode, String mimeType,
                         int responseLength, String requestHead, String requestBody, String responseHead,
                         String responseBody, String normalizedPath, List<HttpParam> params,
                         List<ParamFinding> findings, List<VulnSuggestion> suggestions,
                         boolean looksAuthenticated, List<JwtInfo> jwtFindings, RiskScore riskScore) {
        this.id = id;
        this.capturedAt = capturedAt;
        this.toolSource = toolSource;
        this.method = method;
        this.host = host;
        this.port = port;
        this.secure = secure;
        this.path = path;
        this.url = url;
        this.statusCode = statusCode;
        this.mimeType = mimeType;
        this.responseLength = responseLength;
        this.requestHead = requestHead;
        this.requestBody = requestBody;
        this.responseHead = responseHead;
        this.responseBody = responseBody;
        this.normalizedPath = normalizedPath;
        this.groupKey = method + " " + host + normalizedPath;
        this.params = Collections.unmodifiableList(new ArrayList<>(params));
        this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
        this.suggestions = Collections.unmodifiableList(new ArrayList<>(suggestions));
        this.looksAuthenticated = looksAuthenticated;
        this.jwtFindings = Collections.unmodifiableList(new ArrayList<>(jwtFindings));
        this.riskScore = riskScore == null ? RiskScore.none() : riskScore;
    }

    public Severity highestParamSeverity() {
        Severity max = Severity.INFO;
        for (ParamFinding f : findings) if (f.severity.atLeast(max)) max = f.severity;
        return max;
    }

    public Severity highestVulnConfidence() {
        Severity max = Severity.INFO;
        for (VulnSuggestion s : suggestions) if (s.confidence.atLeast(max)) max = s.confidence;
        return max;
    }
}
