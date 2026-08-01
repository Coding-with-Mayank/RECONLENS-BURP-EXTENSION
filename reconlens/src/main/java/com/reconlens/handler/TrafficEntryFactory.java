package com.reconlens.handler;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.reconlens.analysis.EndpointGrouper;
import com.reconlens.analysis.JwtInspector;
import com.reconlens.analysis.ParameterAnalyzer;
import com.reconlens.analysis.RiskScorer;
import com.reconlens.analysis.VulnerabilityRuleEngine;
import com.reconlens.model.HttpParam;
import com.reconlens.model.JwtInfo;
import com.reconlens.model.ParamFinding;
import com.reconlens.model.ParamType;
import com.reconlens.model.RiskScore;
import com.reconlens.model.TrafficEntry;
import com.reconlens.model.VulnSuggestion;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The only class in this project that touches both "Montoya types" and "our own
 * model" -- everything downstream of this (analysis, UI, export) is Burp-free.
 * That split is deliberate: it's what lets ParameterAnalyzer/EndpointGrouper/
 * VulnerabilityRuleEngine be compiled and unit-tested with plain {@code javac},
 * no Burp installation required, while still being real production logic.
 */
public final class TrafficEntryFactory {

    // Keep memory bounded and keep AI prompts small -- see ClaudeClient for the
    // separate, user-controlled toggle for whether bodies get sent to the API at all.
    private static final int BODY_SNIPPET_LIMIT = 4000;

    private TrafficEntryFactory() {}

    public static TrafficEntry build(long id, String toolSource, HttpRequest request, HttpResponse response) {
        HttpService service = request.httpService();
        String host = service != null ? service.host() : "";
        int port = service != null ? service.port() : 0;
        boolean secure = service != null && service.secure();

        String path = safePathWithoutQuery(request);
        String normalizedPath = EndpointGrouper.normalize(path);

        List<HttpParam> params = extractParams(request);
        List<ParamFinding> findings = ParameterAnalyzer.analyze(params);

        Integer statusCode = response != null ? (int) response.statusCode() : null;
        String mimeType = response != null && response.statedMimeType() != null
                ? response.statedMimeType().toString() : null;
        int responseLength = response != null && response.body() != null ? response.body().length() : 0;

        Map<String, String> responseHeadersLower = new HashMap<>();
        if (response != null) {
            for (HttpHeader h : response.headers()) {
                responseHeadersLower.merge(h.name().toLowerCase(Locale.ROOT), h.value(), (a, b) -> a + "; " + b);
            }
        }
        String responseBodySnippet = response != null ? truncate(response.bodyToString(), BODY_SNIPPET_LIMIT) : null;

        List<VulnSuggestion> suggestions = VulnerabilityRuleEngine.suggest(
                request.method(), params, findings, statusCode, mimeType, responseHeadersLower, responseBodySnippet);

        String requestHead = request.method() + " " + path + "\n" + formatHeaders(request.headers());
        String requestBody = truncate(request.bodyToString(), BODY_SNIPPET_LIMIT);
        String responseHead = response != null
                ? "HTTP " + statusCode + "\n" + formatHeaders(response.headers())
                : "";
        String responseBody = responseBodySnippet != null ? responseBodySnippet : "";

        boolean looksAuthenticated = looksAuthenticated(request.headers());
        List<JwtInfo> jwtFindings = extractJwtFindings(params, request.headers());
        RiskScore riskScore = RiskScorer.score(request.method(), findings, suggestions, looksAuthenticated);

        return new TrafficEntry(id, Instant.now(), toolSource, request.method(), host, port, secure,
                path, safeUrl(request), statusCode, mimeType, responseLength,
                requestHead, requestBody, responseHead, responseBody,
                normalizedPath, params, findings, suggestions,
                looksAuthenticated, jwtFindings, riskScore);
    }

    /** Cheap but useful correlation signal: does this request even look authenticated? */
    private static boolean looksAuthenticated(List<HttpHeader> requestHeaders) {
        for (HttpHeader h : requestHeaders) {
            String name = h.name().toLowerCase(Locale.ROOT);
            if (name.equals("authorization")) return true;
            if (name.equals("cookie") && h.value() != null && !h.value().isBlank()) return true;
        }
        return false;
    }

    /** Looks for JWTs both as a parameter value and in the Authorization header (the far more common spot). */
    private static List<JwtInfo> extractJwtFindings(List<HttpParam> params, List<HttpHeader> requestHeaders) {
        List<JwtInfo> out = new ArrayList<>();
        for (HttpParam p : params) {
            addIfJwt(out, p.value);
        }
        for (HttpHeader h : requestHeaders) {
            if (h.name().equalsIgnoreCase("authorization")) {
                String v = h.value();
                String token = (v != null && v.toLowerCase(Locale.ROOT).startsWith("bearer "))
                        ? v.substring(7).trim() : v;
                addIfJwt(out, token);
            }
        }
        return out;
    }

    private static void addIfJwt(List<JwtInfo> out, String candidate) {
        if (candidate == null || !candidate.startsWith("eyJ")) return; // cheap pre-filter before attempting to decode
        JwtInfo info = JwtInspector.inspect(candidate);
        if (info != null) out.add(info);
    }

    private static List<HttpParam> extractParams(HttpRequest request) {
        List<HttpParam> out = new ArrayList<>();
        for (ParsedHttpParameter p : request.parameters()) {
            out.add(new HttpParam(p.name(), p.value(), mapType(p.type())));
        }
        return out;
    }

    private static ParamType mapType(HttpParameterType t) {
        if (t == null) return ParamType.UNKNOWN;
        try {
            return ParamType.valueOf(t.name());
        } catch (IllegalArgumentException e) {
            // Montoya added/renamed a parameter type we don't know about yet -- degrade
            // gracefully instead of throwing, since this runs on every single request.
            return ParamType.UNKNOWN;
        }
    }

    private static String formatHeaders(List<HttpHeader> headers) {
        StringBuilder sb = new StringBuilder();
        for (HttpHeader h : headers) sb.append(h.name()).append(": ").append(h.value()).append('\n');
        return sb.toString();
    }

    private static String safePathWithoutQuery(HttpRequest request) {
        try {
            return request.pathWithoutQuery();
        } catch (Exception e) {
            return request.path();
        }
    }

    private static String safeUrl(HttpRequest request) {
        try {
            return request.url();
        } catch (Exception e) {
            return request.path();
        }
    }

    private static String truncate(String s, int limit) {
        if (s == null) return "";
        return s.length() <= limit ? s : s.substring(0, limit) + "... [truncated]";
    }
}
