package com.reconlens.analysis;

import com.reconlens.model.HttpParam;
import com.reconlens.model.JwtInfo;
import com.reconlens.model.ParamFinding;
import com.reconlens.model.ParamType;
import com.reconlens.model.ResourceProfile;
import com.reconlens.model.RiskScore;
import com.reconlens.model.Severity;
import com.reconlens.model.TrafficEntry;
import com.reconlens.model.VulnSuggestion;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * These exercise the "brains" of ReconLens in isolation, with no Burp Suite,
 * no Montoya API, and no network involved -- just plain POJOs in, findings out.
 */
class AnalysisTest {

    @Test
    void flagsSequentialIdParameterForIdor() {
        List<HttpParam> params = List.of(new HttpParam("order_id", "1042", ParamType.URL));
        List<ParamFinding> findings = ParameterAnalyzer.analyze(params);

        assertTrue(findings.stream().anyMatch(f -> f.category.equals("Object Identifier")));
        assertTrue(findings.stream().anyMatch(f -> f.category.equals("Sequential integer ID")));
    }

    @Test
    void flagsJwtShapedValueAsHighSeverity() {
        String fakeJwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ";
        List<HttpParam> params = List.of(new HttpParam("token", fakeJwt, ParamType.COOKIE));
        List<ParamFinding> findings = ParameterAnalyzer.analyze(params);

        assertTrue(findings.stream()
                .anyMatch(f -> f.category.equals("JWT-shaped value") && f.severity == Severity.HIGH));
    }

    @Test
    void ignoresBoringParameters() {
        List<HttpParam> params = List.of(new HttpParam("locale", "en-US", ParamType.URL));
        List<ParamFinding> findings = ParameterAnalyzer.analyze(params);
        assertTrue(findings.isEmpty(), "a locale parameter shouldn't trigger any heuristic");
    }

    @Test
    void normalizesNumericAndUuidPathSegments() {
        assertEquals("/api/v2/users/{id}/orders/{uuid}",
                EndpointGrouper.normalize("/api/v2/users/1042/orders/8e9c9c1a-1b2c-4d5e-9f6a-7b8c9d0e1f2a"));
        assertEquals("/health", EndpointGrouper.normalize("/health"));
        assertEquals("/", EndpointGrouper.normalize(""));
    }

    @Test
    void groupsDifferentIdsIntoTheSameNormalizedPath() {
        assertEquals(EndpointGrouper.normalize("/users/1/orders/9"),
                EndpointGrouper.normalize("/users/42/orders/7"));
    }

    @Test
    void suggestsIdorForObjectIdentifierParameter() {
        List<HttpParam> params = List.of(new HttpParam("id", "77", ParamType.URL));
        List<ParamFinding> findings = ParameterAnalyzer.analyze(params);
        List<VulnSuggestion> suggestions = VulnerabilityRuleEngine.suggest(
                "GET", params, findings, 200, "application/json", Map.of(), null);

        assertTrue(suggestions.stream().anyMatch(v -> v.vulnClass.contains("IDOR")));
    }

    @Test
    void flagsPermissiveCorsWithCredentials() {
        Map<String, String> headers = Map.of(
                "access-control-allow-origin", "*",
                "access-control-allow-credentials", "true");
        List<VulnSuggestion> suggestions = VulnerabilityRuleEngine.suggest(
                "GET", List.of(), List.of(), 200, "application/json", headers, null);

        assertTrue(suggestions.stream()
                .anyMatch(v -> v.vulnClass.equals("CORS Misconfiguration") && v.confidence == Severity.HIGH));
    }

    @Test
    void flagsSqlErrorTextInResponseBody() {
        String body = "Warning: you have an error in your SQL syntax near line 1";
        List<VulnSuggestion> suggestions = VulnerabilityRuleEngine.suggest(
                "GET", List.of(), List.of(), 500, "text/html", Map.of(), body);

        assertTrue(suggestions.stream().anyMatch(v -> v.vulnClass.equals("SQL Injection")));
    }

    @Test
    void explainerMentionsMethodPathAndStatus() {
        String explanation = RequestExplainer.explain("POST", "api.example.com", "/v1/orders", 2,
                201, "application/json", 128, List.of(), List.of());

        assertTrue(explanation.contains("POST"));
        assertTrue(explanation.contains("api.example.com"));
        assertTrue(explanation.contains("/v1/orders"));
        assertTrue(explanation.contains("201"));
    }

    // ---------------------------------------------------------------- RiskScorer

    @Test
    void scoresZeroWithNoSignals() {
        RiskScore score = RiskScorer.score("GET", List.of(), List.of(), false);
        assertEquals(0, score.score);
    }

    @Test
    void stateChangingRequestWithObjectIdScoresHigherThanReadOnly() {
        List<HttpParam> params = List.of(new HttpParam("id", "42", ParamType.URL));
        List<ParamFinding> findings = ParameterAnalyzer.analyze(params);
        List<VulnSuggestion> suggestions = VulnerabilityRuleEngine.suggest(
                "GET", params, findings, 200, "application/json", Map.of(), null);

        RiskScore getScore = RiskScorer.score("GET", findings, suggestions, false);
        RiskScore deleteScore = RiskScorer.score("DELETE", findings, suggestions, false);

        assertTrue(deleteScore.score > getScore.score,
                "a DELETE carrying an object identifier should outscore an identical GET");
    }

    @Test
    void authenticatedEndpointScoresHigherThanAnonymousForTheSameFindings() {
        List<HttpParam> params = List.of(new HttpParam("user_id", "7", ParamType.URL));
        List<ParamFinding> findings = ParameterAnalyzer.analyze(params);
        List<VulnSuggestion> suggestions = VulnerabilityRuleEngine.suggest(
                "GET", params, findings, 200, "application/json", Map.of(), null);

        RiskScore anon = RiskScorer.score("GET", findings, suggestions, false);
        RiskScore authed = RiskScorer.score("GET", findings, suggestions, true);

        assertTrue(authed.score > anon.score);
        assertFalse(authed.reasons.isEmpty());
    }

    @Test
    void duplicateFindingsInTheSameCategoryDontInflateTheScore() {
        // Five distinct parameter names that all land in "Object Identifier".
        List<HttpParam> fiveIds = List.of(
                new HttpParam("id", "1", ParamType.URL), new HttpParam("uid", "2", ParamType.URL),
                new HttpParam("account", "3", ParamType.URL), new HttpParam("acct", "4", ParamType.URL),
                new HttpParam("guid", "abc", ParamType.URL));
        List<HttpParam> oneId = List.of(new HttpParam("id", "1", ParamType.URL));

        List<ParamFinding> fiveFindings = ParameterAnalyzer.analyze(fiveIds);
        List<ParamFinding> oneFinding = ParameterAnalyzer.analyze(oneId).stream()
                .filter(f -> f.category.equals("Object Identifier")).toList();

        assertTrue(fiveFindings.size() > oneFinding.size(), "sanity check: five parameters produce more findings than one");

        RiskScore fiveScore = RiskScorer.score("GET", fiveFindings.stream()
                .filter(f -> f.category.equals("Object Identifier")).toList(), List.of(), false);
        RiskScore oneScore = RiskScorer.score("GET", oneFinding, List.of(), false);

        assertEquals(oneScore.score, fiveScore.score,
                "the 'Object Identifier' category should only score once, however many parameters trigger it");
    }

    // ---------------------------------------------------------------- ResourceProfiler

    @Test
    void profilesCrudCoverageAcrossMethods() {
        List<TrafficEntry> entries = List.of(
                entry(1, "GET", "api.example.com", "/users/{id}", "/users/1", 200, "application/json", "{}"),
                entry(2, "PUT", "api.example.com", "/users/{id}", "/users/1", 200, "application/json", "{}"),
                entry(3, "DELETE", "api.example.com", "/users/{id}", "/users/1", 204, null, null));

        List<ResourceProfile> resources = ResourceProfiler.profile(entries);
        assertEquals(1, resources.size());

        ResourceProfile r = resources.get(0);
        assertTrue(r.hasRead());
        assertTrue(r.hasUpdate());
        assertTrue(r.hasDelete());
        assertFalse(r.hasCreate());
        assertEquals(3, r.crudCoverageCount());
    }

    @Test
    void differentPathsProduceDifferentResources() {
        List<TrafficEntry> entries = List.of(
                entry(1, "GET", "api.example.com", "/users/{id}", "/users/1", 200, "application/json", "{}"),
                entry(2, "GET", "api.example.com", "/orders/{id}", "/orders/1", 200, "application/json", "{}"));

        assertEquals(2, ResourceProfiler.profile(entries).size());
    }

    @Test
    void mergesCollectionAndItemPathsIntoOneResource() {
        // GET /orders (list, no id) and GET/PUT/DELETE /orders/{id} (item) are different
        // normalizedPaths but the same underlying resource -- they must collapse into one
        // ResourceProfile with full CRUD coverage, not two separate half-complete rows.
        List<TrafficEntry> entries = List.of(
                entry(1, "GET", "api.example.com", "/orders", "/orders", 200, "application/json", "[]"),
                entry(2, "POST", "api.example.com", "/orders", "/orders", 201, "application/json", "{}"),
                entry(3, "GET", "api.example.com", "/orders/{id}", "/orders/123", 200, "application/json", "{}"),
                entry(4, "PUT", "api.example.com", "/orders/{id}", "/orders/123", 200, "application/json", "{}"),
                entry(5, "DELETE", "api.example.com", "/orders/{id}", "/orders/123", 204, null, null));

        List<ResourceProfile> resources = ResourceProfiler.profile(entries);
        assertEquals(1, resources.size(), "list and item paths for the same resource must merge into one row");

        ResourceProfile orders = resources.get(0);
        assertEquals("/orders", orders.basePath);
        assertTrue(orders.hasCreate());
        assertTrue(orders.hasRead());
        assertTrue(orders.hasUpdate());
        assertTrue(orders.hasDelete());
        assertEquals(4, orders.crudCoverageCount());
        assertEquals(5, orders.memberIds.size());
    }

    @Test
    void unrelatedCollectionPathDoesNotMergeIntoAnotherResource() {
        // "/health" has no id-shaped segment to strip, so it must never be folded into
        // an unrelated resource just because both happen to be top-level collection paths.
        List<TrafficEntry> entries = List.of(
                entry(1, "GET", "api.example.com", "/orders/{id}", "/orders/123", 200, "application/json", "{}"),
                entry(2, "PUT", "api.example.com", "/orders/{id}", "/orders/123", 200, "application/json", "{}"),
                entry(3, "GET", "api.example.com", "/health", "/health", 200, "application/json", "{}"));

        assertEquals(2, ResourceProfiler.profile(entries).size());
    }

    // ---------------------------------------------------------------- ResponseDiffAnalyzer

    @Test
    void flagsSameShapeDifferentValuesAsIdorLead() {
        List<TrafficEntry> members = List.of(
                entry(1, "GET", "api.example.com", "/users/{id}", "/users/5", 200, "application/json",
                        "{\"id\":5,\"name\":\"John\"}"),
                entry(2, "GET", "api.example.com", "/users/{id}", "/users/6", 200, "application/json",
                        "{\"id\":6,\"name\":\"Alice\"}"));

        List<VulnSuggestion> out = ResponseDiffAnalyzer.analyze(members);
        assertTrue(out.stream().anyMatch(v -> v.vulnClass.equals("IDOR / Data Enumeration")));
    }

    @Test
    void flagsIdenticalBodiesAsUnusedIdentifier() {
        String sameBody = "{\"status\":\"ok\"}";
        List<TrafficEntry> members = List.of(
                entry(1, "GET", "api.example.com", "/ping/{id}", "/ping/1", 200, "application/json", sameBody),
                entry(2, "GET", "api.example.com", "/ping/{id}", "/ping/2", 200, "application/json", sameBody));

        List<VulnSuggestion> out = ResponseDiffAnalyzer.analyze(members);
        assertTrue(out.stream().anyMatch(v -> v.vulnClass.equals("Possible Unused Identifier")));
    }

    @Test
    void needsAtLeastTwoComparableResponses() {
        List<TrafficEntry> members = List.of(
                entry(1, "GET", "api.example.com", "/users/{id}", "/users/5", 200, "application/json",
                        "{\"id\":5,\"name\":\"John\"}"));
        assertTrue(ResponseDiffAnalyzer.analyze(members).isEmpty());
    }

    // ---------------------------------------------------------------- JwtInspector

    @Test
    void decodesAlgorithmAndClaimsFromARealBase64UrlJwt() {
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"sub\":\"1234567890\",\"role\":\"admin\",\"exp\":9999999999}";
        String token = b64url(header) + "." + b64url(payload) + "." + b64url("fakesignature");

        JwtInfo info = JwtInspector.inspect(token);
        assertNotNull(info);
        assertEquals("HS256", info.algorithm);
        assertTrue(info.hasExpiry);
        assertTrue(info.claimNames.contains("role"));
        assertTrue(info.warnings.stream().anyMatch(w -> w.contains("role")));
    }

    @Test
    void flagsAlgNoneAndMissingExpiry() {
        String header = "{\"alg\":\"none\"}";
        String payload = "{\"sub\":\"1\"}";
        String token = b64url(header) + "." + b64url(payload);

        JwtInfo info = JwtInspector.inspect(token);
        assertNotNull(info);
        assertFalse(info.hasExpiry);
        assertTrue(info.warnings.stream().anyMatch(w -> w.toLowerCase().contains("none")));
        assertTrue(info.warnings.stream().anyMatch(w -> w.contains("exp")));
    }

    @Test
    void returnsNullForNonJwtValues() {
        assertNull(JwtInspector.inspect("just-a-plain-string"));
        assertNull(JwtInspector.inspect(null));
    }

    // ---------------------------------------------------------------- test helpers

    private static String b64url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static TrafficEntry entry(long id, String method, String host, String normalizedPath, String path,
                                       Integer statusCode, String mimeType, String responseBody) {
        return new TrafficEntry(id, Instant.now(), "PROXY", method, host, 443, true, path,
                "https://" + host + path, statusCode, mimeType,
                responseBody == null ? 0 : responseBody.length(),
                "", "", "", responseBody == null ? "" : responseBody,
                normalizedPath, List.of(), List.of(), List.of(),
                false, List.of(), RiskScore.none());
    }
}
