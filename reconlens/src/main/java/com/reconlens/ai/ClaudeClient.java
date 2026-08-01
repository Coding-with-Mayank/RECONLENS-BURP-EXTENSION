package com.reconlens.ai;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import com.reconlens.model.ParamFinding;
import com.reconlens.model.ResourceProfile;
import com.reconlens.model.RiskScore;
import com.reconlens.model.TrafficEntry;
import com.reconlens.model.VulnSuggestion;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Optional, on-demand enrichment: sends a *derived summary* of one request/response
 * pair to Claude and asks for a plain-English explanation plus a sanity check on the
 * heuristic findings. Nothing is sent anywhere unless the user explicitly turns this
 * on and supplies their own Anthropic API key (from console.anthropic.com, separate
 * from any Claude.ai subscription) -- ReconLens works fully offline without it; see
 * {@code com.reconlens.analysis.RequestExplainer} for the always-on local explanation.
 *
 * Design choice: no JSON library dependency. The request body we send and the
 * response shape we need to parse are both small and fixed, so a couple of tiny
 * hand-rolled helpers below keep this class -- and the whole project -- free of
 * runtime dependencies that would otherwise need shading into the extension jar.
 */
public final class ClaudeClient {

    private static final String PREF_ENABLED = "reconlens.ai.enabled";
    private static final String PREF_KEY = "reconlens.ai.apiKey";
    private static final String PREF_MODEL = "reconlens.ai.model";
    private static final String PREF_INCLUDE_BODY = "reconlens.ai.includeBody";

    private static final String DEFAULT_MODEL = "claude-sonnet-5";
    private static final String API_URL = "https://api.anthropic.com/v1/messages";
    private static final String ANTHROPIC_VERSION = "2023-06-01";
    private static final int MAX_BODY_CHARS_IN_PROMPT = 1500;

    private final MontoyaApi api;
    private final Preferences prefs;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();

    private volatile boolean enabled;
    private volatile String apiKey = "";
    private volatile String model = DEFAULT_MODEL;
    private volatile boolean includeBody;

    public ClaudeClient(MontoyaApi api) {
        this.api = api;
        this.prefs = api.persistence().preferences();
        load();
    }

    public boolean isConfigured() {
        return enabled && apiKey != null && !apiKey.isBlank();
    }

    public boolean isEnabled() { return enabled; }
    public String getApiKey() { return apiKey == null ? "" : apiKey; }
    public String getModel() { return (model == null || model.isBlank()) ? DEFAULT_MODEL : model; }
    public boolean isIncludeBody() { return includeBody; }

    public void update(boolean enabled, String apiKey, String model, boolean includeBody) {
        this.enabled = enabled;
        this.apiKey = apiKey == null ? "" : apiKey;
        this.model = (model == null || model.isBlank()) ? DEFAULT_MODEL : model.trim();
        this.includeBody = includeBody;
        save();
    }

    private void load() {
        this.enabled = "true".equals(prefs.getString(PREF_ENABLED));
        String storedKey = prefs.getString(PREF_KEY);
        this.apiKey = storedKey == null ? "" : storedKey;
        String storedModel = prefs.getString(PREF_MODEL);
        this.model = (storedModel == null || storedModel.isBlank()) ? DEFAULT_MODEL : storedModel;
        this.includeBody = "true".equals(prefs.getString(PREF_INCLUDE_BODY));
    }

    private void save() {
        prefs.setString(PREF_ENABLED, Boolean.toString(enabled));
        prefs.setString(PREF_KEY, apiKey);
        prefs.setString(PREF_MODEL, model);
        prefs.setString(PREF_INCLUDE_BODY, Boolean.toString(includeBody));
    }

    /** Runs synchronously -- callers must invoke this off the Swing EDT (see ReconLensTab, SwingWorker). */
    public String explain(TrafficEntry entry) {
        if (!isConfigured()) {
            return "AI explanations are off. Set an API key under \"AI Settings\" to enable them.";
        }
        return callClaude(buildEntryPrompt(entry), 600);
    }

    /**
     * The resource-level counterpart to {@link #explain(TrafficEntry)}: instead of one
     * request in isolation, this hands Claude the CRUD map, the offline attack-path
     * synthesis, and every finding/risk-score already computed across *all* captured
     * requests for one resource, and asks it to reason about business-logic
     * relationships a fixed rule can't -- e.g. "update and delete both exist here with
     * no distinct ownership check visible; the order-history endpoint on the same host
     * separately exposes an account_id -- these two together are worth chaining."
     * That correlation is the actual value add; the fixed rules elsewhere in this
     * project only ever look at one request or one group at a time.
     */
    public String analyzeResource(ResourceProfile resource, List<TrafficEntry> members, String offlineAttackPath) {
        if (!isConfigured()) {
            return "AI explanations are off. Set an API key under \"AI Settings\" to enable them.";
        }
        return callClaude(buildResourcePrompt(resource, members, offlineAttackPath), 900);
    }

    private String callClaude(String prompt, int maxTokens) {
        String body = "{"
                + "\"model\":" + jsonString(getModel()) + ","
                + "\"max_tokens\":" + maxTokens + ","
                + "\"messages\":[{\"role\":\"user\",\"content\":" + jsonString(prompt) + "}]"
                + "}";
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(API_URL))
                    .timeout(Duration.ofSeconds(30))
                    .header("content-type", "application/json")
                    .header("x-api-key", apiKey)
                    .header("anthropic-version", ANTHROPIC_VERSION)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 != 2) {
                return "Claude API returned HTTP " + resp.statusCode() + ": " + truncate(resp.body(), 300);
            }
            return extractText(resp.body());
        } catch (IOException e) {
            api.logging().logToError("ReconLens AI call failed: " + e);
            return "Could not reach the Claude API: " + e.getMessage();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "AI request was interrupted.";
        }
    }

    private String buildResourcePrompt(ResourceProfile resource, List<TrafficEntry> members, String offlineAttackPath) {
        StringBuilder sb = new StringBuilder();
        sb.append("You are assisting a penetration tester who is authorized to test this target. ");
        sb.append("Below is everything captured for ONE resource (a host+path shape across every HTTP method ");
        sb.append("seen), plus the deterministic, rule-based analysis ReconLens already computed for it. ");
        sb.append("Don't just repeat those rules back -- look for relationships between the requests that a ");
        sb.append("per-request or per-rule view would miss: does combining two of these findings suggest a ");
        sb.append("more specific attack than either alone? Is there a plausible business workflow behind this " );
        sb.append("CRUD surface worth naming? If nothing genuinely combines, say so plainly instead of padding " );
        sb.append("the answer -- a short honest answer beats a long speculative one.\n\n");

        sb.append("Resource: ").append(resource.host).append(resource.basePath).append('\n');
        sb.append("Methods observed: ").append(String.join(", ", resource.methodsSeen)).append('\n');
        sb.append("Requests captured for this resource: ").append(members.size()).append("\n\n");

        sb.append("--- ReconLens's own offline attack-path synthesis (for reference, not to be echoed back) ---\n");
        sb.append(offlineAttackPath).append('\n');

        sb.append("--- Per-request summary ---\n");
        int shown = 0;
        for (TrafficEntry e : members) {
            if (shown >= 15) { sb.append("... (" + (members.size() - shown) + " more requests omitted for length)\n"); break; }
            sb.append("#").append(e.id).append(' ').append(e.method).append(' ').append(e.path)
              .append(" -> ").append(e.statusCode).append(", risk ").append(e.riskScore.score).append("/100\n");
            for (String reason : e.riskScore.reasons) sb.append("    ").append(reason).append('\n');
            shown++;
        }

        return sb.toString();
    }

    private String buildEntryPrompt(TrafficEntry entry) {
        StringBuilder sb = new StringBuilder();
        sb.append("You are assisting a penetration tester who is authorized to test this target. ");
        sb.append("Explain what the following captured HTTP request/response pair is doing, in 3-5 sentences, ");
        sb.append("then sanity-check the heuristic findings below -- confirm, downgrade, or dismiss each one in ");
        sb.append("a short bullet list, based only on the evidence shown.\n\n");

        sb.append("Method: ").append(entry.method).append('\n');
        sb.append("Host: ").append(entry.host).append('\n');
        sb.append("Path: ").append(entry.path).append('\n');
        sb.append("Status: ").append(entry.statusCode).append('\n');
        sb.append("Content-Type: ").append(entry.mimeType).append('\n');
        sb.append("Response length: ").append(entry.responseLength).append(" bytes\n");

        sb.append("\nParameters (name : type):\n");
        for (var p : entry.params) sb.append("  ").append(p.name).append(" : ").append(p.type).append('\n');

        sb.append("\nHeuristic parameter findings:\n");
        for (ParamFinding f : entry.findings) {
            sb.append("  [").append(f.severity).append("] ").append(f.paramName).append(" -- ").append(f.reason).append('\n');
        }

        sb.append("\nHeuristic vulnerability leads:\n");
        for (VulnSuggestion v : entry.suggestions) {
            sb.append("  [").append(v.confidence).append("] ").append(v.vulnClass).append(" -- ").append(v.rationale).append('\n');
        }

        if (includeBody) {
            sb.append("\nRequest body (truncated):\n").append(truncate(entry.requestBody, MAX_BODY_CHARS_IN_PROMPT)).append('\n');
            sb.append("\nResponse body (truncated):\n").append(truncate(entry.responseBody, MAX_BODY_CHARS_IN_PROMPT)).append('\n');
        } else {
            sb.append("\n(Request/response bodies withheld -- enable \"Include bodies\" in AI Settings to send them too.)\n");
        }

        return sb.toString();
    }

    // ---- tiny hand-rolled JSON helpers -------------------------------------------

    private static String jsonString(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    // Matches {"type":"text","text":"..."} blocks in the Messages API response body.
    private static final Pattern TEXT_FIELD =
            Pattern.compile("\"type\"\\s*:\\s*\"text\"\\s*,\\s*\"text\"\\s*:\\s*\"(.*?)(?<!\\\\)\"", Pattern.DOTALL);

    private static String extractText(String responseJson) {
        Matcher m = TEXT_FIELD.matcher(responseJson);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            if (out.length() > 0) out.append("\n\n");
            out.append(unescape(m.group(1)));
        }
        return out.length() > 0 ? out.toString()
                : "Could not parse a text response from Claude: " + truncate(responseJson, 300);
    }

    private static String unescape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                switch (n) {
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    default: sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
