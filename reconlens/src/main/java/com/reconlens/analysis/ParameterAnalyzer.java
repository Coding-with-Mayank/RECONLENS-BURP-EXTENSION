package com.reconlens.analysis;

import com.reconlens.model.HttpParam;
import com.reconlens.model.ParamFinding;
import com.reconlens.model.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Flags parameters that are statistically likely to matter for security testing,
 * purely from their name and shape -- no network calls, no external data, runs on
 * every request in microseconds so it's safe to leave on for an entire engagement.
 *
 * This is deliberately a set of cheap, explainable heuristics rather than a
 * trained classifier: every finding comes with a one-line "why", which matters
 * more than raw precision when a human is going to manually verify each lead.
 */
public final class ParameterAnalyzer {

    private ParameterAnalyzer() {}

    // { category, severity, keywords... } -- name-based heuristics.
    private static final Object[][] NAME_RULES = {
        {"Auth / Session",         Severity.HIGH,   new String[]{"token", "auth", "jwt", "session", "sessid", "sid", "apikey", "api_key", "bearer", "secret"}},
        {"Credential",             Severity.HIGH,   new String[]{"password", "passwd", "pwd", "pass"}},
        {"Access Control",        Severity.HIGH,   new String[]{"role", "admin", "is_admin", "isadmin", "perm", "privilege", "access_level", "scope"}},
        {"Object Identifier",     Severity.MEDIUM, new String[]{"id", "uid", "user_id", "userid", "account", "acct", "order_id", "invoice", "uuid", "guid"}},
        {"Redirect / URL Target", Severity.MEDIUM, new String[]{"redirect", "return", "returnurl", "next", "dest", "destination", "continue", "callback", "target", "url", "link", "out"}},
        {"File / Path",           Severity.MEDIUM, new String[]{"file", "filename", "path", "doc", "document", "template", "include", "page", "dir", "folder"}},
        {"Business Logic / Money", Severity.MEDIUM, new String[]{"price", "amount", "qty", "quantity", "total", "discount", "coupon", "balance", "cost"}},
        {"Debug / Internal",      Severity.LOW,    new String[]{"debug", "test", "verbose", "trace", "internal", "admin_mode", "bypass"}},
        {"Query / Command-ish",   Severity.MEDIUM, new String[]{"cmd", "command", "exec", "query", "filter", "sort", "order_by", "orderby", "search"}},
    };

    private static final Pattern JWT = Pattern.compile("^eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$");
    private static final Pattern UUID = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern SEQUENTIAL_INT = Pattern.compile("^\\d{1,10}$");
    private static final Pattern BASE64ISH = Pattern.compile("^[A-Za-z0-9+/]{20,}={0,2}$");
    private static final Pattern INTERNAL_HOST = Pattern.compile(
        "(?i)^(https?://)?(127\\.0\\.0\\.1|localhost|10\\.\\d+\\.\\d+\\.\\d+|172\\.(1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+" +
        "|192\\.168\\.\\d+\\.\\d+|169\\.254\\.\\d+\\.\\d+|[\\w.-]+\\.internal|[\\w.-]+\\.local)");
    private static final Pattern SERIALIZED_PHP = Pattern.compile("^[aOs]:\\d+:");
    private static final Pattern SERIALIZED_JAVA_B64 = Pattern.compile("^rO0[A-Za-z0-9+/=]+$");

    public static List<ParamFinding> analyze(List<HttpParam> params) {
        List<ParamFinding> findings = new ArrayList<>();
        for (HttpParam p : params) {
            String lname = p.name.toLowerCase(Locale.ROOT);

            for (Object[] rule : NAME_RULES) {
                String category = (String) rule[0];
                Severity severity = (Severity) rule[1];
                String[] keywords = (String[]) rule[2];
                for (String kw : keywords) {
                    if (lname.equals(kw) || lname.contains(kw)) {
                        findings.add(new ParamFinding(p.name, p.type, category, severity,
                            "Name matches the \"" + category + "\" pattern (keyword: \"" + kw + "\")."));
                        break; // one hit per rule per parameter is enough signal
                    }
                }
            }

            findings.addAll(shapeFindings(p));
        }
        return findings;
    }

    /** Findings based on what the *value* looks like, independent of the parameter's name. */
    private static List<ParamFinding> shapeFindings(HttpParam p) {
        List<ParamFinding> out = new ArrayList<>();
        String v = p.value;
        if (v == null || v.isEmpty()) return out;

        if (JWT.matcher(v).matches()) {
            out.add(new ParamFinding(p.name, p.type, "JWT-shaped value", Severity.HIGH,
                "Value looks like a JSON Web Token -- check for alg:none acceptance, weak/guessable " +
                "signing secrets, and whether claims are trusted without server-side re-validation."));
        }
        if (UUID.matcher(v).matches()) {
            out.add(new ParamFinding(p.name, p.type, "UUID-shaped value", Severity.LOW,
                "Value is a UUID. Harder to guess than a sequential ID but still worth an authorization " +
                "(IDOR/BOLA) check using a second account's UUID."));
        } else if (SEQUENTIAL_INT.matcher(v).matches()) {
            out.add(new ParamFinding(p.name, p.type, "Sequential integer ID", Severity.MEDIUM,
                "Value is a small integer. Sequential/guessable IDs are the classic IDOR setup -- try " +
                "adjacent values from a different account's session."));
        }
        if (INTERNAL_HOST.matcher(v).find()) {
            out.add(new ParamFinding(p.name, p.type, "Internal/loopback host reference", Severity.HIGH,
                "Value references a loopback/private/internal-looking host. If this value is later fetched " +
                "server-side, it's a strong SSRF candidate."));
        }
        if (SERIALIZED_PHP.matcher(v).find() || SERIALIZED_JAVA_B64.matcher(v).find()) {
            out.add(new ParamFinding(p.name, p.type, "Serialized object", Severity.HIGH,
                "Value looks like a serialized PHP/Java object. If the server deserializes this, it's worth " +
                "checking for insecure deserialization."));
        } else if (BASE64ISH.matcher(v).matches() && v.length() >= 24) {
            out.add(new ParamFinding(p.name, p.type, "Opaque base64-ish blob", Severity.LOW,
                "Value looks base64-encoded. Worth decoding once to see what it actually carries before " +
                "assuming it's opaque."));
        }
        return out;
    }
}
