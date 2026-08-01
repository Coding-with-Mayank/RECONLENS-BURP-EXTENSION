package com.reconlens.model;

/**
 * A candidate vulnerability class the request/response pair is worth testing for.
 * This is a *lead*, produced entirely offline by pattern matching -- never a confirmed
 * finding, and never something the extension acts on by itself.
 */
public final class VulnSuggestion {
    public final String vulnClass;     // e.g. "IDOR", "SSRF", "Open Redirect"
    public final Severity confidence;  // reuses Severity as a confidence scale
    public final String rationale;     // why the tool thinks so
    public final String testIdea;      // one concrete, manual next step for a human tester

    public VulnSuggestion(String vulnClass, Severity confidence, String rationale, String testIdea) {
        this.vulnClass = vulnClass;
        this.confidence = confidence;
        this.rationale = rationale;
        this.testIdea = testIdea;
    }
}
