package com.reconlens.model;

/** One "this parameter is worth a closer look" observation produced by ParameterAnalyzer. */
public final class ParamFinding {
    public final String paramName;
    public final ParamType paramType;
    public final String category;  // e.g. "Auth / Session", "Object Identifier", "Redirect / URL Target"
    public final Severity severity;
    public final String reason;    // one human-readable sentence

    public ParamFinding(String paramName, ParamType paramType, String category, Severity severity, String reason) {
        this.paramName = paramName;
        this.paramType = paramType;
        this.category = category;
        this.severity = severity;
        this.reason = reason;
    }
}
