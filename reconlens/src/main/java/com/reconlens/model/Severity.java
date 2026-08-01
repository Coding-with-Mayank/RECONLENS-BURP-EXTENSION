package com.reconlens.model;

/** Reused as both "how interesting is this parameter" and "how confident is this lead". */
public enum Severity {
    INFO, LOW, MEDIUM, HIGH;

    public boolean atLeast(Severity other) {
        return this.ordinal() >= other.ordinal();
    }
}
