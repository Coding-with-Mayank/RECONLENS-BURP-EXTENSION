package com.reconlens.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A single 0-100 score with the reasons that produced it -- never a bare
 * number. Every point is attributable to a named signal (see RiskScorer),
 * so a tester can see exactly why one request outranks another instead of
 * trusting a black box.
 */
public final class RiskScore {
    public final int score;
    public final List<String> reasons;

    public RiskScore(int score, List<String> reasons) {
        this.score = Math.max(0, Math.min(100, score));
        this.reasons = Collections.unmodifiableList(new ArrayList<>(reasons));
    }

    public static RiskScore none() {
        return new RiskScore(0, List.of("No notable signals."));
    }
}
