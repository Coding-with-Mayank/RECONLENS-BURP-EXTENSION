package com.reconlens.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Structured result of decoding a JWT's header and payload (base64url -> JSON
 * only -- no signature verification, since that needs a secret/key ReconLens
 * doesn't have and has no business asking for).
 */
public final class JwtInfo {
    public final String algorithm;       // header "alg", e.g. "HS256", "none", "unknown"
    public final boolean hasExpiry;      // payload has an "exp" claim
    public final List<String> claimNames;
    public final List<String> warnings;

    public JwtInfo(String algorithm, boolean hasExpiry, List<String> claimNames, List<String> warnings) {
        this.algorithm = algorithm;
        this.hasExpiry = hasExpiry;
        this.claimNames = Collections.unmodifiableList(new ArrayList<>(claimNames));
        this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
    }
}
