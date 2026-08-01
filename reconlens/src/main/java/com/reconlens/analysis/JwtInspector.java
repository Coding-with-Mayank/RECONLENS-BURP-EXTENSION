package com.reconlens.analysis;

import com.reconlens.model.JwtInfo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Decodes a JWT's header and payload segments (base64url -> JSON) with no
 * external dependency -- {@code java.util.Base64} plus the in-house
 * {@link MiniJson} parser are enough for this. This never touches the
 * signature: verifying one needs the server's secret/key, which ReconLens
 * doesn't have and has no business asking for. This is the difference
 * between "found a JWT" and actually knowing what's in it.
 */
public final class JwtInspector {

    private static final Set<String> INTERESTING_CLAIMS = Set.of(
            "role", "roles", "scope", "scopes", "permissions", "is_admin", "isAdmin",
            "tenant", "tenant_id", "tenantId", "org", "org_id", "email", "user_id", "userId", "sub");

    private JwtInspector() {}

    /** Returns null if the value doesn't decode as a plausible JWT (header + payload both valid JSON objects). */
    public static JwtInfo inspect(String token) {
        if (token == null) return null;
        String[] parts = token.split("\\.", -1);
        if (parts.length < 2) return null;

        Object header = MiniJson.parseBase64UrlJson(parts[0]);
        Object payload = MiniJson.parseBase64UrlJson(parts[1]);
        if (!(header instanceof Map) || !(payload instanceof Map)) return null;

        Map<?, ?> headerMap = (Map<?, ?>) header;
        Map<?, ?> payloadMap = (Map<?, ?>) payload;

        String alg = headerMap.get("alg") == null ? "unknown" : String.valueOf(headerMap.get("alg"));
        boolean hasExpiry = payloadMap.containsKey("exp");

        List<String> claimNames = new ArrayList<>();
        for (Object key : payloadMap.keySet()) claimNames.add(String.valueOf(key));
        Collections.sort(claimNames);

        List<String> warnings = new ArrayList<>();
        if ("none".equalsIgnoreCase(alg)) {
            warnings.add("Algorithm is \"none\" -- if the server actually accepts this, signature checking is bypassed entirely.");
        }
        if (!hasExpiry) {
            warnings.add("No \"exp\" claim -- this token may never expire.");
        }
        for (String interesting : INTERESTING_CLAIMS) {
            if (payloadMap.containsKey(interesting)) {
                warnings.add("Carries a \"" + interesting + "\" claim -- if it's trusted without a fresh " +
                        "server-side lookup, modifying it client-side is worth testing (assuming you can also " +
                        "forge or otherwise obtain a valid signature).");
            }
        }

        return new JwtInfo(alg, hasExpiry, claimNames, warnings);
    }
}
