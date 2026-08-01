package com.reconlens.analysis;

import com.reconlens.model.ParamFinding;
import com.reconlens.model.ResourceProfile;
import com.reconlens.model.TrafficEntry;
import com.reconlens.model.VulnSuggestion;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Synthesizes the individual findings already collected across a resource's
 * member requests into one short, prioritized narrative. This is templated
 * correlation of signals ReconLens already computed elsewhere -- CRUD
 * coverage, parameter categories, vulnerability leads -- not independent
 * reasoning. For an open-ended version of this that can actually reason
 * about business logic instead of following a fixed template, see
 * {@code ClaudeClient.analyzeResource(...)}, which hands this same
 * underlying data to Claude instead.
 */
public final class AttackPathSynthesizer {

    private AttackPathSynthesizer() {}

    public static String synthesize(ResourceProfile resource, List<TrafficEntry> members) {
        StringBuilder sb = new StringBuilder();

        sb.append("Resource: ").append(resource.host).append(resource.basePath).append('\n');
        sb.append("Methods observed: ").append(String.join(", ", resource.methodsSeen)).append('\n');
        int crud = resource.crudCoverageCount();
        sb.append("CRUD coverage: ").append(crud).append("/4");
        if (crud >= 3) {
            sb.append("  -- most of the object lifecycle is reachable from this one shape.");
        }
        sb.append("\n\n");

        Set<String> categories = new LinkedHashSet<>();
        Set<String> vulnClasses = new LinkedHashSet<>();
        for (TrafficEntry e : members) {
            for (ParamFinding f : e.findings) categories.add(f.category);
            for (VulnSuggestion v : e.suggestions) vulnClasses.add(v.vulnClass);
        }

        if (categories.isEmpty() && vulnClasses.isEmpty()) {
            sb.append("No parameter or response signals stood out across this resource's captured traffic.\n");
            return sb.toString();
        }

        List<String> steps = new ArrayList<>();

        if ((resource.hasUpdate() || resource.hasDelete()) && categories.contains("Object Identifier")) {
            steps.add("Confirm object-level authorization on the update/delete methods first -- that's where a " +
                    "broken check has the most impact (data change or loss, not just disclosure).");
        } else if (categories.contains("Object Identifier")) {
            steps.add("Confirm object-level authorization by requesting a different account's ID with your own session.");
        }
        if (categories.contains("Access Control")) {
            steps.add("Try flipping the role/permission-shaped parameter with a low-privilege session.");
        }
        if (categories.contains("Business Logic / Money")) {
            steps.add("Tamper with the price/amount/coupon-shaped parameter and check whether the server " +
                    "recomputes it server-side or trusts the client value.");
        }
        if (categories.contains("Redirect / URL Target")) {
            steps.add("Check the redirect-shaped parameter for open redirect, then for SSRF if it's ever fetched server-side.");
        }
        if (vulnClasses.contains("JWT Weaknesses")) {
            steps.add("Decode the JWT (see the Auth Analysis tab) and check alg handling and whether its claims are re-validated server-side.");
        }
        if (vulnClasses.contains("IDOR / Data Enumeration")) {
            steps.add("Response comparison across captured requests already suggests per-object data -- this is " +
                    "the fastest lead here to convert into a confirmed finding.");
        }
        if (crud >= 3 && categories.contains("Object Identifier")) {
            steps.add("Because Create/Read/Update/Delete all exist on this shape, a confirmed IDOR here likely " +
                    "means full control over another user's object, not just read access -- worth escalating priority.");
        }
        if (steps.isEmpty()) {
            steps.add("Work through the individual findings below one at a time; nothing here combines into a bigger picture yet.");
        }

        sb.append("Suggested order of attack:\n");
        for (int i = 0; i < steps.size(); i++) {
            sb.append(i + 1).append(". ").append(steps.get(i)).append('\n');
        }
        return sb.toString();
    }
}
