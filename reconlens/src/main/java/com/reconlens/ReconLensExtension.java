package com.reconlens;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import com.reconlens.ai.ClaudeClient;
import com.reconlens.analysis.EndpointGroupIndex;
import com.reconlens.handler.ReconHttpHandler;
import com.reconlens.menu.ReconContextMenu;
import com.reconlens.ui.ReconLensTab;

/**
 * ReconLens -- AI Recon &amp; Triage for Burp Suite.
 *
 * <p>Passively watches HTTP traffic Burp already sees, and turns a few thousand
 * proxy history rows into a short, prioritized worklist by:
 * <ul>
 *   <li>explaining each request in plain English,</li>
 *   <li>highlighting parameters worth a closer look (auth tokens, object IDs,
 *       redirect targets, file paths, JWTs, ...),</li>
 *   <li>suggesting candidate vulnerability classes to manually test for, and</li>
 *   <li>grouping near-duplicate endpoints so you triage 60 patterns instead of
 *       4,000 individual requests.</li>
 * </ul>
 *
 * <p>Everything above runs fully offline. An optional, strictly on-demand and
 * opt-in integration with the Claude API can add a richer natural-language
 * explanation for a single request at a time -- see {@link ClaudeClient}.
 */
public final class ReconLensExtension implements BurpExtension {

    public static final String EXTENSION_NAME = "ReconLens - AI Recon & Triage";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        // Single source of truth: every captured request/response, grouped and scored.
        EndpointGroupIndex index = new EndpointGroupIndex();

        // Optional AI enrichment; inert until the user supplies a key under "AI Settings".
        ClaudeClient claudeClient = new ClaudeClient(api);

        // Build the UI first so the handler has somewhere to push rows as traffic arrives.
        ReconLensTab tab = new ReconLensTab(api, index, claudeClient);
        api.userInterface().registerSuiteTab("ReconLens", tab.getComponent());

        // Passive HTTP handler -- never modifies or drops traffic, only observes it.
        api.http().registerHttpHandler(new ReconHttpHandler(api, index, tab));

        // Right-click menu: send anything from Proxy/Repeater/Target/etc. straight into ReconLens.
        api.userInterface().registerContextMenuItemsProvider(new ReconContextMenu(api, index));

        api.logging().logToOutput(EXTENSION_NAME + " loaded.\n"
                + "Use \"Import Proxy History\" in the ReconLens tab to pull in everything already captured.\n"
                + "Reminder: only point this at systems you are authorized to test.");
    }
}
