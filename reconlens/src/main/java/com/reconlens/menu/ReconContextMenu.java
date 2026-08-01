package com.reconlens.menu;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.reconlens.analysis.EndpointGroupIndex;
import com.reconlens.handler.TrafficEntryFactory;
import com.reconlens.model.TrafficEntry;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/**
 * Adds "Send N to ReconLens" to Burp's right-click menu, everywhere a request or
 * response is selected -- Proxy history, Repeater, Target site map, search
 * results, anywhere. This is how you pull in traffic from *before* the extension
 * was loaded, or from a tool you haven't enabled live capture for.
 */
public final class ReconContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final EndpointGroupIndex index;

    public ReconContextMenu(MontoyaApi api, EndpointGroupIndex index) {
        this.api = api;
        this.index = index;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) return List.of();

        JMenuItem item = new JMenuItem("Send " + selected.size() + " to ReconLens");
        item.addActionListener(e -> {
            int added = 0;
            for (HttpRequestResponse rr : selected) {
                try {
                    if (rr.request() == null) continue;
                    TrafficEntry entry = TrafficEntryFactory.build(index.nextId(), "MANUAL", rr.request(), rr.response());
                    index.add(entry);
                    added++;
                } catch (Exception ex) {
                    api.logging().logToError("ReconLens context-menu import failed: " + ex);
                }
            }
            api.logging().logToOutput("ReconLens: imported " + added + " request(s) from the context menu.");
        });
        return List.of(item);
    }
}
