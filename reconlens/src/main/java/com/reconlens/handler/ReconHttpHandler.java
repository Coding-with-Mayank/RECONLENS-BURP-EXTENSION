package com.reconlens.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.reconlens.analysis.EndpointGroupIndex;
import com.reconlens.model.TrafficEntry;
import com.reconlens.ui.ReconLensTab;

/**
 * Passive observer for every HTTP request/response Burp's tools handle. This
 * handler ALWAYS returns {@code continueWith(...)} unchanged -- it never edits,
 * delays, or drops traffic. All the actual work (parsing, scoring, grouping)
 * happens after the fact, off to the side, wrapped defensively so a bug in
 * ReconLens can never take down the rest of Burp's traffic pipeline.
 */
public final class ReconHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final EndpointGroupIndex index;
    private final ReconLensTab tab;

    public ReconHttpHandler(MontoyaApi api, EndpointGroupIndex index, ReconLensTab tab) {
        this.api = api;
        this.index = index;
        this.tab = tab;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Nothing to do on the way out -- we only care once we have a response to pair it with.
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            if (tab.isCaptureEnabled() && tab.isToolCaptured(responseReceived.toolSource().toolType())) {
                HttpRequest initiatingRequest = responseReceived.initiatingRequest();
                TrafficEntry entry = TrafficEntryFactory.build(
                        index.nextId(),
                        responseReceived.toolSource().toolType().name(),
                        initiatingRequest,
                        responseReceived);
                index.add(entry);
            }
        } catch (Exception e) {
            api.logging().logToError("ReconLens failed to process a response: " + e);
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
