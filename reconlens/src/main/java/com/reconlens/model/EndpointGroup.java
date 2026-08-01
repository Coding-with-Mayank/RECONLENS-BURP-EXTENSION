package com.reconlens.model;

import java.util.ArrayList;
import java.util.List;

/**
 * A cluster of requests that hit "the same" endpoint once IDs/UUIDs/hashes in the
 * path are normalized out, e.g. {@code /users/1042/orders/88} and
 * {@code /users/77/orders/12} both collapse to {@code /users/{id}/orders/{id}}.
 */
public final class EndpointGroup {
    public final String key;             // method + host + normalizedPath
    public final String method;
    public final String host;
    public final String normalizedPath;
    public final List<Long> memberIds = new ArrayList<>();

    public EndpointGroup(String key, String method, String host, String normalizedPath) {
        this.key = key;
        this.method = method;
        this.host = host;
        this.normalizedPath = normalizedPath;
    }
}
