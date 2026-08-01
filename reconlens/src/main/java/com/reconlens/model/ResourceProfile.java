package com.reconlens.model;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * All requests that hit the same *resource*, regardless of HTTP method and
 * regardless of whether the request was on the collection path or the item
 * path. {@link EndpointGroup} answers "what does GET /orders/{id} look
 * like"; ResourceProfile answers "what CAN you do to the Orders resource,
 * across every method AND every path shape we've actually seen" -- so
 * GET /orders (list), POST /orders (create), and GET/PUT/DELETE /orders/{id}
 * (read/update/delete) are all recognized as one resource, not two unrelated
 * half-complete rows. This is the CRUD-coverage view: if Create/Read/Update/
 * Delete all exist on one resource, a broken access-control check anywhere
 * in that set likely means more than read-only disclosure.
 */
public final class ResourceProfile {
    public final String key;         // host + basePath
    public final String host;
    public final String basePath;    // e.g. "/orders" -- the collection path, with any trailing id-like segment stripped
    public final Set<String> methodsSeen = new LinkedHashSet<>();
    public final List<Long> memberIds = new ArrayList<>();

    public ResourceProfile(String key, String host, String basePath) {
        this.key = key;
        this.host = host;
        this.basePath = basePath;
    }

    public boolean hasCreate() { return methodsSeen.contains("POST"); }
    public boolean hasRead()   { return methodsSeen.contains("GET"); }
    public boolean hasUpdate() { return methodsSeen.contains("PUT") || methodsSeen.contains("PATCH"); }
    public boolean hasDelete() { return methodsSeen.contains("DELETE"); }

    public int crudCoverageCount() {
        int n = 0;
        if (hasCreate()) n++;
        if (hasRead()) n++;
        if (hasUpdate()) n++;
        if (hasDelete()) n++;
        return n;
    }
}
