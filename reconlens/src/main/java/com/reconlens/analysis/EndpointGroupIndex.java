package com.reconlens.analysis;

import com.reconlens.model.EndpointGroup;
import com.reconlens.model.ResourceProfile;
import com.reconlens.model.TrafficEntry;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Single source of truth for everything ReconLens has captured. One instance is
 * shared between the HTTP handler (writer), the context menu (writer), and the
 * UI (reader + writer via "Import Proxy History"), so all access is synchronized.
 */
public final class EndpointGroupIndex {

    private final AtomicLong nextId = new AtomicLong(1);
    private final List<TrafficEntry> entries = new ArrayList<>();
    private final Map<String, EndpointGroup> groups = new LinkedHashMap<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    public interface Listener {
        void onEntryAdded(TrafficEntry entry, EndpointGroup group);
    }

    public void addListener(Listener l) {
        listeners.add(l);
    }

    /** Reserve the next entry ID. Safe to call from any thread. */
    public long nextId() {
        return nextId.getAndIncrement();
    }

    public synchronized EndpointGroup add(TrafficEntry entry) {
        entries.add(entry);
        EndpointGroup group = groups.computeIfAbsent(entry.groupKey,
                k -> new EndpointGroup(k, entry.method, entry.host, entry.normalizedPath));
        group.memberIds.add(entry.id);
        for (Listener l : listeners) {
            l.onEntryAdded(entry, group);
        }
        return group;
    }

    public synchronized List<TrafficEntry> allEntries() {
        return new ArrayList<>(entries);
    }

    public synchronized List<EndpointGroup> allGroups() {
        return new ArrayList<>(groups.values());
    }

    public synchronized List<TrafficEntry> entriesIn(EndpointGroup group) {
        List<TrafficEntry> out = new ArrayList<>();
        for (TrafficEntry e : entries) {
            if (e.groupKey.equals(group.key)) out.add(e);
        }
        return out;
    }

    /** Same host+path shape across every method -- the CRUD-coverage view, see ResourceProfiler. */
    public synchronized List<TrafficEntry> entriesForResource(ResourceProfile resource) {
        List<TrafficEntry> out = new ArrayList<>();
        for (TrafficEntry e : entries) {
            if ((e.host + ResourceProfiler.basePathOf(e.normalizedPath)).equals(resource.key)) out.add(e);
        }
        return out;
    }

    public synchronized void clear() {
        entries.clear();
        groups.clear();
    }
}
