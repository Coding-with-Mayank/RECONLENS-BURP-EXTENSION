package com.reconlens.ui;

import com.reconlens.model.EndpointGroup;
import com.reconlens.model.Severity;
import com.reconlens.model.TrafficEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

final class GroupTableModel extends AbstractTableModel {

    private static final String[] COLS = {"Method", "Host", "Path (normalized)", "Count", "Max Risk"};

    private final List<EndpointGroup> groups = new ArrayList<>();
    private final List<Severity> maxRisk = new ArrayList<>();

    void setData(List<EndpointGroup> newGroups, List<TrafficEntry> allEntries) {
        groups.clear();
        maxRisk.clear();
        for (EndpointGroup g : newGroups) {
            groups.add(g);
            Severity worst = Severity.INFO;
            for (TrafficEntry e : allEntries) {
                if (!e.groupKey.equals(g.key)) continue;
                if (e.highestParamSeverity().atLeast(worst)) worst = e.highestParamSeverity();
                if (e.highestVulnConfidence().atLeast(worst)) worst = e.highestVulnConfidence();
            }
            maxRisk.add(worst);
        }
        fireTableDataChanged();
    }

    EndpointGroup groupAt(int row) {
        return groups.get(row);
    }

    @Override public int getRowCount() { return groups.size(); }
    @Override public int getColumnCount() { return COLS.length; }
    @Override public String getColumnName(int col) { return COLS[col]; }

    @Override
    public Object getValueAt(int row, int col) {
        EndpointGroup g = groups.get(row);
        switch (col) {
            case 0: return g.method;
            case 1: return g.host;
            case 2: return g.normalizedPath;
            case 3: return g.memberIds.size();
            case 4: return maxRisk.get(row);
            default: return "";
        }
    }
}
