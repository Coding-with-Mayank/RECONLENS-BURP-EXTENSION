package com.reconlens.ui;

import com.reconlens.model.TrafficEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

final class EntryTableModel extends AbstractTableModel {

    private static final String[] COLS = {"#", "Method", "URL", "Status", "Len", "Findings", "Vuln Leads"};

    private final List<TrafficEntry> entries = new ArrayList<>();

    void setData(List<TrafficEntry> newEntries) {
        entries.clear();
        entries.addAll(newEntries);
        fireTableDataChanged();
    }

    TrafficEntry entryAt(int row) {
        return entries.get(row);
    }

    @Override public int getRowCount() { return entries.size(); }
    @Override public int getColumnCount() { return COLS.length; }
    @Override public String getColumnName(int col) { return COLS[col]; }

    @Override
    public Object getValueAt(int row, int col) {
        TrafficEntry e = entries.get(row);
        switch (col) {
            case 0: return e.id;
            case 1: return e.method;
            case 2: return e.url;
            case 3: return e.statusCode == null ? "-" : e.statusCode;
            case 4: return e.responseLength;
            case 5: return e.findings.size();
            case 6: return e.suggestions.size();
            default: return "";
        }
    }
}
