package com.reconlens.ui;

import com.reconlens.model.ResourceProfile;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

final class ResourceTableModel extends AbstractTableModel {

    private static final String[] COLS = {"Host", "Resource (base path)", "Methods", "CRUD", "Requests"};

    private final List<ResourceProfile> resources = new ArrayList<>();

    void setData(List<ResourceProfile> newResources) {
        resources.clear();
        resources.addAll(newResources);
        fireTableDataChanged();
    }

    ResourceProfile resourceAt(int row) {
        return resources.get(row);
    }

    @Override public int getRowCount() { return resources.size(); }
    @Override public int getColumnCount() { return COLS.length; }
    @Override public String getColumnName(int col) { return COLS[col]; }

    @Override
    public Object getValueAt(int row, int col) {
        ResourceProfile r = resources.get(row);
        switch (col) {
            case 0: return r.host;
            case 1: return r.basePath;
            case 2: return String.join(",", r.methodsSeen);
            case 3: return r.crudCoverageCount() + "/4";
            case 4: return r.memberIds.size();
            default: return "";
        }
    }
}
