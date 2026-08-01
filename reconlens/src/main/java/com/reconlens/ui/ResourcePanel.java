package com.reconlens.ui;

import burp.api.montoya.MontoyaApi;

import com.reconlens.ai.ClaudeClient;
import com.reconlens.analysis.AttackPathSynthesizer;
import com.reconlens.analysis.EndpointGroupIndex;
import com.reconlens.analysis.ResourceProfiler;
import com.reconlens.model.ResourceProfile;
import com.reconlens.model.TrafficEntry;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/**
 * "By Resource (CRUD)" tab: same host+path shape across every HTTP method
 * seen, so you can tell at a glance whether an endpoint shape is read-only
 * or exposes the full object lifecycle -- and, for the ones that do, get a
 * prioritized attack order instead of a flat list of individual findings.
 */
public final class ResourcePanel {

    private final MontoyaApi api;
    private final EndpointGroupIndex index;
    private final ClaudeClient claudeClient;

    private final JPanel root = new JPanel(new BorderLayout());
    private final ResourceTableModel model = new ResourceTableModel();
    private final JTable table = new JTable(model);

    private final JTextArea attackPathArea = new JTextArea();
    private final JTextArea aiArea = new JTextArea();
    private final JButton analyzeWithAiButton = new JButton("Analyze Resource with AI");

    public ResourcePanel(MontoyaApi api, EndpointGroupIndex index, ClaudeClient claudeClient) {
        this.api = api;
        this.index = index;
        this.claudeClient = claudeClient;
        buildUi();
    }

    public Component getComponent() {
        return root;
    }

    private void buildUi() {
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onResourceSelected();
        });

        for (JTextArea a : new JTextArea[]{attackPathArea, aiArea}) {
            a.setEditable(false);
            a.setLineWrap(true);
            a.setWrapStyleWord(true);
            a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        }

        analyzeWithAiButton.setEnabled(false);
        analyzeWithAiButton.addActionListener(e -> runAiAnalysis());

        JPanel aiTop = new JPanel(new FlowLayout(FlowLayout.LEFT));
        aiTop.add(analyzeWithAiButton);
        JPanel aiPanel = new JPanel(new BorderLayout());
        aiPanel.add(aiTop, BorderLayout.NORTH);
        aiPanel.add(new JScrollPane(aiArea), BorderLayout.CENTER);

        JTabbedPane detail = new JTabbedPane();
        detail.addTab("Attack Path (offline)", new JScrollPane(attackPathArea));
        detail.addTab("AI Analysis", aiPanel);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detail);
        split.setResizeWeight(0.4);

        root.add(split, BorderLayout.CENTER);
    }

    /** Called by ReconLensTab whenever captured traffic changes. */
    public void refresh() {
        List<ResourceProfile> resources = ResourceProfiler.profile(index.allEntries());

        int selectedRow = table.getSelectedRow();
        ResourceProfile selected = selectedRow >= 0
                ? model.resourceAt(table.convertRowIndexToModel(selectedRow)) : null;

        model.setData(resources);

        if (selected != null) {
            for (int i = 0; i < resources.size(); i++) {
                if (resources.get(i).key.equals(selected.key)) {
                    int viewRow = table.convertRowIndexToView(i);
                    if (viewRow >= 0) table.setRowSelectionInterval(viewRow, viewRow);
                    break;
                }
            }
        }
    }

    private void onResourceSelected() {
        int row = table.getSelectedRow();
        if (row < 0) {
            attackPathArea.setText("");
            aiArea.setText("");
            analyzeWithAiButton.setEnabled(false);
            return;
        }
        ResourceProfile resource = model.resourceAt(table.convertRowIndexToModel(row));
        List<TrafficEntry> members = index.entriesForResource(resource);
        attackPathArea.setText(AttackPathSynthesizer.synthesize(resource, members));
        attackPathArea.setCaretPosition(0);
        aiArea.setText("(not requested yet)");
        analyzeWithAiButton.setEnabled(claudeClient.isConfigured());
    }

    private void runAiAnalysis() {
        int row = table.getSelectedRow();
        if (row < 0) return;
        ResourceProfile resource = model.resourceAt(table.convertRowIndexToModel(row));
        List<TrafficEntry> members = index.entriesForResource(resource);
        String offlinePath = AttackPathSynthesizer.synthesize(resource, members);

        analyzeWithAiButton.setEnabled(false);
        aiArea.setText("Asking Claude...");

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return claudeClient.analyzeResource(resource, members, offlinePath);
            }

            @Override
            protected void done() {
                try {
                    aiArea.setText(get());
                } catch (Exception e) {
                    api.logging().logToError("ReconLens resource AI analysis failed: " + e);
                    aiArea.setText("AI analysis failed: " + e.getMessage());
                } finally {
                    analyzeWithAiButton.setEnabled(claudeClient.isConfigured());
                }
            }
        }.execute();
    }
}
