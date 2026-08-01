package com.reconlens.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.persistence.Preferences;

import com.reconlens.ai.ClaudeClient;
import com.reconlens.analysis.EndpointGroupIndex;
import com.reconlens.analysis.RequestExplainer;
import com.reconlens.analysis.ResponseDiffAnalyzer;
import com.reconlens.export.ReportExporter;
import com.reconlens.handler.TrafficEntryFactory;
import com.reconlens.model.EndpointGroup;
import com.reconlens.model.JwtInfo;
import com.reconlens.model.ParamFinding;
import com.reconlens.model.TrafficEntry;
import com.reconlens.model.VulnSuggestion;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * The ReconLens suite tab: an endpoint-groups table on the left, the individual
 * requests within the selected group on the right, and a detail pane underneath
 * with the raw request/response, the heuristic findings, and (optionally) an
 * AI-generated explanation.
 */
public final class ReconLensTab implements EndpointGroupIndex.Listener {

    private static final String PREF_CAPTURE_ENABLED = "reconlens.captureEnabled";
    private static final String PREF_TOOLS = "reconlens.tools"; // comma-separated ToolType names

    private final MontoyaApi api;
    private final EndpointGroupIndex index;
    private final ClaudeClient claudeClient;
    private final Preferences prefs;

    private final JPanel root = new JPanel(new BorderLayout());
    private final GroupTableModel groupModel = new GroupTableModel();
    private final EntryTableModel entryModel = new EntryTableModel();
    private final JTable groupTable = new JTable(groupModel);
    private final JTable entryTable = new JTable(entryModel);

    private final JTextArea requestArea = new JTextArea();
    private final JTextArea responseArea = new JTextArea();
    private final JTextArea findingsArea = new JTextArea();
    private final JTextArea groupInsightsArea = new JTextArea();
    private final JTextArea authArea = new JTextArea();
    private final JTextArea aiArea = new JTextArea();
    private final JButton explainButton = new JButton("Explain with AI");
    private final JLabel statusBar = new JLabel(" Ready. Only point this at systems you're authorized to test.");

    private final JCheckBox captureToggle = new JCheckBox("Capture traffic", true);
    private final ResourcePanel resourcePanel;

    private volatile Set<ToolType> capturedTools = EnumSet.of(ToolType.PROXY, ToolType.REPEATER);

    public ReconLensTab(MontoyaApi api, EndpointGroupIndex index, ClaudeClient claudeClient) {
        this.api = api;
        this.index = index;
        this.claudeClient = claudeClient;
        this.prefs = api.persistence().preferences();
        this.resourcePanel = new ResourcePanel(api, index, claudeClient);

        loadPreferences();
        index.addListener(this);
        buildUi();
    }

    public Component getComponent() {
        return root;
    }

    public boolean isCaptureEnabled() {
        return captureToggle.isSelected();
    }

    public boolean isToolCaptured(ToolType type) {
        return capturedTools.contains(type);
    }

    // ---------------------------------------------------------------- UI wiring

    private void buildUi() {
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);

        JButton importBtn = new JButton("Import Proxy History");
        importBtn.setToolTipText("Pull everything already sitting in Burp's Proxy HTTP history into ReconLens right now.");
        importBtn.addActionListener(e -> importProxyHistory());

        JButton exportBtn = new JButton("Export Report (.md)");
        exportBtn.addActionListener(e -> exportReport());

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            index.clear();
            refreshGroups();
            resourcePanel.refresh();
            entryModel.setData(List.of());
            clearDetail();
        });

        JButton toolsBtn = new JButton("Tools \u25BE");
        toolsBtn.addActionListener(e -> showToolPicker(toolsBtn));

        JButton aiSettingsBtn = new JButton("AI Settings...");
        aiSettingsBtn.addActionListener(e -> {
            new AiSettingsDialog(SwingUtilities.getWindowAncestor(root), claudeClient).setVisible(true);
            if (entryTable.getSelectedRow() >= 0) {
                explainButton.setEnabled(claudeClient.isConfigured());
            }
        });

        captureToggle.addActionListener(e -> savePreferences());

        toolbar.add(importBtn);
        toolbar.add(exportBtn);
        toolbar.add(clearBtn);
        toolbar.addSeparator();
        toolbar.add(captureToggle);
        toolbar.add(toolsBtn);
        toolbar.addSeparator();
        toolbar.add(aiSettingsBtn);

        groupTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        groupTable.setAutoCreateRowSorter(true);
        groupTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onGroupSelected();
        });

        entryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        entryTable.setAutoCreateRowSorter(true);
        entryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onEntrySelected();
        });

        JSplitPane tables = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(groupTable), new JScrollPane(entryTable));
        tables.setResizeWeight(0.45);

        for (JTextArea a : new JTextArea[]{requestArea, responseArea, findingsArea, groupInsightsArea, authArea, aiArea}) {
            a.setEditable(false);
            a.setLineWrap(true);
            a.setWrapStyleWord(true);
            a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        }

        explainButton.setEnabled(false);
        explainButton.addActionListener(e -> runAiExplanation());
        JPanel aiTop = new JPanel(new FlowLayout(FlowLayout.LEFT));
        aiTop.add(explainButton);
        JPanel aiPanel = new JPanel(new BorderLayout());
        aiPanel.add(aiTop, BorderLayout.NORTH);
        aiPanel.add(new JScrollPane(aiArea), BorderLayout.CENTER);

        JTabbedPane detailTabs = new JTabbedPane();
        detailTabs.addTab("Findings & Leads", new JScrollPane(findingsArea));
        detailTabs.addTab("Group Insights", new JScrollPane(groupInsightsArea));
        detailTabs.addTab("Request", new JScrollPane(requestArea));
        detailTabs.addTab("Response", new JScrollPane(responseArea));
        detailTabs.addTab("Auth Analysis", new JScrollPane(authArea));
        detailTabs.addTab("AI Explanation", aiPanel);

        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tables, detailTabs);
        main.setResizeWeight(0.45);

        JTabbedPane views = new JTabbedPane();
        views.addTab("By Endpoint", main);
        views.addTab("By Resource (CRUD)", resourcePanel.getComponent());

        statusBar.setBorder(new EmptyBorder(2, 6, 2, 6));

        root.add(toolbar, BorderLayout.NORTH);
        root.add(views, BorderLayout.CENTER);
        root.add(statusBar, BorderLayout.SOUTH);
    }

    private void showToolPicker(Component anchor) {
        JPopupMenu menu = new JPopupMenu();
        for (ToolType t : new ToolType[]{ToolType.PROXY, ToolType.REPEATER, ToolType.INTRUDER, ToolType.SCANNER, ToolType.EXTENSIONS}) {
            JCheckBoxMenuItem item = new JCheckBoxMenuItem(t.name(), capturedTools.contains(t));
            item.addActionListener(e -> {
                if (item.isSelected()) capturedTools.add(t); else capturedTools.remove(t);
                savePreferences();
            });
            menu.add(item);
        }
        menu.show(anchor, 0, anchor.getHeight());
    }

    // ---------------------------------------------------------------- data flow

    @Override
    public void onEntryAdded(TrafficEntry entry, EndpointGroup group) {
        SwingUtilities.invokeLater(() -> {
            refreshGroups();
            resourcePanel.refresh();
            statusBar.setText(" Captured #" + entry.id + "  " + entry.method + " " + entry.host + entry.path
                    + "   (" + index.allEntries().size() + " total)");
        });
    }

    private void refreshGroups() {
        List<EndpointGroup> groups = index.allGroups();
        List<TrafficEntry> all = index.allEntries();

        int selectedRow = groupTable.getSelectedRow();
        EndpointGroup selected = selectedRow >= 0
                ? groupModel.groupAt(groupTable.convertRowIndexToModel(selectedRow)) : null;

        groupModel.setData(groups, all);

        if (selected != null) {
            for (int i = 0; i < groups.size(); i++) {
                if (groups.get(i).key.equals(selected.key)) {
                    int viewRow = groupTable.convertRowIndexToView(i);
                    if (viewRow >= 0) groupTable.setRowSelectionInterval(viewRow, viewRow);
                    break;
                }
            }
        }
    }

    private void onGroupSelected() {
        int row = groupTable.getSelectedRow();
        if (row < 0) {
            entryModel.setData(List.of());
            groupInsightsArea.setText("");
            return;
        }
        EndpointGroup group = groupModel.groupAt(groupTable.convertRowIndexToModel(row));
        List<TrafficEntry> members = index.entriesIn(group);
        entryModel.setData(members);
        groupInsightsArea.setText(renderGroupInsights(group, members));
        groupInsightsArea.setCaretPosition(0);
    }

    private String renderGroupInsights(EndpointGroup group, List<TrafficEntry> members) {
        StringBuilder sb = new StringBuilder();
        sb.append("Group: ").append(group.method).append(' ').append(group.host).append(group.normalizedPath).append('\n');
        sb.append("Members captured: ").append(members.size()).append('\n');

        TrafficEntry riskiest = null;
        for (TrafficEntry e : members) {
            if (riskiest == null || e.riskScore.score > riskiest.riskScore.score) riskiest = e;
        }
        if (riskiest != null) {
            sb.append("Highest individual risk score: ").append(riskiest.riskScore.score)
              .append("/100 (request #").append(riskiest.id).append(")\n");
        }

        sb.append("\n--- Cross-request signals (response comparison across this group) ---\n");
        List<VulnSuggestion> diffFindings = ResponseDiffAnalyzer.analyze(members);
        if (diffFindings.isEmpty()) {
            sb.append("(need at least 2 comparable JSON responses in this group -- none found yet, or nothing stood out)\n");
        } else {
            for (VulnSuggestion v : diffFindings) {
                sb.append("[").append(v.confidence).append("] ").append(v.vulnClass).append('\n');
                sb.append("   why: ").append(v.rationale).append('\n');
                sb.append("   try: ").append(v.testIdea).append('\n');
            }
        }

        sb.append("\n--- Per-request risk scores ---\n");
        List<TrafficEntry> sorted = new ArrayList<>(members);
        sorted.sort((a, b) -> b.riskScore.score - a.riskScore.score);
        for (TrafficEntry e : sorted) {
            sb.append("#").append(e.id).append("  ").append(e.riskScore.score).append("/100\n");
        }

        return sb.toString();
    }

    private void onEntrySelected() {
        int row = entryTable.getSelectedRow();
        if (row < 0) {
            clearDetail();
            return;
        }
        TrafficEntry entry = entryModel.entryAt(entryTable.convertRowIndexToModel(row));
        requestArea.setText(entry.requestHead + "\n" + entry.requestBody);
        requestArea.setCaretPosition(0);
        responseArea.setText(entry.responseHead + "\n" + entry.responseBody);
        responseArea.setCaretPosition(0);
        findingsArea.setText(renderFindings(entry));
        findingsArea.setCaretPosition(0);
        authArea.setText(renderAuthAnalysis(entry));
        authArea.setCaretPosition(0);
        aiArea.setText(entry.aiExplanation != null ? entry.aiExplanation : "(not requested yet)");
        explainButton.setEnabled(claudeClient.isConfigured());
    }

    private void clearDetail() {
        requestArea.setText("");
        responseArea.setText("");
        findingsArea.setText("");
        groupInsightsArea.setText("");
        authArea.setText("");
        aiArea.setText("");
        explainButton.setEnabled(false);
    }

    private String renderAuthAnalysis(TrafficEntry entry) {
        if (entry.jwtFindings.isEmpty()) {
            return "No JWT found in this request's parameters or Authorization header.";
        }
        StringBuilder sb = new StringBuilder();
        int i = 1;
        for (JwtInfo j : entry.jwtFindings) {
            sb.append("JWT #").append(i++).append('\n');
            sb.append("  Algorithm: ").append(j.algorithm).append('\n');
            sb.append("  Expiration claim present: ").append(j.hasExpiry ? "yes" : "no").append('\n');
            sb.append("  Claims: ").append(String.join(", ", j.claimNames)).append('\n');
            if (j.warnings.isEmpty()) {
                sb.append("  No specific warnings from static decoding alone.\n");
            } else {
                sb.append("  Warnings:\n");
                for (String w : j.warnings) sb.append("    - ").append(w).append('\n');
            }
            sb.append('\n');
        }
        sb.append("Note: this is a static decode of the header/payload only -- the signature was not checked, " +
                "since that requires the server's secret/key.");
        return sb.toString();
    }

    private String renderFindings(TrafficEntry entry) {
        StringBuilder sb = new StringBuilder();
        sb.append("Risk score: ").append(entry.riskScore.score).append("/100\n");
        for (String reason : entry.riskScore.reasons) sb.append("  ").append(reason).append('\n');
        sb.append('\n');

        sb.append(RequestExplainer.explain(entry.method, entry.host, entry.path, entry.params.size(),
                entry.statusCode, entry.mimeType, entry.responseLength, entry.findings, entry.suggestions));

        sb.append("\n\n--- Parameter findings ---\n");
        if (entry.findings.isEmpty()) sb.append("(none)\n");
        for (ParamFinding f : entry.findings) {
            sb.append("[").append(f.severity).append("] ").append(f.paramName)
              .append(" -- ").append(f.category).append(": ").append(f.reason).append('\n');
        }

        sb.append("\n--- Vulnerability leads ---\n");
        if (entry.suggestions.isEmpty()) sb.append("(none)\n");
        for (VulnSuggestion v : entry.suggestions) {
            sb.append("[").append(v.confidence).append("] ").append(v.vulnClass).append('\n');
            sb.append("   why: ").append(v.rationale).append('\n');
            sb.append("   try: ").append(v.testIdea).append('\n');
        }
        return sb.toString();
    }

    private void runAiExplanation() {
        int row = entryTable.getSelectedRow();
        if (row < 0) return;
        TrafficEntry entry = entryModel.entryAt(entryTable.convertRowIndexToModel(row));
        explainButton.setEnabled(false);
        aiArea.setText("Asking Claude...");

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return claudeClient.explain(entry);
            }

            @Override
            protected void done() {
                try {
                    String result = get();
                    entry.aiExplanation = result;
                    aiArea.setText(result);
                } catch (Exception e) {
                    aiArea.setText("AI explanation failed: " + e.getMessage());
                } finally {
                    explainButton.setEnabled(claudeClient.isConfigured());
                }
            }
        }.execute();
    }

    private void importProxyHistory() {
        int count = 0;
        try {
            for (var item : api.proxy().history()) {
                if (item.request() == null) continue;
                TrafficEntry entry = TrafficEntryFactory.build(index.nextId(), "PROXY", item.request(), item.response());
                index.add(entry);
                count++;
            }
        } catch (Exception ex) {
            api.logging().logToError("ReconLens import failed: " + ex);
        }
        refreshGroups();
        resourcePanel.refresh();
        statusBar.setText(" Imported " + count + " item(s) from Proxy history.");
    }

    private void exportReport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("reconlens-report.md"));
        if (chooser.showSaveDialog(root) == JFileChooser.APPROVE_OPTION) {
            try {
                String md = ReportExporter.render(index.allGroups(), index.allEntries());
                Files.writeString(chooser.getSelectedFile().toPath(), md);
                statusBar.setText(" Report saved to " + chooser.getSelectedFile());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(root, "Could not save report: " + ex.getMessage());
            }
        }
    }

    // ---------------------------------------------------------------- preferences

    private void loadPreferences() {
        String capture = prefs.getString(PREF_CAPTURE_ENABLED);
        if (capture != null) captureToggle.setSelected("true".equals(capture));

        String tools = prefs.getString(PREF_TOOLS);
        if (tools != null && !tools.isBlank()) {
            Set<ToolType> loaded = EnumSet.noneOf(ToolType.class);
            for (String t : tools.split(",")) {
                try {
                    loaded.add(ToolType.valueOf(t));
                } catch (IllegalArgumentException ignored) {
                    // stored value from a different Montoya API version -- skip it
                }
            }
            if (!loaded.isEmpty()) capturedTools = loaded;
        }
    }

    private void savePreferences() {
        prefs.setString(PREF_CAPTURE_ENABLED, Boolean.toString(captureToggle.isSelected()));
        StringBuilder sb = new StringBuilder();
        for (ToolType t : capturedTools) {
            if (sb.length() > 0) sb.append(',');
            sb.append(t.name());
        }
        prefs.setString(PREF_TOOLS, sb.toString());
    }
}
