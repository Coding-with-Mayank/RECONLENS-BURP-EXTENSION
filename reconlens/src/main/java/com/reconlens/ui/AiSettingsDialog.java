package com.reconlens.ui;

import com.reconlens.ai.ClaudeClient;

import javax.swing.*;
import java.awt.*;

/** "AI Settings" dialog: API key, model, and the bodies-in-prompt privacy toggle. */
final class AiSettingsDialog extends JDialog {

    AiSettingsDialog(Window owner, ClaudeClient client) {
        super(owner, "ReconLens - AI Settings", ModalityType.APPLICATION_MODAL);

        JCheckBox enabledBox = new JCheckBox("Enable AI explanations (\"Explain with AI\" button)", client.isEnabled());
        JPasswordField keyField = new JPasswordField(client.getApiKey(), 30);
        JTextField modelField = new JTextField(client.getModel(), 30);
        JCheckBox includeBodyBox = new JCheckBox("Include request/response bodies in the prompt", client.isIncludeBody());

        JTextArea notice = new JTextArea(
                "Uses your own Anthropic API key (console.anthropic.com), billed to your account -- separate " +
                "from any claude.ai subscription. Only sent when you click \"Explain with AI\" on a specific " +
                "request; nothing is sent automatically. With bodies excluded (default), only the method, path, " +
                "parameter names/types, status, and the local heuristic findings are sent -- not raw request/" +
                "response content.");
        notice.setEditable(false);
        notice.setLineWrap(true);
        notice.setWrapStyleWord(true);
        notice.setOpaque(false);
        notice.setFont(UIManager.getFont("Label.font"));
        notice.setFocusable(false);

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;

        c.gridx = 0; c.gridy = 0; c.gridwidth = 2;
        form.add(enabledBox, c);

        c.gridy++; c.gridwidth = 1;
        form.add(new JLabel("Anthropic API key:"), c);
        c.gridx = 1;
        form.add(keyField, c);

        c.gridx = 0; c.gridy++;
        form.add(new JLabel("Model:"), c);
        c.gridx = 1;
        form.add(modelField, c);

        c.gridx = 0; c.gridy++; c.gridwidth = 2;
        form.add(includeBodyBox, c);

        c.gridy++;
        form.add(notice, c);

        JButton save = new JButton("Save");
        JButton cancel = new JButton("Cancel");
        save.addActionListener(e -> {
            client.update(enabledBox.isSelected(), new String(keyField.getPassword()),
                    modelField.getText(), includeBodyBox.isSelected());
            dispose();
        });
        cancel.addActionListener(e -> dispose());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(cancel);
        buttons.add(save);

        setLayout(new BorderLayout());
        add(form, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);
        setSize(500, 340);
        setLocationRelativeTo(owner);
    }
}
