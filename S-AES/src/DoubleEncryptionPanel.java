package src;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class DoubleEncryptionPanel extends JPanel {
    private JTextField plaintextField;
    private JPasswordField firstKeyField;
    private JPasswordField secondKeyField;
    private JTextField encryptedField;
    private ButtonGroup styleGroup;
    private JRadioButton binaryRadioButton;
    private JRadioButton asciiRadioButton;
    private JButton encryptButton;

    public DoubleEncryptionPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        // 明文输入框
        plaintextField = new JTextField(20);
        add(new JLabel("明文:"));
        add(plaintextField);

        // 一重密钥输入框
        firstKeyField = new JPasswordField(20);
        JButton toggleFirstPasswordField = new JButton("显示一重密钥");
        toggleFirstPasswordField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                char c = firstKeyField.getEchoChar();
                if (c == '*' || c == '\u2022') {
                    firstKeyField.setEchoChar((char) 0);
                    toggleFirstPasswordField.setText("隐藏一重密钥");
                } else {
                    firstKeyField.setEchoChar('•');
                    toggleFirstPasswordField.setText("显示一重密钥");
                }
            }
        });
        add(new JLabel("一重密钥:"));
        add(new JPanel(new FlowLayout(), false) {{
            add(firstKeyField);
            add(toggleFirstPasswordField);
        }});

        // 二重密钥输入框
        secondKeyField = new JPasswordField(20);
        JButton toggleSecondPasswordField = new JButton("显示二重密钥");
        toggleSecondPasswordField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                char c = secondKeyField.getEchoChar();
                if (c == '*' || c == '\u2022') {
                    secondKeyField.setEchoChar((char) 0);
                    toggleSecondPasswordField.setText("隐藏二重密钥");
                } else {
                    secondKeyField.setEchoChar('•');
                    toggleSecondPasswordField.setText("显示二重密钥");
                }
            }
        });
        add(new JLabel("二重密钥:"));
        add(new JPanel(new FlowLayout(), false) {{
            add(secondKeyField);
            add(toggleSecondPasswordField);
        }});

        // 加密输出框
        encryptedField = new JTextField(20);
        encryptedField.setEditable(false);
        add(new JLabel("密文:"));
        add(encryptedField);

        // 单选框
        styleGroup = new ButtonGroup();
        binaryRadioButton = new JRadioButton("二进制", true);
        asciiRadioButton = new JRadioButton("ASCII码");
        styleGroup.add(binaryRadioButton);
        styleGroup.add(asciiRadioButton);
        add(binaryRadioButton);
        add(asciiRadioButton);

        // 加密按钮
        encryptButton = new JButton("加密");
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String plaintext = plaintextField.getText();
                String firstKey = new String(firstKeyField.getPassword());
                String secondKey = new String(secondKeyField.getPassword());
                String style = binaryRadioButton.isSelected() ? "1" : "2";
                String encrypted = "";
                if (style.equals("1")) {
                    encrypted = SAES.encrypt(plaintext, firstKey);
                    encrypted = SAES.encrypt(encrypted, secondKey);
                } else {
                    String[] encryptedArray = SAES.charToBinaryStringArray(plaintext);
                    for (int i = 0; i < encryptedArray.length; i++) {
                        encryptedArray[i] = SAES.encrypt(encryptedArray[i], firstKey);
                        encryptedArray[i] = SAES.encrypt(encryptedArray[i], secondKey);
                    }
                    encrypted = SAES.binaryStringArrayToString(encryptedArray);
                }
                encryptedField.setText(encrypted);
            }
        });
        add(encryptButton);
    }
}
