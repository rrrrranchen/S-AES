package src;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class TripleDecryptionPanel extends JPanel {
    private JTextField ciphertextField;
    private JPasswordField firstKeyField;
    private JPasswordField secondKeyField;
    private JPasswordField thirdKeyField;
    private JTextField decryptedField;
    private ButtonGroup styleGroup;
    private JRadioButton binaryRadioButton;
    private JRadioButton asciiRadioButton;
    private JButton decryptButton;

    public TripleDecryptionPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        // 密文输入框
        ciphertextField = new JTextField(20);
        add(new JLabel("密文:"));
        add(ciphertextField);

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

        // 三重密钥输入框
        thirdKeyField = new JPasswordField(20);
        JButton toggleThirdPasswordField = new JButton("显示三重密钥");
        toggleThirdPasswordField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                char c = thirdKeyField.getEchoChar();
                if (c == '*' || c == '\u2022') {
                    thirdKeyField.setEchoChar((char) 0);
                    toggleThirdPasswordField.setText("隐藏三重密钥");
                } else {
                    thirdKeyField.setEchoChar('•');
                    toggleThirdPasswordField.setText("显示三重密钥");
                }
            }
        });
        add(new JLabel("三重密钥:"));
        add(new JPanel(new FlowLayout(), false) {{
            add(thirdKeyField);
            add(toggleThirdPasswordField);
        }});

        // 解密输出框
        decryptedField = new JTextField(20);
        decryptedField.setEditable(false);
        add(new JLabel("明文:"));
        add(decryptedField);

        // 单选框
        styleGroup = new ButtonGroup();
        binaryRadioButton = new JRadioButton("二进制", true);
        asciiRadioButton = new JRadioButton("ASCII码");
        styleGroup.add(binaryRadioButton);
        styleGroup.add(asciiRadioButton);
        add(binaryRadioButton);
        add(asciiRadioButton);

        // 解密按钮
        decryptButton = new JButton("解密");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String ciphertext = ciphertextField.getText();
                String firstKey = new String(firstKeyField.getPassword());
                String secondKey = new String(secondKeyField.getPassword());
                String thirdKey = new String(thirdKeyField.getPassword());
                String style = binaryRadioButton.isSelected() ? "1" : "2";
                String decrypted = "";
                if (style.equals("1")) {
                    decrypted = SAES.decrypt(ciphertext, thirdKey);
                    decrypted = SAES.decrypt(decrypted, secondKey);
                    decrypted = SAES.decrypt(decrypted, firstKey);
                } else {
                    String[] encryptedArray = SAES.charToBinaryStringArray(ciphertext);
                    for (int i = encryptedArray.length - 1; i >= 0; i--) {
                        encryptedArray[i] = SAES.decrypt(encryptedArray[i], thirdKey);
                        encryptedArray[i] = SAES.decrypt(encryptedArray[i], secondKey);
                        encryptedArray[i] = SAES.decrypt(encryptedArray[i], firstKey);
                    }
                    decrypted = SAES.binaryStringArrayToString(encryptedArray);
                }
                decryptedField.setText(decrypted);
            }
        });
        add(decryptButton);
    }
}