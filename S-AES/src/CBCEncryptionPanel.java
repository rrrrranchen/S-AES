package src;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

public class CBCEncryptionPanel extends JPanel {
    private JTextField plaintextField;
    private JPasswordField keyField;
    private JTextField ciphertextField;
    private JButton encryptButton;
    private JRadioButton binaryRadioButton;
    private JRadioButton asciiRadioButton;
    private ButtonGroup styleGroup;

    public CBCEncryptionPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        // 明文输入框
        plaintextField = new JTextField(20);
        add(new JLabel("明文:"));
        add(plaintextField);

        // 密钥输入框
        keyField = new JPasswordField(20);
        JButton togglePasswordField = new JButton("显示密钥");
        togglePasswordField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                char c = keyField.getEchoChar();
                if (c == '*' || c == '\u2022') {
                    keyField.setEchoChar((char) 0);
                    togglePasswordField.setText("隐藏密钥");
                } else {
                    keyField.setEchoChar('•');
                    togglePasswordField.setText("显示密钥");
                }
            }
        });
        add(new JLabel("密钥:"));
        add(new JPanel(new FlowLayout(), false) {{
            add(keyField);
            add(togglePasswordField);
        }});

        // 单选框
        styleGroup = new ButtonGroup();
        binaryRadioButton = new JRadioButton("二进制", true);
        asciiRadioButton = new JRadioButton("ASCII码");
        styleGroup.add(binaryRadioButton);
        styleGroup.add(asciiRadioButton);
        add(binaryRadioButton);
        add(asciiRadioButton);

        // 密文输出框
        ciphertextField = new JTextField(20);
        ciphertextField.setEditable(false);
        add(new JLabel("密文:"));
        add(ciphertextField);

        // 加密按钮
        encryptButton = new JButton("加密");
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String plaintext = plaintextField.getText();
                String key = new String(keyField.getPassword());
                String style = binaryRadioButton.isSelected() ? "1" : "2";
                String ciphertext = "";
                if (style.equals("1")) {
                    // 假设SAES类有一个静态方法cbcEncrypt，接受明文和密钥，返回密文
                    ciphertext = SAES.cbcEncrypt(plaintext, key, 12).toString();
                } else {
                    List<String> encrypted = SAES.stringToBinaryList(plaintext);
                    System.out.println("Plaintext binary list: " + encrypted);
                    String encrypted2 = SAES.convertToBinaryString(encrypted);
                    System.out.println("Plaintext binary string: " + encrypted2);
                    encrypted = SAES.cbcEncrypt(encrypted2, key, 12);
                    System.out.println("Encrypted list after CBC: " + encrypted);
                    ciphertext = SAES.binaryListToString(encrypted);
                    System.out.println("Final ciphertext: " + ciphertext);
                }
                ciphertextField.setText(ciphertext);
            }
        });
        add(encryptButton);
    }
}