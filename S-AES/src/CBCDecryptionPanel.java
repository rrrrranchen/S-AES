package src;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

public class CBCDecryptionPanel extends JPanel {
    private JTextField ciphertextField;
    private JPasswordField keyField;
    private JTextField plaintextField;
    private JButton decryptButton;
    private JRadioButton binaryRadioButton;
    private JRadioButton asciiRadioButton;
    private ButtonGroup styleGroup;

    public CBCDecryptionPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        // 密文输入框
        ciphertextField = new JTextField(20);
        add(new JLabel("密文:"));
        add(ciphertextField);

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

        // 明文输出框
        plaintextField = new JTextField(20);
        plaintextField.setEditable(false);
        add(new JLabel("明文:"));
        add(plaintextField);

        // 解密按钮
        decryptButton = new JButton("解密");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String ciphertext = ciphertextField.getText();
                String key = new String(keyField.getPassword());
                String style = binaryRadioButton.isSelected() ? "1" : "2";
                String plaintext = "";
                if (style.equals("1")) {
                    // 假设SAES类有一个静态方法cbcDecrypt，接受密文和密钥，返回明文
                    plaintext = SAES.cbcDecrypt(ciphertext, key, 12).toString();
                } else {

                    List<String> decrypted = SAES.stringToBinaryList(ciphertext);
                    System.out.println("Decrypted binary list: " + decrypted);
                    String decrypted2 = SAES.convertToBinaryString(decrypted);
                    System.out.println("Decrypted binary string: " + decrypted2);
                    decrypted = SAES.cbcDecrypt(decrypted2, key, 12);
                    System.out.println("Decrypted list after CBC: " + decrypted);
                    plaintext = SAES.binaryListToString(decrypted);
                    System.out.println("Final plaintext: " + plaintext);
                }
                plaintextField.setText(plaintext);
            }
        });
        add(decryptButton);
    }
}