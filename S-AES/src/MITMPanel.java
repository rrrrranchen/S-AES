package src;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MITMPanel extends JPanel {
    private JTextArea plaintextArea;
    private JTextArea ciphertextArea;
    private JTextArea resultsArea;
    private JButton findKeysButton;
    private JTextField timeField;

    public MITMPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        // 多行文本输入框，用于输入多个明文-密文对
        plaintextArea = new JTextArea(10, 30);
        add(new JLabel("已知明文（每行一个）:"));
        JScrollPane plaintextScrollPane = new JScrollPane(plaintextArea);
        add(plaintextScrollPane);

        ciphertextArea = new JTextArea(10, 30);
        add(new JLabel("已知密文（每行一个）:"));
        JScrollPane ciphertextScrollPane = new JScrollPane(ciphertextArea);
        add(ciphertextScrollPane);

        resultsArea = new JTextArea(10, 30);
        resultsArea.setEditable(false);
        JScrollPane resultsScrollPane = new JScrollPane(resultsArea);
        add(resultsScrollPane);

        findKeysButton = new JButton("查找密钥对 K1 和 K2");
        findKeysButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Instant start = Instant.now();
                findKeys();
                Instant end = Instant.now();
                timeField.setText("破解时间: " + Duration.between(start, end).toSeconds() + " 秒");
            }
        });
        add(findKeysButton);

        timeField = new JTextField(20);
        timeField.setEditable(false);
        add(new JLabel("破解时间:"));
        add(timeField);
    }

    private void findKeys() {
        String[] plaintexts = plaintextArea.getText().split("\n");
        String[] ciphertexts = ciphertextArea.getText().split("\n");
        String plaintext = plaintexts[0];
        String ciphertext = ciphertexts[0];

        HashMap<String, String> encryptionResults = new HashMap<>();
        HashMap<String, String> decryptionResults = new HashMap<>();
        HashMap<String, String> keyPairs = new HashMap<>();

        // 多线程加密过程
        ExecutorService executorEncrypt = Executors.newFixedThreadPool(4);
        for (int halfKey = 0; halfKey < 65536; halfKey += 16384) {
            final int startKey = halfKey;
            executorEncrypt.submit(() -> {
                for (int k1 = startKey; k1 < startKey + 16384; k1++) {
                    String key = String.format("%16s", Integer.toBinaryString(k1)).replace(' ', '0');
                    String encrypted = SAES.encrypt(plaintext, key);
                    synchronized (encryptionResults) {
                        encryptionResults.put(encrypted, key);
                    }
                }
            });
        }
        executorEncrypt.shutdown();
        try {
            executorEncrypt.awaitTermination(1, TimeUnit.HOURS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // 多线程解密过程
        ExecutorService executorDecrypt = Executors.newFixedThreadPool(4);
        for (int halfKey = 0; halfKey < 65536; halfKey += 16384) {
            final int startKey = halfKey;
            executorDecrypt.submit(() -> {
                for (int k2 = startKey; k2 < startKey + 16384; k2++) {
                    String key = String.format("%16s", Integer.toBinaryString(k2)).replace(' ', '0');
                    String decrypted = SAES.decrypt(ciphertext, key);
                    synchronized (decryptionResults) {
                        decryptionResults.put(decrypted, key);
                    }
                }
            });
        }
        executorDecrypt.shutdown();
        try {
            executorDecrypt.awaitTermination(1, TimeUnit.HOURS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // 匹配逻辑
        for (String encrypted : encryptionResults.keySet()) {
            if (decryptionResults.containsKey(encrypted)) {
                String k1 = encryptionResults.get(encrypted);
                String k2 = decryptionResults.get(encrypted);
                keyPairs.put(k1, k2);
            }
        }


        for (int i = 1; i < plaintexts.length; i++) {
            HashMap<String, String> newKeyPairs = new HashMap<>(); // 用于存储每一轮筛选后的密钥对
            for (Map.Entry<String, String> entry : keyPairs.entrySet()) {
                String k1 = entry.getKey();
                String k2 = entry.getValue();
                String currentPlaintext = plaintexts[i];
                String currentCiphertext = ciphertexts[i];
                String doubleEncrypted = SAES.encrypt(SAES.encrypt(currentPlaintext, k1), k2);

                if (doubleEncrypted.equals(currentCiphertext)) {
                    newKeyPairs.put(k1, k2);
                }
            }
            keyPairs = newKeyPairs; // 更新keyPairs为筛选后的密钥对
        }

        StringBuilder resultsBuilder = new StringBuilder();
        for (Map.Entry<String, String> entry : keyPairs.entrySet()) {
            String k1 = entry.getKey();
            String k2 = entry.getValue();
            resultsBuilder.append("k1: ").append(k1).append("    k2:").append(k2).append("\n");
        }

        SwingUtilities.invokeLater(() -> {
            if (resultsBuilder.length() == 0) {
                resultsBuilder.append("未找到任何密钥对。");
            }
            resultsArea.setText(resultsBuilder.toString());
        });
    }
}