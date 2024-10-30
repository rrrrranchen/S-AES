package src;

import javax.swing.*;

public class EncryptionApp {
    public static void main(String[] args) {
        JFrame frame = new JFrame("S-AES加密解密应用");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        JTabbedPane tabbedPane = new JTabbedPane();

        EncryptionPanel encryptionPanel = new EncryptionPanel();
        DecryptionPanel decryptionPanel = new DecryptionPanel();
        DoubleEncryptionPanel doubleEncryptionPanel = new DoubleEncryptionPanel();
        TripleEncryptionPanel tripleEncryptionPanel = new TripleEncryptionPanel();
        TripleDecryptionPanel tripleDecryptionPanel = new TripleDecryptionPanel();
        MITMPanel mitmPanel = new MITMPanel();
        CBCEncryptionPanel cbcEncryptionPanel=new CBCEncryptionPanel();
        CBCDecryptionPanel cbcDecryptionPanel=new CBCDecryptionPanel();
        tabbedPane.addTab("加密", encryptionPanel);
        tabbedPane.addTab("解密", decryptionPanel);
        tabbedPane.addTab("双重加密", doubleEncryptionPanel);
        tabbedPane.addTab("MITM", mitmPanel);
        tabbedPane.addTab("三重加密", tripleEncryptionPanel);
        tabbedPane.addTab("三重解密", tripleDecryptionPanel);
        tabbedPane.addTab("CBC加密", cbcEncryptionPanel);
        tabbedPane.addTab("CBC解密", cbcDecryptionPanel);
        frame.add(tabbedPane);
        frame.setVisible(true);
    }
}
