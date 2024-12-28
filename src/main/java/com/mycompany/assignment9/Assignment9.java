//Index No: 22_ENG_059, 22_ENG_093

package com.mycompany.assignment9;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Assignment9 {
    // AES Encryption Key
    private static final String SECRET_KEY = "1234567812345678";

    private JFrame frame;
    private JTextField ipField, messageField;
     private JTextArea sentMessagesArea, receivedMessagesArea, consoleArea;
    private JButton connectButton, sendButton, attachButton, acceptButton, enableEncryptionButton;
    private JFileChooser fileChooser;
    private Socket socket;
    private ServerSocket serverSocket;
    private DataInputStream input;
    private DataOutputStream output;
    private boolean encryptionEnabled = false;

    public Assignment9() {
        frame = new JFrame("Peer-to-Peer Chat");
        frame.setSize(800, 500);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // Layout
        JPanel panel = new JPanel(new BorderLayout());
        JPanel topPanel = new JPanel(new FlowLayout());
        JPanel bottomPanel = new JPanel(new FlowLayout());

        // Components
        ipField = new JTextField(15);
        messageField = new JTextField(20);

        connectButton = new JButton("Connect");
        sendButton = new JButton("Send");
        attachButton = new JButton("Attach");
        acceptButton = new JButton("Accept");
        enableEncryptionButton = new JButton("Enable Encryption");

        fileChooser = new JFileChooser();

        // Adding Components
        topPanel.add(new JLabel("IP Address:"));
        topPanel.add(ipField);
        topPanel.add(connectButton);
        topPanel.add(acceptButton);
        
        // Center panel for chat areas and console
        JPanel centerPanel = new JPanel(new BorderLayout());
        sentMessagesArea = new JTextArea();
        receivedMessagesArea = new JTextArea();
        consoleArea = new JTextArea();
        sentMessagesArea.setEditable(false);
        receivedMessagesArea.setEditable(false);
        consoleArea.setEditable(false);
        consoleArea.setBorder(BorderFactory.createTitledBorder("Console"));

        // SplitPane to separate sent and received messages
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, 
                                              new JScrollPane(sentMessagesArea), 
                                              new JScrollPane(receivedMessagesArea));
        splitPane.setDividerLocation(380);
        splitPane.setResizeWeight(0.5);

        centerPanel.add(splitPane, BorderLayout.CENTER); // Add split pane to center
        centerPanel.add(new JScrollPane(consoleArea), BorderLayout.SOUTH); // Add console area to bottom


        bottomPanel.add(messageField);
        bottomPanel.add(sendButton);
        bottomPanel.add(attachButton);
        bottomPanel.add(enableEncryptionButton);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(centerPanel, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);

        frame.add(panel);
        frame.setVisible(true);
        frame.setLocationRelativeTo(null);

        // Event Listeners
        connectButton.addActionListener(this::connectToClient);
        sendButton.addActionListener(this::sendMessage);
        attachButton.addActionListener(this::attachFile);
        acceptButton.addActionListener(this::acceptConnection);
        enableEncryptionButton.addActionListener(e -> {
            encryptionEnabled = !encryptionEnabled;
            enableEncryptionButton.setText(encryptionEnabled ? "Disable Encryption" : "Enable Encryption");
        });
    }

    // Connecting to peer
    private void connectToClient(ActionEvent e) {
        try {
            String ip = ipField.getText();
            socket = new Socket(ip, 12345); // Connect to peer on port 12345
            input = new DataInputStream(socket.getInputStream());
            output = new DataOutputStream(socket.getOutputStream());
            consoleArea.append("Connected to: " + ip + "\n");
            new Thread(this::receiveMessages).start();
        } catch (IOException ex) {
            consoleArea.append("Failed to connect to peer.\n");
        }
    }

    // Accepting connection
    private void acceptConnection(ActionEvent e) {
        new Thread(() -> {
            try {
                serverSocket = new ServerSocket(12345); // Listen on port 12345
                consoleArea.append("Waiting for connection...\n");
                socket = serverSocket.accept();
                input = new DataInputStream(socket.getInputStream());
                output = new DataOutputStream(socket.getOutputStream());
                consoleArea.append("Connection accepted!\n");
                new Thread(this::receiveMessages).start();
            } catch (IOException ex) {
                consoleArea.append("Error accepting connection.\n");
            }
        }).start();
    }

    // Sending messages
    private void sendMessage(ActionEvent e) {
        try {
            String message = messageField.getText();
            if (encryptionEnabled) {
                message = encrypt(message, SECRET_KEY);
            }
            output.writeUTF(message);
            sentMessagesArea.append("Me: " + messageField.getText() + "\n");
            messageField.setText("");
        } catch (IOException ex) {
            consoleArea.append("Error sending message.\n");
        }
    }

    // Receiving messages and files
    private void receiveMessages() {
        try {
            while (true) {
                String header = input.readUTF(); // Read the message or file header
                if (header.startsWith("FILE:")) {
                    String fileName = header.substring(5); // Extract file name

                    // Prompt the user to select the save location
                    JFileChooser saveChooser = new JFileChooser();
                    saveChooser.setSelectedFile(new File(fileName)); // Default file name
                    int returnValue = saveChooser.showSaveDialog(frame);

                    if (returnValue == JFileChooser.APPROVE_OPTION) {
                        File saveFile = saveChooser.getSelectedFile(); // Get the chosen file path
                        FileOutputStream fileOutput = new FileOutputStream(saveFile);

                        // Receive the file data in chunks
                        byte[] buffer = new byte[4096]; // Chunk size
                        int bytesRead;
                        while (input.available() > 0 && (bytesRead = input.read(buffer)) != -1) {
                            fileOutput.write(buffer, 0, bytesRead); // Write to the chosen file
                        }
                        fileOutput.close();

                        // Display a confirmation message in the chat area and as a popup
                        receivedMessagesArea.append("File received and saved at: " + saveFile.getAbsolutePath() + "\n");
                        JOptionPane.showMessageDialog(frame, 
                            "File saved successfully at: " + saveFile.getAbsolutePath(), 
                            "File Received", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        consoleArea.append("File save canceled by user.\n");
                    }
                } else {
                    // If it's not a file, treat it as a regular message
                    String message = header;
                    if (encryptionEnabled) {
                        message = decrypt(message, SECRET_KEY);
                    }
                    receivedMessagesArea.append("Client: " + message + "\n");
                }
            }
        } catch (IOException ex) {
            consoleArea.append("Connection closed.\n");
        }
    }

    // Attaching files
    private void attachFile(ActionEvent e) {
        int returnValue = fileChooser.showOpenDialog(frame);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                sendFile(file);
            } catch (IOException ex) {
                consoleArea.append("Error sending file.\n");
            }
        }
    }

    // Sending files
    private void sendFile(File file) throws IOException {
        if (file.length() > 1024 * 1024) { // Restrict file size to 1MB
            consoleArea.append("File size exceeds 1MB.\n");
            return;
        }
        output.writeUTF("FILE:" + file.getName()); // Send the file name with prefix
        FileInputStream fileInput = new FileInputStream(file);
        byte[] buffer = new byte[4096]; // Chunk size
        int bytesRead;
        while ((bytesRead = fileInput.read(buffer)) != -1) {
            output.write(buffer, 0, bytesRead); // Send the file data
        }
        fileInput.close();
        sentMessagesArea.append("File sent: " + file.getName() + "\n");
    }

    // Encryption and decryption (XOR Cipher)
    private static String encrypt(String plainText, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String decrypt(String encryptedText, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public static void main(String[] args) {
        new Assignment9();
    }
}