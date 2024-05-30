import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ImageEncryptionGUI extends JFrame {
    private JButton encryptButton;
    private JButton decryptButton;
    private JLabel name;
    private JFileChooser fileChooser;
    private File selectedFile;
    private KeyPair keyPair;

    public ImageEncryptionGUI() {
        setTitle("Image Encryption");
        setSize(400, 500);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS)); 

        name = new JLabel("Please browse your image for encryption/decryption", SwingConstants.CENTER);
        encryptButton = new JButton("Encrypt Image");
        decryptButton = new JButton("Decrypt Image");
        fileChooser = new JFileChooser();

        // Customize button sizes
        Dimension buttonSize = new Dimension(200, 50); 
        encryptButton.setPreferredSize(buttonSize);
        decryptButton.setPreferredSize(buttonSize);

        // Center the label text and buttons
        name.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Create a panel for buttons with FlowLayout
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        // Add components to the main panel
        add(Box.createVerticalStrut(20)); // Add space above label
        add(name);
        add(Box.createVerticalStrut(20)); // Add space below label
        add(buttonPanel); // Add button panel
        add(Box.createVerticalStrut(40)); // Add space below buttons

        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    selectedFile = fileChooser.getSelectedFile();
                    try {
                        encryptImage(selectedFile);
                        JOptionPane.showMessageDialog(null, "Image encrypted successfully!");
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        JOptionPane.showMessageDialog(null, "Error encrypting image: " + ex.getMessage());
                    }
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    selectedFile = fileChooser.getSelectedFile();
                    try {
                        decryptImage(selectedFile);
                        JOptionPane.showMessageDialog(null, "Image decrypted successfully!");
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        JOptionPane.showMessageDialog(null, "Error decrypting image: " + ex.getMessage());
                    }
                }
            }
        });

        // Load or generate key pair
        try {
            loadKeyPair();
            if (keyPair == null) {
                generateKeyPair();
                saveKeyPair();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(null, "Error initializing key pair: " + ex.getMessage());
        }
    }

    private void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Key size is 2048 bits
        keyPair = keyPairGenerator.generateKeyPair();
    }

    private void saveKeyPair() throws IOException {
        FileOutputStream fos = new FileOutputStream("keypair.dat");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(keyPair);
        oos.close();
    }

    private void loadKeyPair() throws IOException, ClassNotFoundException {
        File keyPairFile = new File("keypair.dat");
        if (keyPairFile.exists()) {
            FileInputStream fis = new FileInputStream(keyPairFile);
            ObjectInputStream ois = new ObjectInputStream(fis);
            keyPair = (KeyPair) ois.readObject();
            ois.close();
        }
    }

    private void encryptImage(File imageFile) throws Exception {
        FileInputStream fis = new FileInputStream(imageFile);
        byte[] imageData = new byte[(int) imageFile.length()];
        fis.read(imageData);
        fis.close();

        // Generate AES Key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // Key size is 128 bits
        SecretKey aesKey = keyGenerator.generateKey();

        // Encrypt Image with AES
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedImageData = aesCipher.doFinal(imageData);

        // Encrypt AES Key with RSA Public Key
        PublicKey publicKey = keyPair.getPublic();
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Save Encrypted Image
        FileOutputStream fos = new FileOutputStream("encrypted.jpeg");
        fos.write(encryptedImageData);
        fos.close();

        // Save Encrypted AES Key
        FileOutputStream aesKeyFos = new FileOutputStream("enc_aes_key.dat");
        aesKeyFos.write(encryptedAesKey);
        aesKeyFos.close();
    }

    private void decryptImage(File encryptedImageFile) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();

        FileInputStream fis = new FileInputStream(encryptedImageFile);
        byte[] encryptedImageData = new byte[(int) encryptedImageFile.length()];
        fis.read(encryptedImageData);
        fis.close();

        // Decrypt AES Key with RSA Private Key
        FileInputStream aesKeyFis = new FileInputStream("enc_aes_key.dat");
        byte[] encryptedAesKey = new byte[aesKeyFis.available()];
        aesKeyFis.read(encryptedAesKey);
        aesKeyFis.close();

        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);

        // Decrypt Image with AES Key
        SecretKeySpec aesKeySpec = new SecretKeySpec(decryptedAesKey, "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec);
        byte[] decryptedImageData = aesCipher.doFinal(encryptedImageData);

        // Save Decrypted Image
        FileOutputStream fos = new FileOutputStream("decrypted_image.jpg");
        fos.write(decryptedImageData);
        fos.close();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new ImageEncryptionGUI().setVisible(true);
            }
        });
    }
}
