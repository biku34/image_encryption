# Image Encryption GUI

## Overview

This Java application provides a GUI for encrypting and decrypting images using RSA and AES encryption algorithms.

## Features

- **Encrypt Image**: Encrypts selected image files using AES. The AES key is encrypted with RSA.
- **Decrypt Image**: Decrypts encrypted image files using RSA-decrypted AES key.
- **Key Management**: Generates and saves RSA key pairs if not already present.

## Requirements

- Java Development Kit (JDK) 8 or higher

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/ImageEncryptionGUI.git
   cd ImageEncryptionGUI
   ```

2. **Compile the Java code**:
   ```bash
   javac ImageEncryptionGUI.java
   ```

3. **Run the application**:
   ```bash
   java ImageEncryptionGUI
   ```

## Usage

1. **Launch the Application**: Run the `ImageEncryptionGUI` class.
2. **Encrypt an Image**: Click "Encrypt Image" and select an image. The encrypted image is saved as `encrypted.jpeg`.
3. **Decrypt an Image**: Click "Decrypt Image" and select the encrypted file. The decrypted image is saved as `decrypted_image.jpg`.

## File Outputs

- **encrypted.jpeg**: Encrypted image file.
- **enc_aes_key.dat**: Encrypted AES key.
- **decrypted_image.jpg**: Decrypted image file.
- **keypair.dat**: RSA key pair file.

## License

This project is licensed under the MIT License.

For issues or contributions, visit the [GitHub repository](https://github.com/yourusername/ImageEncryptionGUI).
