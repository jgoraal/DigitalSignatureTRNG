# Digital Signature Application

This application provides a graphical user interface (GUI) for generating RSA key pairs and signing/verifying messages and files using digital signatures. The application uses a True Random Number Generator (TRNG) based on image data to generate high-entropy random bits, which are then used for cryptographic operations.

## Features

- **Generate TRNG Bits**: Uses images to generate random bits for cryptographic operations.
- **Generate RSA Keys**: Create RSA key pairs using the generated random bits.
- **Sign Messages**: Sign text messages with the generated private key.
- **Verify Messages**: Verify the signatures of text messages with the generated public key.
- **Sign Files**: Sign files with the generated private key.
- **Verify Files**: Verify the signatures of files with the generated public key.

## Requirements

- Python 3.x
- `tkinter` library for the GUI
- `pycryptodome` library for cryptographic operations
- `opencv-python` library for image processing
- `numpy` library for numerical operations

## Installation

1. Install the required libraries:
    ```bash
    pip install pycryptodome opencv-python numpy
    ```

2. Download or clone the repository:
    ```bash
    git clone [https://github.com/yourusername/digital-signature-app.git](https://github.com/jgoraal/DigitalSignatureTRNG.git)
    cd digital-signature-app
    ```

3. Run the application:
    ```bash
    python RSA.py
    ```

## Usage

### Generate TRNG Bits

1. Click the "1. Generate TRNG Bits" button.
2. Select a folder containing images (PNG, JPG, JPEG) to be used for generating random bits.
3. The application will process the images and generate random bits.

### Generate RSA Keys

1. Click the "2. Generate RSA Keys" button.
2. Select a directory to save the generated keys.
3. The application will generate an RSA key pair and save the private key as `private.pem` and the public key as `public.pem`.

### Sign Messages

1. Select "Message" as the operation type.
2. Enter the message to be signed in the provided text entry field.
3. Click the "3. Sign Message" button to sign the message.
4. The application will generate and display the signature.

### Verify Messages

1. Select "Message" as the operation type.
2. Enter the message to be verified in the provided text entry field.
3. Click the "4. Verify Message" button to verify the signature.
4. The application will display whether the signature is valid or invalid.

### Sign Files

1. Select "File" as the operation type.
2. Click the "3. Sign File" button.
3. Select the file to be signed.
4. The application will generate and save the file signature.

### Verify Files

1. Select "File" as the operation type.
2. Click the "4. Select File to Verify" button and select the file to be verified.
3. Click the "5. Select Key" button and select the public key file.
4. Click the "6. Verify File" button to verify the file signature.
5. The application will display whether the file signature is valid or invalid.

## GUI Overview

The GUI consists of the following components:

- **Generate TRNG Bits**: Button to generate random bits from images.
- **Generate RSA Keys**: Button to generate RSA key pairs.
- **Message/File Radio Buttons**: Select whether to sign/verify a message or a file.
- **Sign Message**: Button to sign a text message.
- **Verify Message**: Button to verify a text message signature.
- **Sign File**: Button to sign a file.
- **Select File to Verify**: Button to select a file for verification.
- **Select Key**: Button to select a key file for verification.
- **Verify File**: Button to verify a file signature.
- **Status Label**: Displays the status of operations.

## Notes

- Ensure that the images used for generating TRNG bits are of good quality and contain a variety of pixel values for better entropy.
- Keep the private key secure and do not share it with others.
- This application is intended for educational purposes and may not be suitable for production use without further security enhancements.

---
