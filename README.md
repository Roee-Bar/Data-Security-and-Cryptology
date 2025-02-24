# Secure SMS Exchange System

## Overview
This project implements a secure messaging system using multiple cryptographic primitives to ensure confidentiality, integrity, and authentication of SMS communications. The system leverages a combination of symmetric and asymmetric encryption techniques to provide a comprehensive security solution.

## Cryptographic Components

### 1. FEAL (Fast Data Encipherment Algorithm)
- A lightweight block cipher used for message encryption
- 64-bit block size with configurable key size (default: 64-bit)
- 8-round Feistel network structure
- PKCS#7 padding for variable-length messages

### 2. CBC (Cipher Block Chaining)
- Block cipher operation mode that chains blocks together
- Uses random initialization vector (IV) to prevent pattern analysis
- Ensures identical plaintext blocks encrypt to different ciphertext

### 3. Elliptic Curve ElGamal
- Asymmetric encryption for secure key exchange
- Implemented using secp256k1 curve parameters
- Enables secure transmission of the symmetric FEAL key
- Based on the elliptic curve discrete logarithm problem

### 4. Schnorr Digital Signatures
- Provides message authentication and non-repudiation
- Based on the same elliptic curve parameters
- Ensures message integrity and sender authentication
- Offers compact signatures with strong security guarantees

## System Architecture

```
┌─────────────────┐                      ┌─────────────────┐
│     SENDER      │                      │    RECIPIENT    │
│                 │                      │                 │
│  ┌──────────┐   │                      │  ┌──────────┐   │
│  │ Original │   │                      │  │Decrypted │   │
│  │   SMS    │   │                      │  │   SMS    │   │
│  └────┬─────┘   │                      │  └────▲─────┘   │
│       │         │                      │       │         │
│  ┌────▼─────┐   │                      │  ┌────┴─────┐   │
│  │  FEAL    │   │                      │  │   FEAL   │   │
│  │  CBC     │◄──┴──FEAL Key────────────┴──►   CBC    │   │
│  └────┬─────┘   │                      │  └────▲─────┘   │
│       │         │                      │       │         │
│  ┌────▼─────┐   │                      │  ┌────┴─────┐   │
│  │EC-ElGamal│   │  Encrypted SMS +     │  │EC-ElGamal│   │
│  │Encryption│───┴─►  Encrypted Key  ───┴──►Decryption│   │
│  └────┬─────┘   │  + Schnorr Signature │  └────▲─────┘   │
│       │         │                      │       │         │
│  ┌────▼─────┐   │                      │  ┌────┴─────┐   │
│  │ Schnorr  │   │                      │  │ Schnorr  │   │
│  │Signature │   │                      │  │  Verify  │   │
│  └──────────┘   │                      │  └──────────┘   │
└─────────────────┘                      └─────────────────┘
```

## Implementation Details

### Message Exchange Flow
1. Sender generates a random symmetric key for FEAL
2. This symmetric key is encrypted using recipient's EC-ElGamal public key
3. The SMS message is encrypted with FEAL in CBC mode using the symmetric key
4. Sender signs the encrypted SMS using Schnorr signature with their private key
5. Recipient verifies signature using sender's Schnorr public key
6. Recipient decrypts the FEAL key using their EC-ElGamal private key
7. Finally, recipient decrypts the SMS using the recovered FEAL key and IV

### Code Structure
- **feal.py**: Implementation of the FEAL block cipher
- **cbc.py**: CBC mode implementation for block ciphers
- **ec_elgamal.py**: Elliptic curve operations and ElGamal encryption scheme
- **schnorr_signature.py**: Schnorr signature implementation
- **main.py**: Demonstration script showing the complete SMS exchange process

## Security Features

- **Confidentiality**: Messages are encrypted using FEAL in CBC mode
- **Key Exchange**: Secure symmetric key delivery through EC-ElGamal encryption
- **Authentication**: Message integrity verification via Schnorr digital signatures
- **Randomization**: IV generation for CBC prevents pattern analysis
- **Padding**: PKCS#7 padding ensures proper block alignment

## Security Considerations

- FEAL is used here for educational purposes; in production, AES would be preferred
- The implementation demonstrates proper cryptographic principles
- Each message exchange uses fresh IVs to prevent replay attacks
- The project implements proper key management practices
- Full end-to-end encryption is provided with no plaintext transmission

## Installation and Usage

### Prerequisites
- Python 3.6+
- No external dependencies required (uses Python standard library only)

### Running the Demo
```bash
python main.py
```

### Sample Output
```
Secure SMS Exchange System Demo
--------------------------------------------------

1. Initializing cryptographic components...
2. Generating keys for Alice and Bob...
   Keys generated successfully
--------------------------------------------------

3. Alice preparing to send SMS to Bob...
   Original message: Hello Bob! This is a secure message from Alice.
   Generated FEAL symmetric key
4. Encrypting FEAL key using EC-ElGamal...
   FEAL key encrypted successfully
5. Encrypting SMS using FEAL in CBC mode...
   SMS encrypted successfully
6. Signing encrypted SMS using Schnorr signature...
   Signature generated successfully
--------------------------------------------------

7. Bob receiving and verifying the message...
   Verifying Schnorr signature...
   Signature verified successfully
8. Decrypting FEAL key using EC-ElGamal...
   FEAL key decrypted successfully
9. Decrypting SMS using FEAL in CBC mode...
   SMS decrypted successfully
--------------------------------------------------

Final Results:
Original SMS: Hello Bob! This is a secure message from Alice.
Decrypted SMS: Hello Bob! This is a secure message from Alice.
Message integrity: ✓
--------------------------------------------------
```

## Customizing the Project
To modify the project for your needs:
- Edit `main.py` to change the SMS message
- Adjust the key size in FEAL constructor (`key_size` parameter)
- Modify CBC implementation for different block ciphers
- Change elliptic curve parameters for different security levels

## Educational Value
This project demonstrates:
- Implementation of symmetric and asymmetric cryptography
- Hybrid encryption systems combining multiple crypto primitives
- Secure key exchange protocols
- Digital signature implementation
- Block cipher modes of operation
- Practical cryptographic programming in Python

## Future Enhancements
Potential improvements include:
- Implementing AES as an alternative to FEAL
- Adding key rotation mechanisms
- Supporting message compression before encryption
- Creating a simple UI for demonstration purposes
- Implementing perfect forward secrecy through ephemeral keys
