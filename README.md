# 🔐 Basic Cryptography Demo Application
# TEST-DEMO-COMMIT##kk
A comprehensive Java application demonstrating various cryptographic concepts including symmetric encryption, key derivation, and Diffie-Hellman key exchange.

## 🌟 Features

### 1. 📝 Write and Encrypt Notes
- Enter any message (e.g., "Wi-Fi password is: 12345")
- Use a passphrase to encrypt the message
- Get a Base64-encoded encrypted message to share

### 2. 🔒 Symmetric Encryption (AES-256-GCM)
- Uses AES-256 in GCM (Galois/Counter Mode) for authenticated encryption
- Derives encryption keys from passphrases using SHA-256
- Includes initialization vectors (IV) for security
- Provides authentication to detect tampering

### 3. 🔓 Decrypt Notes
- Paste an encrypted message
- Enter the correct passphrase
- Retrieve the original message

### 4. 🤝 Diffie-Hellman Key Exchange
- Simulates secure key exchange between two parties (Alice and Bob)
- Generates public/private key pairs
- Derives shared secrets without transmitting private keys
- Demonstrates end-to-end encryption using the shared secret

### 5. 🛡️ Security Demonstrations
- Password strength analysis
- Secure hashing (SHA-256, SHA-512)
- Timing attack resistance
- Secure random number generation

## 🚀 Quick Start

### Prerequisites
- Java 8 or higher
- No external dependencies required (uses built-in Java cryptography)

### Compilation and Execution

1. **Compile the application:**
```bash
javac -d . src/main/java/com/example/crypto/*.java
```

2. **Run the interactive application:**
```bash
java com.example.crypto.CryptographyApp
```

3. **Run the automated test suite:**
```bash
java com.example.crypto.CryptographyTest
```

## 📋 Usage Examples

### Interactive Mode

When you run `CryptographyApp`, you'll see a menu:

```
🔐 Basic Cryptography Demo Application
=====================================

📋 Choose an option:
1. 🔒 Encrypt a note
2. 🔓 Decrypt a note
3. 🤝 Demonstrate Key Exchange (Diffie-Hellman)
4. 🚪 Exit
```

### Example Workflow

1. **Encrypt a message:**
   - Choose option 1
   - Enter: "Meeting password is: secret123"
   - Enter passphrase: "myPassphrase"
   - Get encrypted message: `AbCdEf123...` (Base64 encoded)

2. **Share the encrypted message:**
   - Send the Base64 string to the recipient
   - Share the passphrase through a separate secure channel

3. **Decrypt the message:**
   - Recipient chooses option 2
   - Pastes the encrypted message
   - Enters the same passphrase
   - Gets the original message back

### Key Exchange Demo

The key exchange demonstration shows:
- Alice and Bob generate key pairs
- They exchange public keys
- Both derive the same shared secret
- They use the shared secret for encryption

## 🔒 Security Features

### Encryption Details
- **Algorithm:** AES-256-GCM (Advanced Encryption Standard with Galois/Counter Mode)
- **Key Size:** 256 bits
- **Authentication:** Built-in with GCM mode
- **IV:** 96-bit random initialization vector per encryption
- **Key Derivation:** SHA-256 hash of passphrase

### Key Exchange Details
- **Algorithm:** Diffie-Hellman
- **Key Size:** 2048 bits
- **Security:** Provides perfect forward secrecy

### Best Practices Implemented
- ✅ Cryptographically secure random number generation
- ✅ Constant-time comparisons to prevent timing attacks
- ✅ Proper IV/nonce handling
- ✅ Authenticated encryption (GCM mode)
- ✅ No hardcoded keys or secrets

## 📁 Project Structure

```
src/main/java/com/example/crypto/
├── CryptographyApp.java      # Main interactive application
├── SymmetricCrypto.java      # AES encryption/decryption
├── KeyExchange.java          # Diffie-Hellman implementation
├── CryptographyDemo.java     # Security concept demonstrations
└── CryptographyTest.java     # Automated test suite
```

## 🎓 Educational Value

This application demonstrates:

1. **Symmetric Cryptography:** How AES works with proper key derivation
2. **Key Exchange:** How two parties can establish a shared secret
3. **Security Principles:** Timing attacks, password strength, secure random generation
4. **Real-world Applications:** Secure messaging, password managers, VPN protocols

## ⚠️ Important Security Notes

### For Educational Use Only
This application is designed for learning cryptographic concepts. For production use:

- Use established libraries like Bouncy Castle
- Implement proper key derivation functions (PBKDF2, scrypt, Argon2)
- Add salt to password hashing
- Use certificate-based authentication for key exchange
- Implement proper error handling and logging

### Common Pitfalls Avoided
- ❌ ECB mode (uses GCM instead)
- ❌ Fixed IVs (generates random IV each time)
- ❌ Unauthenticated encryption (GCM provides authentication)
- ❌ Timing attacks (constant-time comparisons where needed)

## 🛠️ Extending the Application

You can extend this application by:

1. Adding RSA encryption for asymmetric cryptography
2. Implementing digital signatures
3. Adding file encryption capabilities
4. Creating a simple chat application
5. Adding elliptic curve cryptography (ECC)

## 📚 Further Reading

- [Java Cryptography Architecture (JCA)](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

## 📄 License

This project is for educational purposes. Feel free to use and modify for learning about cryptography.
