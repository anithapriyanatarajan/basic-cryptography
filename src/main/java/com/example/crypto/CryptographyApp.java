package com.example.crypto;

import java.util.Scanner;

/**
 * Main application class for demonstrating various cryptographic operations
 * including symmetric encryption, key derivation, and key exchange.
 */
public class CryptographyApp {
    
    private static final Scanner scanner = new Scanner(System.in);
    private static final SymmetricCrypto symmetricCrypto = new SymmetricCrypto();
    private static final KeyExchange keyExchange = new KeyExchange();
    
    public static void main(String[] args) {
        System.out.println("🔐 Basic Cryptography Demo Application");
        System.out.println("=====================================");
        
        while (true) {
            displayMenu();
            int choice = getChoice();
            
            try {
                switch (choice) {
                    case 1:
                        encryptNote();
                        break;
                    case 2:
                        decryptNote();
                        break;
                    case 3:
                        demonstrateKeyExchange();
                        break;
                    case 4:
                        System.out.println("👋 Goodbye!");
                        return;
                    default:
                        System.out.println("❌ Invalid choice. Please try again.");
                }
            } catch (Exception e) {
                System.out.println("❌ Error: " + e.getMessage());
            }
            
            System.out.println("\nPress Enter to continue...");
            scanner.nextLine();
        }
    }
    
    private static void displayMenu() {
        System.out.println("\n📋 Choose an option:");
        System.out.println("1. 🔒 Encrypt a note");
        System.out.println("2. 🔓 Decrypt a note");
        System.out.println("3. 🤝 Demonstrate Key Exchange (Diffie-Hellman)");
        System.out.println("4. 🚪 Exit");
        System.out.print("Enter your choice (1-4): ");
    }
    
    private static int getChoice() {
        try {
            int choice = Integer.parseInt(scanner.nextLine().trim());
            return choice;
        } catch (NumberFormatException e) {
            return -1;
        }
    }
    
    private static void encryptNote() {
        System.out.println("\n🔒 ENCRYPT A NOTE");
        System.out.println("================");
        
        System.out.print("📝 Enter your note: ");
        String note = scanner.nextLine();
        
        System.out.print("🔑 Enter passphrase: ");
        String passphrase = scanner.nextLine();
        
        try {
            String encryptedNote = symmetricCrypto.encrypt(note, passphrase);
            System.out.println("\n✅ Note encrypted successfully!");
            System.out.println("📤 Share this encrypted message:");
            System.out.println("┌" + "─".repeat(50) + "┐");
            System.out.println("│ " + encryptedNote);
            System.out.println("└" + "─".repeat(50) + "┘");
            System.out.println("\n💡 The recipient will need the same passphrase to decrypt this message.");
        } catch (Exception e) {
            System.out.println("❌ Encryption failed: " + e.getMessage());
        }
    }
    
    private static void decryptNote() {
        System.out.println("\n🔓 DECRYPT A NOTE");
        System.out.println("================");
        
        System.out.print("📥 Enter encrypted message: ");
        String encryptedMessage = scanner.nextLine();
        
        System.out.print("🔑 Enter passphrase: ");
        String passphrase = scanner.nextLine();
        
        try {
            String decryptedNote = symmetricCrypto.decrypt(encryptedMessage, passphrase);
            System.out.println("\n✅ Note decrypted successfully!");
            System.out.println("📝 Original message: " + decryptedNote);
        } catch (Exception e) {
            System.out.println("❌ Decryption failed: " + e.getMessage());
            System.out.println("💡 Make sure you entered the correct passphrase and encrypted message.");
        }
    }
    
    private static void demonstrateKeyExchange() {
        System.out.println("\n🤝 DIFFIE-HELLMAN KEY EXCHANGE DEMO");
        System.out.println("===================================");
        
        try {
            // Simulate two users
            System.out.println("👤 Simulating Alice and Bob...");
            
            // Generate key pairs for both users
            var aliceKeyPair = keyExchange.generateKeyPair();
            var bobKeyPair = keyExchange.generateKeyPair();
            
            System.out.println("\n1️⃣ Alice generates her public/private key pair");
            System.out.println("   Public key: " + keyExchange.publicKeyToBase64(aliceKeyPair.getPublic()));
            
            System.out.println("\n2️⃣ Bob generates his public/private key pair");
            System.out.println("   Public key: " + keyExchange.publicKeyToBase64(bobKeyPair.getPublic()));
            
            // Exchange public keys and derive shared secrets
            byte[] aliceSharedSecret = keyExchange.deriveSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());
            byte[] bobSharedSecret = keyExchange.deriveSharedSecret(bobKeyPair.getPrivate(), aliceKeyPair.getPublic());
            
            System.out.println("\n3️⃣ Both derive the same shared secret from exchanged public keys");
            System.out.println("   Alice's shared secret: " + bytesToHex(aliceSharedSecret));
            System.out.println("   Bob's shared secret:   " + bytesToHex(bobSharedSecret));
            
            boolean secretsMatch = java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret);
            System.out.println("   Secrets match: " + (secretsMatch ? "✅ YES" : "❌ NO"));
            
            if (secretsMatch) {
                // Demonstrate encryption with shared secret
                System.out.println("\n4️⃣ Now they can use the shared secret to encrypt messages!");
                System.out.print("📝 Enter a message for Alice to send to Bob: ");
                String message = scanner.nextLine();
                
                String encryptedMessage = symmetricCrypto.encryptWithKey(message, aliceSharedSecret);
                System.out.println("🔒 Alice encrypts: " + encryptedMessage);
                
                String decryptedMessage = symmetricCrypto.decryptWithKey(encryptedMessage, bobSharedSecret);
                System.out.println("🔓 Bob decrypts: " + decryptedMessage);
            }
            
        } catch (Exception e) {
            System.out.println("❌ Key exchange demo failed: " + e.getMessage());
        }
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
