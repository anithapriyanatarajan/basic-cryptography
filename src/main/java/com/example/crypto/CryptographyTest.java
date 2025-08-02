package com.example.crypto;

/**
 * Test class that demonstrates all cryptographic functionality
 * without requiring user input. Useful for automated testing
 * and educational purposes.
 */
public class CryptographyTest {
    
    public static void main(String[] args) {
        System.out.println("🧪 CRYPTOGRAPHY TEST SUITE");
        System.out.println("===========================");
        
        try {
            testSymmetricEncryption();
            testKeyExchange();
            testHashingDemo();
            testPasswordSecurity();
            testTimingAttacks();
            
            System.out.println("\n✅ All tests completed successfully!");
            
        } catch (Exception e) {
            System.err.println("❌ Test failed: " + e.getMessage());
            System.err.println("Error details: " + e.getClass().getSimpleName());
        }
    }
    
    private static void testSymmetricEncryption() throws Exception {
        System.out.println("\n🔐 Testing Symmetric Encryption");
        System.out.println("===============================");
        
        SymmetricCrypto crypto = new SymmetricCrypto();
        String originalMessage = "Wi-Fi password is: 12345";
        String passphrase = "mySecretPassphrase";
        
        System.out.println("Original message: " + originalMessage);
        System.out.println("Passphrase: " + passphrase);
        
        // Encrypt
        String encrypted = crypto.encrypt(originalMessage, passphrase);
        System.out.println("Encrypted: " + encrypted);
        
        // Decrypt
        String decrypted = crypto.decrypt(encrypted, passphrase);
        System.out.println("Decrypted: " + decrypted);
        
        // Verify
        boolean success = originalMessage.equals(decrypted);
        System.out.println("Encryption/Decryption successful: " + (success ? "✅" : "❌"));
        
        // Test with wrong passphrase
        try {
            crypto.decrypt(encrypted, "wrongPassphrase");
            System.out.println("❌ Wrong passphrase should have failed!");
        } catch (Exception e) {
            System.out.println("✅ Correctly rejected wrong passphrase");
        }
    }
    
    private static void testKeyExchange() throws Exception {
        System.out.println("\n🤝 Testing Diffie-Hellman Key Exchange");
        System.out.println("======================================");
        
        KeyExchange keyExchange = new KeyExchange();
        SymmetricCrypto crypto = new SymmetricCrypto();
        
        // Demonstrate key exchange
        var result = keyExchange.demonstrateKeyExchange();
        
        System.out.println("Alice's public key: " + result.getAlicePublicKeyBase64().substring(0, 50) + "...");
        System.out.println("Bob's public key: " + result.getBobPublicKeyBase64().substring(0, 50) + "...");
        System.out.println("Shared secrets match: " + (result.areSecretsMatching() ? "✅" : "❌"));
        System.out.println("Shared secret (hex): " + result.getSharedSecretHex().substring(0, 32) + "...");
        
        // Test encryption with shared secret
        if (result.areSecretsMatching()) {
            String message = "Secret message using shared key!";
            String encrypted = crypto.encryptWithKey(message, result.getAliceSharedSecret());
            String decrypted = crypto.decryptWithKey(encrypted, result.getBobSharedSecret());
            
            System.out.println("Original: " + message);
            System.out.println("Encrypted: " + encrypted);
            System.out.println("Decrypted: " + decrypted);
            System.out.println("Key exchange encryption successful: " + 
                             (message.equals(decrypted) ? "✅" : "❌"));
        }
    }
    
    private static void testHashingDemo() throws Exception {
        CryptographyDemo.demonstrateHashing("Hello, World!");
    }
    
    private static void testPasswordSecurity() {
        CryptographyDemo.demonstratePasswordSecurity("P@ssw0rd123!");
        CryptographyDemo.demonstratePasswordSecurity("password");
    }
    
    private static void testTimingAttacks() {
        CryptographyDemo.demonstrateTimingAttacks("secretkey123", "secretkey124");
        CryptographyDemo.demonstrateTimingAttacks("secretkey123", "wrongguess");
    }
}
