package com.example.crypto;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Implements Diffie-Hellman key exchange for secure key establishment
 * between two parties over an insecure channel.
 */
public class KeyExchange {
    
    private static final String ALGORITHM = "DH";
    private static final int KEY_SIZE = 2048; // 2048-bit Diffie-Hellman
    
    /**
     * Generates a Diffie-Hellman key pair.
     * 
     * @return KeyPair containing public and private keys
     * @throws Exception if key generation fails
     */
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }
    
    /**
     * Derives a shared secret using own private key and other party's public key.
     * 
     * @param privateKey Own private key
     * @param publicKey Other party's public key
     * @return Shared secret as byte array
     * @throws Exception if key agreement fails
     */
    public byte[] deriveSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }
    
    /**
     * Converts a public key to Base64 string for transmission.
     * 
     * @param publicKey The public key to encode
     * @return Base64 encoded public key
     */
    public String publicKeyToBase64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
    
    /**
     * Converts a Base64 string back to a public key.
     * 
     * @param base64PublicKey Base64 encoded public key
     * @return PublicKey object
     * @throws Exception if key reconstruction fails
     */
    public PublicKey publicKeyFromBase64(String base64PublicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Demonstrates a complete key exchange between two parties.
     * This method simulates the entire process for educational purposes.
     * 
     * @return Information about the key exchange process
     * @throws Exception if the demonstration fails
     */
    public KeyExchangeResult demonstrateKeyExchange() throws Exception {
        // Party A (Alice) generates her key pair
        KeyPair aliceKeyPair = generateKeyPair();
        
        // Party B (Bob) generates his key pair
        KeyPair bobKeyPair = generateKeyPair();
        
        // Alice derives shared secret using her private key and Bob's public key
        byte[] aliceSharedSecret = deriveSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());
        
        // Bob derives shared secret using his private key and Alice's public key
        byte[] bobSharedSecret = deriveSharedSecret(bobKeyPair.getPrivate(), aliceKeyPair.getPublic());
        
        // Verify that both parties derived the same shared secret
        boolean secretsMatch = MessageDigest.isEqual(aliceSharedSecret, bobSharedSecret);
        
        return new KeyExchangeResult(
            aliceKeyPair,
            bobKeyPair,
            aliceSharedSecret,
            bobSharedSecret,
            secretsMatch
        );
    }
    
    /**
     * Data class to hold the results of a key exchange demonstration.
     */
    public static class KeyExchangeResult {
        private final KeyPair aliceKeyPair;
        private final KeyPair bobKeyPair;
        private final byte[] aliceSharedSecret;
        private final byte[] bobSharedSecret;
        private final boolean secretsMatch;
        
        public KeyExchangeResult(KeyPair aliceKeyPair, KeyPair bobKeyPair, 
                               byte[] aliceSharedSecret, byte[] bobSharedSecret, 
                               boolean secretsMatch) {
            this.aliceKeyPair = aliceKeyPair;
            this.bobKeyPair = bobKeyPair;
            this.aliceSharedSecret = aliceSharedSecret;
            this.bobSharedSecret = bobSharedSecret;
            this.secretsMatch = secretsMatch;
        }
        
        public KeyPair getAliceKeyPair() { return aliceKeyPair; }
        public KeyPair getBobKeyPair() { return bobKeyPair; }
        public byte[] getAliceSharedSecret() { return aliceSharedSecret; }
        public byte[] getBobSharedSecret() { return bobSharedSecret; }
        public boolean areSecretsMatching() { return secretsMatch; }
        
        public String getAlicePublicKeyBase64() {
            return Base64.getEncoder().encodeToString(aliceKeyPair.getPublic().getEncoded());
        }
        
        public String getBobPublicKeyBase64() {
            return Base64.getEncoder().encodeToString(bobKeyPair.getPublic().getEncoded());
        }
        
        public String getSharedSecretHex() {
            if (!secretsMatch) return "N/A - Secrets don't match";
            
            StringBuilder hex = new StringBuilder();
            for (byte b : aliceSharedSecret) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        }
    }
}
