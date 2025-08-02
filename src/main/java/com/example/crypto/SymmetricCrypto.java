package com.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Handles symmetric encryption using AES-256 in GCM mode with proper key derivation.
 * Uses SHA-256 to derive encryption keys from user passphrases.
 */
public class SymmetricCrypto {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 16; // 128 bits
    private static final int KEY_LENGTH = 32; // 256 bits
    
    /**
     * Encrypts a message using AES-256-GCM with a passphrase-derived key.
     * 
     * @param message The plaintext message to encrypt
     * @param passphrase The passphrase used to derive the encryption key
     * @return Base64 encoded string containing IV + encrypted data
     * @throws Exception if encryption fails
     */
    public String encrypt(String message, String passphrase) throws Exception {
        // Derive key from passphrase using SHA-256
        SecretKey key = deriveKeyFromPassphrase(passphrase);
        
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        // Initialize cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        
        // Encrypt the message
        byte[] encryptedData = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        
        // Combine IV and encrypted data
        byte[] encryptedWithIv = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encryptedData, 0, encryptedWithIv, iv.length, encryptedData.length);
        
        // Return Base64 encoded result
        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }
    
    /**
     * Decrypts a message using AES-256-GCM with a passphrase-derived key.
     * 
     * @param encryptedMessage Base64 encoded string containing IV + encrypted data
     * @param passphrase The passphrase used to derive the decryption key
     * @return The decrypted plaintext message
     * @throws Exception if decryption fails
     */
    public String decrypt(String encryptedMessage, String passphrase) throws Exception {
        // Decode from Base64
        byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedMessage);
        
        // Extract IV and encrypted data
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encryptedData = new byte[encryptedWithIv.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedWithIv, 0, iv, 0, iv.length);
        System.arraycopy(encryptedWithIv, iv.length, encryptedData, 0, encryptedData.length);
        
        // Derive key from passphrase
        SecretKey key = deriveKeyFromPassphrase(passphrase);
        
        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        
        // Decrypt the data
        byte[] decryptedData = cipher.doFinal(encryptedData);
        
        return new String(decryptedData, StandardCharsets.UTF_8);
    }
    
    /**
     * Encrypts a message using a provided key (used for key exchange scenarios).
     * 
     * @param message The plaintext message to encrypt
     * @param keyBytes The encryption key as byte array
     * @return Base64 encoded string containing IV + encrypted data
     * @throws Exception if encryption fails
     */
    public String encryptWithKey(String message, byte[] keyBytes) throws Exception {
        // Use first 32 bytes of the shared secret as AES key
        byte[] aesKeyBytes = new byte[KEY_LENGTH];
        System.arraycopy(keyBytes, 0, aesKeyBytes, 0, Math.min(keyBytes.length, KEY_LENGTH));
        
        SecretKey key = new SecretKeySpec(aesKeyBytes, ALGORITHM);
        
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        // Initialize cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        
        // Encrypt the message
        byte[] encryptedData = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        
        // Combine IV and encrypted data
        byte[] encryptedWithIv = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encryptedData, 0, encryptedWithIv, iv.length, encryptedData.length);
        
        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }
    
    /**
     * Decrypts a message using a provided key (used for key exchange scenarios).
     * 
     * @param encryptedMessage Base64 encoded string containing IV + encrypted data
     * @param keyBytes The decryption key as byte array
     * @return The decrypted plaintext message
     * @throws Exception if decryption fails
     */
    public String decryptWithKey(String encryptedMessage, byte[] keyBytes) throws Exception {
        // Decode from Base64
        byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedMessage);
        
        // Extract IV and encrypted data
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encryptedData = new byte[encryptedWithIv.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedWithIv, 0, iv, 0, iv.length);
        System.arraycopy(encryptedWithIv, iv.length, encryptedData, 0, encryptedData.length);
        
        // Use first 32 bytes of the shared secret as AES key
        byte[] aesKeyBytes = new byte[KEY_LENGTH];
        System.arraycopy(keyBytes, 0, aesKeyBytes, 0, Math.min(keyBytes.length, KEY_LENGTH));
        
        SecretKey key = new SecretKeySpec(aesKeyBytes, ALGORITHM);
        
        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        
        // Decrypt the data
        byte[] decryptedData = cipher.doFinal(encryptedData);
        
        return new String(decryptedData, StandardCharsets.UTF_8);
    }
    
    /**
     * Derives an AES key from a passphrase using SHA-256.
     * 
     * @param passphrase The user's passphrase
     * @return SecretKey for AES encryption
     * @throws Exception if key derivation fails
     */
    private SecretKey deriveKeyFromPassphrase(String passphrase) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(passphrase.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(hash, ALGORITHM);
    }
    
    /**
     * Generates a random AES key (for demonstration purposes).
     * 
     * @return A random AES-256 key
     * @throws Exception if key generation fails
     */
    public SecretKey generateRandomKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256); // AES-256
        return keyGenerator.generateKey();
    }
}
