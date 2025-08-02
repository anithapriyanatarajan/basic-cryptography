package com.example.crypto;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Demonstrates various cryptographic concepts and best practices.
 * This class provides educational examples of hashing, random number generation,
 * and secure coding practices.
 */
public class CryptographyDemo {
    
    /**
     * Demonstrates different hash functions and their properties.
     * 
     * @param input The input string to hash
     * @throws Exception if hashing fails
     */
    public static void demonstrateHashing(String input) throws Exception {
        System.out.println("\n🔍 HASHING DEMONSTRATION");
        System.out.println("========================");
        System.out.println("Input: \"" + input + "\"");
        
        // SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] sha256Hash = sha256.digest(input.getBytes());
        System.out.println("SHA-256: " + bytesToHex(sha256Hash));
        
        // SHA-512
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] sha512Hash = sha512.digest(input.getBytes());
        System.out.println("SHA-512: " + bytesToHex(sha512Hash));
        
        // Demonstrate deterministic property
        byte[] sha256Hash2 = MessageDigest.getInstance("SHA-256").digest(input.getBytes());
        System.out.println("Same input produces same hash: " + 
                         MessageDigest.isEqual(sha256Hash, sha256Hash2));
    }
    
    /**
     * Demonstrates secure random number generation.
     */
    public static void demonstrateSecureRandom() {
        System.out.println("\n🎲 SECURE RANDOM DEMONSTRATION");
        System.out.println("==============================");
        
        SecureRandom secureRandom = new SecureRandom();
        
        // Generate random bytes
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        System.out.println("Random bytes (hex): " + bytesToHex(randomBytes));
        
        // Generate random integers
        System.out.println("Random integers:");
        for (int i = 0; i < 5; i++) {
            System.out.println("  " + secureRandom.nextInt(1000));
        }
        
        // Generate random Base64 token
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        System.out.println("Random token: " + token);
    }
    
    /**
     * Demonstrates password security concepts.
     * 
     * @param password The password to analyze
     */
    public static void demonstratePasswordSecurity(String password) {
        System.out.println("\n🔐 PASSWORD SECURITY ANALYSIS");
        System.out.println("=============================");
        System.out.println("Password: \"" + password + "\"");
        
        // Basic strength analysis
        int score = 0;
        if (password.length() >= 8) score++;
        if (password.matches(".*[a-z].*")) score++;
        if (password.matches(".*[A-Z].*")) score++;
        if (password.matches(".*[0-9].*")) score++;
        if (password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) score++;
        
        System.out.println("Length: " + password.length() + " characters");
        System.out.println("Contains lowercase: " + password.matches(".*[a-z].*"));
        System.out.println("Contains uppercase: " + password.matches(".*[A-Z].*"));
        System.out.println("Contains digits: " + password.matches(".*[0-9].*"));
        System.out.println("Contains special chars: " + 
                         password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*"));
        
        String strength;
        switch (score) {
            case 0: case 1: strength = "❌ Very Weak"; break;
            case 2: strength = "🔴 Weak"; break;
            case 3: strength = "🟡 Medium"; break;
            case 4: strength = "🟢 Strong"; break;
            case 5: strength = "✅ Very Strong"; break;
            default: strength = "Unknown"; break;
        }
        
        System.out.println("Strength: " + strength);
        
        // Show hash (simulating storage)
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes());
            System.out.println("Hash for storage: " + bytesToHex(hash));
            System.out.println("💡 In real applications, use bcrypt, scrypt, or Argon2 instead of SHA-256!");
        } catch (Exception e) {
            System.out.println("Error computing hash: " + e.getMessage());
        }
    }
    
    /**
     * Demonstrates timing attack resistance concepts.
     * 
     * @param secret The secret value
     * @param guess The guessed value
     */
    public static void demonstrateTimingAttacks(String secret, String guess) {
        System.out.println("\n⏱️ TIMING ATTACK DEMONSTRATION");
        System.out.println("==============================");
        
        // Vulnerable comparison (stops at first mismatch)
        long startTime = System.nanoTime();
        boolean vulnerableResult = vulnerableEquals(secret, guess);
        long vulnerableTime = System.nanoTime() - startTime;
        
        // Secure comparison (constant time)
        startTime = System.nanoTime();
        boolean secureResult = secureEquals(secret, guess);
        long secureTime = System.nanoTime() - startTime;
        
        System.out.println("Secret:  \"" + secret + "\"");
        System.out.println("Guess:   \"" + guess + "\"");
        System.out.println("Vulnerable comparison time: " + vulnerableTime + " ns");
        System.out.println("Secure comparison time:     " + secureTime + " ns");
        System.out.println("Results match: " + (vulnerableResult == secureResult));
        System.out.println("💡 Secure comparison takes consistent time regardless of input!");
    }
    
    /**
     * Vulnerable string comparison that stops at first mismatch.
     */
    private static boolean vulnerableEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        for (int i = 0; i < a.length(); i++) {
            if (a.charAt(i) != b.charAt(i)) return false;
        }
        return true;
    }
    
    /**
     * Secure string comparison that always checks all characters.
     */
    private static boolean secureEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        boolean result = true;
        for (int i = 0; i < a.length(); i++) {
            result &= (a.charAt(i) == b.charAt(i));
        }
        return result;
    }
    
    /**
     * Converts byte array to hexadecimal string.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
