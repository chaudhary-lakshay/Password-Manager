package PasswordManager;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Derives an AES key from a master password via PBKDF2 and performs
 * AES/GCM encryption with a fresh random IV per call.
 */
public class CryptoUtil {
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    // OWASP currently recommends 600,000 iterations for PBKDF2-HMAC-SHA256.
    // This number is expected to keep rising as hardware gets faster — that's
    // the whole point of an iteration count, not a one-time tuning.
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int KEY_LENGTH_BITS = 256;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SecretKey secretKey;

    public CryptoUtil(char[] masterPassword, byte[] salt) throws Exception {
        this.secretKey = deriveKey(masterPassword, salt);
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
            Arrays.fill(password, '\0');
        }
    }

    public String encrypt(String data) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        byte[] ivAndCiphertext = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
        System.arraycopy(encrypted, 0, ivAndCiphertext, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(ivAndCiphertext);
    }

    public String decrypt(String encryptedData) throws Exception {
        byte[] ivAndCiphertext;
        try {
            ivAndCiphertext = Base64.getDecoder().decode(encryptedData);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("encryptedData is not valid Base64", e);
        }

        if (ivAndCiphertext.length < GCM_IV_LENGTH) {
            throw new IllegalArgumentException(
                    "encryptedData is too short to contain a " + GCM_IV_LENGTH + "-byte IV");
        }

        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(ivAndCiphertext, 0, iv, 0, GCM_IV_LENGTH);

        byte[] ciphertext = new byte[ivAndCiphertext.length - GCM_IV_LENGTH];
        System.arraycopy(ivAndCiphertext, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        byte[] decrypted = cipher.doFinal(ciphertext);

        return new String(decrypted, StandardCharsets.UTF_8);
    }
}