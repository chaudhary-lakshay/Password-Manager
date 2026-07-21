package PasswordManager;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Derives an AES key from a master password via PBKDF2 and performs
 * AES/GCM encryption with a fresh random IV per call.
 */
public class CryptoUtil {
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int KEY_LENGTH_BITS = 256;

    private final SecretKey secretKey;

    public CryptoUtil(char[] masterPassword, byte[] salt) throws Exception {
        this.secretKey = deriveKey(masterPassword, salt);
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    public String encrypt(String data) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        byte[] encrypted = cipher.doFinal(data.getBytes());

        byte[] ivAndCiphertext = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
        System.arraycopy(encrypted, 0, ivAndCiphertext, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(ivAndCiphertext);
    }

    public String decrypt(String encryptedData) throws Exception {
        byte[] ivAndCiphertext = Base64.getDecoder().decode(encryptedData);

        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(ivAndCiphertext, 0, iv, 0, GCM_IV_LENGTH);

        byte[] ciphertext = new byte[ivAndCiphertext.length - GCM_IV_LENGTH];
        System.arraycopy(ivAndCiphertext, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        byte[] decrypted = cipher.doFinal(ciphertext);

        return new String(decrypted);
    }
}