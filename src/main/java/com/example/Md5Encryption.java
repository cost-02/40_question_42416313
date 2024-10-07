package com.example;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class Md5Encryption {
    private static final String CHARSET_UTF_8 = "utf-8";
    private static final String SECRET_KEY_ALGORITHM = "DESede";
    private static final String TRANSFORMATION_PADDING = "DESede/CBC/PKCS5Padding";

    /* Encryption Method */
    public String encrypt(String message) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("md5");
        final byte[] digestOfPassword = md.digest("HG58YZ3CR9".getBytes(CHARSET_UTF_8));

        final byte[] keyBytes = new byte[24];
        System.arraycopy(digestOfPassword, 0, keyBytes, 0, 16);
        System.arraycopy(digestOfPassword, 0, keyBytes, 16, 8);

        final SecretKey key = new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM);
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]); // utilizza IV zero per semplicità
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        final byte[] plainTextBytes = message.getBytes(CHARSET_UTF_8);
        final byte[] cipherText = cipher.doFinal(plainTextBytes);
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /* Decryption Method */
    public String decrypt(String encryptedText) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("md5");
        final byte[] digestOfPassword = md.digest("HG58YZ3CR9".getBytes(CHARSET_UTF_8));

        final byte[] keyBytes = new byte[24];
        System.arraycopy(digestOfPassword, 0, keyBytes, 0, 16);
        System.arraycopy(digestOfPassword, 0, keyBytes, 16, 8);

        final SecretKey key = new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM);
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher decipher = Cipher.getInstance(TRANSFORMATION_PADDING);
        decipher.init(Cipher.DECRYPT_MODE, key, iv);

        final byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        final byte[] plainText = decipher.doFinal(encryptedBytes);
        return new String(plainText, CHARSET_UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String text = "TEST STRING TO ENCRYPT";
        Md5Encryption encryptor = new Md5Encryption();
        String codedtext = encryptor.encrypt(text);
        String decodedtext = encryptor.decrypt(codedtext);

        System.out.println("Encrypted: " + codedtext);
        System.out.println("Decrypted: " + decodedtext);
    }
}
