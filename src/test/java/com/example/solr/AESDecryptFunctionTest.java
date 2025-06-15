package com.example.solr;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AESDecryptFunctionTest {

   @Test
    public void testDecryptValid() {
        // Contoh plaintext dan key
        String key = "1234567890123456";
        String plaintext = "HelloWorld";

        // Enkripsi manual (gunakan kode yang sama dengan Solr)
        String encryptedBase64Url = encryptToBase64Url(plaintext, key);

        // Dekripsi
        String decrypted = AESDecryptFunction.decrypt(encryptedBase64Url, key);
        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testDecryptInvalidBase64() {
        String decrypted = AESDecryptFunction.decrypt("!@#$%^", "1234567890123456");
        assertEquals(decrypted, "N/A"); // Karena kode decrypt mengembalikan null pada error
    }

    @Test
    public void testDecryptNullInput() {
        String decrypted = AESDecryptFunction.decrypt(null, "1234567890123456");
        assertEquals(decrypted, "N/A");
    }

    // Helper method sama persis dengan logic di function
    private static String encryptToBase64Url(String plaintext, String secretKey) {
        try {
            byte[] iv = new byte[]{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 5};
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CFB/NoPadding");
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(secretKey.getBytes(java.nio.charset.StandardCharsets.UTF_8), "AES");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, new javax.crypto.spec.IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String b64 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(encrypted);
            return b64;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
