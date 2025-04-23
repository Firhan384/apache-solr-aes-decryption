package com.example.solr;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AESDecryptFunctionTest {

   @Test
    public void testEncryptDecryptConsistency() throws Exception {
        String secretKey = "your_key_here";
        String original = "testing123testing@gmail.com";
        String encrypted = "your_encrypted_string_here"; // Replace with actual encrypted string

        String decrypted = AESDecryptFunction.decrypt(encrypted, secretKey);

        assertEquals(original, decrypted);
    }

   @Test
    void testDecryptInvalidInput() {
        String secretKey = "your_key_here";
        String invalidInput = "!@#^&*()";

        String decrypted = AESDecryptFunction.decrypt(invalidInput, secretKey);

        assertEquals("N/A", decrypted);   
    }

}
