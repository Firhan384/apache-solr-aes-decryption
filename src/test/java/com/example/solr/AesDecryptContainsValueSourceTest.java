package com.example.solr;
import org.apache.lucene.queries.function.FunctionValues;
import org.apache.lucene.queries.function.ValueSource;
import org.apache.lucene.index.LeafReaderContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collections;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class AesDecryptContainsValueSourceTest {

    @Mock
    private ValueSource mockSource;
    @Mock
    private LeafReaderContext mockReaderContext;
    @Mock
    private FunctionValues mockFieldValues;

    private static final String SECRET_KEY = "abcdefghijklmnop"; // 16-byte key for AES
    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final byte[] IV = new byte[]{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 5};

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    // Helper method to encrypt data for testing
    private String encrypt(String plainText, String secretKey) throws Exception {
        Key key = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return encodeBase64Url(encrypted);
    }

    // Helper method for base64url encode (mirroring the decode in original class)
    private String encodeBase64Url(byte[] data) {
        String base64 = Base64.encodeBase64String(data);
        return base64.replace('+', '-').replace('/', '_').replace("=", "");
    }

    @Test
    void testIntVal_containsPattern() throws Exception {
        String originalValue = "hello world";
        String encryptedValue = encrypt(originalValue, SECRET_KEY);
        String pattern = "world";

        when(mockSource.getValues(any(Map.class), eq(mockReaderContext))).thenReturn(mockFieldValues);
        when(mockFieldValues.strVal(0)).thenReturn(encryptedValue);

        AESDecryptFunction.AesDecryptContainsValueSource aesDecryptContainsValueSource =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource, SECRET_KEY, pattern);

        FunctionValues values = aesDecryptContainsValueSource.getValues(Collections.emptyMap(), mockReaderContext);

        assertEquals(1, values.intVal(0), "Should return 1 when decrypted value contains the pattern");
    }

    @Test
    void testIntVal_doesNotContainPattern() throws Exception {
        String originalValue = "hello universe";
        String encryptedValue = encrypt(originalValue, SECRET_KEY);
        String pattern = "world";

        when(mockSource.getValues(any(Map.class), eq(mockReaderContext))).thenReturn(mockFieldValues);
        when(mockFieldValues.strVal(0)).thenReturn(encryptedValue);

        AESDecryptFunction.AesDecryptContainsValueSource aesDecryptContainsValueSource =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource, SECRET_KEY, pattern);

        FunctionValues values = aesDecryptContainsValueSource.getValues(Collections.emptyMap(), mockReaderContext);

        assertEquals(0, values.intVal(0), "Should return 0 when decrypted value does not contain the pattern");
    }

    @Test
    void testIntVal_emptyEncryptedValue() throws IOException {
        String pattern = "test";

        when(mockSource.getValues(any(Map.class), eq(mockReaderContext))).thenReturn(mockFieldValues);
        when(mockFieldValues.strVal(0)).thenReturn("");

        AESDecryptFunction.AesDecryptContainsValueSource aesDecryptContainsValueSource =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource, SECRET_KEY, pattern);

        FunctionValues values = aesDecryptContainsValueSource.getValues(Collections.emptyMap(), mockReaderContext);

        assertEquals(0, values.intVal(0), "Should return 0 for empty encrypted value");
    }

    @Test
    void testIntVal_nullEncryptedValue() throws IOException {
        String pattern = "test";

        when(mockSource.getValues(any(Map.class), eq(mockReaderContext))).thenReturn(mockFieldValues);
        when(mockFieldValues.strVal(0)).thenReturn(null);

        AESDecryptFunction.AesDecryptContainsValueSource aesDecryptContainsValueSource =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource, SECRET_KEY, pattern);

        FunctionValues values = aesDecryptContainsValueSource.getValues(Collections.emptyMap(), mockReaderContext);

        assertEquals(0, values.intVal(0), "Should return 0 for null encrypted value");
    }

    @Test
    void testIntVal_decryptionFails() throws IOException {
        // Provide an invalid encrypted value to cause decryption failure
        String invalidEncryptedValue = "invalid_base64_string";
        String pattern = "test";

        when(mockSource.getValues(any(Map.class), eq(mockReaderContext))).thenReturn(mockFieldValues);
        when(mockFieldValues.strVal(0)).thenReturn(invalidEncryptedValue);

        AESDecryptFunction.AesDecryptContainsValueSource aesDecryptContainsValueSource =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource, SECRET_KEY, pattern);

        FunctionValues values = aesDecryptContainsValueSource.getValues(Collections.emptyMap(), mockReaderContext);

        assertEquals(0, values.intVal(0), "Should return 0 when decryption fails");
    }

    @Test
    void testIntVal_nullPattern() throws Exception {
        String originalValue = "some text";
        String encryptedValue = encrypt(originalValue, SECRET_KEY);

        when(mockSource.getValues(any(Map.class), eq(mockReaderContext))).thenReturn(mockFieldValues);
        when(mockFieldValues.strVal(0)).thenReturn(encryptedValue);

        AESDecryptFunction.AesDecryptContainsValueSource aesDecryptContainsValueSource =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource, SECRET_KEY, null); // Null pattern

        FunctionValues values = aesDecryptContainsValueSource.getValues(Collections.emptyMap(), mockReaderContext);

        assertEquals(0, values.intVal(0), "Should return 0 if pattern is null");
    }

    @Test
    void testDescription() {
        String pattern = "xyz";
        when(mockSource.description()).thenReturn("myfield");
        AESDecryptFunction.AesDecryptContainsValueSource aesDecryptContainsValueSource =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource, SECRET_KEY, pattern);

        assertEquals("aesdecrypt_contains(myfield," + SECRET_KEY + "," + pattern + ")",
                aesDecryptContainsValueSource.description());
    }

    @Test
    void testEqualsAndHashCode() {
        ValueSource mockSource1 = mock(ValueSource.class);
        ValueSource mockSource2 = mock(ValueSource.class); // This mock is intentionally different from mockSource1

        // REMOVED: when(mockSource1.equals(any())).thenReturn(true);
        // This is the problematic line causing InvalidUseOfMatchers error.
        // Mockito does not support stubbing equals/hashCode with matchers.

        AESDecryptFunction.AesDecryptContainsValueSource vs1 =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource1, SECRET_KEY, "pattern1");
        AESDecryptFunction.AesDecryptContainsValueSource vs2 =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource1, SECRET_KEY, "pattern1"); // Same source, key, pattern
        AESDecryptFunction.AesDecryptContainsValueSource vs3 =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource2, SECRET_KEY, "pattern1"); // Different source object
        AESDecryptFunction.AesDecryptContainsValueSource vs4 =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource1, "differentKey", "pattern1"); // Different key
        AESDecryptFunction.AesDecryptContainsValueSource vs5 =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource1, SECRET_KEY, "pattern2"); // Different pattern

        // Test equals
        assertTrue(vs1.equals(vs2), "vs1 and vs2 should be equal");
        assertEquals(vs1.hashCode(), vs2.hashCode(), "Hash codes for equal objects must be equal");

        assertFalse(vs1.equals(vs3), "vs1 and vs3 should not be equal due to different source");
        assertFalse(vs1.equals(vs4), "vs1 and vs4 should not be equal due to different secret key");
        assertFalse(vs1.equals(vs5), "vs1 and vs5 should not be equal due to different pattern");
        assertFalse(vs1.equals(null), "vs1 should not be equal to null");
        assertFalse(vs1.equals("some_string"), "vs1 should not be equal to an object of different class");

        // Test hash code consistency
        assertEquals(vs1.hashCode(), vs1.hashCode(), "Hash code should be consistent");
        // It's generally not guaranteed that hash codes will be different for non-equal objects,
        // but for a robust test, it's good to ensure they are different when components are different.
        // However, the primary test for hashCode is consistency with equals.
        // The following line might fail if Object.hash() returns the same hash for different mock objects,
        // which is possible but less common. The most important check is that equal objects have equal hash codes.
        assertNotEquals(vs1.hashCode(), vs3.hashCode(), "Hash codes should ideally be different for non-equal objects (different source)");
    }

    @Test
    void testOtherFunctionValuesMethods() throws Exception {
        String originalValue = "test";
        String encryptedValue = encrypt(originalValue, SECRET_KEY);
        String pattern = "test";

        when(mockSource.getValues(any(Map.class), eq(mockReaderContext))).thenReturn(mockFieldValues);
        when(mockFieldValues.strVal(0)).thenReturn(encryptedValue);
        when(mockFieldValues.exists(0)).thenReturn(true);

        AESDecryptFunction.AesDecryptContainsValueSource aesDecryptContainsValueSource =
                new AESDecryptFunction.AesDecryptContainsValueSource(mockSource, SECRET_KEY, pattern);

        FunctionValues values = aesDecryptContainsValueSource.getValues(Collections.emptyMap(), mockReaderContext);

        // print data values
        System.out.println("Values: " + values);

        // Stub mockSource.description() for a meaningful toString result
        when(mockSource.description()).thenReturn("myField");

        assertEquals("aesdecrypt_contains(myField," + SECRET_KEY + "," + pattern + ")=1", values.toString(0));
        assertEquals("1", values.strVal(0));
        assertEquals(1.0f, values.floatVal(0));
        assertEquals(1L, values.longVal(0));
        assertEquals(1.0d, values.doubleVal(0));
        assertTrue(values.boolVal(0));
        assertEquals(1, values.objectVal(0));
        assertTrue(values.exists(0));
    }
}