package com.example.solr;

import org.apache.commons.codec.binary.Base64;
import org.apache.lucene.queries.function.ValueSource;
import org.apache.lucene.queries.function.FunctionValues;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.solr.common.util.NamedList;
import org.apache.solr.search.FunctionQParser;
import org.apache.solr.search.SyntaxError;
import org.apache.solr.search.ValueSourceParser;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AESDecryptFunction extends ValueSourceParser {
    private static final Logger log = LoggerFactory.getLogger(AESDecryptFunction.class);

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final byte[] IV = new byte[]{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 5};

    @Override
    public void init(@SuppressWarnings({"rawtypes"})NamedList args) {
        // Initialization if needed
    }

    /**
     * Default: aesdecrypt(field, key)
     */
    @Override
    public ValueSource parse(FunctionQParser fp) throws SyntaxError {
        ValueSource fieldValue = fp.parseValueSource();
        String secretKey = fp.parseArg();
        return new AesDecryptValueSource(fieldValue, secretKey);
    }

    /**
     * ValueSource untuk fungsi aesdecrypt(field, key)
     */
    static class AesDecryptValueSource extends ValueSource {
        private final ValueSource source;
        private final String secretKey;

        AesDecryptValueSource(ValueSource source, String secretKey) {
            this.source = source;
            this.secretKey = secretKey;
        }

        @Override
        public String description() {
            return "aesdecrypt(" + source.description() + ")";
        }

        @Override
        public FunctionValues getValues(Map context, LeafReaderContext readerContext) throws IOException {
            final FunctionValues fieldValues = source.getValues(context, readerContext);

            return new FunctionValues() {
                @Override
                public String strVal(int doc) throws IOException {
                    String encryptedValue = fieldValues.strVal(doc);
                    if (encryptedValue == null || encryptedValue.isEmpty()) {
                        return "N/A";
                    }
                    try {
                        return decrypt(encryptedValue, secretKey);
                    } catch (Exception e) {
                        throw new IOException("Decryption failed", e);
                    }
                }
                @Override public boolean exists(int doc) throws IOException { return fieldValues.exists(doc); }
                @Override public String toString(int doc) throws IOException { return description() + "=" + strVal(doc); }
                @Override public float floatVal(int doc) throws IOException { return 0; }
                @Override public int intVal(int doc) throws IOException { return 0; }
                @Override public long longVal(int doc) throws IOException { return 0; }
                @Override public double doubleVal(int doc) throws IOException { return 0; }
                @Override public boolean boolVal(int doc) throws IOException { return false; }
                @Override public Object objectVal(int doc) throws IOException { return strVal(doc); }
            };
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AesDecryptValueSource that = (AesDecryptValueSource) o;
            return source.equals(that.source) && secretKey.equals(that.secretKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(source, secretKey);
        }
    }

    /**
     * ValueSourceParser tambahan untuk fungsi contains:
     * fq=aesdecrypt_contains(field, key, substring):1
     */
    public static class AESDecryptContainsFunction extends ValueSourceParser {
        @Override
        public void init(@SuppressWarnings({"rawtypes"})NamedList args) {
            // Nothing
        }

        @Override
        public ValueSource parse(FunctionQParser fp) throws SyntaxError {
            ValueSource fieldValue = fp.parseValueSource();
            String secretKey = fp.parseArg();
            String pattern = fp.parseArg();
            return new AesDecryptContainsValueSource(fieldValue, secretKey, pattern);
        }
    }

    /**
     * ValueSource: return 1 jika hasil dekripsi mengandung substring
     */
    static class AesDecryptContainsValueSource extends ValueSource {
        private final ValueSource source;
        private final String secretKey;
        private final String pattern;

        AesDecryptContainsValueSource(ValueSource source, String secretKey, String pattern) {
            this.source = source;
            this.secretKey = secretKey;
            this.pattern = pattern;
        }

        @Override
        public String description() {
            return "aesdecrypt_contains(" + source.description() + "," + secretKey + "," + pattern + ")";
        }

        @Override
        public FunctionValues getValues(Map context, LeafReaderContext readerContext) throws IOException {
            final FunctionValues fieldValues = source.getValues(context, readerContext);

            return new FunctionValues() {
                @Override
                public int intVal(int doc) throws IOException {
                    String encryptedValue = fieldValues.strVal(doc);
                    if (encryptedValue == null || encryptedValue.isEmpty()) {
                        return 0;
                    }
                    String decrypted = decrypt(encryptedValue, secretKey);
                    if (decrypted != null && pattern != null && decrypted.contains(pattern)) {
                        return 1;
                    }
                    return 0;
                }
                @Override public boolean exists(int doc) throws IOException { return fieldValues.exists(doc); }
                @Override public String toString(int doc) throws IOException { return description() + "=" + intVal(doc); }
                @Override public String strVal(int doc) throws IOException { return Integer.toString(intVal(doc)); }
                @Override public float floatVal(int doc) throws IOException { return intVal(doc); }
                @Override public long longVal(int doc) throws IOException { return intVal(doc); }
                @Override public double doubleVal(int doc) throws IOException { return intVal(doc); }
                @Override public boolean boolVal(int doc) throws IOException { return intVal(doc) == 1; }
                @Override public Object objectVal(int doc) throws IOException { return intVal(doc); }
            };
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AesDecryptContainsValueSource that = (AesDecryptContainsValueSource) o;
            return source.equals(that.source) && secretKey.equals(that.secretKey) && pattern.equals(that.pattern);
        }

        @Override
        public int hashCode() {
            return Objects.hash(source, secretKey, pattern);
        }
    }

    /** Utility for base64url decode */
    private static byte[] decodeBase64Url(String base64UrlStr) {
        if (base64UrlStr == null || base64UrlStr.isEmpty()) return new byte[0];
        String padded = base64UrlStr.replace('-', '+').replace('_', '/');
        switch (padded.length() % 4) {
            case 0: break;
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
            case 1: return new byte[0];
        }
        return Base64.decodeBase64(padded);
    }

    /** AES decrypt util */
    public static String decrypt(String encryptedText, String secretKey) {
        if (encryptedText == null || encryptedText.isEmpty() || encryptedText.equalsIgnoreCase("N/A")) {
            log.warn("Encrypted text is null or empty");
            return "N/A";
        }
        try {
            byte[] decodedText = decodeBase64Url(encryptedText);
            if (decodedText.length == 0) return "N/A";
            Key key = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
            byte[] decrypted = cipher.doFinal(decodedText);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Decryption error: {}", e.getMessage(), e);
            return "N/A";
        }
    }
}