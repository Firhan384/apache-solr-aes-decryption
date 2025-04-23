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

    @Override
    public ValueSource parse(FunctionQParser fp) throws SyntaxError {
        ValueSource fieldValue = fp.parseValueSource();
        String secretKey = fp.parseArg();
        return new AesDecryptValueSource(fieldValue, secretKey);
    }

    static class AesDecryptValueSource extends ValueSource {
        private final ValueSource source;
        private final String secretKey;

        AesDecryptValueSource(ValueSource source, String secretKey) {
            this.source = source;
            this.secretKey = secretKey;

            log.info("AesDecryptValueSource initialized with source: {} and secretKey: {}", source, secretKey);
            log.info("AESDecryptFunction initialized successfully");
        }

        @Override
        public String description() {
            return source.description() + "_decrypted";
        }

        @Override
        @SuppressWarnings({"rawtypes", "unchecked"})
        public FunctionValues getValues(Map context, LeafReaderContext readerContext) throws IOException {
            final FunctionValues fieldValues = source.getValues(context, readerContext);
            
            return new FunctionValues() {
                @Override
                public String strVal(int doc) throws IOException {
                    String encryptedValue = fieldValues.strVal(doc);

                    // log
                    log.info("[FunctionValues] Original Base64 URL from Solr: {}", fieldValues.objectVal(doc));

                    if (encryptedValue == null || encryptedValue.isEmpty()) {
                        // print log message
                       log.warn("Encrypted value is null or empty for doc: {}", doc);
                        return null;
                    }

                    // log message if encryptedValue is null or empty
                    log.info("Attempting to decrypt value: {}", encryptedValue);

                    try {
                        String decrypted = decrypt(encryptedValue, secretKey);
                        log.info("Decrypted value for doc {}: {}", doc, decrypted);
                        return decrypted;
                    } catch (Exception e) {
                        log.error("Decryption failed for value: {}", encryptedValue, e);
                        throw new IOException("Decryption failed", e);
                    }
                }

                @Override
                public boolean exists(int doc) throws IOException {
                    return fieldValues.exists(doc);
                }

                @Override
                public String toString(int doc) throws IOException {
                    return description() + "=" + strVal(doc);
                }

                // Implement other required methods with default values
                @Override
                public float floatVal(int doc) throws IOException {
                    return 0;
                }

                @Override
                public int intVal(int doc) throws IOException {
                    return 0;
                }

                @Override
                public long longVal(int doc) throws IOException {
                    return 0;
                }

                @Override
                public double doubleVal(int doc) throws IOException {
                    return 0;
                }

                @Override
                public boolean boolVal(int doc) throws IOException {
                    return false;
                }

                @Override
                public Object objectVal(int doc) throws IOException {
                    return strVal(doc);
                }
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

    private static byte[] decodeBase64Url(String base64UrlStr) {
        // Validasi dasar
        if (base64UrlStr == null || base64UrlStr.isEmpty()) {
            return new byte[0];
        }
        
        // Validasi karakter
        if (!base64UrlStr.matches("^[A-Za-z0-9\\-_]*$")) {
            System.err.println("Invalid Base64 URL characters: " + base64UrlStr);
            return new byte[0]; // Atau tangani secara khusus
        }

        String padded = base64UrlStr.replace('-', '+').replace('_', '/');
        switch (padded.length() % 4) {
            case 0: break; // Sudah benar
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
            case 1: 
                System.err.println("Invalid Base64 URL string length: " + base64UrlStr);
                return new byte[0]; // Mengembalikan array kosong daripada throw exception
        }

        return Base64.decodeBase64(padded);
    }



    public static String decrypt(String encryptedText, String secretKey) {
        log.info("Trying to decrypt: {} with key: {}", encryptedText, 
            secretKey != null ? "[REDACTED]" : "null");

        if (encryptedText == null || encryptedText.isEmpty() || encryptedText.equalsIgnoreCase("N/A")) {
            return "N/A";
        }

        try {
            byte[] decodedText = decodeBase64Url(encryptedText);
            if (decodedText.length == 0) {
                return "N/A"; // Menangani kasus base64 yang tidak valid
            }

            Key key = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
            byte[] decrypted = cipher.doFinal(decodedText);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("Error decrypting value: " + encryptedText + ", " + e.getMessage());
            return "N/A"; // Mengembalikan string kosong jika terjadi kesalahan
        }
    }
}