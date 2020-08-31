package com.castiel;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jivesoftware.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Provider;
import java.security.Security;

public class AesEncryptor implements Encryptor {
    //private static final Logger log = LoggerFactory.getLogger(AesEncryptor.class);

    private static final String ALGORITHM = "AES/CBC/PKCS7Padding";

    private static final byte[] INIT_PARM = new byte[] {
            -51, -111, -89, -59, 39, -117, 57, -32, -6, 114,
            -48, 41, -125, 101, -99, 116 };

    private static final byte[] DEFAULT_KEY = new byte[] {
            -14, 70, 93, 42, -47, 115, 11, 24, -53, -122,
            -107, -93, -79, -27, -119, 39 };

    private static boolean isInitialized = false;

    private byte[] cipherKey = null;

    public AesEncryptor() {
        initialize();
    }

    public AesEncryptor(String key) {
        initialize();
        setKey(key);
    }

    public String encrypt(String value) {
        if (value == null)
            return null;
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return Base64.encodeBytes(cipher(bytes, getKey(), 1));
    }

    public String decrypt(String value) {
        if (value == null)
            return null;
        byte[] bytes = cipher(Base64.decode(value), getKey(), 2);
        if (bytes == null)
            return null;
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private byte[] cipher(byte[] attribute, byte[] key, int mode) {
        byte[] result = null;
        try {
            Key aesKey = new SecretKeySpec(key, "AES");
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            aesCipher.init(mode, aesKey, new IvParameterSpec(INIT_PARM));
            result = aesCipher.doFinal(attribute);
        } catch (Exception e) {
            //log.error("AES cipher failed", e);
        }
        return result;
    }

    private byte[] getKey() {
        return (this.cipherKey == null) ? DEFAULT_KEY : this.cipherKey;
    }

    private void setKey(byte[] key) {
        this.cipherKey = editKey(key);
    }

    public void setKey(String key) {
        if (key == null) {
            this.cipherKey = null;
            return;
        }
        byte[] bytes = key.getBytes(StandardCharsets.UTF_8);
        setKey(editKey(bytes));
    }

    private byte[] editKey(byte[] key) {
        if (key == null)
            return null;
        byte[] result = new byte[DEFAULT_KEY.length];
        for (int x = 0; x < DEFAULT_KEY.length; x++)
            result[x] = (x < key.length) ? key[x] : DEFAULT_KEY[x];
        return result;
    }

    private synchronized void initialize() {
        if (!isInitialized)
            try {
                Security.addProvider((Provider)new BouncyCastleProvider());
                isInitialized = true;
            } catch (Throwable t) {
                //log.warn("JCE provider failure; unable to load BC", t);
            }
    }
}
