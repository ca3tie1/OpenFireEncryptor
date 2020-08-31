package com.castiel;

public interface Encryptor {
    String encrypt(String paramString);

    String decrypt(String paramString);

    void setKey(String paramString);
}
