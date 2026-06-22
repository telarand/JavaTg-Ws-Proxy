package com.github.telarand.ws_android.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * Предоставляет API:
 *   Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(data)
 *   (decryptor работает так же)
 *
 * Использует стандартный JCA (Java Cryptography Architecture).
 */
public final class AesCtr {

    private AesCtr() {}

    private static Cipher createCipher(byte[] key, byte[] iv, int mode) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(mode, keySpec, ivSpec);
            return cipher;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("AES/CTR cipher init failed: " + e.getMessage(), e);
        }
    }

    public static final class AES {
        private final byte[] key;

        public AES(byte[] key) {
            if (key == null) throw new NullPointerException("Key cannot be null");
            if (key.length != 16 && key.length != 24 && key.length != 32)
                throw new IllegalArgumentException("AES key must be 16/24/32 bytes");
            this.key = key.clone();
        }

        public byte[] getKey() { return key.clone(); }
    }

    public static final class CTR {
        private final byte[] iv;

        public CTR(byte[] iv) {
            if (iv == null) throw new NullPointerException("IV cannot be null");
            if (iv.length != 16) throw new IllegalArgumentException("CTR IV must be 16 bytes");
            this.iv = iv.clone();
        }

        public byte[] getIv() { return iv.clone(); }
    }

    public static final class Encryptor {
        private final Cipher cipher;

        private Encryptor(Cipher cipher) { this.cipher = cipher; }

        /**
         * Шифрует/дешифрует очередной блок данных.
         */
        public byte[] update(byte[] data) {
            if (data == null || data.length == 0) return new byte[0];
            return cipher.update(data);
        }

        /**
         * Перегрузка для работы с частью массива.
         */
        public byte[] update(byte[] src, int offset, int len) {
            if (len == 0) return new byte[0];
            byte[] slice = new byte[len];
            System.arraycopy(src, offset, slice, 0, len);
            return update(slice);
        }

        /**
         * Завершает шифрование (для CTR возвращает остаток).
         * Переименовано с finalize, чтобы не конфликтовать с Object.finalize().
         */
        public byte[] doFinal() {
            try {
                return cipher.doFinal();
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("AES/CTR doFinal failed: " + e.getMessage(), e);
            }
        }
    }

    public static final class CipherFactory {
        private final byte[] key;
        private final byte[] iv;

        public CipherFactory(AES algorithm, CTR mode) {
            this.key = algorithm.getKey();
            this.iv = mode.getIv();
        }

        public Encryptor encryptor() {
            return new Encryptor(createCipher(key, iv, Cipher.ENCRYPT_MODE));
        }

        public Encryptor decryptor() {
            return encryptor();
        }
    }

    public static byte[] encrypt(byte[] key, byte[] iv, byte[] data) {
        AES aes = new AES(key);
        CTR ctr = new CTR(iv);
        CipherFactory factory = new CipherFactory(aes, ctr);
        Encryptor enc = factory.encryptor();
        byte[] part = enc.update(data);
        byte[] last = enc.doFinal();
        if (last.length == 0) return part;
        byte[] res = new byte[part.length + last.length];
        System.arraycopy(part, 0, res, 0, part.length);
        System.arraycopy(last, 0, res, part.length, last.length);
        return res;
    }

    public static byte[] decrypt(byte[] key, byte[] iv, byte[] data) {
        return encrypt(key, iv, data);
    }
}