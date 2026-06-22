package com.github.telarand.ws_android.bridge;

import com.github.telarand.ws_android.crypto.AesCtr;
import com.github.telarand.ws_android.utils.MTProtoUtils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Разбивает зашифрованный поток на отдельные MTProto-пакеты.
 */
public final class MsgSplitter {

    private final AesCtr.Encryptor dec;
    private final int proto;
    private byte[] cipherBuf;
    private byte[] plainBuf;
    private boolean disabled;

    public MsgSplitter(byte[] relayInit, int protoInt) {
        byte[] key = new byte[32];
        System.arraycopy(relayInit, 8, key, 0, 32);
        byte[] iv = new byte[16];
        System.arraycopy(relayInit, 40, iv, 0, 16);

        AesCtr.AES aes = new AesCtr.AES(key);
        AesCtr.CTR ctr = new AesCtr.CTR(iv);
        AesCtr.CipherFactory factory = new AesCtr.CipherFactory(aes, ctr);
        this.dec = factory.encryptor();

        this.dec.update(MTProtoUtils.ZERO_64);

        this.proto = protoInt;
        this.cipherBuf = new byte[0];
        this.plainBuf = new byte[0];
        this.disabled = false;
    }

    /**
     * Разбивает очередной кусок зашифрованных данных на пакеты.
     * @param chunk зашифрованные байты
     * @return список пакетов (каждый пакет – байтовый массив)
     */
    public List<byte[]> split(byte[] chunk) {
        if (chunk == null || chunk.length == 0) return new ArrayList<>();
        if (disabled) {
            List<byte[]> result = new ArrayList<>();
            result.add(chunk);
            return result;
        }

        byte[] newCipher = new byte[cipherBuf.length + chunk.length];
        System.arraycopy(cipherBuf, 0, newCipher, 0, cipherBuf.length);
        System.arraycopy(chunk, 0, newCipher, cipherBuf.length, chunk.length);
        cipherBuf = newCipher;

        byte[] decryptedPart = dec.update(chunk);
        byte[] newPlain = new byte[plainBuf.length + decryptedPart.length];
        System.arraycopy(plainBuf, 0, newPlain, 0, plainBuf.length);
        System.arraycopy(decryptedPart, 0, newPlain, plainBuf.length, decryptedPart.length);
        plainBuf = newPlain;

        List<byte[]> parts = new ArrayList<>();
        int offset = 0;
        int bufLen = cipherBuf.length;

        while (offset < bufLen) {
            Integer packetLen = nextPacketLen(offset);
            if (packetLen == null) break;
            if (packetLen <= 0) {
                byte[] tail = new byte[cipherBuf.length - offset];
                System.arraycopy(cipherBuf, offset, tail, 0, tail.length);
                parts.add(tail);
                offset = bufLen;
                disabled = true;
                break;
            }
            byte[] packet = new byte[packetLen];
            System.arraycopy(cipherBuf, offset, packet, 0, packetLen);
            parts.add(packet);
            offset += packetLen;
        }

        if (offset > 0) {
            byte[] newCipher2 = new byte[cipherBuf.length - offset];
            System.arraycopy(cipherBuf, offset, newCipher2, 0, newCipher2.length);
            cipherBuf = newCipher2;
            byte[] newPlain2 = new byte[plainBuf.length - offset];
            System.arraycopy(plainBuf, offset, newPlain2, 0, newPlain2.length);
            plainBuf = newPlain2;
        }

        return parts;
    }

    /**
     * Возвращает все оставшиеся данные как один пакет (flush).
     */
    public List<byte[]> flush() {
        if (cipherBuf.length == 0) return new ArrayList<>();
        List<byte[]> result = new ArrayList<>();
        byte[] tail = new byte[cipherBuf.length];
        System.arraycopy(cipherBuf, 0, tail, 0, tail.length);
        result.add(tail);
        cipherBuf = new byte[0];
        plainBuf = new byte[0];
        return result;
    }

    /**
     * Определяет длину следующего пакета, начиная с offset.
     * @return длину пакета или null, если данных недостаточно.
     */
    private Integer nextPacketLen(int offset) {
        int avail = plainBuf.length - offset;
        if (avail <= 0) return null;

        if (proto == MTProtoUtils.PROTO_ABRIDGED_INT) {
            return nextAbridgedLen(offset, avail);
        } else if (proto == MTProtoUtils.PROTO_INTERMEDIATE_INT ||
                   proto == MTProtoUtils.PROTO_PADDED_INTERMEDIATE_INT) {
            return nextIntermediateLen(offset, avail);
        } else {
            return 0;
        }
    }

    private Integer nextAbridgedLen(int offset, int avail) {
        int first = plainBuf[offset] & 0xFF;
        int headerLen;
        int payloadLen;
        if (first == 0x7F || first == 0xFF) {
            if (avail < 4) return null;
            payloadLen = ByteBuffer.wrap(plainBuf, offset + 1, 4).order(ByteOrder.LITTLE_ENDIAN).getInt() * 4;
            headerLen = 4;
        } else {
            payloadLen = (first & 0x7F) * 4;
            headerLen = 1;
        }
        if (payloadLen <= 0) return 0;
        int packetLen = headerLen + payloadLen;
        if (avail < packetLen) return null;
        return packetLen;
    }

    private Integer nextIntermediateLen(int offset, int avail) {
        if (avail < 4) return null;
        int payloadLen = ByteBuffer.wrap(plainBuf, offset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0x7FFFFFFF;
        if (payloadLen <= 0) return 0;
        int packetLen = 4 + payloadLen;
        if (avail < packetLen) return null;
        return packetLen;
    }
}