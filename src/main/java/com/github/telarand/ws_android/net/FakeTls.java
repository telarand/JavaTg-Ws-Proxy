package com.github.telarand.ws_android.net;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.github.telarand.ws_android.utils.Logger;
import com.github.telarand.ws_android.stats.Stats;

/**
 * Fake TLS (ee-secret) для входящих соединений.
 *
 * Обновлено до ядра основной ветки:
 *  - ServerHello собирается динамически из ClientHello: выбор шифра
 *    (TLS_AES_128_GCM_SHA256 -> AES_256 -> CHACHA20), зеркалирование
 *    постквантовой группы X25519MLKEM768, если клиент её предложил;
 *  - запись ApplicationData после CCS стала 64..160 байт (профилированный
 *    размер не определялся на Android) вместо 1900..2100 — старый размер
 *    выдаёт классический MTProxy и режется DPI;
 *  - публичный ключ X25519 — валидный элемент поля (старший бит сброшен);
 *  - replay-кэш ClientHello: повтор hello = активное зондирование -> маскировка;
 *  - задержка отправки ServerHello 8..24 мс.
 */
public final class FakeTls {

    private static final String TAG = "FakeTls";

    public static final int TLS_RECORD_HANDSHAKE = 0x16;
    public static final int TLS_RECORD_CCS = 0x14;
    public static final int TLS_RECORD_APPDATA = 0x17;

    public static final byte[] TLS_VERSION_10 = {0x03, 0x01};
    public static final byte[] TLS_VERSION_12 = {0x03, 0x03};
    public static final byte[] TLS_VERSION_13 = {0x03, 0x04};

    public static final int CLIENT_RANDOM_OFFSET = 11;
    public static final int CLIENT_RANDOM_LEN = 32;
    public static final int SESSION_ID_OFFSET = 44;
    public static final int SESSION_ID_LEN = 32;

    public static final int TIMESTAMP_TOLERANCE = 120;
    public static final int TLS_APPDATA_MAX = 16384;

    public static final int EXT_SUPPORTED_VERSIONS = 0x002b;
    public static final int EXT_KEY_SHARE = 0x0033;

    public static final int GROUP_X25519 = 0x001d;
    public static final int GROUP_X25519MLKEM768 = 0x11ec;

    public static final int X25519_KEY_LEN = 32;
    public static final int X25519MLKEM768_CLIENT_SHARE_LEN = 1216;
    public static final int MLKEM768_CIPHERTEXT_LEN = 1088;

    /** TLS 1.3 наборы в порядке предпочтения типичного сервера. */
    private static final int[] CIPHER_PREFERENCE = {0x1301, 0x1303, 0x1302};

    /** Границы единственной AppData-записи после CCS (аналог FALLBACK_APPDATA_RANGE). */
    public static final int FALLBACK_APPDATA_MIN = 64;
    public static final int FALLBACK_APPDATA_MAX = 160;

    /** Задержка перед отправкой ServerHello, мс (SERVER_HELLO_DELAY). */
    public static final int SERVER_HELLO_DELAY_MIN_MS = 8;
    public static final int SERVER_HELLO_DELAY_MAX_MS = 24;

    /** Окно replay-кэша: 2*TOLERANCE+1 (REPLAY_WINDOW). */
    public static final int REPLAY_WINDOW_SECONDS = 2 * TIMESTAMP_TOLERANCE + 1;
    public static final int REPLAY_CACHE_SIZE = 65536;

    private static final byte[] _CCS_FRAME = {
            (byte) 0x14, 0x03, 0x03, 0x00, 0x01, 0x01
    };

    private static final int _SH_RANDOM_OFF = 11;

    private static final SecureRandom secureRandom = new SecureRandom();

    private FakeTls() {}

    // ------------------------------------------------------------------
    //  Replay-кэш (порт _ReplayCache)
    // ------------------------------------------------------------------

    private static final Object replayLock = new Object();
    private static final LinkedHashMap<String, Long> replayExpiry = new LinkedHashMap<>();

    /**
     * true, если такой client_random встречен впервые; false — это replay.
     */
    public static boolean replayFirstSeen(byte[] clientRandom) {
        long now = System.nanoTime() / 1_000_000_000L;
        String key = bytesToHex(clientRandom);
        synchronized (replayLock) {
            Iterator<Map.Entry<String, Long>> it = replayExpiry.entrySet().iterator();
            while (it.hasNext()) {
                if (it.next().getValue() <= now) {
                    it.remove();
                } else {
                    break; // вставка по порядку => протухшие в начале
                }
            }
            if (replayExpiry.containsKey(key)) {
                return false;
            }
            if (replayExpiry.size() >= REPLAY_CACHE_SIZE) {
                Iterator<Map.Entry<String, Long>> first = replayExpiry.entrySet().iterator();
                first.next();
                first.remove();
            }
            replayExpiry.put(key, now + REPLAY_WINDOW_SECONDS);
            return true;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    //  Разбор ClientHello (порт parse_client_hello)
    // ------------------------------------------------------------------

    public static final class ClientHelloInfo {
        public final Set<Integer> cipherSuites;
        public final Map<Integer, Integer> keyShares; // named group -> длина key_exchange

        ClientHelloInfo(Set<Integer> cipherSuites, Map<Integer, Integer> keyShares) {
            this.cipherSuites = cipherSuites;
            this.keyShares = keyShares;
        }
    }

    private static final ClientHelloInfo EMPTY_HELLO_INFO =
            new ClientHelloInfo(new HashSet<Integer>(), new HashMap<Integer, Integer>());

    public static ClientHelloInfo parseClientHello(byte[] data) {
        try {
            int pos = 5 + 4 + 2 + CLIENT_RANDOM_LEN;
            pos += 1 + (data[pos] & 0xFF); // session id

            int suitesLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            pos += 2;
            int suitesEnd = pos + suitesLen;
            if (suitesEnd > data.length) {
                return EMPTY_HELLO_INFO;
            }
            Set<Integer> suites = new HashSet<>();
            for (int off = pos; off + 1 < suitesEnd; off += 2) {
                suites.add(((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF));
            }
            pos = suitesEnd;

            pos += 1 + (data[pos] & 0xFF); // compression methods

            int extTotal = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            pos += 2;
            int extEnd = Math.min(pos + extTotal, data.length);
            Map<Integer, Integer> keyShares = new HashMap<>();
            while (pos + 4 <= extEnd) {
                int extType = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
                int extLen = ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);
                pos += 4;
                if (extType == EXT_KEY_SHARE && pos + 2 <= extEnd) {
                    int sharesLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
                    int sharesEnd = Math.min(pos + 2 + sharesLen, extEnd);
                    int off = pos + 2;
                    while (off + 4 <= sharesEnd) {
                        int group = ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
                        int keyLen = ((data[off + 2] & 0xFF) << 8) | (data[off + 3] & 0xFF);
                        off += 4 + keyLen;
                        if (off <= sharesEnd && !keyShares.containsKey(group)) {
                            keyShares.put(group, keyLen);
                        }
                    }
                }
                pos += extLen;
            }
            return new ClientHelloInfo(suites, keyShares);
        } catch (Exception e) {
            return EMPTY_HELLO_INFO;
        }
    }

    private static int selectCipherSuite(ClientHelloInfo info) {
        for (int suite : CIPHER_PREFERENCE) {
            if (info.cipherSuites.contains(suite)) {
                return suite;
            }
        }
        return CIPHER_PREFERENCE[0];
    }

    /** Валидный публичный ключ X25519: элемент поля ниже 2^255. */
    private static byte[] x25519PublicKey() {
        byte[] key = new byte[X25519_KEY_LEN];
        secureRandom.nextBytes(key);
        key[X25519_KEY_LEN - 1] &= 0x7f;
        return key;
    }

    /** Зеркалим гибридную постквантовую группу, если клиент её предложил. */
    private static int serverKeyShareGroup(ClientHelloInfo info) {
        Integer len = info.keyShares.get(GROUP_X25519MLKEM768);
        return (len != null && len == X25519MLKEM768_CLIENT_SHARE_LEN)
                ? GROUP_X25519MLKEM768 : GROUP_X25519;
    }

    private static int appdataLen() {
        return FALLBACK_APPDATA_MIN
                + secureRandom.nextInt(FALLBACK_APPDATA_MAX - FALLBACK_APPDATA_MIN + 1);
    }

    // ------------------------------------------------------------------
    //  Проверка ClientHello
    // ------------------------------------------------------------------

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            mac.init(keySpec);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 failed", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= (a[i] ^ b[i]);
        }
        return result == 0;
    }

    public static class TlsHelloInfo {
        public final byte[] clientRandom;
        public final byte[] sessionId;
        public final int timestamp;

        public TlsHelloInfo(byte[] clientRandom, byte[] sessionId, int timestamp) {
            this.clientRandom = clientRandom;
            this.sessionId = sessionId;
            this.timestamp = timestamp;
        }
    }

    public static TlsHelloInfo verifyClientHello(byte[] data, byte[] secret) {
        int n = data.length;
        if (n < 43) return null;
        if (data[0] != TLS_RECORD_HANDSHAKE) return null;
        if (data[5] != 0x01) return null;

        byte[] clientRandom = new byte[CLIENT_RANDOM_LEN];
        System.arraycopy(data, CLIENT_RANDOM_OFFSET, clientRandom, 0, CLIENT_RANDOM_LEN);

        byte[] zeroed = data.clone();
        Arrays.fill(zeroed, CLIENT_RANDOM_OFFSET, CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN, (byte)0);

        byte[] expected = hmacSha256(secret, zeroed);

        byte[] expectedFirst28 = new byte[28];
        System.arraycopy(expected, 0, expectedFirst28, 0, 28);
        byte[] clientFirst28 = new byte[28];
        System.arraycopy(clientRandom, 0, clientFirst28, 0, 28);
        if (!constantTimeEquals(expectedFirst28, clientFirst28)) {
            return null;
        }

        byte[] tsXor = new byte[4];
        for (int i = 0; i < 4; i++) {
            tsXor[i] = (byte) (clientRandom[28 + i] ^ expected[28 + i]);
        }
        int timestamp = ByteBuffer.wrap(tsXor).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();

        long now = System.currentTimeMillis() / 1000;
        if (Math.abs(now - timestamp) > TIMESTAMP_TOLERANCE) {
            return null;
        }

        byte[] sessionId;
        if (n >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20) {
            sessionId = new byte[SESSION_ID_LEN];
            System.arraycopy(data, SESSION_ID_OFFSET, sessionId, 0, SESSION_ID_LEN);
        } else {
            sessionId = new byte[SESSION_ID_LEN];
        }

        return new TlsHelloInfo(clientRandom, sessionId, timestamp);
    }

    // ------------------------------------------------------------------
    //  ServerHello
    // ------------------------------------------------------------------

    private static void putBE16(byte[] buf, int off, int value) {
        buf[off] = (byte) ((value >> 8) & 0xFF);
        buf[off + 1] = (byte) (value & 0xFF);
    }

    /**
     * ServerHello + CCS + одна AppData-запись.
     * Клиенты Telegram разбирают ровно эти три записи и проверяют HMAC
     * по всем, поэтому форма фиксирована, а размеры могут варьироваться.
     */
    public static byte[] buildServerHello(byte[] secret, byte[] clientRandom,
                                          byte[] sessionId, ClientHelloInfo info) {
        if (sessionId == null || sessionId.length != SESSION_ID_LEN) {
            sessionId = new byte[SESSION_ID_LEN];
        }
        if (info == null) {
            info = EMPTY_HELLO_INFO;
        }

        int group = serverKeyShareGroup(info);
        byte[] keyExchange = (group == GROUP_X25519MLKEM768)
                ? new byte[MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN]
                : new byte[X25519_KEY_LEN];
        secureRandom.nextBytes(keyExchange);
        keyExchange[keyExchange.length - 1] &= 0x7f; // валидный X25519-элемент в хвосте

        byte[] extSupportedVersions = new byte[6];      // type(2)+len(2)+0304
        putBE16(extSupportedVersions, 0, EXT_SUPPORTED_VERSIONS);
        putBE16(extSupportedVersions, 2, 2);
        extSupportedVersions[4] = TLS_VERSION_13[0];
        extSupportedVersions[5] = TLS_VERSION_13[1];

        byte[] extKeyShare = new byte[8 + keyExchange.length]; // type(2)+len(2)+group(2)+klen(2)+kex
        putBE16(extKeyShare, 0, EXT_KEY_SHARE);
        putBE16(extKeyShare, 2, 4 + keyExchange.length);
        putBE16(extKeyShare, 4, group);
        putBE16(extKeyShare, 6, keyExchange.length);
        System.arraycopy(keyExchange, 0, extKeyShare, 8, keyExchange.length);

        int extTotal = extSupportedVersions.length + extKeyShare.length;
        int bodyLen = 2 + 32 + 1 + sessionId.length + 2 + 1 + 2 + extTotal;
        int messageLen = 1 + 3 + bodyLen;
        int shRecordLen = 5 + messageLen;

        byte[] sh = new byte[shRecordLen];
        sh[0] = (byte) TLS_RECORD_HANDSHAKE;
        sh[1] = TLS_VERSION_12[0];
        sh[2] = TLS_VERSION_12[1];
        putBE16(sh, 3, messageLen);
        int p = 5;
        sh[p++] = 0x02; // handshake type = ServerHello
        sh[p++] = (byte) ((bodyLen >> 16) & 0xFF);
        sh[p++] = (byte) ((bodyLen >> 8) & 0xFF);
        sh[p++] = (byte) (bodyLen & 0xFF);
        sh[p++] = TLS_VERSION_12[0];
        sh[p++] = TLS_VERSION_12[1];
        p += 32; // server random (заполнится HMAC-ом ниже)
        sh[p++] = (byte) sessionId.length;
        System.arraycopy(sessionId, 0, sh, p, sessionId.length);
        p += sessionId.length;
        putBE16(sh, p, selectCipherSuite(info));
        p += 2;
        sh[p++] = 0x00; // compression
        putBE16(sh, p, extTotal);
        p += 2;
        System.arraycopy(extSupportedVersions, 0, sh, p, extSupportedVersions.length);
        p += extSupportedVersions.length;
        System.arraycopy(extKeyShare, 0, sh, p, extKeyShare.length);

        int appdataLen = appdataLen();
        byte[] appRecord = new byte[5 + appdataLen];
        appRecord[0] = (byte) TLS_RECORD_APPDATA;
        appRecord[1] = TLS_VERSION_12[0];
        appRecord[2] = TLS_VERSION_12[1];
        putBE16(appRecord, 3, appdataLen);
        byte[] appData = new byte[appdataLen];
        secureRandom.nextBytes(appData);
        System.arraycopy(appData, 0, appRecord, 5, appdataLen);

        ByteBuffer responseBuf = ByteBuffer.allocate(sh.length + _CCS_FRAME.length + appRecord.length);
        responseBuf.put(sh);
        responseBuf.put(_CCS_FRAME);
        responseBuf.put(appRecord);
        byte[] response = responseBuf.array();

        ByteBuffer hmacInput = ByteBuffer.allocate(clientRandom.length + response.length);
        hmacInput.put(clientRandom);
        hmacInput.put(response);
        byte[] serverRandom = hmacSha256(secret, hmacInput.array());

        System.arraycopy(serverRandom, 0, response, _SH_RANDOM_OFF, 32);

        return response;
    }

    /** Задержка SERVER_HELLO_DELAY (8..24 мс). */
    public static void applyServerHelloDelay() {
        try {
            Thread.sleep(SERVER_HELLO_DELAY_MIN_MS
                    + secureRandom.nextInt(SERVER_HELLO_DELAY_MAX_MS - SERVER_HELLO_DELAY_MIN_MS + 1));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ------------------------------------------------------------------
    //  TLS-обёртка исходящих данных
    // ------------------------------------------------------------------

    public static byte[] wrapTlsRecord(byte[] data) {
        if (data == null || data.length == 0) return new byte[0];
        ByteBuffer out = ByteBuffer.allocate(data.length + (5 * ((data.length + TLS_APPDATA_MAX - 1) / TLS_APPDATA_MAX)));
        int offset = 0;
        while (offset < data.length) {
            int chunkSize = Math.min(TLS_APPDATA_MAX, data.length - offset);
            out.put((byte) TLS_RECORD_APPDATA);
            out.put(TLS_VERSION_12);
            out.putShort((short) chunkSize);
            out.put(data, offset, chunkSize);
            offset += chunkSize;
        }
        byte[] result = new byte[out.position()];
        out.rewind();
        out.get(result);
        return result;
    }

    public static class FakeTlsStream extends InputStream{
        private final Socket socket;
        private final InputStream input;
        private final OutputStream output;
        private final ByteArrayOutputStream readBuffer = new ByteArrayOutputStream();
        private int readLeft = 0;

        public FakeTlsStream(Socket socket) throws IOException {
            this.socket = socket;
            this.input = socket.getInputStream();
            this.output = socket.getOutputStream();
        }

        public byte[] readexactly(int n) throws IOException {
            while (readBuffer.size() < n) {
                byte[] payload = readTlsPayload();
                if (payload == null || payload.length == 0) {
                    throw new EOFException("Unexpected end of TLS stream");
                }
                readBuffer.write(payload);
            }
            byte[] result = new byte[n];
            System.arraycopy(readBuffer.toByteArray(), 0, result, 0, n);
            byte[] remaining = new byte[readBuffer.size() - n];
            System.arraycopy(readBuffer.toByteArray(), n, remaining, 0, remaining.length);
            readBuffer.reset();
            readBuffer.write(remaining);
            return result;
        }

        public byte[] readBytes(int n) throws IOException {
            if (readBuffer.size() > 0) {
                int avail = Math.min(n, readBuffer.size());
                byte[] result = new byte[avail];
                System.arraycopy(readBuffer.toByteArray(), 0, result, 0, avail);
                byte[] remaining = new byte[readBuffer.size() - avail];
                System.arraycopy(readBuffer.toByteArray(), avail, remaining, 0, remaining.length);
                readBuffer.reset();
                readBuffer.write(remaining);
                return result;
            }
            byte[] payload = readTlsPayload();
            if (payload == null || payload.length == 0) {
                return new byte[0];
            }
            if (payload.length > n) {
                readBuffer.write(payload, n, payload.length - n);
                byte[] result = new byte[n];
                System.arraycopy(payload, 0, result, 0, n);
                return result;
            }
            return payload;
        }

        private byte[] readTlsPayload() throws IOException {
            if (readLeft > 0) {
                byte[] data = new byte[readLeft];
                int totalRead = 0;
                while (totalRead < readLeft) {
                    int n = input.read(data, totalRead, readLeft - totalRead);
                    if (n < 0) break;
                    totalRead += n;
                }
                readLeft = 0;
                return data;
            }

            while (true) {
                byte[] header = new byte[5];
                int totalRead = 0;
                while (totalRead < 5) {
                    int n = input.read(header, totalRead, 5 - totalRead);
                    if (n < 0) throw new EOFException("Connection closed while reading TLS header");
                    totalRead += n;
                }
                int rtype = header[0] & 0xFF;
                int recLen = ((header[3] & 0xFF) << 8) | (header[4] & 0xFF);

                if (rtype == TLS_RECORD_CCS) {
                    if (recLen > 0) {
                        long skipped = input.skip(recLen);
                        if (skipped < recLen) {
                            byte[] discard = new byte[recLen];
                            int read = 0;
                            while (read < recLen) {
                                int n = input.read(discard, read, recLen - read);
                                if (n < 0) throw new EOFException("Unexpected EOF while skipping CCS");
                                read += n;
                            }
                        }
                    }
                    continue;
                }

                if (rtype != TLS_RECORD_APPDATA) {
                    return new byte[0];
                }

                byte[] data = new byte[recLen];
                int read = 0;
                while (read < recLen) {
                    int n = input.read(data, read, recLen - read);
                    if (n < 0) break;
                    read += n;
                }
                if (read == 0) {
                    return new byte[0];
                }
                if (read < recLen) {
                    readLeft = recLen - read;
                }
                return data;
            }
        }

        public void write(byte[] data) throws IOException {
            output.write(wrapTlsRecord(data));
        }

        public void drain() throws IOException {
            output.flush();
        }

        public void close() throws IOException {
            socket.close();
        }

        public boolean isClosed() {
            return socket.isClosed();
        }

        @Override
        public int read() throws IOException {
            byte[] b = new byte[1];
            int n = read(b, 0, 1);
            return n == 1 ? (b[0] & 0xFF) : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            byte[] data = readBytes(len);
            if (data.length == 0) return -1;
            int copyLen = Math.min(data.length, len);
            System.arraycopy(data, 0, b, off, copyLen);
            return copyLen;
        }
    }

    public static void proxyToMaskingDomain(Socket clientSocket,
                                            byte[] initialData,
                                            String domain,
                                            String label) throws IOException {
        Stats.INSTANCE.incConnectionsMasked();
        Logger.d(TAG, "[" + label + "] masking -> " + domain + ":443");

        Socket upstream = new Socket();
        try {
            upstream.connect(new InetSocketAddress(domain, 443), 10000);
            upstream.setSoTimeout(30000);

            OutputStream upstreamOut = upstream.getOutputStream();
            InputStream upstreamIn = upstream.getInputStream();

            if (initialData != null && initialData.length > 0) {
                upstreamOut.write(initialData);
                upstreamOut.flush();
            }

            InputStream clientIn = clientSocket.getInputStream();
            OutputStream clientOut = clientSocket.getOutputStream();

            ExecutorService executor = Executors.newFixedThreadPool(2);

            executor.submit(() -> {
                try {
                    byte[] buffer = new byte[16384];
                    int len;
                    while ((len = clientIn.read(buffer)) != -1) {
                        upstreamOut.write(buffer, 0, len);
                        upstreamOut.flush();
                    }
                } catch (IOException e) {
                } finally {
                    try { clientSocket.close(); } catch (Exception ignored) {}
                    executor.shutdownNow();
                }
            });

            executor.submit(() -> {
                try {
                    byte[] buffer = new byte[16384];
                    int len;
                    while ((len = upstreamIn.read(buffer)) != -1) {
                        clientOut.write(buffer, 0, len);
                        clientOut.flush();
                    }
                } catch (IOException e) {
                } finally {
                    try { clientSocket.close(); } catch (Exception ignored) {}
                    executor.shutdownNow();
                }
            });

            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);

        } catch (Exception e) {
            Logger.w(TAG, "[" + label + "] masking error: " + e.getMessage());
        } finally {
            try { upstream.close(); } catch (Exception ignored) {}
        }
    }
}
