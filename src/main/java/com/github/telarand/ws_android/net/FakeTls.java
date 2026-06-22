package com.github.telarand.ws_android.net;

import android.util.Log;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.github.telarand.ws_android.stats.Stats;

/**
 * Содержит:
 * - константы TLS
 * - verifyClientHello / buildServerHello
 * - wrapTlsRecord
 * - FakeTlsStream (обёртка над сокетом с буферизацией TLS-записей)
 * - proxyToMaskingDomain (прокси через маскирующий домен)
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

    private static final byte[] _CCS_FRAME = {
            (byte) 0x14, 0x03, 0x03, 0x00, 0x01, 0x01
    };

    private static final byte[] _SERVER_HELLO_TEMPLATE = new byte[]{
            (byte) 0x16, 0x03, 0x03, 0x00, 0x7A,
            (byte) 0x02, 0x00, 0x00, 0x76,
            (byte) 0x03, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            (byte) 0x20,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            (byte) 0x13, 0x01, 0x00,
            0x00, 0x2E,
            0x00, 0x33, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x2B, 0x00, 0x02, 0x03, 0x04
    };

    private static final int _SH_RANDOM_OFF = 11;
    private static final int _SH_SESSID_OFF = 44;
    private static final int _SH_PUBKEY_OFF = 89;

    private static final SecureRandom secureRandom = new SecureRandom();

    private FakeTls() {}

    /**
     * Создаёт HMAC-SHA256 от данных с заданным ключом.
     */
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

    /**
     * Безопасное сравнение массивов (по времени).
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= (a[i] ^ b[i]);
        }
        return result == 0;
    }


    /**
     * Результат проверки ClientHello.
     */
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

    /**
     * Проверяет ClientHello и возвращает информацию или null.
     */
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

    /**
     * Строит ServerHello, CCS и фейковый ApplicationData.
     */
    public static byte[] buildServerHello(byte[] secret, byte[] clientRandom, byte[] sessionId) {
        byte[] sh = _SERVER_HELLO_TEMPLATE.clone();

        if (sessionId != null && sessionId.length == SESSION_ID_LEN) {
            System.arraycopy(sessionId, 0, sh, _SH_SESSID_OFF, SESSION_ID_LEN);
        }

        byte[] pubkey = new byte[32];
        secureRandom.nextBytes(pubkey);
        System.arraycopy(pubkey, 0, sh, _SH_PUBKEY_OFF, 32);

        byte[] ccs = _CCS_FRAME;

        int encryptedSize = 1900 + secureRandom.nextInt(201);
        byte[] encryptedData = new byte[encryptedSize];
        secureRandom.nextBytes(encryptedData);
        ByteBuffer appRecord = ByteBuffer.allocate(5 + encryptedSize);
        appRecord.put((byte) TLS_RECORD_APPDATA);
        appRecord.put(TLS_VERSION_12);
        appRecord.putShort((short) encryptedSize);
        appRecord.put(encryptedData);
        byte[] appRecordBytes = appRecord.array();

        ByteBuffer responseBuf = ByteBuffer.allocate(sh.length + ccs.length + appRecordBytes.length);
        responseBuf.put(sh);
        responseBuf.put(ccs);
        responseBuf.put(appRecordBytes);
        byte[] response = responseBuf.array();

        ByteBuffer hmacInput = ByteBuffer.allocate(clientRandom.length + response.length);
        hmacInput.put(clientRandom);
        hmacInput.put(response);
        byte[] serverRandom = hmacSha256(secret, hmacInput.array());

        System.arraycopy(serverRandom, 0, sh, _SH_RANDOM_OFF, 32);

        ByteBuffer finalBuf = ByteBuffer.allocate(sh.length + ccs.length + appRecordBytes.length);
        finalBuf.put(sh);
        finalBuf.put(ccs);
        finalBuf.put(appRecordBytes);
        return finalBuf.array();
    }

    /**
     * Упаковывает данные в TLS Application Data записи (по 16KB).
     */
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

    /**
     * Обёртка над сокетом для чтения/записи TLS-записей.
     * Буферизирует Application Data и обрабатывает CCS.
     */
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

        /**
         * Читает ровно n байт из потока (с учётом буфера).
         */
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

        /**
         * Читает до n байт (не блокирует, если в буфере есть данные).
         */
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

        /**
         * Читает один TLS-запись и возвращает Application Data.
         * Пропускает CCS.
         */
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

        /**
         * Записывает данные, обёрнутые в TLS Application Data записи.
         */
        public void write(byte[] data) throws IOException {
            output.write(wrapTlsRecord(data));
        }

        /**
         * Сбрасывает буфер вывода.
         */
        public void drain() throws IOException {
            output.flush();
        }

        /**
         * Закрывает сокет.
         */
        public void close() throws IOException {
            socket.close();
        }

        /**
         * Проверяет, закрыт ли сокет.
         */
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


    /**
     * Проксирует соединение через маскирующий домен (443).
     * Использует два потока для двунаправленного релея.
     */
    public static void proxyToMaskingDomain(Socket clientSocket,
                                            byte[] initialData,
                                            String domain,
                                            String label) throws IOException {
        Stats.INSTANCE.incConnectionsMasked();
        Log.d(TAG, "[" + label + "] masking -> " + domain + ":443");

        try (Socket upstream = new Socket(domain, 443)) {
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
            Log.w(TAG, "[" + label + "] masking error: " + e.getMessage());
        }
    }
}