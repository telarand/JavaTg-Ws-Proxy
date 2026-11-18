package com.github.telarand.ws_android.net;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.github.telarand.ws_android.config.ConfigManager;
import com.github.telarand.ws_android.config.ProxyConfig;

/**
 * Низкоуровневый WebSocket-клиент.
 * Поддерживает только бинарные фреймы (opcode 0x2), PING, PONG, CLOSE.
 *
 * Обновлено до ядра основной ветки:
 *  - ALPN "http/1.1" для WS-соединений (ClientHello без ALPN режется DPI);
 *  - ALPN "h2" для H2-транспорта (используется CfH2Pool);
 *  - явный таймаут TCP-подключения;
 *  - режим secure=false (порт 80, без TLS);
 *  - раздельные host / SNI для domain fronting.
 */
public final class RawWebSocket implements Closeable {

    public static final int OP_BINARY = 0x2;
    public static final int OP_CLOSE  = 0x8;
    public static final int OP_PING   = 0x9;
    public static final int OP_PONG   = 0xA;

    public static final String ALPN_HTTP_1_1 = "http/1.1";
    public static final String ALPN_H2       = "h2";

    private final Socket socket;
    private final InputStream input;
    private final OutputStream output;
    private volatile boolean closed = false;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SSLSocketFactory sslSocketFactory;

    static {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                    }
            }, new java.security.SecureRandom());
            sslSocketFactory = ctx.getSocketFactory();
        } catch (Exception e) {
            throw new RuntimeException("Failed to init SSL context", e);
        }
    }

    private RawWebSocket(Socket socket) throws IOException {
        this.socket = socket;
        this.input = socket.getInputStream();
        this.output = socket.getOutputStream();
    }

    /**
     * Устанавливает WebSocket-соединение (TLS, порт 443).
     * Совместимо со старым вызовом: host == IP или домен, domain — для SNI и Host.
     */
    public static RawWebSocket connect(String host, String domain, float timeout, String path)
            throws IOException, WsHandshakeException {
        return connect(host, domain, timeout, path, null, true);
    }

    /**
     * Полная версия подключения.
     * @param host      IP-адрес или имя хоста (куда реально идёт TCP)
     * @param domain    домен для Host-заголовка
     * @param timeout   таймаут в секундах
     * @param path      путь WebSocket (по умолчанию "/apiws")
     * @param sni       переопределение SNI (domain fronting); null — использовать domain
     * @param secure    true — TLS:443, false — plaintext:80 (disable_secure)
     */
    public static RawWebSocket connect(String host, String domain, float timeout, String path,
                                       String sni, boolean secure)
            throws IOException, WsHandshakeException {
        if (path == null || path.isEmpty()) {
            path = "/apiws";
        }
        int timeoutMs = (int) (timeout * 1000);
        if (timeoutMs <= 0) timeoutMs = 30000;

        Socket socket;
        if (secure) {
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket();
            // Явный таймаут TCP-подключения (createSocket(host, port) вешается навсегда)
            sslSocket.connect(new InetSocketAddress(host, 443), Math.max(timeoutMs, 10000));
            sslSocket.setSoTimeout(timeoutMs);
            sslSocket.setKeepAlive(true);

            SSLParameters params = sslSocket.getSSLParameters();
            String sniHost = (sni != null && !sni.isEmpty()) ? sni : domain;
            if (sniHost != null && !sniHost.isEmpty()) {
                params.setServerNames(java.util.Collections.singletonList(
                        new SNIHostName(sniHost)
                ));
            }
            // ClientHello без ALPN — аномалия, которую режет DPI.
            // Для WS обязательно HTTP/1.1 (Upgrade не работает поверх h2).
            params.setApplicationProtocols(new String[]{ALPN_HTTP_1_1});
            sslSocket.setSSLParameters(params);
            sslSocket.startHandshake();
            socket = sslSocket;
        } else {
            Socket plain = new Socket();
            plain.connect(new InetSocketAddress(host, 80), Math.max(timeoutMs, 10000));
            plain.setSoTimeout(timeoutMs);
            plain.setKeepAlive(true);
            socket = plain;
        }

        try {
            setSockOpts(socket);

            byte[] wsKeyBytes = new byte[16];
            RANDOM.nextBytes(wsKeyBytes);
            String wsKey = Base64.getEncoder().encodeToString(wsKeyBytes);

            String request = "GET " + path + " HTTP/1.1\r\n" +
                    "Host: " + domain + "\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: " + wsKey + "\r\n" +
                    "Sec-WebSocket-Version: 13\r\n" +
                    "Sec-WebSocket-Protocol: binary\r\n" +
                    "\r\n";

            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes("UTF-8"));
            out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
            List<String> responseLines = new ArrayList<>();
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.isEmpty()) break;
                    responseLines.add(line.trim());
                }
            } catch (SocketTimeoutException e) {
                socket.close();
                throw new IOException("Timeout reading handshake response", e);
            }

            if (responseLines.isEmpty()) {
                socket.close();
                throw new WsHandshakeException(0, "empty response");
            }

            String firstLine = responseLines.get(0);
            String[] parts = firstLine.split(" ", 3);
            int statusCode;
            try {
                statusCode = (parts.length >= 2) ? Integer.parseInt(parts[1]) : 0;
            } catch (NumberFormatException e) {
                statusCode = 0;
            }

            if (statusCode == 101) {
                return new RawWebSocket(socket);
            }

            java.util.Map<String, String> headers = new java.util.HashMap<>();
            for (int i = 1; i < responseLines.size(); i++) {
                String line = responseLines.get(i);
                int idx = line.indexOf(':');
                if (idx > 0) {
                    String key = line.substring(0, idx).trim().toLowerCase();
                    String value = line.substring(idx + 1).trim();
                    headers.put(key, value);
                }
            }
            String location = headers.get("location");
            socket.close();
            throw new WsHandshakeException(statusCode, firstLine, headers, location);
        } catch (IOException e) {
            try { socket.close(); } catch (Exception ignored) {}
            throw e;
        } catch (RuntimeException e) {
            try { socket.close(); } catch (Exception ignored) {}
            throw e;
        }
    }

    private static void setSockOpts(Socket sock) {
        try {
            sock.setTcpNoDelay(true);
        } catch (Exception ignored) {}
        ProxyConfig config = ConfigManager.getProxyConfig();
        int bufSize = config.getBufferSize();
        try {
            sock.setReceiveBufferSize(bufSize);
            sock.setSendBufferSize(bufSize);
        } catch (Exception ignored) {}
    }

    public synchronized void send(byte[] data) throws IOException {
        if (closed) throw new IOException("WebSocket already closed");
        byte[] frame = buildFrame(OP_BINARY, data, true);
        output.write(frame);
        output.flush();
    }

    public synchronized void sendBatch(List<byte[]> parts) throws IOException {
        if (closed) throw new IOException("WebSocket already closed");
        for (byte[] part : parts) {
            output.write(buildFrame(OP_BINARY, part, true));
        }
        output.flush();
    }

    public byte[] recv() throws IOException {
        while (!closed) {
            Frame frame = readFrame();
            int opcode = frame.opcode;
            byte[] payload = frame.payload;

            if (opcode == OP_CLOSE) {
                closed = true;
                try {
                    byte[] closeFrame = buildFrame(OP_CLOSE, payload != null ? payload : new byte[0], true);
                    output.write(closeFrame);
                    output.flush();
                } catch (Exception ignored) {}
                return null;
            }

            if (opcode == OP_PING) {
                try {
                    byte[] pongFrame = buildFrame(OP_PONG, payload != null ? payload : new byte[0], true);
                    output.write(pongFrame);
                    output.flush();
                } catch (Exception ignored) {}
                continue;
            }

            if (opcode == OP_PONG) {
                continue;
            }

            if (opcode == 0x1 || opcode == 0x2) {
                return payload;
            }
        }
        return null;
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        try {
            byte[] closeFrame = buildFrame(OP_CLOSE, new byte[0], true);
            output.write(closeFrame);
            output.flush();
        } catch (Exception ignored) {}
        try {
            socket.close();
        } catch (Exception ignored) {}
    }

    private static class Frame {
        int opcode;
        byte[] payload;
        Frame(int opcode, byte[] payload) {
            this.opcode = opcode;
            this.payload = payload;
        }
    }

    private static byte[] buildFrame(int opcode, byte[] data, boolean mask) {
        int length = (data != null) ? data.length : 0;
        ByteBuffer buf;
        byte[] maskKey = null;
        byte[] masked = null;

        int headerLen = 2;
        if (length >= 126) {
            headerLen += (length <= 65535) ? 2 : 8;
        }
        if (mask) {
            headerLen += 4;
        }

        buf = ByteBuffer.allocate(headerLen + length);
        buf.order(ByteOrder.BIG_ENDIAN);

        buf.put((byte) (0x80 | (opcode & 0x0F)));

        int maskBit = mask ? 0x80 : 0x00;
        if (length < 126) {
            buf.put((byte) (maskBit | length));
        } else if (length <= 65535) {
            buf.put((byte) (maskBit | 126));
            buf.putShort((short) length);
        } else {
            buf.put((byte) (maskBit | 127));
            buf.putLong(length);
        }

        if (mask) {
            maskKey = new byte[4];
            RANDOM.nextBytes(maskKey);
            buf.put(maskKey);
            if (length > 0) {
                masked = xorMask(data, maskKey);
                buf.put(masked);
            }
        } else {
            if (length > 0) {
                buf.put(data);
            }
        }

        byte[] result = new byte[buf.position()];
        buf.rewind();
        buf.get(result);
        return result;
    }

    private Frame readFrame() throws IOException {
        byte[] header = new byte[2];
        readExact(header, 0, 2);
        int opcode = header[0] & 0x0F;
        int length = header[1] & 0x7F;
        boolean masked = (header[1] & 0x80) != 0;

        if (length == 126) {
            byte[] ext = new byte[2];
            readExact(ext, 0, 2);
            length = ((ext[0] & 0xFF) << 8) | (ext[1] & 0xFF);
        } else if (length == 127) {
            byte[] ext = new byte[8];
            readExact(ext, 0, 8);
            length = (int) ((ext[0] & 0xFFL) << 56 |
                            (ext[1] & 0xFFL) << 48 |
                            (ext[2] & 0xFFL) << 40 |
                            (ext[3] & 0xFFL) << 32 |
                            (ext[4] & 0xFFL) << 24 |
                            (ext[5] & 0xFFL) << 16 |
                            (ext[6] & 0xFFL) << 8  |
                            (ext[7] & 0xFFL));
        }

        byte[] maskKey = null;
        if (masked) {
            maskKey = new byte[4];
            readExact(maskKey, 0, 4);
        }

        byte[] payload = null;
        if (length > 0) {
            payload = new byte[length];
            readExact(payload, 0, length);
            if (masked) {
                payload = xorMask(payload, maskKey);
            }
        } else {
            payload = new byte[0];
        }

        return new Frame(opcode, payload);
    }

    private void readExact(byte[] buffer, int offset, int len) throws IOException {
        int totalRead = 0;
        while (totalRead < len) {
            int n = input.read(buffer, offset + totalRead, len - totalRead);
            if (n < 0) {
                throw new EOFException("Unexpected end of stream");
            }
            totalRead += n;
        }
    }

    private static byte[] xorMask(byte[] data, byte[] mask) {
        if (data == null || data.length == 0) return data;
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ mask[i & 3]);
        }
        return result;
    }

    public static class WsHandshakeException extends IOException {
        private final int statusCode;
        private final String statusLine;
        private final java.util.Map<String, String> headers;
        private final String location;

        public WsHandshakeException(int statusCode, String statusLine,
                                    java.util.Map<String, String> headers,
                                    String location) {
            super("HTTP " + statusCode + ": " + statusLine);
            this.statusCode = statusCode;
            this.statusLine = statusLine;
            this.headers = headers != null ? headers : new java.util.HashMap<>();
            this.location = location;
        }

        public WsHandshakeException(int statusCode, String statusLine) {
            this(statusCode, statusLine, null, null);
        }

        public int getStatusCode() { return statusCode; }
        public String getStatusLine() { return statusLine; }
        public java.util.Map<String, String> getHeaders() { return headers; }
        public String getLocation() { return location; }

        public boolean isRedirect() {
            return statusCode == 301 || statusCode == 302 ||
                   statusCode == 303 || statusCode == 307 || statusCode == 308;
        }
    }

    public boolean isClosed() {
        return socket == null || socket.isClosed();
    }
}
