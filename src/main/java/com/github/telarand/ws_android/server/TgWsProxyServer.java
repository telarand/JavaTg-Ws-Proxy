package com.github.telarand.ws_android.server;

import android.util.Log;

import com.github.telarand.ws_android.balancer.Balancer;
import com.github.telarand.ws_android.bridge.Bridge;
import com.github.telarand.ws_android.bridge.CryptoCtx;
import com.github.telarand.ws_android.bridge.MsgSplitter;
import com.github.telarand.ws_android.config.ConfigManager;
import com.github.telarand.ws_android.config.ProxyConfig;
import com.github.telarand.ws_android.crypto.AesCtr;
import com.github.telarand.ws_android.net.RawWebSocket;
import com.github.telarand.ws_android.net.FakeTls;
import com.github.telarand.ws_android.pool.Pools;
import com.github.telarand.ws_android.stats.Stats;
import com.github.telarand.ws_android.utils.MTProtoUtils;


import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

/**
 * Главный сервер Telegram MTProto WebSocket прокси.
 */
public final class TgWsProxyServer {

    private static final String TAG = "TgWsProxy";

    private static final double DC_FAIL_COOLDOWN = 30.0;
    private static final double WS_FAIL_TIMEOUT = 2.0;

    private static final Set<String> wsBlacklist = ConcurrentHashMap.newKeySet();
    private static final Map<String, Double> dcFailUntil = new ConcurrentHashMap<>();

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "tg-proxy-worker");
        t.setDaemon(true);
        return t;
    });

    private ServerSocket serverSocket;
    private volatile boolean running = false;
    private Thread serverThread;

    /**
     * Запускает сервер на основе текущего ProxyConfig.
     * @throws IOException при ошибке запуска
     */
    public void start() throws IOException {
        if (running) return;
        ProxyConfig config = ConfigManager.getProxyConfig();
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(config.getHost(), config.getPort()));
        running = true;

        initPoolsAndDomains();

        serverThread = new Thread(this::runServerLoop, "tg-proxy-main");
        serverThread.setDaemon(true);
        serverThread.start();

        Log.i(TAG, "Server started on " + config.getHost() + ":" + config.getPort());
        printStartupInfo();
    }

    /**
     * Останавливает сервер.
     */
    public void stop() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (Exception ignored) {}
        if (serverThread != null) {
            serverThread.interrupt();
            try { serverThread.join(1000); } catch (InterruptedException ignored) {}
        }
        Pools.WS_POOL.reset();
        Pools.CF_WORKER_POOL.reset();
        wsBlacklist.clear();
        dcFailUntil.clear();
        Log.i(TAG, "Server stopped");
    }

    private void initPoolsAndDomains() {
        ProxyConfig config = ConfigManager.getProxyConfig();
        if (config.isFallbackCfproxy()) {
            List<String> userDomains = config.getCfproxyUserDomains();
            if (!userDomains.isEmpty()) {
                Balancer.INSTANCE.updateDomainsList(userDomains);
            } else {
                ConfigManager.startCfproxyDomainRefresh();
            }
        }
        executor.submit(() -> {
            Pools.WS_POOL.warmup();
            Pools.CF_WORKER_POOL.warmup();
        });
    }

    private void runServerLoop() {
        while (running) {
            try {
                Socket clientSocket = serverSocket.accept();
                clientSocket.setTcpNoDelay(true);
                executor.submit(() -> handleClient(clientSocket));
            } catch (SocketException e) {
                if (running) Log.w(TAG, "SocketException: " + e.getMessage());
                break;
            } catch (IOException e) {
                Log.e(TAG, "Accept error: " + e.getMessage(), e);
            }
        }
    }

    private void handleClient(Socket clientSocket) {
        Stats.INSTANCE.incConnectionsTotal();
        Stats.INSTANCE.incConnectionsActive();

        String label = clientSocket.getRemoteSocketAddress().toString();
        ProxyConfig config = ConfigManager.getProxyConfig();

        try {
            clientSocket.setSoTimeout(10000);

            ClientInitResult initResult = readClientInit(clientSocket, config.getSecretBytes(), label);
            if (initResult == null) {
                return;
            }

            byte[] handshake = initResult.handshake;
            InputStream effectiveIn = initResult.inputStream;
            String effectiveLabel = initResult.label;

            HandshakeInfo handshakeInfo = tryHandshake(handshake, config.getSecretBytes());
            if (handshakeInfo == null) {
                Stats.INSTANCE.incConnectionsBad();
                Log.w(TAG, "[" + effectiveLabel + "] bad handshake (wrong secret or proto)");
                try {
                    while (effectiveIn.read(new byte[4096]) > 0) {}
                } catch (Exception ignored) {}
                return;
            }

            int dc = handshakeInfo.dc;
            boolean isMedia = handshakeInfo.isMedia;
            byte[] protoTag = handshakeInfo.protoTag;
            byte[] clientDecPrekeyIv = handshakeInfo.clientDecPrekeyIv;

            int protoInt;
            if (Arrays.equals(protoTag, MTProtoUtils.PROTO_TAG_ABRIDGED)) {
                protoInt = MTProtoUtils.PROTO_ABRIDGED_INT;
            } else if (Arrays.equals(protoTag, MTProtoUtils.PROTO_TAG_INTERMEDIATE)) {
                protoInt = MTProtoUtils.PROTO_INTERMEDIATE_INT;
            } else {
                protoInt = MTProtoUtils.PROTO_PADDED_INTERMEDIATE_INT;
            }

            int dcIdx = isMedia ? -dc : dc;
            String mediaTag = isMedia ? " media" : "";
            String dcKey = dc + (isMedia ? "m" : "");

            Log.d(TAG, String.format("[%s] handshake ok: DC%d%s proto=0x%08X",
                    effectiveLabel, dc, mediaTag, protoInt));

            byte[] relayInit = generateRelayInit(protoTag, dcIdx);
            CryptoCtx ctx = buildCryptoCtx(clientDecPrekeyIv, config.getSecretBytes(), relayInit);

            Map<Integer, String> dcRedirects = config.getDcRedirects();
            if (!dcRedirects.containsKey(dc) || wsBlacklist.contains(dcKey)) {
                Log.i(TAG, String.format("[%s] DC%d%s %s -> fallback",
                        effectiveLabel, dc, mediaTag,
                        dcRedirects.containsKey(dc) ? "WS blacklisted" : "not in config"));
                MsgSplitter splitter = null;
                try {
                    splitter = new MsgSplitter(relayInit, protoInt);
                } catch (Exception ignored) {}
                boolean ok = Bridge.doFallback(clientSocket, relayInit, effectiveLabel, dc, isMedia, ctx, splitter);
                if (!ok) {
                    Log.w(TAG, String.format("[%s] DC%d%s no fallback available", effectiveLabel, dc, mediaTag));
                }
                return;
            }

            double now = System.currentTimeMillis() / 1000.0;
            double failUntil = dcFailUntil.getOrDefault(dcKey, 0.0);
            double wsTimeout = (now < failUntil) ? WS_FAIL_TIMEOUT : 10.0;

            List<String> domains = MTProtoUtils.wsDomains(dc, isMedia);
            String targetIp = dcRedirects.get(dc);
            RawWebSocket ws = null;
            boolean wsFailedRedirect = false;
            boolean allRedirects = true;

            ws = Pools.WS_POOL.get(dc, isMedia, targetIp, domains);
            if (ws != null) {
                Log.i(TAG, String.format("[%s] DC%d%s -> pool hit via %s", effectiveLabel, dc, mediaTag, targetIp));
            } else {
                for (String domain : domains) {
                    Log.i(TAG, String.format("[%s] DC%d%s -> wss://%s/apiws via %s",
                            effectiveLabel, dc, mediaTag, domain, targetIp));
                    try {
                        ws = RawWebSocket.connect(targetIp, domain, (float) wsTimeout, "/apiws");
                        allRedirects = false;
                        break;
                    } catch (RawWebSocket.WsHandshakeException e) {
                        Stats.INSTANCE.incWsErrors();
                        if (e.isRedirect()) {
                            wsFailedRedirect = true;
                            Log.w(TAG, String.format("[%s] DC%d%s got %d from %s -> %s",
                                    effectiveLabel, dc, mediaTag, e.getStatusCode(), domain, e.getLocation()));
                            continue;
                        } else {
                            allRedirects = false;
                            Log.w(TAG, String.format("[%s] DC%d%s WS handshake: %s",
                                    effectiveLabel, dc, mediaTag, e.getStatusLine()));
                        }
                    } catch (Exception e) {
                        Stats.INSTANCE.incWsErrors();
                        allRedirects = false;
                        Log.w(TAG, String.format("[%s] DC%d%s WS connect failed: %s",
                                effectiveLabel, dc, mediaTag, e.getMessage()));
                    }
                }
            }

            if (ws == null) {
                if (wsFailedRedirect && allRedirects) {
                    wsBlacklist.add(dcKey);
                    Log.w(TAG, String.format("[%s] DC%d%s blacklisted for WS (all 302)",
                            effectiveLabel, dc, mediaTag));
                } else if (wsFailedRedirect) {
                    dcFailUntil.put(dcKey, now + DC_FAIL_COOLDOWN);
                } else {
                    dcFailUntil.put(dcKey, now + DC_FAIL_COOLDOWN);
                    Log.i(TAG, String.format("[%s] DC%d%s WS cooldown for %ds",
                            effectiveLabel, dc, mediaTag, (int) DC_FAIL_COOLDOWN));
                }

                MsgSplitter splitterFb = null;
                try {
                    splitterFb = new MsgSplitter(relayInit, protoInt);
                } catch (Exception ignored) {}
                boolean ok = Bridge.doFallback(clientSocket, relayInit, effectiveLabel, dc, isMedia, ctx, splitterFb);
                if (ok) {
                    Log.i(TAG, String.format("[%s] DC%d%s fallback closed", effectiveLabel, dc, mediaTag));
                }
                return;
            }

            dcFailUntil.remove(dcKey);
            Stats.INSTANCE.incConnectionsWs();

            MsgSplitter splitter = null;
            try {
                splitter = new MsgSplitter(relayInit, protoInt);
                Log.d(TAG, String.format("[%s] MsgSplitter activated for proto 0x%08X", effectiveLabel, protoInt));
            } catch (Exception ignored) {}

            ws.send(relayInit);

            Bridge.bridgeWsReencrypt(clientSocket, ws, effectiveLabel, ctx, dc, isMedia, splitter);

        } catch (SocketTimeoutException e) {
            Log.w(TAG, "[" + label + "] timeout during handshake");
        } catch (EOFException e) {
            Log.d(TAG, "[" + label + "] client disconnected");
        } catch (IOException e) {
            Log.e(TAG, "[" + label + "] IO error: " + e.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "[" + label + "] unexpected: " + e.getMessage(), e);
        } finally {
            Stats.INSTANCE.decConnectionsActive();
            try { clientSocket.close(); } catch (Exception ignored) {}
        }
    }

    private static class ClientInitResult {
        byte[] handshake;
        InputStream inputStream;
        String label;
        ClientInitResult(byte[] handshake, InputStream in, String label) {
            this.handshake = handshake;
            this.inputStream = in;
            this.label = label;
        }
    }

    private static class HandshakeInfo {
        int dc;
        boolean isMedia;
        byte[] protoTag;
        byte[] clientDecPrekeyIv;
        HandshakeInfo(int dc, boolean isMedia, byte[] protoTag, byte[] clientDecPrekeyIv) {
            this.dc = dc;
            this.isMedia = isMedia;
            this.protoTag = protoTag;
            this.clientDecPrekeyIv = clientDecPrekeyIv;
        }
    }

    /**
     * Читает начальные данные клиента, обрабатывает PROXY protocol и Fake TLS.
     */
    private ClientInitResult readClientInit(Socket clientSocket, byte[] secret, String label) throws IOException {
        ProxyConfig config = ConfigManager.getProxyConfig();
        InputStream in = clientSocket.getInputStream();
        OutputStream out = clientSocket.getOutputStream();

        if (config.isProxyProtocol()) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "ASCII"));
            try {
                String line = reader.readLine();
                if (line != null && line.startsWith("PROXY ")) {
                    String[] parts = line.split(" ");
                    if (parts.length >= 6) {
                        label = parts[2] + ":" + parts[4];
                    }
                    Log.d(TAG, "[" + label + "] PROXY protocol: " + line);
                } else {
                    Log.d(TAG, "[" + label + "] expected PROXY header, got: " + (line != null ? line.substring(0, Math.min(60, line.length())) : "null"));
                }
            } catch (Exception e) {
                Log.w(TAG, "[" + label + "] PROXY parse error: " + e.getMessage());
            }
        }

        byte[] firstByte = new byte[1];
        try {
            int n = readWithTimeout(in, firstByte, 0, 1, 10000);
            if (n < 0) {
                Log.d(TAG, "[" + label + "] client disconnected before handshake");
                return null;
            }
        } catch (SocketTimeoutException e) {
            Log.w(TAG, "[" + label + "] timeout reading first byte");
            return null;
        }

        String fakeTlsDomain = config.getFakeTlsDomain();

        if (firstByte[0] == FakeTls.TLS_RECORD_HANDSHAKE && fakeTlsDomain != null && !fakeTlsDomain.isEmpty()) {
            byte[] headerRest = new byte[4];
            try {
                int n = readWithTimeout(in, headerRest, 0, 4, 10000);
                if (n < 4) {
                    Log.d(TAG, "[" + label + "] incomplete TLS record header");
                    return null;
                }
            } catch (SocketTimeoutException e) {
                Log.w(TAG, "[" + label + "] timeout reading TLS header");
                return null;
            }

            byte[] tlsHeader = new byte[5];
            System.arraycopy(firstByte, 0, tlsHeader, 0, 1);
            System.arraycopy(headerRest, 0, tlsHeader, 1, 4);
            int recordLen = ((tlsHeader[3] & 0xFF) << 8) | (tlsHeader[4] & 0xFF);

            byte[] recordBody = new byte[recordLen];
            try {
                int n = readWithTimeout(in, recordBody, 0, recordLen, 10000);
                if (n < recordLen) {
                    Log.d(TAG, "[" + label + "] incomplete TLS record body");
                    return null;
                }
            } catch (SocketTimeoutException e) {
                Log.w(TAG, "[" + label + "] timeout reading TLS body");
                return null;
            }

            byte[] clientHello = new byte[5 + recordLen];
            System.arraycopy(tlsHeader, 0, clientHello, 0, 5);
            System.arraycopy(recordBody, 0, clientHello, 5, recordLen);

            FakeTls.TlsHelloInfo tlsInfo = FakeTls.verifyClientHello(clientHello, secret);
            if (tlsInfo == null) {
                Log.d(TAG, "[" + label + "] Fake TLS verify failed -> masking to " + fakeTlsDomain);
                proxyToMaskingDomain(clientSocket, clientHello, fakeTlsDomain, label);
                return null;
            }

            Log.d(TAG, "[" + label + "] Fake TLS handshake ok (ts=" + tlsInfo.timestamp + ")");

            byte[] serverHello = FakeTls.buildServerHello(secret, tlsInfo.clientRandom, tlsInfo.sessionId);
            out.write(serverHello);
            out.flush();

            FakeTls.FakeTlsStream tlsStream = new FakeTls.FakeTlsStream(clientSocket);
            byte[] handshake;
            try {
                handshake = tlsStream.readexactly(MTProtoUtils.HANDSHAKE_LEN);
            } catch (EOFException e) {
                Log.d(TAG, "[" + label + "] incomplete obfs2 init inside TLS");
                return null;
            }

            return new ClientInitResult(handshake, tlsStream, label);
        } else {
            if (fakeTlsDomain != null && !fakeTlsDomain.isEmpty()) {
                Log.d(TAG, "[" + label + "] non-TLS byte 0x" + String.format("%02X", firstByte[0]) + " -> HTTP redirect");
                String redirect = "HTTP/1.1 301 Moved Permanently\r\n" +
                        "Location: https://" + fakeTlsDomain + "/\r\n" +
                        "Content-Length: 0\r\n" +
                        "Connection: close\r\n\r\n";
                out.write(redirect.getBytes("ASCII"));
                out.flush();
                return null;
            }

            byte[] rest = new byte[MTProtoUtils.HANDSHAKE_LEN - 1];
            try {
                int n = readWithTimeout(in, rest, 0, rest.length, 10000);
                if (n < rest.length) {
                    Log.d(TAG, "[" + label + "] client disconnected before handshake");
                    return null;
                }
            } catch (SocketTimeoutException e) {
                Log.w(TAG, "[" + label + "] timeout reading handshake");
                return null;
            }

            byte[] handshake = new byte[MTProtoUtils.HANDSHAKE_LEN];
            System.arraycopy(firstByte, 0, handshake, 0, 1);
            System.arraycopy(rest, 0, handshake, 1, rest.length);
            return new ClientInitResult(handshake, in, label);
        }
    }

    /**
     * Вспомогательный метод для чтения с таймаутом (использует setSoTimeout).
     */
    private int readWithTimeout(InputStream in, byte[] buffer, int offset, int len, int timeoutMs) throws IOException {
        return in.read(buffer, offset, len);
    }

    /**
     * Проксирует соединение на маскирующий домен.
     */
    private void proxyToMaskingDomain(Socket clientSocket, byte[] initialData, String domain, String label) {
        try {
            FakeTls.proxyToMaskingDomain(clientSocket, initialData, domain, label);
        } catch (Exception e) {
            Log.w(TAG, "[" + label + "] masking error: " + e.getMessage());
        }
    }


    /**
     * Пытается расшифровать handshake и вернуть информацию.
     */
    private HandshakeInfo tryHandshake(byte[] handshake, byte[] secret) {
        if (handshake.length < MTProtoUtils.HANDSHAKE_LEN) return null;

        int skip = MTProtoUtils.SKIP_LEN;
        int prekeyLen = MTProtoUtils.PREKEY_LEN;
        int ivLen = MTProtoUtils.IV_LEN;

        byte[] decPrekeyAndIv = new byte[prekeyLen + ivLen];
        System.arraycopy(handshake, skip, decPrekeyAndIv, 0, decPrekeyAndIv.length);
        byte[] decPrekey = new byte[prekeyLen];
        byte[] decIv = new byte[ivLen];
        System.arraycopy(decPrekeyAndIv, 0, decPrekey, 0, prekeyLen);
        System.arraycopy(decPrekeyAndIv, prekeyLen, decIv, 0, ivLen);

        byte[] key = sha256(concatBytes(decPrekey, secret));

        AesCtr.AES aes = new AesCtr.AES(key);
        AesCtr.CTR ctr = new AesCtr.CTR(decIv);
        AesCtr.CipherFactory factory = new AesCtr.CipherFactory(aes, ctr);
        AesCtr.Encryptor decryptor = factory.encryptor();

        byte[] decrypted = decryptor.update(handshake);

        byte[] protoTag = new byte[4];
        System.arraycopy(decrypted, MTProtoUtils.PROTO_TAG_POS, protoTag, 0, 4);
        if (!Arrays.equals(protoTag, MTProtoUtils.PROTO_TAG_ABRIDGED) &&
                !Arrays.equals(protoTag, MTProtoUtils.PROTO_TAG_INTERMEDIATE) &&
                !Arrays.equals(protoTag, MTProtoUtils.PROTO_TAG_SECURE)) {
            return null;
        }

        int dcIdx = (short) ((decrypted[MTProtoUtils.DC_IDX_POS] & 0xFF) |
                ((decrypted[MTProtoUtils.DC_IDX_POS + 1] & 0xFF) << 8));
        int dc = Math.abs(dcIdx);
        boolean isMedia = dcIdx < 0;

        return new HandshakeInfo(dc, isMedia, protoTag, decPrekeyAndIv);
    }

    /**
     * Генерирует relay_init.
     */
    private byte[] generateRelayInit(byte[] protoTag, int dcIdx) {
        byte[] rnd = new byte[MTProtoUtils.HANDSHAKE_LEN];
        while (true) {
            RANDOM.nextBytes(rnd);
            if (MTProtoUtils.RESERVED_FIRST_BYTES.contains((int) rnd[0] & 0xFF)) continue;
            if (startsWithAny(rnd, MTProtoUtils.RESERVED_STARTS)) continue;
            if (Arrays.equals(Arrays.copyOfRange(rnd, 4, 8), MTProtoUtils.RESERVED_CONTINUE)) continue;
            break;
        }

        byte[] encKey = Arrays.copyOfRange(rnd, MTProtoUtils.SKIP_LEN, MTProtoUtils.SKIP_LEN + MTProtoUtils.PREKEY_LEN);
        byte[] encIv = Arrays.copyOfRange(rnd, MTProtoUtils.SKIP_LEN + MTProtoUtils.PREKEY_LEN,
                MTProtoUtils.SKIP_LEN + MTProtoUtils.PREKEY_LEN + MTProtoUtils.IV_LEN);

        AesCtr.AES aes = new AesCtr.AES(encKey);
        AesCtr.CTR ctr = new AesCtr.CTR(encIv);
        AesCtr.CipherFactory factory = new AesCtr.CipherFactory(aes, ctr);
        AesCtr.Encryptor encryptor = factory.encryptor();

        byte[] encryptedFull = encryptor.update(rnd);

        ByteBuffer tailPlain = ByteBuffer.allocate(8);
        tailPlain.put(protoTag);
        tailPlain.putShort((short) dcIdx);
        byte[] random2 = new byte[2];
        RANDOM.nextBytes(random2);
        tailPlain.put(random2);
        byte[] tailPlainBytes = tailPlain.array();

        byte[] keystreamTail = new byte[8];
        for (int i = 0; i < 8; i++) {
            keystreamTail[i] = (byte) (encryptedFull[56 + i] ^ rnd[56 + i]);
        }

        byte[] encryptedTail = new byte[8];
        for (int i = 0; i < 8; i++) {
            encryptedTail[i] = (byte) (tailPlainBytes[i] ^ keystreamTail[i]);
        }

        byte[] result = rnd.clone();
        System.arraycopy(encryptedTail, 0, result, MTProtoUtils.PROTO_TAG_POS, 8);
        return result;
    }

    /**
     * Строит CryptoCtx.
     */
    private CryptoCtx buildCryptoCtx(byte[] clientDecPrekeyIv, byte[] secret, byte[] relayInit) {
        byte[] cltDecPrekey = Arrays.copyOfRange(clientDecPrekeyIv, 0, MTProtoUtils.PREKEY_LEN);
        byte[] cltDecIv = Arrays.copyOfRange(clientDecPrekeyIv, MTProtoUtils.PREKEY_LEN,
                MTProtoUtils.PREKEY_LEN + MTProtoUtils.IV_LEN);
        byte[] cltDecKey = sha256(concatBytes(cltDecPrekey, secret));

        byte[] cltEncPrekeyIv = reverse(clientDecPrekeyIv);
        byte[] cltEncKey = sha256(concatBytes(
                Arrays.copyOfRange(cltEncPrekeyIv, 0, MTProtoUtils.PREKEY_LEN), secret));
        byte[] cltEncIv = Arrays.copyOfRange(cltEncPrekeyIv, MTProtoUtils.PREKEY_LEN,
                MTProtoUtils.PREKEY_LEN + MTProtoUtils.IV_LEN);

        AesCtr.CipherFactory cfCltDec = new AesCtr.CipherFactory(
                new AesCtr.AES(cltDecKey), new AesCtr.CTR(cltDecIv));
        AesCtr.Encryptor cltDecryptor = cfCltDec.encryptor();
        cltDecryptor.update(MTProtoUtils.ZERO_64);

        AesCtr.CipherFactory cfCltEnc = new AesCtr.CipherFactory(
                new AesCtr.AES(cltEncKey), new AesCtr.CTR(cltEncIv));
        AesCtr.Encryptor cltEncryptor = cfCltEnc.encryptor();

        byte[] relayEncKey = Arrays.copyOfRange(relayInit, MTProtoUtils.SKIP_LEN,
                MTProtoUtils.SKIP_LEN + MTProtoUtils.PREKEY_LEN);
        byte[] relayEncIv = Arrays.copyOfRange(relayInit,
                MTProtoUtils.SKIP_LEN + MTProtoUtils.PREKEY_LEN,
                MTProtoUtils.SKIP_LEN + MTProtoUtils.PREKEY_LEN + MTProtoUtils.IV_LEN);
        byte[] relayDecPrekeyIv = reverse(Arrays.copyOfRange(relayInit,
                MTProtoUtils.SKIP_LEN,
                MTProtoUtils.SKIP_LEN + MTProtoUtils.PREKEY_LEN + MTProtoUtils.IV_LEN));
        byte[] relayDecKey = Arrays.copyOfRange(relayDecPrekeyIv, 0, MTProtoUtils.KEY_LEN);
        byte[] relayDecIv = Arrays.copyOfRange(relayDecPrekeyIv, MTProtoUtils.KEY_LEN,
                MTProtoUtils.KEY_LEN + MTProtoUtils.IV_LEN);

        AesCtr.CipherFactory cfTgEnc = new AesCtr.CipherFactory(
                new AesCtr.AES(relayEncKey), new AesCtr.CTR(relayEncIv));
        AesCtr.Encryptor tgEncryptor = cfTgEnc.encryptor();
        tgEncryptor.update(MTProtoUtils.ZERO_64);

        AesCtr.CipherFactory cfTgDec = new AesCtr.CipherFactory(
                new AesCtr.AES(relayDecKey), new AesCtr.CTR(relayDecIv));
        AesCtr.Encryptor tgDecryptor = cfTgDec.encryptor();

        return new CryptoCtx(cltDecryptor, cltEncryptor, tgEncryptor, tgDecryptor);
    }

    private static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] concatBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static byte[] reverse(byte[] src) {
        byte[] dst = new byte[src.length];
        for (int i = 0; i < src.length; i++) {
            dst[i] = src[src.length - 1 - i];
        }
        return dst;
    }

    private static boolean startsWithAny(byte[] data, Set<byte[]> prefixes) {
        for (byte[] prefix : prefixes) {
            if (data.length >= prefix.length) {
                boolean match = true;
                for (int i = 0; i < prefix.length; i++) {
                    if (data[i] != prefix[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
        }
        return false;
    }

    private void printStartupInfo() {
        ProxyConfig config = ConfigManager.getProxyConfig();
        Log.i(TAG, "============================================================");
        Log.i(TAG, "  Telegram MTProto WS Bridge Proxy");
        Log.i(TAG, "  Listening on   " + config.getHost() + ":" + config.getPort());
        Log.i(TAG, "  Secret:        " + config.getSecret());
        if (config.getFakeTlsDomain() != null && !config.getFakeTlsDomain().isEmpty()) {
            Log.i(TAG, "  Fake TLS:      " + config.getFakeTlsDomain());
        }
        Log.i(TAG, "  Target DC IPs:");
        for (Map.Entry<Integer, String> entry : config.getDcRedirects().entrySet()) {
            Log.i(TAG, "    DC" + entry.getKey() + ": " + entry.getValue());
        }
        if (config.isFallbackCfproxy()) {
            String userDomain = config.getCfproxyUserDomains().isEmpty() ? "auto" : "user";
            Log.i(TAG, "  CF proxy:      enabled (" + userDomain + ")");
        }
        if (!config.getCfproxyWorkerDomains().isEmpty()) {
            Log.i(TAG, "  CF worker:     enabled (" + String.join(", ", config.getCfproxyWorkerDomains()) + ")");
        }
        Log.i(TAG, "============================================================");
        String linkHost = MTProtoUtils.getLinkHost(config.getHost());
        String ddLink = "tg://proxy?server=" + linkHost +
                "&port=" + config.getPort() +
                "&secret=dd" + config.getSecret();
        Log.i(TAG, "  Connect:");
        if (config.getFakeTlsDomain() != null && !config.getFakeTlsDomain().isEmpty()) {
            String domainHex = bytesToHex(config.getFakeTlsDomain().getBytes());
            String eeLink = "tg://proxy?server=" + linkHost +
                    "&port=" + config.getPort() +
                    "&secret=ee" + config.getSecret() + domainHex;
            Log.i(TAG, "    " + eeLink);
        } else {
            Log.i(TAG, "    " + ddLink);
        }
        Log.i(TAG, "============================================================");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}