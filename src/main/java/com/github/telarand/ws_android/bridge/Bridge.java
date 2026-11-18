package com.github.telarand.ws_android.bridge;

import com.github.telarand.ws_android.utils.Logger;
import com.github.telarand.ws_android.balancer.Balancer;
import com.github.telarand.ws_android.config.ConfigManager;
import com.github.telarand.ws_android.config.ProxyConfig;
import com.github.telarand.ws_android.crypto.AesCtr;
import com.github.telarand.ws_android.net.CfH2Pool;
import com.github.telarand.ws_android.net.H2Channel;
import com.github.telarand.ws_android.net.RawWebSocket;
import com.github.telarand.ws_android.pool.Pools;
import com.github.telarand.ws_android.stats.Stats;
import com.github.telarand.ws_android.utils.MTProtoUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public final class Bridge {

    private static final String TAG = "Bridge";

    /** Backoff прямого TCP-fallback (порт reset_tcp_backoff/_tcp_fallback). */
    private static final double TCP_BACKOFF_INITIAL = 30.0;
    private static final double TCP_BACKOFF_MAX = 3600.0;
    private static final Map<String, Integer> tcpFailures = new ConcurrentHashMap<>();
    private static final Map<String, Double> tcpRetryAfter = new ConcurrentHashMap<>();
    private static final Set<String> tcpConnecting = ConcurrentHashMap.newKeySet();

    private static final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "bridge-worker");
        t.setDaemon(true);
        return t;
    });

    public static void resetTcpBackoff() {
        tcpFailures.clear();
        tcpRetryAfter.clear();
        tcpConnecting.clear();
    }

    public static boolean doFallback(Socket clientSocket,
                                     byte[] relayInit,
                                     String label,
                                     int dc,
                                     boolean isMedia,
                                     CryptoCtx ctx,
                                     MsgSplitter splitter) throws IOException {
        return doFallback(clientSocket, relayInit, label, dc, false, isMedia, ctx, splitter, null);
    }

    /**
     * Порт do_fallback: cf_worker -> cf (для media — H2) -> tcp.
     * @param isTestDc  тестовый DC (получен как dc >= 10000 или force_test_dc)
     * @param protoTag  исходный тег протокола клиента (нужен для H2-моста)
     */
    public static boolean doFallback(Socket clientSocket,
                                     byte[] relayInit,
                                     String label,
                                     int dc,
                                     boolean isTestDc,
                                     boolean isMedia,
                                     CryptoCtx ctx,
                                     MsgSplitter splitter,
                                     byte[] protoTag) throws IOException {
        ProxyConfig config = ConfigManager.getProxyConfig();
        Map<Integer, String> ipTable = isTestDc ? MTProtoUtils.DC_TEST_IPS : MTProtoUtils.DC_DEFAULT_IPS;
        String fallbackDst = ipTable.get(dc);
        boolean useCf = config.isFallbackCfproxy() && !isTestDc;
        List<String> workerDomains = config.getCfproxyWorkerDomains();

        List<String> methods = new ArrayList<>();
        if (!workerDomains.isEmpty() && fallbackDst != null) {
            methods.add("cf_worker");
        }
        if (useCf) {
            methods.add("cf");
        }
        if (fallbackDst != null) {
            methods.add("tcp");
        }

        for (String method : methods) {
            if ("cf_worker".equals(method) && fallbackDst != null) {
                boolean ok = cfproxyWorkerFallback(clientSocket, relayInit, label, ctx,
                        dc, isTestDc, isMedia, fallbackDst, splitter);
                if (ok) return true;
            } else if ("cf".equals(method)) {
                // Медиа сначала пробуем через HTTP/2 (cf_h2), затем обычный CF WS
                if (isMedia && config.isH2Enabled() && protoTag != null) {
                    H2Channel channel = null;
                    try {
                        channel = Pools.CF_H2_POOL.open(dc, label);
                    } catch (IOException e) {
                        Logger.w(TAG, String.format("[%s] H2 pool error: %s", label, e.getMessage()));
                    }
                    if (channel != null) {
                        Stats.INSTANCE.incConnectionsH2();
                        Stats.INSTANCE.incConnectionsCfproxy();
                        try {
                            bridgeH2(clientSocket, channel, ctx, protoTag);
                        } finally {
                            channel.close();
                        }
                        return true;
                    }
                }
                boolean ok = cfproxyFallback(clientSocket, relayInit, label, ctx,
                        dc, isMedia, splitter);
                if (ok) return true;
            } else if ("tcp".equals(method) && fallbackDst != null) {
                boolean ok = tcpFallback(clientSocket, relayInit, label, ctx,
                        fallbackDst, 443);
                if (ok) return true;
            }
        }
        return false;
    }

    private static boolean cfproxyWorkerFallback(Socket clientSocket,
                                                 byte[] relayInit,
                                                 String label,
                                                 CryptoCtx ctx,
                                                 int dc,
                                                 boolean isTestDc,
                                                 boolean isMedia,
                                                 String fallbackDst,
                                                 MsgSplitter splitter) {
        String mediaTag = isMedia ? " media" : "";
        List<String> workerDomains = ConfigManager.getProxyConfig().getCfproxyWorkerDomains();
        if (workerDomains.isEmpty()) return false;

        List<String> shuffled = new ArrayList<>(workerDomains);
        Collections.shuffle(shuffled, new Random());

        for (String workerDomain : shuffled) {
            RawWebSocket ws = null;
            try {
                if (!isTestDc) {
                    ws = Pools.CF_WORKER_POOL.get(dc, workerDomain, fallbackDst);
                    if (ws != null) {
                        Logger.i(TAG, String.format("[%s] DC%d%s -> CF worker pool hit via %s for %s",
                                label, dc, mediaTag, workerDomain, fallbackDst));
                    }
                }
                if (ws == null) {
                    String query = "dst=" + URLEncoder.encode(fallbackDst, StandardCharsets.UTF_8.name())
                            + "&dc=" + dc;
                    String path = "/apiws?" + query;
                    Logger.i(TAG, String.format("[%s] DC%d%s -> trying CF worker %s for %s",
                            label, dc, mediaTag, workerDomain, fallbackDst));
                    ws = RawWebSocket.connect(workerDomain, workerDomain, 10.0f, path,
                            null, !ConfigManager.getProxyConfig().isDisableSecure());
                }
            } catch (Exception e) {
                Logger.w(TAG, String.format("[%s] DC%d%s CF worker %s failed: %s",
                        label, dc, mediaTag, workerDomain, e.getMessage()));
                continue;
            }

            if (ws != null) {
                Stats.INSTANCE.incConnectionsCfproxy();
                try {
                    ws.send(relayInit);
                    bridgeWsReencrypt(clientSocket, ws, label, ctx, dc, isMedia, splitter);
                    return true;
                } catch (IOException e) {
                    Logger.w(TAG, "WS bridge failed", e);
                    try { ws.close(); } catch (Exception ignored) {}
                }
            }
        }
        return false;
    }

    private static boolean cfproxyFallback(Socket clientSocket,
                                           byte[] relayInit,
                                           String label,
                                           CryptoCtx ctx,
                                           int dc,
                                           boolean isMedia,
                                           MsgSplitter splitter) {
        String mediaTag = isMedia ? " media" : "";
        Logger.i(TAG, String.format("[%s] DC%d%s -> trying CF proxy", label, dc, mediaTag));

        RawWebSocket ws = null;
        String chosenDomain = null;
        boolean secure = !ConfigManager.getProxyConfig().isDisableSecure();

        Iterator<String> domainIter = Balancer.INSTANCE.getDomainsForDc(dc);
        while (domainIter.hasNext()) {
            String baseDomain = domainIter.next();
            String domain = "kws" + dc + "." + baseDomain;
            try {
                ws = RawWebSocket.connect(domain, domain, 10.0f, "/apiws", null, secure);
                chosenDomain = baseDomain;
                break;
            } catch (Exception e) {
                Logger.w(TAG, String.format("[%s] DC%d%s CF proxy failed: %s",
                        label, dc, mediaTag, e.getMessage()));
            }
        }

        if (ws == null) return false;

        if (chosenDomain != null) {
            boolean updated = Balancer.INSTANCE.updateDomainForDc(dc, chosenDomain);
            if (updated) {
                Logger.i(TAG, String.format("[%s] Switched active CF domain", label));
            }
        }

        Stats.INSTANCE.incConnectionsCfproxy();
        try {
            ws.send(relayInit);
            bridgeWsReencrypt(clientSocket, ws, label, ctx, dc, isMedia, splitter);
            return true;
        } catch (IOException e) {
            Logger.w(TAG, "WS bridge failed", e);
            try { ws.close(); } catch (Exception ignored) {}
            return false;
        }
    }

    /** Порт _tcp_fallback: пропуск по backoff, коннект-таймаут 10 c. */
    private static boolean tcpFallback(Socket clientSocket,
                                       byte[] relayInit,
                                       String label,
                                       CryptoCtx ctx,
                                       String dst,
                                       int port) {
        String key = dst + ":" + port;
        double now = System.nanoTime() / 1_000_000_000.0;
        Double after = tcpRetryAfter.get(key);
        if (tcpConnecting.contains(key) || (after != null && now < after)) {
            Logger.d(TAG, String.format("[%s] TCP fallback to %s skipped (backoff or connecting)", label, key));
            return false;
        }

        tcpConnecting.add(key);
        Socket remoteSocket = null;
        try {
            try {
                Logger.i(TAG, String.format("[%s] TCP fallback to %s", label, key));
                remoteSocket = new Socket();
                remoteSocket.connect(new InetSocketAddress(dst, port), 10000);
                remoteSocket.setSoTimeout(30000);
                OutputStream out = remoteSocket.getOutputStream();
                out.write(relayInit);
                out.flush();
            } catch (Exception e) {
                int failures = tcpFailures.getOrDefault(key, 0) + 1;
                tcpFailures.put(key, failures);
                double delay = Math.min(TCP_BACKOFF_INITIAL * Math.pow(2, Math.min(failures - 1, 7)),
                        TCP_BACKOFF_MAX);
                tcpRetryAfter.put(key, System.nanoTime() / 1_000_000_000.0 + delay);
                Logger.w(TAG, String.format("[%s] TCP fallback to %s failed: %s; retry in %.0fs",
                        label, key, e.getMessage(), delay));
                try { if (remoteSocket != null) remoteSocket.close(); } catch (Exception ignored) {}
                return false;
            } finally {
                tcpConnecting.remove(key);
            }

            tcpFailures.remove(key);
            tcpRetryAfter.remove(key);
            Stats.INSTANCE.incConnectionsTcpFallback();
            try {
                bridgeTcpReencrypt(clientSocket, remoteSocket, label, ctx);
                return true;
            } catch (IOException e) {
                Logger.d(TAG, "[" + label + "] tcp bridge io: " + e.getMessage());
                return false;
            }
        } finally {
            try { if (remoteSocket != null) remoteSocket.close(); } catch (Exception ignored) {}
        }
    }

    /**
     * Порт bridge_h2: клиент <-> HTTP/2-канал с перешифрованием.
     * Ошибка конечной точки доставляется клиенту специальным пакетом.
     */
    public static void bridgeH2(Socket clientSocket,
                                H2Channel channel,
                                CryptoCtx ctx,
                                byte[] protoTag) {
        String label = channel.getLabel();
        long startTime = System.currentTimeMillis();
        InputStream clientIn;
        OutputStream clientOut;
        try {
            clientIn = clientSocket.getInputStream();
            clientOut = clientSocket.getOutputStream();
        } catch (IOException e) {
            return;
        }

        H2Channel.AesLike dec = aesLike(clientIn, ctx.cltDec);
        long[] downBytes = {0};

        // upload: читаем пакеты клиента и отправляем POST-ами
        Future<?> upload = executor.submit(() -> {
            try {
                while (true) {
                    byte[] body = H2Channel.readPacket(clientIn, dec, protoTag);
                    Stats.INSTANCE.addBytesUp(body.length);
                    channel.countUp(body.length);
                    if (!channel.send(body)) {
                        break;
                    }
                }
            } catch (Exception e) {
                Logger.d(TAG, "[" + label + "] h2 upload ended: " + e.getMessage());
                channel.fail(new IOException("native upload ended: " + e.getMessage()));
            }
        });

        // download: ответы канала -> клиент
        Future<?> download = executor.submit(() -> {
            try {
                while (true) {
                    byte[] reply = channel.receive();
                    byte[] packet = H2Channel.encodeReply(reply, protoTag);
                    downBytes[0] += reply.length;
                    Stats.INSTANCE.addBytesDown(reply.length);
                    channel.countDown(reply.length);
                    clientOut.write(packet);
                    clientOut.flush();
                }
            } catch (Exception e) {
                Logger.d(TAG, "[" + label + "] h2 download ended: " + e.getMessage());
            }
        });

        try {
            // ждём завершения любого направления
            while (!upload.isDone() && !download.isDone()) {
                Thread.sleep(50);
            }
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        } finally {
            upload.cancel(true);
            download.cancel(true);
            channel.close();
            int transportError = channel.getTransportError();
            if (transportError != 0) {
                try {
                    ByteBuffer err = ByteBuffer.allocate(4).order(java.nio.ByteOrder.LITTLE_ENDIAN);
                    err.putInt(transportError);
                    byte[] errPacket = H2Channel.encodeReply(err.array(), protoTag);
                    clientOut.write(errPacket);
                    clientOut.flush();
                    Stats.INSTANCE.addBytesDown(4);
                } catch (Exception ignored) {}
            }
        }

        double elapsed = (System.currentTimeMillis() - startTime) / 1000.0;
        Stats.INSTANCE.addBytesUp(channel.getUp());
        Logger.i(TAG, String.format("[%s] H2 channel=%d session closed: ^%s v%s in %.1fs",
                label, channel.getChannelId(),
                MTProtoUtils.humanBytes(channel.getUp()),
                MTProtoUtils.humanBytes(downBytes[0]),
                elapsed));
    }

    private static H2Channel.AesLike aesLike(InputStream in, AesCtr.Encryptor dec) {
        return new H2Channel.AesLike() {
            @Override
            public byte[] update(byte[] data) {
                return dec.update(data);
            }

            @Override
            public int read(byte[] out, int off, int len) throws IOException {
                return in.read(out, off, len);
            }
        };
    }

    public static void bridgeWsReencrypt(Socket clientSocket,
                                         RawWebSocket ws,
                                         String label,
                                         CryptoCtx ctx,
                                         int dc,
                                         boolean isMedia,
                                         MsgSplitter splitter) throws IOException {
        String dcTag = (dc > 0) ? "DC" + dc + (isMedia ? "m" : "") : "DC?";
        InputStream clientIn = clientSocket.getInputStream();
        OutputStream clientOut = clientSocket.getOutputStream();

        long startTime = System.currentTimeMillis();
        long[] upBytes = {0};
        long[] downBytes = {0};
        long[] upPackets = {0};
        long[] downPackets = {0};

        Runnable tcpToWs = () -> {
            try {
                byte[] buffer = new byte[65536];
                while (true) {
                    int len = clientIn.read(buffer);
                    if (len < 0) {
                        if (splitter != null) {
                            List<byte[]> tail = splitter.flush();
                            if (!tail.isEmpty()) {
                                ws.send(tail.get(0));
                            }
                        }
                        break;
                    }
                    Stats.INSTANCE.addBytesUp(len);
                    upBytes[0] += len;
                    upPackets[0]++;
                    byte[] plain = ctx.cltDec.update(buffer, 0, len);
                    byte[] encrypted = ctx.tgEnc.update(plain);
                    if (splitter != null) {
                        List<byte[]> parts = splitter.split(encrypted);
                        if (!parts.isEmpty()) {
                            if (parts.size() > 1) {
                                ws.sendBatch(parts);
                            } else {
                                ws.send(parts.get(0));
                            }
                        }
                    } else {
                        ws.send(encrypted);
                    }
                }
            } catch (Exception e) {
                Logger.d(TAG, "[" + label + "] tcp->ws ended: " + e.getMessage());
            }
        };

        Runnable wsToTcp = () -> {
            try {
                while (true) {
                    byte[] data = ws.recv();
                    if (data == null) break;
                    Stats.INSTANCE.addBytesDown(data.length);
                    downBytes[0] += data.length;
                    downPackets[0]++;
                    byte[] plain = ctx.tgDec.update(data);
                    byte[] encrypted = ctx.cltEnc.update(plain);
                    clientOut.write(encrypted);
                    clientOut.flush();
                }
            } catch (Exception e) {
                Logger.d(TAG, "[" + label + "] ws->tcp ended: " + e.getMessage());
            }
        };

        Future<?> f1 = executor.submit(tcpToWs);
        Future<?> f2 = executor.submit(wsToTcp);

        try {
            while (true) {
                if (f1.isDone() || f2.isDone()) break;
                Thread.sleep(100);
            }
        } catch (InterruptedException ignored) {}

        f1.cancel(true);
        f2.cancel(true);

        long elapsed = (System.currentTimeMillis() - startTime) / 1000;
        Logger.i(TAG, String.format("[%s] %s WS session closed: ^%s (%d pkts) v%s (%d pkts) in %.1fs",
                label, dcTag,
                MTProtoUtils.humanBytes(upBytes[0]), upPackets[0],
                MTProtoUtils.humanBytes(downBytes[0]), downPackets[0],
                (double) elapsed));

        try { ws.close(); } catch (Exception ignored) {}
        try { clientSocket.close(); } catch (Exception ignored) {}
    }

    public static void bridgeTcpReencrypt(Socket clientSocket,
                                          Socket remoteSocket,
                                          String label,
                                          CryptoCtx ctx) throws IOException {
        InputStream clientIn = clientSocket.getInputStream();
        OutputStream clientOut = clientSocket.getOutputStream();
        InputStream remoteIn = remoteSocket.getInputStream();
        OutputStream remoteOut = remoteSocket.getOutputStream();

        Runnable forwardUp = () -> {
            try {
                byte[] buffer = new byte[65536];
                while (true) {
                    int len = clientIn.read(buffer);
                    if (len < 0) break;
                    Stats.INSTANCE.addBytesUp(len);
                    byte[] plain = ctx.cltDec.update(buffer, 0, len);
                    byte[] encrypted = ctx.tgEnc.update(plain);
                    remoteOut.write(encrypted);
                    remoteOut.flush();
                }
            } catch (Exception e) {
                Logger.d(TAG, "[" + label + "] forward up ended: " + e.getMessage());
            }
        };

        Runnable forwardDown = () -> {
            try {
                byte[] buffer = new byte[65536];
                while (true) {
                    int len = remoteIn.read(buffer);
                    if (len < 0) break;
                    Stats.INSTANCE.addBytesDown(len);
                    byte[] plain = ctx.tgDec.update(buffer, 0, len);
                    byte[] encrypted = ctx.cltEnc.update(plain);
                    clientOut.write(encrypted);
                    clientOut.flush();
                }
            } catch (Exception e) {
                Logger.d(TAG, "[" + label + "] forward down ended: " + e.getMessage());
            }
        };

        Future<?> f1 = executor.submit(forwardUp);
        Future<?> f2 = executor.submit(forwardDown);

        try {
            while (true) {
                if (f1.isDone() || f2.isDone()) break;
                Thread.sleep(100);
            }
        } catch (InterruptedException ignored) {}

        f1.cancel(true);
        f2.cancel(true);

        try { clientSocket.close(); } catch (Exception ignored) {}
        try { remoteSocket.close(); } catch (Exception ignored) {}
    }

    public static CryptoCtx createCryptoCtx(byte[] clientKey, byte[] clientIv,
                                            byte[] tgKey, byte[] tgIv) {
        AesCtr.AES aesClt = new AesCtr.AES(clientKey);
        AesCtr.CTR ctrClt = new AesCtr.CTR(clientIv);
        AesCtr.CipherFactory cfClt = new AesCtr.CipherFactory(aesClt, ctrClt);

        AesCtr.AES aesTg = new AesCtr.AES(tgKey);
        AesCtr.CTR ctrTg = new AesCtr.CTR(tgIv);
        AesCtr.CipherFactory cfTg = new AesCtr.CipherFactory(aesTg, ctrTg);

        return new CryptoCtx(
                cfClt.decryptor(),
                cfClt.encryptor(),
                cfTg.encryptor(),
                cfTg.decryptor()
        );
    }
}
