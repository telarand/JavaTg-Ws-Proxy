package com.github.telarand.ws_android.bridge;

import android.util.Log;

import com.github.telarand.ws_android.balancer.Balancer;
import com.github.telarand.ws_android.config.ConfigManager;
import com.github.telarand.ws_android.config.ProxyConfig;
import com.github.telarand.ws_android.crypto.AesCtr;
import com.github.telarand.ws_android.net.RawWebSocket;
import com.github.telarand.ws_android.pool.Pools;
import com.github.telarand.ws_android.stats.Stats;
import com.github.telarand.ws_android.utils.MTProtoUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public final class Bridge {

    private static final String TAG = "Bridge";
    private static final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "bridge-worker");
        t.setDaemon(true);
        return t;
    });

    public static boolean doFallback(Socket clientSocket,
                                     byte[] relayInit,
                                     String label,
                                     int dc,
                                     boolean isMedia,
                                     CryptoCtx ctx,
                                     MsgSplitter splitter) throws IOException {
        ProxyConfig config = ConfigManager.getProxyConfig();
        String fallbackDst = MTProtoUtils.DC_DEFAULT_IPS.get(dc);
        boolean useCf = config.isFallbackCfproxy();
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
                        dc, isMedia, fallbackDst, splitter);
                if (ok) return true;
            } else if ("cf".equals(method)) {
                boolean ok = cfproxyFallback(clientSocket, relayInit, label, ctx,
                        dc, isMedia, splitter);
                if (ok) return true;
            } else if ("tcp".equals(method) && fallbackDst != null) {
                String mediaTag = isMedia ? " media" : "";
                Log.i(TAG, String.format("[%s] DC%d%s -> TCP fallback to %s:443",
                        label, dc, mediaTag, fallbackDst));
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
                                                 boolean isMedia,
                                                 String fallbackDst,
                                                 MsgSplitter splitter) {
        String mediaTag = isMedia ? " media" : "";
        List<String> workerDomains = ConfigManager.getProxyConfig().getCfproxyWorkerDomains();
        if (workerDomains.isEmpty()) return false;

        Collections.shuffle(workerDomains, new Random());

        for (String workerDomain : workerDomains) {
            RawWebSocket ws = null;
            try {
                ws = Pools.CF_WORKER_POOL.get(dc, workerDomain, fallbackDst);
                if (ws != null) {
                    Log.i(TAG, String.format("[%s] DC%d%s -> CF worker pool hit for %s",
                            label, dc, mediaTag, fallbackDst));
                } else {
                    String query = "dst=" + URLEncoder.encode(fallbackDst, StandardCharsets.UTF_8.name())
                            + "&dc=" + dc;
                    String path = "/apiws?" + query;
                    Log.i(TAG, String.format("[%s] DC%d%s -> trying CF worker %s for %s",
                            label, dc, mediaTag, workerDomain, fallbackDst));
                    ws = RawWebSocket.connect(workerDomain, workerDomain, 10.0f, path);
                }
            } catch (Exception e) {
                Log.w(TAG, String.format("[%s] DC%d%s CF worker %s failed: %s",
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
                    Log.w(TAG, "WS bridge failed", e);
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
        Log.i(TAG, String.format("[%s] DC%d%s -> trying CF proxy", label, dc, mediaTag));

        RawWebSocket ws = null;
        String chosenDomain = null;

        Iterator<String> domainIter = Balancer.INSTANCE.getDomainsForDc(dc);
        while (domainIter.hasNext()) {
            String baseDomain = domainIter.next();
            String domain = "kws" + dc + "." + baseDomain;
            try {
                ws = RawWebSocket.connect(domain, domain, 10.0f, "/apiws");
                chosenDomain = baseDomain;
                break;
            } catch (Exception e) {
                Log.w(TAG, String.format("[%s] DC%d%s CF proxy failed: %s",
                        label, dc, mediaTag, e.getMessage()));
            }
        }

        if (ws == null) return false;

        if (chosenDomain != null) {
            boolean updated = Balancer.INSTANCE.updateDomainForDc(dc, chosenDomain);
            if (updated) {
                Log.i(TAG, String.format("[%s] Switched active CF domain", label));
            }
        }

        Stats.INSTANCE.incConnectionsCfproxy();
        try {
            ws.send(relayInit);
            bridgeWsReencrypt(clientSocket, ws, label, ctx, dc, isMedia, splitter);
            return true;
        } catch (IOException e) {
            Log.w(TAG, "WS bridge failed", e);
            try { ws.close(); } catch (Exception ignored) {}
            return false;
        }
    }

    private static boolean tcpFallback(Socket clientSocket,
                                       byte[] relayInit,
                                       String label,
                                       CryptoCtx ctx,
                                       String dst,
                                       int port) {
        Socket remoteSocket = null;
        try {
            remoteSocket = new Socket(dst, port);
            remoteSocket.setSoTimeout(30000);
            OutputStream out = remoteSocket.getOutputStream();
            out.write(relayInit);
            out.flush();

            Stats.INSTANCE.incConnectionsTcpFallback();
            bridgeTcpReencrypt(clientSocket, remoteSocket, label, ctx);
            return true;
        } catch (Exception e) {
            Log.w(TAG, String.format("[%s] TCP fallback to %s:%d failed: %s",
                    label, dst, port, e.getMessage()));
            try { if (remoteSocket != null) remoteSocket.close(); } catch (Exception ignored) {}
            return false;
        }
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
                Log.d(TAG, "[" + label + "] tcp->ws ended: " + e.getMessage());
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
                Log.d(TAG, "[" + label + "] ws->tcp ended: " + e.getMessage());
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
        Log.i(TAG, String.format("[%s] %s WS session closed: ^%s (%d pkts) v%s (%d pkts) in %.1fs",
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
                Log.d(TAG, "[" + label + "] forward up ended: " + e.getMessage());
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
                Log.d(TAG, "[" + label + "] forward down ended: " + e.getMessage());
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