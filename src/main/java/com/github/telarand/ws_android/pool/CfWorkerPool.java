package com.github.telarand.ws_android.pool;

import android.util.Log;

import com.github.telarand.ws_android.config.ConfigManager;
import com.github.telarand.ws_android.config.ProxyConfig;
import com.github.telarand.ws_android.net.RawWebSocket;
import com.github.telarand.ws_android.stats.Stats;
import com.github.telarand.ws_android.utils.MTProtoUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/**
 * Пул WebSocket-соединений для Cloudflare Worker.
 */
public final class CfWorkerPool {

    private static final String TAG = "CfWorkerPool";
    private static final double WS_POOL_MAX_AGE = 120.0;

    private final Map<CfKey, Deque<WsEntry>> idle = new ConcurrentHashMap<>();
    private final Set<CfKey> refilling = ConcurrentHashMap.newKeySet();

    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "cf-worker-pool-refill");
        t.setDaemon(true);
        return t;
    });

    private static final class CfKey {
        final int dc;
        final String workerDomain;
        CfKey(int dc, String workerDomain) {
            this.dc = dc;
            this.workerDomain = workerDomain;
        }
        @Override public boolean equals(Object o) {
            if (!(o instanceof CfKey)) return false;
            CfKey k = (CfKey) o;
            return dc == k.dc && workerDomain.equals(k.workerDomain);
        }
        @Override public int hashCode() {
            return 31 * dc + workerDomain.hashCode();
        }
    }

    private static final class WsEntry {
        final RawWebSocket ws;
        final double created;
        WsEntry(RawWebSocket ws) {
            this.ws = ws;
            this.created = System.nanoTime() / 1_000_000_000.0;
        }
    }

    public RawWebSocket get(int dc, String workerDomain, String fallbackDst) {
        CfKey key = new CfKey(dc, workerDomain);
        Deque<WsEntry> bucket = idle.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>());

        double now = System.nanoTime() / 1_000_000_000.0;

        while (!bucket.isEmpty()) {
            WsEntry entry = bucket.poll();
            RawWebSocket ws = entry.ws;
            double age = now - entry.created;
            boolean isClosed = ws.isClosed();
            if (age > WS_POOL_MAX_AGE || isClosed) {
                quietClose(ws);
                continue;
            }
            Stats.INSTANCE.incCfPoolHits();
            Log.d(TAG, String.format("CF worker pool hit DC%d (age=%.1fs, left=%d)",
                    dc, age, bucket.size()));
            scheduleRefill(key, fallbackDst);
            return ws;
        }

        Stats.INSTANCE.incCfPoolMisses();
        scheduleRefill(key, fallbackDst);
        return null;
    }

    private void scheduleRefill(CfKey key, String fallbackDst) {
        if (refilling.add(key)) {
            executor.submit(() -> {
                try {
                    refill(key, fallbackDst);
                } catch (Exception e) {
                    Log.w(TAG, "Refill failed for " + key.dc + "/" + key.workerDomain, e);
                } finally {
                    refilling.remove(key);
                }
            });
        }
    }

    private void refill(CfKey key, String fallbackDst) {
        Deque<WsEntry> bucket = idle.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>());
        int currentSize = bucket.size();
        int needed = ConfigManager.getProxyConfig().getPoolSize() - currentSize;
        if (needed <= 0) return;

        List<CompletableFuture<RawWebSocket>> futures = new ArrayList<>(needed);
        for (int i = 0; i < needed; i++) {
            futures.add(CompletableFuture.supplyAsync(() ->
                    connectOne(key.workerDomain, fallbackDst, key.dc), executor));
        }

        for (CompletableFuture<RawWebSocket> future : futures) {
            try {
                RawWebSocket ws = future.get(8, TimeUnit.SECONDS);
                if (ws != null) {
                    bucket.add(new WsEntry(ws));
                }
            } catch (Exception ignored) {}
        }

        Log.d(TAG, String.format("CF worker pool refilled DC%d: %d ready", key.dc, bucket.size()));
    }

    private RawWebSocket connectOne(String workerDomain, String fallbackDst, int dc) {
        String query;
        try {
            query = "dst=" + URLEncoder.encode(fallbackDst, StandardCharsets.UTF_8.name())
                    + "&dc=" + dc;
        } catch (UnsupportedEncodingException e) {
            query = "dst=" + fallbackDst + "&dc=" + dc;
        }
        String path = "/apiws?" + query;
        try {
            return RawWebSocket.connect(workerDomain, workerDomain, 8.0f, path);
        } catch (IOException e) {
            return null;
        }
    }

    private void quietClose(RawWebSocket ws) {
        try {
            if (ws != null) ws.close();
        } catch (Exception ignored) {}
    }

    public void warmup() {
        ProxyConfig config = ConfigManager.getProxyConfig();
        Map<Integer, String> defaultIps = MTProtoUtils.DC_DEFAULT_IPS;
        Map<Integer, String> redirects = config.getDcRedirects();

        Map<Integer, String> fallbacks = new HashMap<>();
        for (Map.Entry<Integer, String> entry : defaultIps.entrySet()) {
            int dc = entry.getKey();
            if (!redirects.containsKey(dc)) {
                fallbacks.put(dc, entry.getValue());
            }
        }

        if (fallbacks.isEmpty() || config.getCfproxyWorkerDomains().isEmpty()) {
            Log.i(TAG, "CF worker pool warmup skipped (no fallback DCs or no worker domains)");
            return;
        }

        for (String workerDomain : config.getCfproxyWorkerDomains()) {
            for (Map.Entry<Integer, String> entry : fallbacks.entrySet()) {
                int dc = entry.getKey();
                String fallbackDst = entry.getValue();
                CfKey key = new CfKey(dc, workerDomain);
                scheduleRefill(key, fallbackDst);
            }
        }

        Log.i(TAG, "CF worker pool warmup started for " + fallbacks.size() + " DC(s)");
    }

    public void reset() {
        for (Deque<WsEntry> bucket : idle.values()) {
            for (WsEntry entry : bucket) {
                quietClose(entry.ws);
            }
            bucket.clear();
        }
        idle.clear();
        refilling.clear();
        executor.shutdownNow();
    }
}