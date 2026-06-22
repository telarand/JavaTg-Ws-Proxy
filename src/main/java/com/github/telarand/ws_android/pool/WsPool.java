package com.github.telarand.ws_android.pool;

import android.util.Log;

import com.github.telarand.ws_android.config.ConfigManager;
import com.github.telarand.ws_android.config.ProxyConfig;
import com.github.telarand.ws_android.net.RawWebSocket;
import com.github.telarand.ws_android.stats.Stats;
import com.github.telarand.ws_android.utils.MTProtoUtils;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;

/**
 * Пул WebSocket-соединений для обычных DC (не Cloudflare).
 */
public final class WsPool {

    private static final String TAG = "WsPool";
    private static final double WS_POOL_MAX_AGE = 120.0;

    private final Map<PoolKey, Deque<WsEntry>> idle = new ConcurrentHashMap<>();
    private final Set<PoolKey> refilling = ConcurrentHashMap.newKeySet();

    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "ws-pool-refill");
        t.setDaemon(true);
        return t;
    });

    private static final class PoolKey {
        final int dc;
        final boolean isMedia;
        PoolKey(int dc, boolean isMedia) { this.dc = dc; this.isMedia = isMedia; }
        @Override public boolean equals(Object o) {
            if (!(o instanceof PoolKey)) return false;
            PoolKey k = (PoolKey) o;
            return dc == k.dc && isMedia == k.isMedia;
        }
        @Override public int hashCode() {
            return 31 * dc + (isMedia ? 1 : 0);
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

    /**
     * Получает соединение из пула или создаёт новое (с фоновым пополнением).
     * @param dc        номер DC
     * @param isMedia   флаг медиа-домена
     * @param targetIp  IP-адрес для подключения
     * @param domains   список доменов для проб (по порядку)
     * @return          объект RawWebSocket или null, если не удалось
     */
    public RawWebSocket get(int dc, boolean isMedia, String targetIp, List<String> domains) {
        PoolKey key = new PoolKey(dc, isMedia);
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
            Stats.INSTANCE.incPoolHits();
            Log.d(TAG, String.format("WS pool hit DC%d%s (age=%.1fs, left=%d)",
                    dc, isMedia ? "m" : "", age, bucket.size()));
            scheduleRefill(key, targetIp, domains);
            return ws;
        }

        Stats.INSTANCE.incPoolMisses();
        scheduleRefill(key, targetIp, domains);
        return null;
    }

    private void scheduleRefill(PoolKey key, String targetIp, List<String> domains) {
        if (refilling.add(key)) {
            executor.submit(() -> {
                try {
                    refill(key, targetIp, domains);
                } catch (Exception e) {
                    Log.w(TAG, "Refill failed for " + key.dc + "/" + key.isMedia, e);
                } finally {
                    refilling.remove(key);
                }
            });
        }
    }

    private void refill(PoolKey key, String targetIp, List<String> domains) {
        Deque<WsEntry> bucket = idle.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>());
        int currentSize = bucket.size();
        int needed = ConfigManager.getProxyConfig().getPoolSize() - currentSize;
        if (needed <= 0) return;

        List<CompletableFuture<RawWebSocket>> futures = new ArrayList<>(needed);
        for (int i = 0; i < needed; i++) {
            futures.add(CompletableFuture.supplyAsync(() -> connectOne(targetIp, domains), executor));
        }

        for (CompletableFuture<RawWebSocket> future : futures) {
            try {
                RawWebSocket ws = future.get(8, TimeUnit.SECONDS);
                if (ws != null) {
                    bucket.add(new WsEntry(ws));
                }
            } catch (Exception ignored) {
            }
        }

        Log.d(TAG, String.format("WS pool refilled DC%d%s: %d ready",
                key.dc, key.isMedia ? "m" : "", bucket.size()));
    }

    private RawWebSocket connectOne(String targetIp, List<String> domains) {
        for (String domain : domains) {
            try {
                return RawWebSocket.connect(targetIp, domain, 8.0f, "/apiws");
            } catch (RawWebSocket.WsHandshakeException e) {
                if (e.isRedirect()) {
                    continue;
                }
                return null;
            } catch (IOException e) {
                return null;
            }
        }
        return null;
    }

    private void quietClose(RawWebSocket ws) {
        try {
            if (ws != null) ws.close();
        } catch (Exception ignored) {}
    }

    /**
     * Запускает пополнение для всех DC из dc_redirects (и для isMedia = true/false).
     */
    public void warmup() {
        ProxyConfig config = ConfigManager.getProxyConfig();
        Map<Integer, String> redirects = config.getDcRedirects();
        for (Map.Entry<Integer, String> entry : redirects.entrySet()) {
            int dc = entry.getKey();
            String targetIp = entry.getValue();
            if (targetIp == null || targetIp.isEmpty()) continue;
            for (boolean isMedia : new boolean[]{false, true}) {
                List<String> domains = MTProtoUtils.wsDomains(dc, isMedia);
                PoolKey key = new PoolKey(dc, isMedia);
                scheduleRefill(key, targetIp, domains);
            }
        }
        Log.i(TAG, "WS pool warmup started for " + redirects.size() + " DC(s)");
    }

    /**
     * Полностью очищает пул.
     */
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