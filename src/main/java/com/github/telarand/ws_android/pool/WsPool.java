package com.github.telarand.ws_android.pool;

import com.github.telarand.ws_android.utils.Logger;
import com.github.telarand.ws_android.config.ConfigManager;
import com.github.telarand.ws_android.config.ProxyConfig;
import com.github.telarand.ws_android.net.RawWebSocket;
import com.github.telarand.ws_android.stats.Stats;
import com.github.telarand.ws_android.utils.MTProtoUtils;
import com.github.telarand.ws_android.pool.PoolTimingConfig;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;

/**
 * Пул WebSocket-соединений для прямых DC (не Cloudflare).
 *
 * Обновлено до ядра основной ветки:
 *  - domain fronting: SNI "sprinthost.ru" + Host kws*.web.telegram.org;
 *    запоминание удачного режима (fronting-first / direct-first);
 *  - фоновая ротация: чистка протухших соединений каждые 5 c,
 *    автопополнение пула до целевого размера;
 *  - экспоненциальный backoff неудачных пополнений (1 c .. 1 ч);
 *  - поддержка тестовых DC (путь /apiws_test).
 */
public final class WsPool {

    private static final String TAG = "WsPool";
    private static final String FRONTING_SNI = "sprinthost.ru";

    private final Map<PoolKey, Deque<WsEntry>> idle = new ConcurrentHashMap<>();
    private final Set<PoolKey> refilling = ConcurrentHashMap.newKeySet();
    private final Set<PoolKey> rotating = ConcurrentHashMap.newKeySet();
    private final Map<PoolKey, Double> refillAfter = new ConcurrentHashMap<>();
    private final Map<PoolKey, Integer> refillFailures = new ConcurrentHashMap<>();

    /** sticky-флаг: начинать ли следующий коннект с fronting */
    private volatile boolean tryFrontingFirst = false;

    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2, r -> {
        Thread t = new Thread(r, "ws-pool-rotate");
        t.setDaemon(true);
        return t;
    });

    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "ws-pool-refill");
        t.setDaemon(true);
        return t;
    });

    private static final class PoolKey {
        final int dc;
        final boolean isMedia;
        final boolean isTestDc;
        PoolKey(int dc, boolean isMedia, boolean isTestDc) {
            this.dc = dc;
            this.isMedia = isMedia;
            this.isTestDc = isTestDc;
        }
        @Override public boolean equals(Object o) {
            if (!(o instanceof PoolKey)) return false;
            PoolKey k = (PoolKey) o;
            return dc == k.dc && isMedia == k.isMedia && isTestDc == k.isTestDc;
        }
        @Override public int hashCode() {
            return (31 * dc + (isMedia ? 1 : 0)) * 2 + (isTestDc ? 1 : 0);
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
     * Получает соединение из пула (с фоновым пополнением и ротацией).
     * @param dc        номер DC
     * @param isMedia   флаг медиа-домена
     * @param targetIp  IP-адрес для подключения
     * @param domains   список доменов для проб (по порядку)
     * @return          объект RawWebSocket или null, если не удалось
     */
    public RawWebSocket get(int dc, boolean isMedia, String targetIp, List<String> domains) {
        return get(dc, isMedia, targetIp, domains, false);
    }

    public RawWebSocket get(int dc, boolean isMedia, String targetIp, List<String> domains, boolean isTestDc) {
        PoolKey key = new PoolKey(dc, isMedia, isTestDc);
        Deque<WsEntry> bucket = idle.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>());

        double now = System.nanoTime() / 1_000_000_000.0;
        double maxAge = PoolTimingConfig.getWsPoolMaxAge();

        while (!bucket.isEmpty()) {
            WsEntry entry = bucket.poll();
            RawWebSocket ws = entry.ws;
            double age = now - entry.created;
            boolean isClosed = ws.isClosed();
            if (age > maxAge || isClosed) {
                quietClose(ws);
                continue;
            }
            Stats.INSTANCE.incPoolHits();
            Logger.d(TAG, String.format("WS pool hit DC%d%s%s (age=%.1fs, left=%d)",
                    dc, isTestDc ? "t" : "", isMedia ? "m" : "", age, bucket.size()));
            schedule(key, targetIp, domains);
            return ws;
        }

        Stats.INSTANCE.incPoolMisses();
        schedule(key, targetIp, domains);
        return null;
    }

    private void schedule(PoolKey key, String targetIp, List<String> domains) {
        scheduleRotation(key, targetIp, domains);
        scheduleRefill(key, targetIp, domains);
    }

    private void scheduleRefill(PoolKey key, String targetIp, List<String> domains) {
        double now = System.nanoTime() / 1_000_000_000.0;
        Double after = refillAfter.get(key);
        if (after != null && now < after) {
            return;
        }
        if (refilling.add(key)) {
            executor.submit(() -> {
                try {
                    refill(key, targetIp, domains);
                } catch (Exception e) {
                    Logger.w(TAG, "Refill failed for " + key.dc + "/" + key.isMedia, e);
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
        if (needed <= 0) {
            refillFailures.remove(key);
            refillAfter.remove(key);
            return;
        }

        String path = key.isTestDc ? MTProtoUtils.WS_PATH_TEST : MTProtoUtils.WS_PATH;
        int connected = 0;

        List<CompletableFuture<RawWebSocket>> futures = new ArrayList<>(needed);
        for (int i = 0; i < needed; i++) {
            futures.add(CompletableFuture.supplyAsync(() -> connectOne(targetIp, domains, path), executor));
        }

        for (CompletableFuture<RawWebSocket> future : futures) {
            try {
                RawWebSocket ws = future.get(16, TimeUnit.SECONDS);
                if (ws != null) {
                    bucket.add(new WsEntry(ws));
                    connected++;
                }
            } catch (Exception ignored) {
            }
        }

        if (connected > 0) {
            refillFailures.remove(key);
            refillAfter.remove(key);
        } else {
            int failures = refillFailures.getOrDefault(key, 0) + 1;
            refillFailures.put(key, failures);
            double delay = Math.min(1.0 * (1L << Math.min(failures - 1, 12)), 3600.0);
            refillAfter.put(key, System.nanoTime() / 1_000_000_000.0 + delay);
            Logger.i(TAG, String.format("WS pool refill failed for DC%d%s%s, retry in %.0fs",
                    key.dc, key.isTestDc ? "t" : "", key.isMedia ? "m" : "", delay));
        }

        Logger.d(TAG, String.format("WS pool refilled DC%d%s%s: %d ready",
                key.dc, key.isTestDc ? "t" : "", key.isMedia ? "m" : "", bucket.size()));
    }

    /** Аналог _connect_one из ядра: чередование direct/fronting со sticky-предпочтением. */
    private RawWebSocket connectOne(String targetIp, List<String> domains, String path) {
        for (String domain : domains) {
            boolean[] modes = tryFrontingFirst ? new boolean[]{true, false} : new boolean[]{false, true};
            for (boolean fronted : modes) {
                try {
                    RawWebSocket ws;
                    if (fronted) {
                        ws = RawWebSocket.connect(targetIp, domain, 7.0f, path, FRONTING_SNI, true);
                    } else {
                        ws = RawWebSocket.connect(targetIp, domain, 8.0f, path, null, true);
                    }
                    tryFrontingFirst = fronted;
                    if (fronted) {
                        Stats.INSTANCE.incConnectionsFronting();
                    }
                    Logger.d(TAG, String.format("WS pool connected %s%s via %s (fronting=%s)",
                            domain, path, targetIp, fronted));
                    return ws;
                } catch (RawWebSocket.WsHandshakeException e) {
                    Stats.INSTANCE.incWsErrors();
                    if (e.isRedirect()) {
                        Logger.d(TAG, String.format("WS pool connect %s%s via %s (fronting=%s): HTTP %d",
                                domain, path, targetIp, fronted, e.getStatusCode()));
                        continue;
                    }
                    Logger.d(TAG, String.format("WS pool connect %s%s via %s (fronting=%s): %s",
                            domain, path, targetIp, fronted, e.getStatusLine()));
                } catch (Exception e) {
                    Stats.INSTANCE.incWsErrors();
                    Logger.d(TAG, String.format("WS pool connect %s%s via %s (fronting=%s): %s",
                            domain, path, targetIp, fronted, e.getMessage()));
                }
            }
        }
        return null;
    }

    /** Фоновая ротация: удаление протухших соединений + поддержка размера пула. */
    private void scheduleRotation(PoolKey key, String targetIp, List<String> domains) {
        if (!rotating.add(key)) {
            return;
        }
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                Deque<WsEntry> bucket = idle.get(key);
                if (bucket == null) return;
                double now = System.nanoTime() / 1_000_000_000.0;
                double maxAge = PoolTimingConfig.getWsPoolMaxAge();
                int expired = 0;
                Iterator<WsEntry> it = bucket.iterator();
                while (it.hasNext()) {
                    WsEntry entry = it.next();
                    if (now - entry.created >= maxAge || entry.ws.isClosed()) {
                        it.remove();
                        expired++;
                        quietClose(entry.ws);
                    }
                }
                if (expired > 0) {
                    Logger.d(TAG, String.format("WS pool rotated DC%d%s%s: %d stale, %d ready",
                            key.dc, key.isTestDc ? "t" : "", key.isMedia ? "m" : "",
                            expired, bucket.size()));
                }
                scheduleRefill(key, targetIp, domains);
            } catch (Exception e) {
                Logger.d(TAG, "rotate error: " + e.getMessage());
            }
        }, 5, 5, TimeUnit.SECONDS);
    }

    private void quietClose(RawWebSocket ws) {
        try {
            if (ws != null) ws.close();
        } catch (Exception ignored) {}
    }

    public void warmup() {
        ProxyConfig config = ConfigManager.getProxyConfig();
        Map<Integer, String> redirects = config.getDcRedirects();
        for (Map.Entry<Integer, String> entry : redirects.entrySet()) {
            int dc = entry.getKey();
            String targetIp = entry.getValue();
            if (targetIp == null || targetIp.isEmpty()) continue;
            for (boolean isMedia : new boolean[]{false, true}) {
                List<String> domains = MTProtoUtils.wsDomains(dc, isMedia);
                PoolKey key = new PoolKey(dc, isMedia, config.isForceTestDc());
                schedule(key, targetIp, domains);
            }
        }
        Logger.i(TAG, "WS pool warmup started for " + redirects.size() + " DC(s)");
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
        rotating.clear();
        refillAfter.clear();
        refillFailures.clear();
        tryFrontingFirst = false;
        scheduler.shutdownNow();
        executor.shutdownNow();
    }
}
