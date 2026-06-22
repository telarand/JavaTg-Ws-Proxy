package com.github.telarand.ws_android.stats;

import java.util.concurrent.atomic.AtomicLong;

import com.github.telarand.ws_android.utils.MTProtoUtils;

/**
 * Глобальная статистика соединений, трафика и пулов.
 */
public final class Stats {

    private final AtomicLong connectionsTotal = new AtomicLong(0);
    private final AtomicLong connectionsActive = new AtomicLong(0);
    private final AtomicLong connectionsWs = new AtomicLong(0);
    private final AtomicLong connectionsTcpFallback = new AtomicLong(0);
    private final AtomicLong connectionsCfproxy = new AtomicLong(0);
    private final AtomicLong connectionsBad = new AtomicLong(0);
    private final AtomicLong connectionsMasked = new AtomicLong(0);
    private final AtomicLong wsErrors = new AtomicLong(0);
    private final AtomicLong bytesUp = new AtomicLong(0);
    private final AtomicLong bytesDown = new AtomicLong(0);
    private final AtomicLong poolHits = new AtomicLong(0);
    private final AtomicLong poolMisses = new AtomicLong(0);
    private final AtomicLong cfPoolHits = new AtomicLong(0);
    private final AtomicLong cfPoolMisses = new AtomicLong(0);

    public static final Stats INSTANCE = new Stats();

    private Stats() {
    }


    public void incConnectionsTotal() {
        connectionsTotal.incrementAndGet();
    }

    public void incConnectionsActive() {
        connectionsActive.incrementAndGet();
    }

    public void decConnectionsActive() {
        connectionsActive.decrementAndGet();
    }

    public void incConnectionsWs() {
        connectionsWs.incrementAndGet();
    }

    public void incConnectionsTcpFallback() {
        connectionsTcpFallback.incrementAndGet();
    }

    public void incConnectionsCfproxy() {
        connectionsCfproxy.incrementAndGet();
    }

    public void incConnectionsBad() {
        connectionsBad.incrementAndGet();
    }

    public void incConnectionsMasked() {
        connectionsMasked.incrementAndGet();
    }

    public void incWsErrors() {
        wsErrors.incrementAndGet();
    }

    public void addBytesUp(long bytes) {
        bytesUp.addAndGet(bytes);
    }

    public void addBytesDown(long bytes) {
        bytesDown.addAndGet(bytes);
    }

    public void incPoolHits() {
        poolHits.incrementAndGet();
    }

    public void incPoolMisses() {
        poolMisses.incrementAndGet();
    }

    public void incCfPoolHits() {
        cfPoolHits.incrementAndGet();
    }

    public void incCfPoolMisses() {
        cfPoolMisses.incrementAndGet();
    }

    /**
     * Вызывать при открытии нового соединения (увеличивает total и active).
     */
    public void onConnectionOpened() {
        connectionsTotal.incrementAndGet();
        connectionsActive.incrementAndGet();
    }

    /**
     * Вызывать при закрытии соединения (уменьшает active).
     */
    public void onConnectionClosed() {
        connectionsActive.decrementAndGet();
    }

    /**
     * Возвращает строку со всеми показателями.
     */
    public String summary() {
        long poolTotal = poolHits.get() + poolMisses.get();
        String poolS = (poolTotal > 0) ? (poolHits.get() + "/" + poolTotal) : "n/a";

        long cfPoolTotal = cfPoolHits.get() + cfPoolMisses.get();
        String cfPoolS = (cfPoolTotal > 0) ? (cfPoolHits.get() + "/" + cfPoolTotal) : "n/a";

        return "total=" + connectionsTotal.get() +
                " active=" + connectionsActive.get() +
                " ws=" + connectionsWs.get() +
                " tcp_fb=" + connectionsTcpFallback.get() +
                " cf=" + connectionsCfproxy.get() +
                " bad=" + connectionsBad.get() +
                " masked=" + connectionsMasked.get() +
                " err=" + wsErrors.get() +
                " pool=" + poolS +
                " cf_pool=" + cfPoolS +
                " up=" + MTProtoUtils.humanBytes(bytesUp.get()) +
                " down=" + MTProtoUtils.humanBytes(bytesDown.get());
    }

    public void reset() {
        connectionsTotal.set(0);
        connectionsActive.set(0);
        connectionsWs.set(0);
        connectionsTcpFallback.set(0);
        connectionsCfproxy.set(0);
        connectionsBad.set(0);
        connectionsMasked.set(0);
        wsErrors.set(0);
        bytesUp.set(0);
        bytesDown.set(0);
        poolHits.set(0);
        poolMisses.set(0);
        cfPoolHits.set(0);
        cfPoolMisses.set(0);
    }
}