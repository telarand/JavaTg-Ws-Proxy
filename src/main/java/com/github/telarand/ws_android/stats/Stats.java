package com.github.telarand.ws_android.stats;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Глобальная статистика соединений, трафика и пулов.
 */
public final class Stats {

    private final AtomicLong connectionsTotal = new AtomicLong(0);
    private final AtomicLong connectionsActive = new AtomicLong(0);
    private final AtomicLong connectionsWs = new AtomicLong(0);
    private final AtomicLong connectionsH2 = new AtomicLong(0);
    private final AtomicLong h2TcpConnections = new AtomicLong(0);
    private final AtomicLong h2Requests = new AtomicLong(0);
    private final AtomicLong h2Errors = new AtomicLong(0);
    private final AtomicLong connectionsTcpFallback = new AtomicLong(0);
    private final AtomicLong connectionsCfproxy = new AtomicLong(0);
    private final AtomicLong connectionsFronting = new AtomicLong(0);
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

    public void incConnectionsH2() {
        connectionsH2.incrementAndGet();
    }

    public void incH2TcpConnections() {
        h2TcpConnections.incrementAndGet();
    }

    public void incH2Requests() {
        h2Requests.incrementAndGet();
    }

    public void incH2Errors() {
        h2Errors.incrementAndGet();
    }

    public void incConnectionsTcpFallback() {
        connectionsTcpFallback.incrementAndGet();
    }

    public void incConnectionsCfproxy() {
        connectionsCfproxy.incrementAndGet();
    }

    public void incConnectionsFronting() {
        connectionsFronting.incrementAndGet();
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

    /** Сводка в формате stats.summary() ядра. */
    public String summary() {
        long poolTotal = poolHits.get() + poolMisses.get();
        String poolS = poolTotal > 0 ? poolHits.get() + "/" + poolTotal : "n/a";
        long cfTotal = cfPoolHits.get() + cfPoolMisses.get();
        String cfPoolS = cfTotal > 0 ? cfPoolHits.get() + "/" + cfTotal : "n/a";
        return "total=" + connectionsTotal.get()
                + " active=" + connectionsActive.get()
                + " ws=" + connectionsWs.get()
                + " h2=" + connectionsH2.get()
                + " h2_tcp=" + h2TcpConnections.get()
                + " h2_req=" + h2Requests.get()
                + " h2_err=" + h2Errors.get()
                + " tcp_fb=" + connectionsTcpFallback.get()
                + " cf=" + connectionsCfproxy.get()
                + " front=" + connectionsFronting.get()
                + " bad=" + connectionsBad.get()
                + " masked=" + connectionsMasked.get()
                + " err=" + wsErrors.get()
                + " pool=" + poolS
                + " cf_pool=" + cfPoolS
                + " up=" + MTProtoUtilsHolder.humanBytes(bytesUp.get())
                + " down=" + MTProtoUtilsHolder.humanBytes(bytesDown.get());
    }

    /** Отдельный держатель, чтобы не создавать цикл импортов в stat-пакете. */
    private static final class MTProtoUtilsHolder {
        static String humanBytes(long n) {
            return com.github.telarand.ws_android.utils.MTProtoUtils.humanBytes(n);
        }
    }
}
