package com.github.telarand.ws_android.pool;

/**
 * Глобальные экземпляры пулов.
 */
public final class Pools {
    public static final WsPool WS_POOL = new WsPool();
    public static final CfWorkerPool CF_WORKER_POOL = new CfWorkerPool();

    private Pools() {}
}