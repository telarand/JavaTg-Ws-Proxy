package com.github.telarand.ws_android.pool;

import com.github.telarand.ws_android.net.CfH2Pool;

public final class Pools {
    public static final WsPool WS_POOL = new WsPool();
    public static final CfWorkerPool CF_WORKER_POOL = new CfWorkerPool();
    /** HTTP/2-каналы к Cloudflare для медиа. */
    public static final CfH2Pool CF_H2_POOL = new CfH2Pool();

    private Pools() {}
}
