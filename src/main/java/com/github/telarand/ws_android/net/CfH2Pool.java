package com.github.telarand.ws_android.net;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.github.telarand.ws_android.balancer.Balancer;
import com.github.telarand.ws_android.stats.Stats;
import com.github.telarand.ws_android.utils.Logger;
import com.github.telarand.ws_android.utils.MTProtoUtils;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Пул HTTP/2-каналов к Cloudflare для медиа-трафика.
 *
 * На каждый CF-домен (kws{dc}.{base}) создаётся один H2Lane со своим
 * OkHttpClient (HTTP/2 мультиплексирование и переиспользование соединения
 * берёт на себя OkHttp). Лейны переживают много каналов; при ошибках домен
 * уходит в cooldown на DOMAIN_COOLDOWN секунд.
 */
public final class CfH2Pool {

    private static final String TAG = "CfH2";

    public static final double DOMAIN_COOLDOWN = 30.0;
    public static final double SETUP_TIMEOUT = 8.0;
    public static final int REQUEST_TIMEOUT_SECONDS = 65;
    public static final int CONNECT_TIMEOUT_SECONDS = 8;

    private static final MediaType OCTET_STREAM =
            MediaType.parse("application/octet-stream");

    private final Map<String, H2Lane> lanes = new ConcurrentHashMap<>();
    private final Map<String, Object> hostLocks = new HashMap<>();
    private final Map<String, Double> failedUntil = new ConcurrentHashMap<>();
    private final Map<Integer, Double> setupRetryAfter = new ConcurrentHashMap<>();
    private final Object locksGuard = new Object();

    private final ExecutorService setupExecutor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "cf-h2-setup");
        t.setDaemon(true);
        return t;
    });

    private volatile boolean closed = false;
    private int nextChannel = 0;

    /**
     * Открывает канал для медиа DC или возвращает null (маршрут недоступен,
     * нужно использовать WS). Бросает IOException, если пул закрыт.
     */
    public H2Channel open(int dc, String label) throws IOException {
        if (closed) {
            throw new IOException("H2 pool closed");
        }
        double now = now();
        Double after = setupRetryAfter.get(dc);
        if (after != null && now < after) {
            return null;
        }
        Future<H2Channel> future = setupExecutor.submit(() -> openInternal(dc, label));
        try {
            return future.get((long) SETUP_TIMEOUT, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            setupRetryAfter.put(dc, now() + DOMAIN_COOLDOWN);
            Stats.INSTANCE.incH2Errors();
            Logger.w(TAG, String.format("[%s] H2 DC%d setup timed out; using WS for %.0fs",
                    label, dc, DOMAIN_COOLDOWN));
            return null;
        } catch (Exception e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            Logger.w(TAG, "[" + label + "] H2 open error: " + e.getMessage());
            return null;
        }
    }

    private H2Channel openInternal(int dc, String label) throws IOException {
        if (closed) {
            throw new IOException("H2 pool closed");
        }
        if (!MTProtoUtils.DC_DEFAULT_IPS.containsKey(dc)) {
            Logger.w(TAG, String.format("[%s] H2 unsupported DC%d -> existing WS route", label, dc));
            return null;
        }
        Iterator<String> domainIter = Balancer.INSTANCE.getDomainsForDc(dc);
        while (domainIter.hasNext()) {
            String baseDomain = domainIter.next();
            String host = "kws" + dc + "." + baseDomain;
            Object lock;
            synchronized (locksGuard) {
                lock = hostLocks.computeIfAbsent(host, k -> new Object());
            }
            synchronized (lock) {
                if (closed) {
                    throw new IOException("H2 pool closed");
                }
                double now = now();
                Double failed = failedUntil.get(host);
                if (failed != null && now < failed) {
                    continue;
                }
                H2Lane lane = lanes.get(host);
                if (lane == null) {
                    lane = new H2Lane(host);
                    try {
                        lane.preflight();
                    } catch (IOException e) {
                        Stats.INSTANCE.incH2Errors();
                        failedUntil.put(host, now() + DOMAIN_COOLDOWN);
                        Logger.w(TAG, String.format("[%s] H2 preflight failed host=%s: %s: %s",
                                label, host, e.getClass().getSimpleName(), e.getMessage()));
                        lane.close();
                        continue;
                    }
                    if (closed) {
                        lane.close();
                        throw new IOException("H2 pool closed during preflight");
                    }
                    lanes.put(host, lane);
                }
                int channelId;
                synchronized (this) {
                    channelId = ++nextChannel;
                }
                H2Channel channel = new H2Channel(lane, channelId, label);
                lane.addChannel(channel);
                Balancer.INSTANCE.updateDomainForDc(dc, baseDomain);
                Logger.i(TAG, String.format("[%s] ROUTE DC%d media -> H2 channel=%d host=%s channels=%d",
                        label, dc, channelId, host, lane.channelCount()));
                return channel;
            }
        }
        Logger.d(TAG, String.format("[%s] H2 DC%d unavailable; using WS", label, dc));
        return null;
    }

    public void close() {
        closed = true;
        for (H2Lane lane : lanes.values()) {
            lane.close();
        }
        lanes.clear();
        setupExecutor.shutdownNow();
    }

    private static double now() {
        return System.nanoTime() / 1_000_000_000.0;
    }

    // ------------------------------------------------------------------
    //  Лейн: один домен — один OkHttpClient (HTTP/2)
    // ------------------------------------------------------------------

    public final class H2Lane {

        private final String host;
        private final OkHttpClient client;
        private final List<H2Channel> channels = new ArrayList<>();
        private final Object channelsLock = new Object();

        private volatile double failedUntilAt = 0;
        private long requests = 0;
        private long responses = 0;
        private long errors = 0;

        H2Lane(String host) {
            this.host = host;
            this.client = new OkHttpClient.Builder()
                    .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .readTimeout(REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .writeTimeout(REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .callTimeout(REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    // Без авторетраев: повторная отправка пакета = дубликат для Telegram
                    .retryOnConnectionFailure(false)
                    .protocols(java.util.Arrays.asList(Protocol.HTTP_2, Protocol.HTTP_1_1))
                    .build();
        }

        String getHost() { return host; }

        void addChannel(H2Channel channel) {
            synchronized (channelsLock) {
                channels.add(channel);
            }
        }

        void removeChannel(H2Channel channel) {
            synchronized (channelsLock) {
                channels.remove(channel);
            }
        }

        int channelCount() {
            synchronized (channelsLock) {
                return channels.size();
            }
        }

        void submit(Runnable task) {
            setupExecutor.submit(task);
        }

        /** Preflight: HEAD /api должен прийти по HTTP/2 со статусом 2xx/405/501. */
        void preflight() throws IOException {
            Request request = new Request.Builder()
                    .url("https://" + host + "/api")
                    .head()
                    .build();
            try (Response response = client.newCall(request).execute()) {
                if (response.protocol() != Protocol.HTTP_2) {
                    throw new IOException("CF /api preflight negotiated " + response.protocol());
                }
                int code = response.code();
                if (!(200 <= code && code < 300 || code == 405 || code == 501)) {
                    throw new IOException("CF /api preflight HTTP " + code);
                }
                Logger.d(TAG, "H2 preflight ready host=" + host + " status=" + code);
            }
        }

        /**
         * POST /api с одним MTProto-пакетом; возвращает тело ответа.
         */
        byte[] post(byte[] body, int channelId, String label) throws IOException {
            requests++;
            Stats.INSTANCE.incH2Requests();

            Request request = new Request.Builder()
                    .url("https://" + host + "/api")
                    .header("content-type", "application/octet-stream")
                    .header("accept-encoding", "identity")
                    .post(RequestBody.create(OCTET_STREAM, body))
                    .build();

            try (Response response = client.newCall(request).execute()) {
                if (response.protocol() != Protocol.HTTP_2) {
                    throw new IOException("CF /api downgraded to " + response.protocol());
                }
                int code = response.code();
                if (code == 403 || code == 404 || code == 429 || code == 444) {
                    throw new H2Channel.MTProtoTransportError(-code, "HTTP " + code);
                }
                if (code != 200) {
                    throw new IOException("CF /api HTTP " + code);
                }
                String contentType = response.header("content-type", "");
                if (contentType != null && contentType.toLowerCase().contains("text/html")) {
                    throw new IOException("CF /api returned HTML instead of MTProto");
                }
                String lengthHeader = response.header("content-length");
                long declaredLength = -1;
                if (lengthHeader != null) {
                    try {
                        declaredLength = Long.parseLong(lengthHeader.trim());
                    } catch (NumberFormatException ignored) {
                        declaredLength = -1;
                    }
                    if (declaredLength < 0 || declaredLength > H2Channel.MAX_PACKET) {
                        throw new IOException("H2 response Content-Length exceeds native packet bound");
                    }
                }

                byte[] content = readBody(response.body().byteStream(),
                        (int) Math.max(declaredLength, 0));
                long received = content.length;

                if (declaredLength >= 0 && received != declaredLength) {
                    throw new IOException("incomplete H2 response body");
                }
                if (received % 4 != 0) {
                    throw new IOException("CF /api response is not an aligned MTProto packet");
                }
                if (received == 4) {
                    int payload = (content[0] & 0xFF) | (content[1] & 0xFF) << 8
                            | (content[2] & 0xFF) << 16 | (content[3] & 0xFF) << 24;
                    if (payload < 0) {
                        throw new H2Channel.MTProtoTransportError(payload, "HTTP 200 payload");
                    }
                }
                responses++;
                return content;
            } catch (H2Channel.MTProtoTransportError e) {
                errors++;
                throw e;
            } catch (IOException | RuntimeException e) {
                errors++;
                failedUntilAt = now() + DOMAIN_COOLDOWN;
                if (e instanceof IOException) {
                    throw (IOException) e;
                }
                throw new IOException(e.getMessage(), e);
            }
        }

        private byte[] readBody(java.io.InputStream in, int declared) throws IOException {
            if (declared > 0) {
                byte[] out = new byte[declared];
                int total = 0;
                while (total < declared) {
                    int n = in.read(out, total, declared - total);
                    if (n < 0) break;
                    total += n;
                }
                return out;
            }
            java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[65536];
            int n;
            int total = 0;
            while ((n = in.read(chunk)) > 0) {
                total += n;
                if (total > H2Channel.MAX_PACKET) {
                    throw new IOException("H2 response exceeds native packet bound");
                }
                buf.write(chunk, 0, n);
            }
            return buf.toByteArray();
        }

        void close() {
            synchronized (channelsLock) {
                for (H2Channel channel : new ArrayList<>(channels)) {
                    try {
                        channel.close();
                    } catch (Exception ignored) {}
                }
                channels.clear();
            }
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
            Logger.d(TAG, "H2 lane closed host=" + host
                    + " requests=" + requests + " responses=" + responses + " errors=" + errors);
        }

        boolean isFailed() {
            return now() < failedUntilAt;
        }
    }
}
