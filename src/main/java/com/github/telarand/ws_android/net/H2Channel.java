package com.github.telarand.ws_android.net;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import com.github.telarand.ws_android.stats.Stats;
import com.github.telarand.ws_android.utils.Logger;
import com.github.telarand.ws_android.utils.MTProtoUtils;

/**
 * Канал доставки MTProto-пакетов поверх HTTP/2 POST.
 *
 * Один канал обслуживает одно медиа-соединение клиента:
 *  - upload: пакеты клиента уходят POST https://host/api (параллельно, до 8 в полёте);
 *  - download: ответы кладутся в очередь и отдаются нативному клиенту
 *    в порядке поступления (транспорт MTProto допускает любой порядок).
 *
 * Упрощение относительно Python-ядра: авто-replay зависших запросов не
 * переносился. Любая ошибка запроса (в т.ч. таймаут 65 c) закрывает канал —
 * клиент Telegram переподключится и получит другой маршрут.
 */
public final class H2Channel {

    private static final String TAG = "CfH2";

    public static final int MAX_PACKET = 4 * 1024 * 1024;
    public static final int MAX_PLAIN_PADDING = 256;
    public static final int MAX_CHANNEL_REQUESTS = 8;
    public static final int MAX_CHANNEL_BYTES = 8 * 1024 * 1024;
    public static final int QUEUE_CAPACITY = 16;

    private static final int REQUEST_WAIT_SECONDS = 65;

    /** Ошибка конечной точки, которую нужно отдать нативному клиенту как пакет. */
    public static final class MTProtoTransportError extends IOException {
        public final int code;
        public MTProtoTransportError(int code, String source) {
            super(code + " (" + source + ")");
            this.code = code;
        }
    }

    private final CfH2Pool.H2Lane lane;
    private final int channelId;
    private final String label;

    private final ArrayBlockingQueue<byte[]> queue = new ArrayBlockingQueue<>(QUEUE_CAPACITY);
    private final Object stateLock = new Object();
    private final Semaphore inFlight = new Semaphore(MAX_CHANNEL_REQUESTS, true);

    private boolean closed = false;
    private int transportError = 0;
    private long pendingBytes = 0;

    private long requests = 0;
    private long up = 0;
    private long down = 0;

    /** Пустой массив — «пилюля» закрытия канала в очереди. */
    private static final byte[] POISON = new byte[0];

    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    H2Channel(CfH2Pool.H2Lane lane, int channelId, String label) {
        this.lane = lane;
        this.channelId = channelId;
        this.label = label;
    }

    public String getLabel() { return label; }
    public int getChannelId() { return channelId; }
    public boolean isClosed() { return closed; }
    public int getTransportError() { return transportError; }
    public long getUp() { return up; }
    public long getDown() { return down; }
    public long getRequests() { return requests; }

    /**
     * Ставит пакет в очередь на отправку асинхронно.
     * @return false если канал уже закрыт
     */
    public boolean send(byte[] body) {
        synchronized (stateLock) {
            if (closed) {
                return false;
            }
            if (pendingBytes + body.length > MAX_CHANNEL_BYTES) {
                failInternal(new IOException("H2 channel pending bytes exceeded bound"));
                return false;
            }
            pendingBytes += body.length;
            requests++;
        }

        boolean acquired = false;
        try {
            acquired = inFlight.tryAcquire(REQUEST_WAIT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (!acquired) {
            releasePending(body.length);
            failInternal(new IOException("H2 channel request slots exhausted"));
            return true; // канал уже закрывается, ответ придёт через очередь
        }

        lane.submit(() -> {
            try {
                byte[] reply = lane.post(body, channelId, label);
                deliver(reply, body.length);
            } catch (Exception e) {
                failInternal(e);
            } finally {
                inFlight.release();
            }
        });
        return true;
    }

    private void releasePending(int len) {
        synchronized (stateLock) {
            pendingBytes -= len;
        }
    }

    private void deliver(byte[] reply, int bodyLen) {
        releasePending(bodyLen);
        if (reply == null || reply.length == 0) {
            return; // пустые ответы не доставляются (как в ядре)
        }
        synchronized (stateLock) {
            if (closed) return;
        }
        if (!queue.offer(reply)) {
            failInternal(new IOException("H2 client response queue exceeded bound"));
        }
    }

    /**
     * Блокирующе получает следующий ответ или бросает IOException при закрытии канала.
     */
    public byte[] receive() throws IOException {
        while (true) {
            byte[] value;
            try {
                value = queue.take();
            } catch (InterruptedException e) {
                throw new IOException("H2 receive interrupted");
            }
            if (value == POISON || value.length == 0) {
                synchronized (stateLock) {
                    if (transportError != 0) {
                        throw new MTProtoTransportError(transportError, "endpoint");
                    }
                }
                throw new IOException("H2 channel closed");
            }
            return value;
        }
    }

    public void fail(Exception error) {
        failInternal(error);
    }

    private void failInternal(Exception error) {
        synchronized (stateLock) {
            if (closed) return;
            closed = true;
            if (error instanceof MTProtoTransportError) {
                transportError = ((MTProtoTransportError) error).code;
            }
            pendingBytes = 0;
        }
        Stats.INSTANCE.incH2Errors();
        if (error instanceof MTProtoTransportError) {
            Logger.w(TAG, String.format("[%s] H2 channel=%d MTProto transport error=%s; reporting to client",
                    label, channelId, error.getMessage()));
        } else {
            Logger.w(TAG, String.format("[%s] H2 channel=%d request failed: %s: %s; closing native channel",
                    label, channelId, error.getClass().getSimpleName(), error.getMessage()));
        }
        wakeWithPoison();
    }

    public void close() {
        synchronized (stateLock) {
            if (closed) return;
            closed = true;
        }
        lane.removeChannel(this);
        wakeWithPoison();
        Logger.d(TAG, String.format("[%s] H2 channel=%d closed requests=%d up=%d down=%d",
                label, channelId, requests, up, down));
    }

    private void wakeWithPoison() {
        queue.clear();
        while (!queue.offer(POISON)) {
            queue.poll();
        }
    }

    public void countUp(int n) { up += n; }
    public void countDown(int n) { down += n; }

    // ------------------------------------------------------------------
    //  Чтение/кодирование MTProto-пакетов
    // ------------------------------------------------------------------

    /**
     * Читает один MTProto-пакет из потока клиента (в расшифрованном виде).
     * quick-бит отбрасывается (в ядре используется только для статистики).
     */
    public static byte[] readPacket(InputStream in, AesLike dec, byte[] protoTag) throws IOException {
        long length;
        if (Arrays.equals(protoTag, MTProtoUtils.PROTO_TAG_ABRIDGED)) {
            int first = in.read();
            if (first < 0) throw new EOFException("native EOF");
            int words = first & 0x7f;
            if (words == 0x7f) {
                byte[] ext = readPlain(dec, 3);
                words = (ext[0] & 0xFF) | ((ext[1] & 0xFF) << 8) | ((ext[2] & 0xFF) << 16);
            }
            length = (long) words * 4;
        } else {
            byte[] hdr = readPlain(dec, 4);
            long value = ((long) hdr[0] & 0xFF) | ((long) hdr[1] & 0xFF) << 8
                    | ((long) hdr[2] & 0xFF) << 16 | ((long) hdr[3] & 0xFF) << 24;
            length = value & 0x7fffffffL;
        }

        long maxLen = MAX_PACKET + (Arrays.equals(protoTag, MTProtoUtils.PROTO_TAG_SECURE)
                ? MAX_PLAIN_PADDING : 0);
        if (length < 24 || length > maxLen) {
            throw new IOException("native packet length outside supported range: " + length);
        }
        byte[] body = readPlain(dec, (int) length);
        if (Arrays.equals(protoTag, MTProtoUtils.PROTO_TAG_SECURE)) {
            int packetLength;
            int maxPadding;
            boolean zeroAuth = true;
            for (int i = 0; i < 8; i++) {
                if (body[i] != 0) { zeroAuth = false; break; }
            }
            if (zeroAuth) {
                packetLength = 20 + ((body[16] & 0xFF) | (body[17] & 0xFF) << 8
                        | (body[18] & 0xFF) << 16 | (body[19] & 0xFF) << 24);
                maxPadding = MAX_PLAIN_PADDING;
            } else {
                packetLength = 24 + (int) ((length - 24) / 16) * 16;
                maxPadding = 15;
            }
            int padding = (int) length - packetLength;
            if (packetLength < 24 || packetLength > (int) length || padding > maxPadding) {
                throw new IOException(String.format(
                        "invalid padded native packet: frame=%d packet=%d padding=%d limit=%d",
                        length, packetLength, padding, maxPadding));
            }
            body = Arrays.copyOf(body, packetLength);
        }
        if (body.length % 4 != 0 || body.length > MAX_PACKET) {
            throw new IOException("invalid native packet alignment or size");
        }
        return body;
    }

    /** Кодирует ответ конечной точки в транспортный пакет для клиента. */
    public static byte[] encodeReply(byte[] body, byte[] protoTag) throws IOException {
        if (body == null || body.length == 0 || body.length % 4 != 0 || body.length > MAX_PACKET) {
            throw new IOException("invalid HTTP MTProto response length: "
                    + (body == null ? 0 : body.length));
        }
        if (Arrays.equals(protoTag, MTProtoUtils.PROTO_TAG_ABRIDGED)) {
            int words = body.length / 4;
            byte[] out = new byte[(words < 0x7f ? 1 : 4) + body.length];
            int off;
            if (words < 0x7f) {
                out[0] = (byte) words;
                off = 1;
            } else {
                out[0] = (byte) 0x7f;
                out[1] = (byte) (words & 0xFF);
                out[2] = (byte) ((words >> 8) & 0xFF);
                out[3] = (byte) ((words >> 16) & 0xFF);
                off = 4;
            }
            System.arraycopy(body, 0, out, off, body.length);
            return out;
        }
        byte[] padding = Arrays.equals(protoTag, MTProtoUtils.PROTO_TAG_SECURE)
                ? new byte[RANDOM.nextInt(4)] : new byte[0];
        ByteBuffer out = ByteBuffer.allocate(4 + body.length + padding.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        out.putInt(body.length + padding.length);
        out.put(body);
        out.put(padding);
        return out.array();
    }

    /** Расшифровывающее чтение точного количества байт. */
    private static byte[] readPlain(AesLike dec, int count) throws IOException {
        byte[] cipher = new byte[count];
        int total = 0;
        while (total < count) {
            int n = dec.read(cipher, total, count - total);
            if (n < 0) throw new EOFException("native EOF");
            total += n;
        }
        return dec.update(cipher);
    }

    /** Минимальный интерфейс расшифровывающего потока (чтобы не тянуть crypto в net). */
    public interface AesLike {
        byte[] update(byte[] data);
        int read(byte[] out, int off, int len) throws IOException;
    }
}
