package com.github.telarand.ws_android.utils;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;

import okhttp3.Dns;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Утилитный класс.
 * Содержит константы MTProto, методы для работы с хостами и HTTP-клиент
 * с привязкой IP для GitHub (обход DNS).
 */
public final class MTProtoUtils {

    private MTProtoUtils() {
    }

    public static final byte[] ZERO_64 = new byte[64];
    public static final int HANDSHAKE_LEN = 64;
    public static final int SKIP_LEN = 8;
    public static final int PREKEY_LEN = 32;
    public static final int KEY_LEN = 32;
    public static final int IV_LEN = 16;
    public static final int PROTO_TAG_POS = 56;
    public static final int DC_IDX_POS = 60;

    public static final byte[] PROTO_TAG_ABRIDGED =
            { (byte) 0xEF, (byte) 0xEF, (byte) 0xEF, (byte) 0xEF };
    public static final byte[] PROTO_TAG_INTERMEDIATE =
            { (byte) 0xEE, (byte) 0xEE, (byte) 0xEE, (byte) 0xEE };
    public static final byte[] PROTO_TAG_SECURE =
            { (byte) 0xDD, (byte) 0xDD, (byte) 0xDD, (byte) 0xDD };

    public static final int PROTO_ABRIDGED_INT              = 0xEFEFEFEF;
    public static final int PROTO_INTERMEDIATE_INT          = 0xEEEEEEEE;
    public static final int PROTO_PADDED_INTERMEDIATE_INT   = 0xDDDDDDDD;

    public static final Set<Integer> RESERVED_FIRST_BYTES;
    static {
        Set<Integer> set = new HashSet<>();
        set.add(0xEF);
        RESERVED_FIRST_BYTES = Collections.unmodifiableSet(set);
    }

    private static final List<byte[]> RESERVED_STARTS_LIST = new ArrayList<>();
    static {
        RESERVED_STARTS_LIST.add("HEAD".getBytes());
        RESERVED_STARTS_LIST.add("POST".getBytes());
        RESERVED_STARTS_LIST.add("GET ".getBytes());
        RESERVED_STARTS_LIST.add(PROTO_TAG_INTERMEDIATE);
        RESERVED_STARTS_LIST.add(PROTO_TAG_SECURE);
        RESERVED_STARTS_LIST.add(new byte[] { 0x16, 0x03, 0x01, 0x02 });
    }

    public static final byte[] RESERVED_CONTINUE = { 0, 0, 0, 0 };

    private static final Map<String, String> GITHUB_IPS;
    static {
        Map<String, String> map = new HashMap<>();
        map.put("release-assets.githubusercontent.com", "185.199.109.133");
        map.put("raw.githubusercontent.com", "185.199.109.133");
        GITHUB_IPS = Collections.unmodifiableMap(map);
    }

    public static final Map<Integer, String> DC_DEFAULT_IPS;
    static {
        Map<Integer, String> map = new HashMap<>();
        map.put(1, "149.154.175.50");
        map.put(2, "149.154.167.51");
        map.put(3, "149.154.175.100");
        map.put(4, "149.154.167.91");
        map.put(5, "149.154.171.5");
        map.put(203, "91.105.192.100");
        DC_DEFAULT_IPS = Collections.unmodifiableMap(map);
    }
    
    public static final Set<byte[]> RESERVED_STARTS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList(
            "HEAD".getBytes(),
            "POST".getBytes(),
            "GET ".getBytes(),
            PROTO_TAG_INTERMEDIATE,
            PROTO_TAG_SECURE,
            new byte[]{0x16, 0x03, 0x01, 0x02}
        ))
    );

    /**
     * Проверяет, начинается ли переданный массив с одного из зарезервированных префиксов.
     */
    public static boolean isReservedStart(byte[] data) {
        if (data == null || data.length == 0) return false;
        for (byte[] prefix : RESERVED_STARTS_LIST) {
            if (data.length >= prefix.length) {
                boolean match = true;
                for (int i = 0; i < prefix.length; i++) {
                    if (data[i] != prefix[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
        }
        return false;
    }

    /**
     * Возвращает список WebSocket-доменов для заданного DC.
     * @param dc      номер DC
     * @param isMedia true – медиа-домены, false – обычные, null – трактуется как true
     */
    public static List<String> wsDomains(int dc, Boolean isMedia) {
        if (dc == 203) dc = 2;
        boolean media = (isMedia == null) || isMedia;
        if (media) {
            return Arrays.asList(
                    "kws" + dc + "-1.web.telegram.org",
                    "kws" + dc + ".web.telegram.org"
            );
        } else {
            return Arrays.asList(
                    "kws" + dc + ".web.telegram.org",
                    "kws" + dc + "-1.web.telegram.org"
            );
        }
    }

    /**
     * Форматирует количество байт в удобочитаемую строку (B, KB, MB, GB, TB).
     */
    public static String humanBytes(long n) {
        String[] units = { "B", "KB", "MB", "GB" };
        double val = n;
        for (String unit : units) {
            if (Math.abs(val) < 1024) {
                return String.format(Locale.US, "%.1f%s", val, unit);
            }
            val /= 1024;
        }
        return String.format(Locale.US, "%.1fTB", val);
    }

    /**
     * Возвращает локальный IP-адрес, если передан "0.0.0.0",
     * иначе возвращает сам переданный хост.
     * Метод использует UDP-соединение с 8.8.8.8 для определения интерфейса.
     */
    public static String getLinkHost(String host) {
        if ("0.0.0.0".equals(host)) {
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.connect(InetAddress.getByName("8.8.8.8"), 80);
                InetAddress localAddr = socket.getLocalAddress();
                return localAddr != null ? localAddr.getHostAddress() : "127.0.0.1";
            } catch (SocketException | UnknownHostException e) {
                return "127.0.0.1";
            }
        } else {
            return host;
        }
    }

    /**
     * Создаёт и возвращает OkHttpClient, который для доменов из GITHUB_IPS
     * использует заранее заданный IP-адрес (вместо обращения к DNS).
     * Для всех остальных хостов используется системный DNS.
     */
    public static OkHttpClient buildGithubClient() {
        Dns customDns = hostname -> {
            String ip = GITHUB_IPS.get(hostname);
            if (ip != null) {
                try {
                    return Collections.singletonList(InetAddress.getByName(ip));
                } catch (UnknownHostException e) {
                    return Dns.SYSTEM.lookup(hostname);
                }
            }
            return Dns.SYSTEM.lookup(hostname);
        };

        return new OkHttpClient.Builder()
                .dns(customDns)
                .build();
    }

    /**
     * Пример использования кастомного клиента для выполнения GET-запроса
     * к GitHub (сырые файлы). Возвращает тело ответа в виде строки.
     * @throws IOException при сетевых ошибках или если ответ не 2xx
     */
    public static String fetchGithubRaw(String url) throws IOException {
        OkHttpClient client = buildGithubClient();
        Request request = new Request.Builder()
                .url(url)
                .build();
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("HTTP error: " + response.code());
            }
            return response.body().string();
        }
    }
}