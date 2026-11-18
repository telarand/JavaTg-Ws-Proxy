package com.github.telarand.ws_android.config;

import com.github.telarand.ws_android.utils.Logger;
import com.github.telarand.ws_android.utils.MTProtoUtils;
import com.github.telarand.ws_android.balancer.Balancer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Управление конфигурацией, загрузка и обновление доменов CF-прокси.
 */
public final class ConfigManager {

    private static final String TAG = "ConfigManager";

    private static final String CFPROXY_DOMAINS_URL =
            "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";

    private static final List<String> CFPROXY_ENC = Arrays.asList(
            "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com",
            "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com", "bxaxtxmrw.com", "dmohrsgmohcrwb.com",
            "vwbmtmoi.com", "khgrre.com", "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com",
            "orgcnunpj.com", "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com"
    );

    private static final String DECODED_SUFFIX = ".co.uk";
    private static final int CFPROXY_MIN_VALID_DOMAINS = 3;
    private static final ProxyConfig PROXY_CONFIG = new ProxyConfig();

    private static ScheduledExecutorService scheduler;
    private static volatile boolean refreshRunning = false;

    private ConfigManager() {}

    public static ProxyConfig getProxyConfig() {
        return PROXY_CONFIG;
    }

    private static String decodeCfproxyDomain(String s) {
        if (!s.endsWith(".com")) {
            return s;
        }
        String prefix = s.substring(0, s.length() - 4);
        int n = 0;
        for (char c : prefix.toCharArray()) {
            if (Character.isLetter(c)) n++;
        }
        StringBuilder decoded = new StringBuilder();
        for (char c : prefix.toCharArray()) {
            if (Character.isLetter(c)) {
                int base = (c >= 'a' && c <= 'z') ? 'a' : 'A';
                int offset = (c - base - n) % 26;
                if (offset < 0) offset += 26;
                decoded.append((char)(base + offset));
            } else {
                decoded.append(c);
            }
        }
        decoded.append(DECODED_SUFFIX);
        return decoded.toString();
    }


    private static boolean isValidDomain(String domain) {
        if (domain == null || domain.isEmpty() || domain.length() > 253) return false;
        if (domain.startsWith(".") || domain.endsWith(".")) return false;
        String[] labels = domain.split("\\.");
        if (labels.length < 2) return false;
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) return false;
            if (label.charAt(0) == '-' || label.charAt(label.length() - 1) == '-') return false;
            if (!label.matches("[a-zA-Z0-9\\-]+")) return false;
        }
        String tld = labels[labels.length - 1];
        if (tld.length() < 2) return false;
        boolean hasLetter = false;
        for (char c : tld.toCharArray()) {
            if (Character.isLetter(c)) { hasLetter = true; break; }
        }
        return hasLetter;
    }

    private static List<String> normalizeDomainPool(List<String> domains) {
        Set<String> seen = new HashSet<>();
        List<String> result = new ArrayList<>();
        for (String domain : domains) {
            if (domain == null) continue;
            String cleaned = domain.trim().toLowerCase();
            if (!isValidDomain(cleaned)) continue;
            if (seen.contains(cleaned)) continue;
            seen.add(cleaned);
            result.add(cleaned);
        }
        return result;
    }

    private static List<String> fetchCfproxyDomainList() {
        OkHttpClient client = MTProtoUtils.buildGithubClient();
        String randomParam = "?r=" + System.currentTimeMillis();
        Request request = new Request.Builder()
                .url(CFPROXY_DOMAINS_URL + randomParam)
                .header("User-Agent", "tg-ws-proxy")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                Logger.w(TAG, "Failed to fetch CF proxy domains, HTTP " + response.code());
                return Collections.emptyList();
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(response.body().byteStream()));
            List<String> lines = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
                lines.add(trimmed);
            }
            List<String> decoded = new ArrayList<>();
            for (String enc : lines) {
                decoded.add(decodeCfproxyDomain(enc));
            }
            return decoded;
        } catch (IOException e) {
            Logger.w(TAG, "IOException fetching CF proxy domains: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    public static synchronized void refreshCfproxyDomains() {
        ProxyConfig config = getProxyConfig();
        if (!config.getCfproxyUserDomains().isEmpty()) {
            return;
        }

        List<String> fetched = fetchCfproxyDomainList();
        List<String> pool = normalizeDomainPool(fetched);

        if (pool.size() >= CFPROXY_MIN_VALID_DOMAINS) {
            Balancer.INSTANCE.updateDomainsList(pool);
            Logger.i(TAG, "CF proxy domain pool updated from GitHub (" + pool.size() + " domains)");
            return;
        }

        if (!fetched.isEmpty()) {
            Logger.w(TAG, "Ignoring fetched CF proxy domains due to low-quality payload " +
                    "(total=" + fetched.size() + ", valid=" + pool.size() +
                    ", required>=" + CFPROXY_MIN_VALID_DOMAINS + "); keeping current domain pool");
        } else {
            Logger.w(TAG, "CF proxy domain refresh failed or empty response; keeping current domain pool");
        }
    }

    public static synchronized void startCfproxyDomainRefresh() {
        if (refreshRunning) {
            stopCfproxyDomainRefresh();
        }

        List<String> defaultDecoded = new ArrayList<>();
        for (String enc : CFPROXY_ENC) {
            defaultDecoded.add(decodeCfproxyDomain(enc));
        }
        Balancer.INSTANCE.updateDomainsList(defaultDecoded);

        refreshCfproxyDomains();

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "cfproxy-domains-refresh");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(ConfigManager::refreshCfproxyDomains, 1, 1, TimeUnit.HOURS);
        refreshRunning = true;
        Logger.i(TAG, "CF proxy domain refresh started (hourly)");
    }

    public static synchronized void stopCfproxyDomainRefresh() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            try {
                if (!scheduler.awaitTermination(1, TimeUnit.SECONDS)) {
                }
            } catch (InterruptedException ignored) {}
            scheduler = null;
            refreshRunning = false;
            Logger.i(TAG, "CF proxy domain refresh stopped");
        }
    }

    /**
     * Преобразует строку или список строк в список уникальных доменов
     */
    public static List<String> coerceDomainList(List<String> values) {
        List<String> items = new ArrayList<>();
        if (values != null) {
            for (String entry : values) {
                if (entry == null) continue;
                String[] parts = entry.replace(',', ' ').replace(';', ' ').split("\\s+");
                for (String p : parts) {
                    if (!p.isEmpty()) items.add(p);
                }
            }
        }
        Set<String> seen = new HashSet<>();
        List<String> result = new ArrayList<>();
        for (String item : items) {
            String key = item.toLowerCase();
            if (!seen.contains(key)) {
                seen.add(key);
                result.add(item);
            }
        }
        return result;
    }

    /**
     * Парсит список строк вида "DC:IP" в Map<Integer, String>
     */
    public static Map<Integer, String> parseDcIpList(List<String> dcIpList) {
        Map<Integer, String> redirects = new HashMap<>();
        for (String entry : dcIpList) {
            if (!entry.contains(":")) {
                throw new IllegalArgumentException("Invalid --dc-ip format: " + entry + ", expected DC:IP");
            }
            String[] parts = entry.split(":", 2);
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid --dc-ip format: " + entry);
            }
            int dc;
            try {
                dc = Integer.parseInt(parts[0].trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid DC number: " + parts[0]);
            }
            String ip = parts[1].trim();
            if (!ip.matches("(\\d{1,3}\\.){3}\\d{1,3}")) {
                throw new IllegalArgumentException("Invalid IP address: " + ip);
            }
            String[] octets = ip.split("\\.");
            for (String octet : octets) {
                if (Integer.parseInt(octet) > 255) {
                    throw new IllegalArgumentException("Invalid IP address: " + ip);
                }
            }
            redirects.put(dc, ip);
        }
        return redirects;
    }
}