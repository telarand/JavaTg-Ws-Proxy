package com.github.telarand.ws_android;

import com.github.telarand.ws_android.config.ConfigManager;
import com.github.telarand.ws_android.config.ProxyConfig;
import com.github.telarand.ws_android.server.TgWsProxyServer;
import com.github.telarand.ws_android.stats.Stats;
import com.github.telarand.ws_android.utils.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Standalone-ядро. Запускается через gradle,
 * управляется флагами командной строки — полный аналог main() из tg_ws_proxy.py.
 */
public class Main {

    private static final String TAG = "Main";

    public static void main(String[] args) {
        // ---- Разбор флагов ----
        int port = 1443;
        String host = "127.0.0.1";
        String secretArg = null;
        boolean verbose = false;
        String logFile = null;
        double logMaxMb = 5;
        int logBackups = 1;
        int bufKb = 256;
        int poolSize = 4;
        boolean noH2 = false;
        boolean noCfproxy = false;
        boolean noSecure = false;
        String fakeTlsDomain = "";
        boolean forceTestDc = false;
        boolean proxyProtocol = false;

        List<String> dcIpList = new ArrayList<>();
        boolean dcIpGiven = false;
        List<String> cfproxyDomains = new ArrayList<>();
        List<String> cfproxyWorkerDomains = new ArrayList<>();

        try {
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                switch (a) {
                    case "--port":
                        port = Integer.parseInt(requireValue(args, ++i, a));
                        break;
                    case "--host":
                        host = requireValue(args, ++i, a);
                        break;
                    case "--secret":
                        secretArg = requireValue(args, ++i, a);
                        break;
                    case "--dc-ip":
                        dcIpGiven = true;
                        if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                            dcIpList.add(args[++i]);
                        }
                        break;
                    case "-v":
                    case "--verbose":
                        verbose = true;
                        break;
                    case "--log-file":
                        logFile = requireValue(args, ++i, a);
                        break;
                    case "--log-max-mb":
                        logMaxMb = Double.parseDouble(requireValue(args, ++i, a));
                        break;
                    case "--log-backups":
                        logBackups = Integer.parseInt(requireValue(args, ++i, a));
                        break;
                    case "--buf-kb":
                        bufKb = Integer.parseInt(requireValue(args, ++i, a));
                        break;
                    case "--pool-size":
                        poolSize = Integer.parseInt(requireValue(args, ++i, a));
                        break;
                    case "--cfproxy-domain":
                        cfproxyDomains.add(requireValue(args, ++i, a));
                        break;
                    case "--cfproxy-worker-domain":
                        cfproxyWorkerDomains.add(requireValue(args, ++i, a));
                        break;
                    case "--no-h2":
                        noH2 = true;
                        break;
                    case "--cfproxy-h2-media": // скрытый флаг совместимости (deprecated)
                        noH2 = false;
                        break;
                    case "--no-cfproxy":
                        noCfproxy = true;
                        break;
                    case "--no-secure":
                        noSecure = true;
                        break;
                    case "--fake-tls-domain":
                        fakeTlsDomain = requireValue(args, ++i, a).trim();
                        break;
                    case "--force-test-dc":
                        forceTestDc = true;
                        break;
                    case "--proxy-protocol":
                        proxyProtocol = true;
                        break;
                    case "-h":
                    case "--help":
                        printHelp();
                        return;
                    default:
                        System.err.println("error: unrecognized arguments: " + a);
                        System.err.println("Use --help for usage");
                        System.exit(2);
                }
            }
        } catch (NumberFormatException e) {
            System.err.println("error: invalid numeric value: " + e.getMessage());
            System.err.println("Use --help for usage");
            System.exit(2);
        }

        if (noH2 && argsContains(args, "--cfproxy-h2-media")) {
            System.err.println("error: argument --cfproxy-h2-media: not allowed with argument --no-h2");
            System.exit(2);
        }

        Logger.init(verbose, logFile, logMaxMb, logBackups);

        // ---- DC redirects ----
        // Без флага: дефолт как в ядре; голый --dc-ip: пустой список (без редиректов).
        List<String> effectiveDcIp = dcIpGiven ? dcIpList
                : java.util.Arrays.asList("2:149.154.167.220", "4:149.154.167.220");

        Map<Integer, String> dcRedirects;
        try {
            dcRedirects = ConfigManager.parseDcIpList(effectiveDcIp);
        } catch (IllegalArgumentException e) {
            System.err.println("ERROR: " + e.getMessage());
            Logger.shutdown();
            System.exit(1);
            return;
        }

        // ---- Secret ----
        String secretHex;
        if (secretArg != null && !secretArg.isEmpty()) {
            secretHex = secretArg.trim();
            if (secretHex.length() != 32 || !secretHex.matches("[0-9a-fA-F]+")) {
                System.err.println("ERROR: Secret must be exactly 32 hex characters");
                Logger.shutdown();
                System.exit(1);
                return;
            }
        } else {
            byte[] random = new byte[16];
            new java.security.SecureRandom().nextBytes(random);
            StringBuilder sb = new StringBuilder();
            for (byte b : random) sb.append(String.format("%02x", b));
            secretHex = sb.toString();
            Logger.i(TAG, "Generated secret: " + secretHex);
        }

        // ---- Применение конфигурации ----
        ProxyConfig config = ConfigManager.getProxyConfig();
        config.setPort(port);
        config.setHost(host);
        config.setSecret(secretHex);
        config.getDcRedirects().clear();
        config.getDcRedirects().putAll(dcRedirects);
        config.setBufferSize(Math.max(4, bufKb) * 1024);
        config.setPoolSize(Math.max(0, poolSize));
        config.setFallbackCfproxy(!noCfproxy);
        config.getCfproxyUserDomains().clear();
        config.getCfproxyUserDomains().addAll(ConfigManager.coerceDomainList(cfproxyDomains));
        config.getCfproxyWorkerDomains().clear();
        config.getCfproxyWorkerDomains().addAll(ConfigManager.coerceDomainList(cfproxyWorkerDomains));
        config.setCfproxyH2Media(!noH2);
        config.setDisableSecure(noSecure);
        config.setFakeTlsDomain(fakeTlsDomain);
        config.setProxyProtocol(proxyProtocol);
        config.setForceTestDc(forceTestDc);

        // ---- Запуск ----
        final TgWsProxyServer server = new TgWsProxyServer();
        try {
            server.start();
        } catch (Exception e) {
            Logger.e(TAG, "Failed to start server: " + e.getMessage(), e);
            Logger.shutdown();
            System.exit(1);
        }

        // Периодическая статистика (аналог log_stats из ядра, раз в 60 с)
        ScheduledExecutorService statsScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "stats-logger");
            t.setDaemon(true);
            return t;
        });
        statsScheduler.scheduleAtFixedRate(() -> {
            try {
                Logger.i("stats", Stats.INSTANCE.summary());
            } catch (Exception ignored) {}
        }, 60, 60, TimeUnit.SECONDS);

        // Корректное завершение по Ctrl+C / SIGTERM
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                Logger.i(TAG, "Shutting down. Final stats: " + Stats.INSTANCE.summary());
            } catch (Exception ignored) {}
            statsScheduler.shutdownNow();
            try {
                server.stop();
            } catch (Exception ignored) {}
            ConfigManager.stopCfproxyDomainRefresh();
            Logger.shutdown();
        }, "shutdown-hook"));

        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static boolean argsContains(String[] args, String flag) {
        for (String a : args) {
            if (flag.equals(a)) return true;
        }
        return false;
    }

    private static String requireValue(String[] args, int idx, String flag) {
        if (idx >= args.length) {
            System.err.println("error: argument " + flag + ": expected one argument");
            System.exit(2);
        }
        return args[idx];
    }

    private static void printHelp() {
        System.out.println("usage: gradlew run --args='<flags>'  (или java -cp build/libs/JavaTg-Ws-Proxy-1.0.jar com.github.telarand.ws_android.Main <flags>)");
        System.out.println();
        System.out.println("Telegram MTProto WebSocket Bridge Proxy");
        System.out.println();
        System.out.println("options:");
        System.out.println("  --port PORT              Listen port (default 1443)");
        System.out.println("  --host HOST              Listen host (default 127.0.0.1)");
        System.out.println("  --secret SECRET          MTProto proxy secret (32 hex chars).");
        System.out.println("                           Auto-generated if not provided.");
        System.out.println("  --dc-ip DC:IP            Target IP for a DC, e.g. --dc-ip 2:149.154.167.220");
        System.out.println("                           (repeatable; bare --dc-ip disables redirects)");
        System.out.println("  -v, --verbose            Debug logging");
        System.out.println("  --log-file PATH          Log to file with rotation (default: stderr only)");
        System.out.println("  --log-max-mb MB          Max log file size in MB before rotation (default 5)");
        System.out.println("  --log-backups N          Number of rotated log files to keep (min 1)");
        System.out.println("  --buf-kb KB              Socket send/recv buffer size in KB (default 256)");
        System.out.println("  --pool-size N            WS connection pool size per DC (default 4, 0 disables direct WS)");
        System.out.println("  --cfproxy-domain DOMAIN  User defined Cloudflare-proxied domain for H2 media");
        System.out.println("                           and WS fallback (repeatable)");
        System.out.println("  --cfproxy-worker-domain DOMAIN");
        System.out.println("                           Cloudflare Worker domain for WS fallback");
        System.out.println("                           (tried before other fallback methods, repeatable)");
        System.out.println("  --no-h2                  Disable HTTP/2 multiplexing for CF media (enabled by default)");
        System.out.println("  --no-cfproxy             Disable Cloudflare proxy fallback");
        System.out.println("  --no-secure              Use 80 port for CF-proxy and CF-worker connections");
        System.out.println("  --fake-tls-domain DOMAIN Enable Fake TLS (ee-secret) masking with the given");
        System.out.println("                           SNI domain, e.g. example.com");
        System.out.println("  --force-test-dc          Force ALL traffic to Telegram TEST datacenters");
        System.out.println("  --proxy-protocol         Accept PROXY protocol v1 header");
        System.out.println("  -h, --help               Show this help message and exit");
    }
}
