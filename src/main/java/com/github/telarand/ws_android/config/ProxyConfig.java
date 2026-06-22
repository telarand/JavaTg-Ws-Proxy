package com.github.telarand.ws_android.config;

import java.util.*;

/**
 * Конфигурация прокси-сервера.
 */
public class ProxyConfig {

    private int port = 1443;
    private String host = "127.0.0.1";
    private String secret;
    private final Map<Integer, String> dcRedirects = new HashMap<>();
    private int bufferSize = 256 * 1024;
    private int poolSize = 4;
    private boolean fallbackCfproxy = true;
    private final List<String> cfproxyUserDomains = new ArrayList<>();
    private final List<String> cfproxyWorkerDomains = new ArrayList<>();
    private String fakeTlsDomain = "";
    private boolean proxyProtocol = false;

    public ProxyConfig() {
        byte[] random = new byte[16];
        new Random().nextBytes(random);
        this.secret = bytesToHex(random);
        dcRedirects.put(2, "149.154.167.220");
        dcRedirects.put(4, "149.154.167.220");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }

    public Map<Integer, String> getDcRedirects() { return dcRedirects; }

    public int getBufferSize() { return bufferSize; }
    public void setBufferSize(int bufferSize) { this.bufferSize = bufferSize; }

    public int getPoolSize() { return poolSize; }
    public void setPoolSize(int poolSize) { this.poolSize = poolSize; }

    public boolean isFallbackCfproxy() { return fallbackCfproxy; }
    public void setFallbackCfproxy(boolean fallbackCfproxy) { this.fallbackCfproxy = fallbackCfproxy; }

    public List<String> getCfproxyUserDomains() { return cfproxyUserDomains; }

    public List<String> getCfproxyWorkerDomains() { return cfproxyWorkerDomains; }

    public String getFakeTlsDomain() { return fakeTlsDomain; }
    public void setFakeTlsDomain(String fakeTlsDomain) { this.fakeTlsDomain = fakeTlsDomain; }

    public boolean isProxyProtocol() { return proxyProtocol; }
    public void setProxyProtocol(boolean proxyProtocol) { this.proxyProtocol = proxyProtocol; }

    public byte[] getSecretBytes() {
        return hexStringToByteArray(this.secret);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}