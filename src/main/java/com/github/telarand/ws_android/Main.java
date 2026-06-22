package com.github.telarand.ws_android;

import com.github.telarand.ws_android.config.ConfigManager;
import com.github.telarand.ws_android.config.ProxyConfig;
import com.github.telarand.ws_android.server.TgWsProxyServer;

import java.util.HashMap;
import java.util.Map;

public class Main {

    public static void main(String[] args) {
        ProxyConfig config = ConfigManager.getProxyConfig();
        config.setHost("0.0.0.0");
        config.setPort(1443);

        StringBuilder secret = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            secret.append(String.format("%02x", (int)(Math.random() * 256)));
        }
        config.setSecret(secret.toString());

        Map<Integer, String> dcRedirects = new HashMap<>();
        dcRedirects.put(2, "149.154.167.220");
        dcRedirects.put(4, "149.154.167.220");
        config.getDcRedirects().putAll(dcRedirects);

        TgWsProxyServer server = new TgWsProxyServer();
        try {
            server.start();
            System.out.println("Server started. Press Ctrl+C to stop.");
            Thread.currentThread().join();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            server.stop();
        }
    }
}