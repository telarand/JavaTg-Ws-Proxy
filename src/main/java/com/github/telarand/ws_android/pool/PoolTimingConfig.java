package com.github.telarand.ws_android.pool;

/**
 * Централизованное хранилище времени жизни пулов (standalone-версия без
 * SharedPreferences). Значения читаются пулами динамически (при каждом get()).
 * Переопределение при старте: системные свойства ws.pool.max.age / cf.pool.max.age.
 */
public final class PoolTimingConfig {

    public static final int DEFAULT_WS_POOL_MAX_AGE = 120;
    public static final int DEFAULT_CF_POOL_MAX_AGE = 100;
    public static final int MIN_VALUE = 10;
    public static final int MAX_VALUE = 3600;

    private static volatile int wsPoolMaxAge = DEFAULT_WS_POOL_MAX_AGE;
    private static volatile int cfPoolMaxAge = DEFAULT_CF_POOL_MAX_AGE;

    private PoolTimingConfig() {}

    static {
        wsPoolMaxAge = clamp(parseProp("ws.pool.max.age", DEFAULT_WS_POOL_MAX_AGE));
        cfPoolMaxAge = clamp(parseProp("cf.pool.max.age", DEFAULT_CF_POOL_MAX_AGE));
    }

    private static int parseProp(String key, int def) {
        String v = System.getProperty(key);
        if (v == null || v.isEmpty()) return def;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    public static int getWsPoolMaxAge() { return wsPoolMaxAge; }

    public static int getCfPoolMaxAge() { return cfPoolMaxAge; }

    public static void setWsPoolMaxAge(int seconds) {
        wsPoolMaxAge = clamp(seconds);
    }

    public static void setCfPoolMaxAge(int seconds) {
        cfPoolMaxAge = clamp(seconds);
    }

    /** Сбрасывает оба значения к дефолту. */
    public static void resetToDefaults() {
        wsPoolMaxAge = DEFAULT_WS_POOL_MAX_AGE;
        cfPoolMaxAge = DEFAULT_CF_POOL_MAX_AGE;
    }

    private static int clamp(int v) {
        if (v < MIN_VALUE) return MIN_VALUE;
        if (v > MAX_VALUE) return MAX_VALUE;
        return v;
    }
}
