package com.github.telarand.ws_android.utils;

import android.util.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Standalone-версия Logger ядра: вывод в консоль (учитывая --verbose) и
 * файловое логирование с ротацией (аналог --log-file/--log-max-mb/--log-backups
 * из Python-ядра).
 */
public final class Logger {

    private static volatile boolean verbose = false;
    private static volatile LogFile fileLogger = null;

    private Logger() {}

    /** Инициализация файлового логирования. path == null - только консоль. */
    public static synchronized void init(boolean verboseMode, String path,
                                         double maxMb, int backups) {
        verbose = verboseMode;
        if (path != null && !path.isEmpty()) {
            try {
                fileLogger = new LogFile(Paths.get(path),
                        Math.max(0.1, maxMb), Math.max(1, backups));
            } catch (Exception e) {
                Log.e("Logger", "File logging disabled: " + e.getMessage());
                fileLogger = null;
            }
        }
    }

    public static void setVerbose(boolean v) {
        verbose = v;
    }

    public static boolean isVerbose() {
        return verbose;
    }

    private static void toFile(String level, String tag, String msg) {
        LogFile fl = fileLogger;
        if (fl != null) fl.append(level, tag, msg);
    }

    private static void toFile(String level, String tag, String msg, Throwable tr) {
        if (tr != null) {
            toFile(level, tag, msg + " | " + tr.getClass().getSimpleName() + ": " + tr.getMessage());
            StackTraceElement[] st = tr.getStackTrace();
            for (int i = 0; i < Math.min(st.length, 20); i++) {
                toFile(level, tag, "    at " + st[i].toString());
            }
        } else {
            toFile(level, tag, msg);
        }
    }

    public static void d(String tag, String msg) {
        if (verbose) Log.d(tag, msg);
        toFile("D", tag, msg);
    }

    public static void i(String tag, String msg) {
        Log.i(tag, msg);
        toFile("I", tag, msg);
    }

    public static void w(String tag, String msg) {
        Log.w(tag, msg);
        toFile("W", tag, msg);
    }

    public static void w(String tag, String msg, Throwable tr) {
        Log.w(tag, msg, tr);
        toFile("W", tag, msg, tr);
    }

    public static void e(String tag, String msg) {
        Log.e(tag, msg);
        toFile("E", tag, msg);
    }

    public static void e(String tag, String msg, Throwable tr) {
        Log.e(tag, msg, tr);
        toFile("E", tag, msg, tr);
    }

    /** Закрывает файловый лог (вызывается при завершении работы). */
    public static synchronized void shutdown() {
        LogFile fl = fileLogger;
        fileLogger = null;
        if (fl != null) fl.close();
    }

    /** Простой файловый лог с ротацией по размеру: app.log -> app.log.1 -> app.log.N. */
    private static final class LogFile {
        private final Path path;
        private final long maxBytes;
        private final int backups;
        private final SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);

        LogFile(Path path, double maxMb, int backups) throws IOException {
            this.path = path.toAbsolutePath();
            this.maxBytes = (long) (maxMb * 1024 * 1024);
            this.backups = backups;
            Path parent = this.path.getParent();
            if (parent != null) Files.createDirectories(parent);
        }

        synchronized void append(String level, String tag, String msg) {
            String line = fmt.format(new Date()) + "  " + level + "/" + tag + ": " + msg + "\n";
            try {
                Files.write(path, line.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                if (Files.size(path) > maxBytes) {
                    rotate();
                }
            } catch (IOException ignored) {
                // Файловый лог не должен ронять ядро
            }
        }

        private void rotate() throws IOException {
            // app.log.(backups-1) удаляем, остальные сдвигаем вверх
            Path last = sibling(backups);
            if (Files.exists(last)) {
                Files.delete(last);
            }
            for (int i = backups - 1; i >= 1; i--) {
                Path from = sibling(i);
                Path to = sibling(i + 1);
                if (Files.exists(from)) {
                    Files.move(from, to, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
            Files.move(path, sibling(1), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }

        private Path sibling(int n) {
            return path.resolveSibling(path.getFileName().toString() + "." + n);
        }

        void close() {
        }
    }
}
