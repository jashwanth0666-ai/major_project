package com.aiwatchdog.util;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.prefs.Preferences;

/** Per-user folder selection for the JavaFX metadata monitor. */
public final class DesktopMonitorPreferences {
    private static final Preferences PREFS = Preferences.userNodeForPackage(DesktopMonitorPreferences.class);
    private static final String KEY = "local-monitor-roots";
    private DesktopMonitorPreferences() { }

    public static List<Path> getRoots() {
        String saved = PREFS.get(KEY, "");
        if (!saved.isBlank()) return saved.lines().filter(line -> !line.isBlank()).map(Path::of).toList();
        String env = System.getenv("AI_WATCHDOG_MONITOR_DIRS");
        if (env != null && !env.isBlank()) return List.of(env.split(",")).stream().map(String::trim)
                .filter(part -> !part.isBlank()).map(Path::of).toList();
        Path home = Path.of(System.getProperty("user.home"));
        return List.of("Downloads", "Desktop", "Documents").stream().map(home::resolve)
                .filter(Files::isDirectory).toList();
    }

    public static void setRoots(List<Path> roots) {
        PREFS.put(KEY, roots == null ? "" : String.join(System.lineSeparator(), roots.stream()
                .map(path -> path.toAbsolutePath().normalize().toString()).toList()));
    }
}
