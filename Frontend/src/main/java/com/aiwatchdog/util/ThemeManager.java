package com.aiwatchdog.util;

import atlantafx.base.theme.PrimerDark;
import atlantafx.base.theme.PrimerLight;
import javafx.animation.FadeTransition;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.Parent;
import javafx.util.Duration;

import java.io.IOException;
import java.util.Locale;
import java.util.prefs.Preferences;

/** Applies a saved application theme to the JavaFX scene without restarting it. */
public final class ThemeManager {
    public enum ThemeMode { LIGHT, DARK, SYSTEM }

    private static final String THEME_KEY = "theme-mode";
    private static final Preferences PREFERENCES = Preferences.userNodeForPackage(ThemeManager.class);
    private static ThemeMode currentMode = readSavedMode();
    private static Scene currentScene;

    private ThemeManager() { }

    public static void init(Scene scene) {
        currentScene = scene;
        String stylesheet = ThemeManager.class.getResource("/css/app.css").toExternalForm();
        if (!scene.getStylesheets().contains(stylesheet)) scene.getStylesheets().add(stylesheet);
        applyTheme(currentMode, false);
    }

    public static void applyTheme(ThemeMode mode) { applyTheme(mode, true); }

    private static void applyTheme(ThemeMode mode, boolean persist) {
        if (mode == null) return;
        currentMode = mode;
        if (persist) PREFERENCES.put(THEME_KEY, mode.name());

        boolean dark = mode == ThemeMode.DARK || (mode == ThemeMode.SYSTEM && isSystemDarkMode());
        Application.setUserAgentStylesheet(dark
                ? new PrimerDark().getUserAgentStylesheet()
                : new PrimerLight().getUserAgentStylesheet());

        if (currentScene == null) return;
        Parent root = currentScene.getRoot();
        if (dark) root.getStyleClass().add("theme-dark");
        else root.getStyleClass().remove("theme-dark");
        if (persist) {
            root.setOpacity(0.94);
            FadeTransition transition = new FadeTransition(Duration.millis(160), root);
            transition.setToValue(1);
            transition.play();
        }
    }

    public static ThemeMode getCurrentMode() { return currentMode; }

    private static ThemeMode readSavedMode() {
        try { return ThemeMode.valueOf(PREFERENCES.get(THEME_KEY, ThemeMode.SYSTEM.name())); }
        catch (IllegalArgumentException exception) { return ThemeMode.SYSTEM; }
    }

    private static boolean isSystemDarkMode() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        try {
            if (os.contains("win")) {
                Process process = new ProcessBuilder("reg", "query",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                        "/v", "AppsUseLightTheme").redirectErrorStream(true).start();
                String output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                return process.waitFor() == 0 && output.toLowerCase(Locale.ROOT).contains("0x0");
            }
            if (os.contains("mac")) {
                Process process = new ProcessBuilder("defaults", "read", "-g", "AppleInterfaceStyle")
                        .redirectErrorStream(true).start();
                String output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                return process.waitFor() == 0 && output.toLowerCase(Locale.ROOT).contains("dark");
            }
            return System.getenv().getOrDefault("GTK_THEME", "").toLowerCase(Locale.ROOT).contains("dark");
        } catch (IOException | InterruptedException exception) {
            if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
            return false;
        }
    }
}
