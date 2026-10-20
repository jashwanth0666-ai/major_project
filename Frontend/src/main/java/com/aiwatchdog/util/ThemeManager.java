package com.aiwatchdog.util;

import atlantafx.base.theme.PrimerDark;
import atlantafx.base.theme.PrimerLight;
import javafx.application.Application;
import javafx.scene.Scene;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.prefs.Preferences;

public class ThemeManager {
    public enum ThemeMode { LIGHT, DARK, SYSTEM }
    
    private static final Preferences PREFERENCES = Preferences.userNodeForPackage(ThemeManager.class);
    private static ThemeMode currentMode = readSavedMode();
    private static Scene currentScene;
    
    public static void init(Scene scene) {
        currentScene = scene;
        applyTheme(currentMode);
    }
    
    public static void setScene(Scene scene) {
        currentScene = scene;
        applyTheme(currentMode);
    }
    
    public static Scene getCurrentScene() {
        return currentScene;
    }
    
    public static void applyTheme(ThemeMode mode) {
        if (mode == null) return;
        currentMode = mode;
        PREFERENCES.put("theme-mode", mode.name());
        boolean isDark = false;
        
        if (mode == ThemeMode.SYSTEM) {
            isDark = isSystemDarkMode();
        } else {
            isDark = (mode == ThemeMode.DARK);
        }
        
        if (isDark) {
            Application.setUserAgentStylesheet(new PrimerDark().getUserAgentStylesheet());
            if (currentScene != null) {
                currentScene.getStylesheets().removeIf(css -> css.contains("app-light.css"));
                if (!currentScene.getStylesheets().toString().contains("app-dark.css")) {
                    currentScene.getStylesheets().add(ThemeManager.class.getResource("/css/app-dark.css").toExternalForm());
                }
                if (!currentScene.getStylesheets().toString().contains("wd-dark-buttons-fx.css")) {
                    currentScene.getStylesheets().add(ThemeManager.class.getResource("/css/wd-dark-buttons-fx.css").toExternalForm());
                }
                installRefinedStyles();
                if (currentScene.getRoot() != null && !currentScene.getRoot().getStyleClass().contains("dark")) {
                    currentScene.getRoot().getStyleClass().add("dark");
                }
            }
        } else {
            Application.setUserAgentStylesheet(new PrimerLight().getUserAgentStylesheet());
            if (currentScene != null) {
                currentScene.getStylesheets().removeIf(css -> css.contains("app-dark.css") || css.contains("wd-dark-buttons-fx.css"));
                if (!currentScene.getStylesheets().toString().contains("app-light.css")) {
                    currentScene.getStylesheets().add(ThemeManager.class.getResource("/css/app-light.css").toExternalForm());
                }
                installRefinedStyles();
                if (currentScene.getRoot() != null) {
                    currentScene.getRoot().getStyleClass().remove("dark");
                    currentScene.getRoot().getStylesheets().removeIf(css -> css.contains("app-dark.css") || css.contains("wd-dark-buttons-fx.css"));
                }
            }
        }
    }
    
    public static ThemeMode getCurrentMode() { return currentMode; }

    private static void installRefinedStyles() {
        if (currentScene == null) return;
        String stylesheet = ThemeManager.class.getResource("/css/app-refined.css").toExternalForm();
        currentScene.getStylesheets().remove(stylesheet);
        currentScene.getStylesheets().add(stylesheet);
    }

    private static ThemeMode readSavedMode() {
        try { return ThemeMode.valueOf(PREFERENCES.get("theme-mode", ThemeMode.LIGHT.name())); }
        catch (IllegalArgumentException exception) { return ThemeMode.LIGHT; }
    }
    
    private static boolean isSystemDarkMode() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("win")) {
                Process proc = Runtime.getRuntime().exec("reg query \"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Themes\\\\Personalize\" /v AppsUseLightTheme");
                BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("0x0")) {
                        return true; // 0 means dark mode
                    }
                }
                return false; // 1 means light mode
            }
            // For macOS or Linux, default to dark for now
            return true;
        } catch (Exception e) {
            return true; // default fallback
        }
    }
}
