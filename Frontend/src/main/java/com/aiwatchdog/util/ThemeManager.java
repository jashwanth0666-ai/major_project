package com.aiwatchdog.util;

import atlantafx.base.theme.PrimerDark;
import atlantafx.base.theme.PrimerLight;
import javafx.application.Application;
import javafx.scene.Scene;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ThemeManager {
    public enum ThemeMode { LIGHT, DARK, SYSTEM }
    
    private static ThemeMode currentMode = ThemeMode.SYSTEM;
    private static Scene currentScene;
    
    public static void init(Scene scene) {
        currentScene = scene;
        applyTheme(ThemeMode.SYSTEM);
    }
    
    public static void applyTheme(ThemeMode mode) {
        currentMode = mode;
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
            }
        } else {
            Application.setUserAgentStylesheet(new PrimerLight().getUserAgentStylesheet());
            if (currentScene != null) {
                currentScene.getStylesheets().removeIf(css -> css.contains("app-dark.css"));
                if (!currentScene.getStylesheets().toString().contains("app-light.css")) {
                    currentScene.getStylesheets().add(ThemeManager.class.getResource("/css/app-light.css").toExternalForm());
                }
            }
        }
    }
    
    public static ThemeMode getCurrentMode() { return currentMode; }
    
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
