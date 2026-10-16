package com.aiwatchdog.util;

import javafx.application.Platform;
import javafx.stage.Stage;

import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import javax.imageio.ImageIO;
import java.util.concurrent.atomic.AtomicBoolean;

/** Optional Windows notification-area integration. It does not install startup persistence. */
public final class SystemTraySupport implements AutoCloseable {
    private final Stage stage;
    private final Runnable openAlerts;
    private final AtomicBoolean exiting = new AtomicBoolean();
    private TrayIcon trayIcon;

    private SystemTraySupport(Stage stage, Runnable openAlerts) {
        this.stage = stage;
        this.openAlerts = openAlerts;
    }

    public static SystemTraySupport install(Stage stage, Runnable openAlerts) {
        SystemTraySupport support = new SystemTraySupport(stage, openAlerts);
        return support.install() ? support : null;
    }

    private boolean install() {
        if (!SystemTray.isSupported()) return false;
        try {
            PopupMenu menu = new PopupMenu();
            MenuItem dashboard = new MenuItem("Open AI WatchDog");
            dashboard.addActionListener(event -> Platform.runLater(this::showDashboard));
            menu.add(dashboard);
            MenuItem alerts = new MenuItem("Inspect alerts");
            alerts.addActionListener(event -> Platform.runLater(() -> {
                showDashboard();
                openAlerts.run();
            }));
            menu.add(alerts);
            menu.addSeparator();
            MenuItem exit = new MenuItem("Exit");
            exit.addActionListener(event -> Platform.runLater(() -> {
                exiting.set(true);
                Platform.exit();
            }));
            menu.add(exit);

            trayIcon = new TrayIcon(loadTrayImage(), "AI WatchDog security monitor", menu);
            trayIcon.setImageAutoSize(true);
            trayIcon.addActionListener(event -> Platform.runLater(this::showDashboard));
            SystemTray.getSystemTray().add(trayIcon);
            Platform.setImplicitExit(false);
            return true;
        } catch (java.awt.AWTException | SecurityException exception) {
            trayIcon = null;
            return false;
        }
    }

    public boolean isInstalled() { return trayIcon != null; }

    public boolean shouldHideOnClose() { return isInstalled() && !exiting.get(); }

    public void showNotification(String title, String message) {
        TrayIcon icon = trayIcon;
        if (icon != null) icon.displayMessage(title, message, TrayIcon.MessageType.WARNING);
    }

    private BufferedImage loadTrayImage() {
        try (var stream = SystemTraySupport.class.getResourceAsStream("/icons/watchdog-tray.png")) {
            if (stream == null) return fallbackImage();
            BufferedImage source = ImageIO.read(stream);
            if (source == null) return fallbackImage();
            BufferedImage trayImage = new BufferedImage(64, 64, BufferedImage.TYPE_INT_ARGB);
            Graphics2D graphics = trayImage.createGraphics();
            try {
                graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
                graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                graphics.drawImage(source, 0, 0, 64, 64, null);
            } finally {
                graphics.dispose();
            }
            return trayImage;
        } catch (IOException | RuntimeException exception) {
            return fallbackImage();
        }
    }

    private BufferedImage fallbackImage() {
        BufferedImage image = new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB);
        Graphics2D graphics = image.createGraphics();
        try {
            graphics.setColor(new java.awt.Color(16, 185, 129));
            graphics.fillRoundRect(1, 1, 14, 14, 5, 5);
            graphics.setColor(java.awt.Color.WHITE);
            graphics.drawString("W", 3, 12);
        } finally {
            graphics.dispose();
        }
        return image;
    }

    private void showDashboard() {
        if (!stage.isShowing()) stage.show();
        stage.toFront();
        stage.requestFocus();
    }

    @Override
    public void close() {
        TrayIcon icon = trayIcon;
        trayIcon = null;
        if (icon != null) SystemTray.getSystemTray().remove(icon);
    }
}
