package com.aiwatchdog;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import com.aiwatchdog.util.ThemeManager;
import com.aiwatchdog.util.SystemTraySupport;
import javafx.application.Platform;
import javafx.scene.image.Image;

import java.io.InputStream;

public class MainApp extends Application {
    private com.aiwatchdog.controller.MainController mainController;
    private SystemTraySupport systemTray;

    @Override
    public void start(Stage stage) throws Exception {
        FXMLLoader loader = new FXMLLoader(MainApp.class.getResource("/fxml/main.fxml"));
        Scene scene = new Scene(loader.load(), 1280, 780);
        mainController = loader.getController();

        // Initialize UI button motion helper
        com.aiwatchdog.ui.WdButtonFx.installAll(scene.getRoot());

        ThemeManager.init(scene);

        stage.setTitle("AI WatchDog | Phishing Detection Platform");
        try (InputStream icon = MainApp.class.getResourceAsStream("/icons/watchdog-tray.png")) {
            if (icon != null) stage.getIcons().add(new Image(icon));
        }
        stage.setMinWidth(1150);
        stage.setMinHeight(680);
        stage.setScene(scene);
        systemTray = SystemTraySupport.install(stage, mainController::openAlertsFromTray);
        if (systemTray != null) mainController.setSystemTraySupport(systemTray);
        stage.setOnCloseRequest(event -> {
            if (systemTray != null && systemTray.shouldHideOnClose()) {
                event.consume();
                stage.hide();
            }
        });
        stage.setMaximized(true);
        stage.show();
    }

    @Override
    public void stop() {
        if (mainController != null) mainController.close();
        if (systemTray != null) systemTray.close();
        Platform.setImplicitExit(true);
    }

    public static void main(String[] args) { launch(args); }
}
