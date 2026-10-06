package com.aiwatchdog;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import com.aiwatchdog.util.ThemeManager;

public class MainApp extends Application {
    private com.aiwatchdog.controller.MainController mainController;

    @Override
    public void start(Stage stage) throws Exception {
        FXMLLoader loader = new FXMLLoader(MainApp.class.getResource("/fxml/main.fxml"));
        Scene scene = new Scene(loader.load(), 1280, 780);
        mainController = loader.getController();

        // Initialize UI button motion helper
        com.aiwatchdog.ui.WdButtonFx.installAll(scene.getRoot());

        ThemeManager.init(scene);

        stage.setTitle("AI WatchDog | Phishing Detection Platform");
        stage.setMinWidth(1150);
        stage.setMinHeight(680);
        stage.setScene(scene);
        stage.show();
    }

    @Override
    public void stop() {
        if (mainController != null) mainController.close();
    }

    public static void main(String[] args) { launch(args); }
}
