package com.aiwatchdog;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import com.aiwatchdog.util.ThemeManager;
import com.aiwatchdog.controller.MainController;

public class MainApp extends Application {
    private MainController mainController;

    @Override
    public void start(Stage stage) throws Exception {
        FXMLLoader loader = new FXMLLoader(MainApp.class.getResource("/fxml/main.fxml"));
        Scene scene = new Scene(loader.load(), 1320, 860);
        mainController = loader.getController();

        ThemeManager.init(scene);
        mainController.syncThemeSelection();

        stage.setTitle("AI WatchDog | Local Security");
        stage.setMinWidth(1000);
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
