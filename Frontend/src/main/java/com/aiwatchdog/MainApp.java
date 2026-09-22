package com.aiwatchdog;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import com.aiwatchdog.util.ThemeManager;

public class MainApp extends Application {
    @Override
    public void start(Stage stage) throws Exception {
        FXMLLoader loader = new FXMLLoader(MainApp.class.getResource("/fxml/main.fxml"));
        Scene scene = new Scene(loader.load(), 1080, 600);
        
        // Initialize Theme Manager (Defaults to SYSTEM)
        ThemeManager.init(scene);
        
        stage.setTitle("AI WatchDog | Phishing Detection & Secure Access");
        stage.setMinWidth(1100);
        stage.setMinHeight(700);
        stage.setScene(scene);
        stage.show();
    }
    public static void main(String[] args) { launch(args); }
}
