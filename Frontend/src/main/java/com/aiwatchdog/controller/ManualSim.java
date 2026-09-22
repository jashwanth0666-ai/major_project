package com.aiwatchdog.controller;

import javafx.application.Platform;

public class ManualSim {
    public static void simulate(MainController controller, javafx.scene.control.Button getStarted, javafx.scene.control.Button completeSetup, javafx.scene.control.Button navScanner, javafx.scene.control.TextField urlInput, javafx.scene.control.Button analyzeBtn, javafx.scene.control.Label resultTitle, javafx.scene.control.Label resultScore) {
        new Thread(() -> {
            try {
                Thread.sleep(1000);
                Platform.runLater(getStarted::fire);
                Thread.sleep(1000);
                Platform.runLater(completeSetup::fire);
                Thread.sleep(1000);
                Platform.runLater(navScanner::fire);
                
                Thread.sleep(2000);
                System.out.println("SIM: Starting Benign URL Test...");
                Platform.runLater(() -> {
                    urlInput.setText("https://www.google.com");
                    analyzeBtn.fire();
                });
                
                Thread.sleep(5000);
                Platform.runLater(() -> {
                    System.out.println("SIM: Benign URL Result Title: " + resultTitle.getText());
                    System.out.println("SIM: Benign URL Risk Score: " + resultScore.getText());
                });
                
                Thread.sleep(1000);
                System.out.println("SIM: Starting Suspicious URL Test...");
                Platform.runLater(() -> {
                    navScanner.fire();
                    urlInput.setText("http://secure-login-paypal-update.com");
                    analyzeBtn.fire();
                });
                
                Thread.sleep(5000);
                Platform.runLater(() -> {
                    System.out.println("SIM: Suspicious URL Result Title: " + resultTitle.getText());
                    System.out.println("SIM: Suspicious URL Risk Score: " + resultScore.getText());
                });
                
                Thread.sleep(1000);
                System.out.println("SIM: Starting Invalid URL Test...");
                Platform.runLater(() -> {
                    navScanner.fire();
                    urlInput.setText("not-a-url");
                    analyzeBtn.fire();
                });
                
                Thread.sleep(1000);
                Platform.runLater(() -> {
                    System.out.println("SIM: Invalid URL complete. App should not crash.");
                });
                
                Thread.sleep(1000);
                System.out.println("SIM: Starting Empty Input Test...");
                Platform.runLater(() -> {
                    navScanner.fire();
                    urlInput.setText("");
                    analyzeBtn.fire();
                });
                
                Thread.sleep(1000);
                System.out.println("SIM: Simulation complete, exiting.");
                System.exit(0);
                
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
}
