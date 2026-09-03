package com.aiwatchdog.controller;

import com.aiwatchdog.model.AnalysisResult;
import com.aiwatchdog.model.ThreatLevel;
import com.aiwatchdog.service.BrowserMonitorService;
import com.aiwatchdog.service.DemoPhishingDetectionEngine;
import com.aiwatchdog.service.PhishingDetectionEngine;
import javafx.animation.FadeTransition;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.PauseTransition;
import javafx.animation.ParallelTransition;
import javafx.animation.ScaleTransition;
import javafx.animation.Timeline;
import javafx.animation.TranslateTransition;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.util.Duration;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

public class MainController {
    @FXML
    private StackPane root, pageStack;
    @FXML
    private VBox welcomePage, setupPage, dashboardPage, scannerPage, threatsPage, activityPage, insightsPage,
            settingsPage, analysisPage, resultPage;
    @FXML
    private BorderPane appShell;
    @FXML
    private TextField urlInput;
    @FXML
    private Label analysisUrl, analysisStage, resultTitle, resultSubtitle, resultScore, resultDecision, resultReason,
            dashboardScore, scannedCount, blockedCount, activityStatus, toast;
    @FXML
    private ProgressBar analysisProgress;
    @FXML
    private ListView<String> featureList, threatList, activityList;
    @FXML
    private Button proceedButton;
    private final PhishingDetectionEngine engine = new DemoPhishingDetectionEngine();
    private final BrowserMonitorService browser = new BrowserMonitorService();
    private int scanned = 1284;
    private int blocked = 37;
    private final DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm");

    @FXML
    private void initialize() {
        showOnly(welcomePage);
    }

    @FXML
    private void startProtection() {
        showOnly(setupPage);
    }

    @FXML
    private void completeSetup() {
        showOnly(appShell);
        showPage(dashboardPage);
        notifyUser("Protection is active");
    }

    @FXML
    private void navigateDashboard() {
        showPage(dashboardPage);
    }

    @FXML
    private void navigateScanner() {
        showPage(scannerPage);
    }

    @FXML
    private void navigateThreats() {
        showPage(threatsPage);
    }

    @FXML
    private void navigateActivity() {
        showPage(activityPage);
    }

    @FXML
    private void navigateInsights() {
        showPage(insightsPage);
    }

    @FXML
    private void navigateSettings() {
        showPage(settingsPage);
    }

    @FXML
    private void simulateRandom() {
        analyze(browser.simulateRandomEvent());
    }

    @FXML
    private void simulateSafe() {
        analyze(browser.safe());
    }

    @FXML
    private void simulateSuspicious() {
        analyze(browser.suspicious());
    }

    @FXML
    private void simulatePhishing() {
        analyze(browser.phishing());
    }

    @FXML
    private void analyzeManual() {
        if (urlInput.getText().isBlank())
            notifyUser("Enter a URL to analyze");
        else
            analyze(urlInput.getText());
    }

    @FXML
    private void backToDashboard() {
        showPage(dashboardPage);
    }

    @FXML
    private void proceedAnyway() {
        notifyUser("Proceeding is simulated in Demo Mode");
        showPage(dashboardPage);
    }

    private void analyze(String url) {
        AnalysisResult result = engine.analyze(url);
        analysisUrl.setText(result.url());
        analysisProgress.setProgress(0);
        analysisStage.setText("Detecting URL and preparing feature scan...");
        featureList.getItems().setAll(result.features());
        showPage(analysisPage);
        Timeline scan = new Timeline(
                new KeyFrame(Duration.ZERO, new KeyValue(analysisProgress.progressProperty(), 0)),
                new KeyFrame(Duration.millis(360),
                        event -> analysisStage.setText("Extracting lexical and security features..."),
                        new KeyValue(analysisProgress.progressProperty(), 0.28)),
                new KeyFrame(Duration.millis(720),
                        event -> analysisStage.setText("Evaluating domain structure and threat indicators..."),
                        new KeyValue(analysisProgress.progressProperty(), 0.62)),
                new KeyFrame(Duration.millis(1100),
                        event -> analysisStage.setText("Calculating risk and access decision..."),
                        new KeyValue(analysisProgress.progressProperty(), 0.88)),
                new KeyFrame(Duration.millis(1420), event -> showResult(result),
                        new KeyValue(analysisProgress.progressProperty(), 1)));
        scan.play();
    }

    private void showResult(AnalysisResult result) {
        analysisProgress.setProgress(1);
        resultTitle.setText(result.level() == ThreatLevel.PHISHING ? "ACCESS BLOCKED" : result.label());
        resultSubtitle.setText(result.level() == ThreatLevel.SAFE ? "Website appears safe"
                : result.level() == ThreatLevel.SUSPICIOUS ? "Suspicious website detected"
                        : "Phishing website detected");
        resultScore.setText(result.score() + " / 100");
        resultDecision.setText(result.decision());
        resultReason.setText(String.join("  •  ", result.reasons()));
        proceedButton.setVisible(result.level() == ThreatLevel.SUSPICIOUS);
        scanned++;
        if (result.level() == ThreatLevel.PHISHING || result.level() == ThreatLevel.HIGH_RISK)
            blocked++;
        scannedCount.setText(String.format("%,d", scanned));
        blockedCount.setText(String.valueOf(blocked));
        dashboardScore.setText(result.score() + " / 100");
        String entry = timeFormat.format(LocalTime.now()) + "  ·  " + result.url() + "  ·  " + result.label();
        activityList.getItems().add(0, entry);
        if (result.level() != ThreatLevel.SAFE)
            threatList.getItems().add(0, entry);
        activityStatus.setText(result.label() + " analysis completed");
        showPage(resultPage);
        ScaleTransition reveal = new ScaleTransition(Duration.millis(260), resultTitle);
        reveal.setFromX(0.94);
        reveal.setFromY(0.94);
        reveal.setToX(1);
        reveal.setToY(1);
        reveal.play();
    }

    private void showPage(Node page) {
        pageStack.getChildren().forEach(child -> child.setVisible(child == page));
        page.toFront();
        page.setOpacity(0);
        page.setTranslateY(8);
        FadeTransition fade = new FadeTransition(Duration.millis(220), page);
        fade.setToValue(1);
        TranslateTransition slide = new TranslateTransition(Duration.millis(220), page);
        slide.setToY(0);
        new ParallelTransition(fade, slide).play();
    }

    private void showOnly(Node page) {
        root.getChildren().forEach(child -> child.setVisible(child == page));
        page.toFront();
        page.setOpacity(0);
        FadeTransition fade = new FadeTransition(Duration.millis(300), page);
        fade.setToValue(1);
        fade.play();
    }

    private void notifyUser(String message) {
        toast.setText(message);
        toast.setVisible(true);
        PauseTransition pause = new PauseTransition(Duration.seconds(2.5));
        pause.setOnFinished(e -> toast.setVisible(false));
        pause.play();
    }
}
