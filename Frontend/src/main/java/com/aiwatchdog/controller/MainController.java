package com.aiwatchdog.controller;

import com.aiwatchdog.model.AnalyzeResponse;
import com.aiwatchdog.service.ApiService;
import javafx.animation.FadeTransition;
import javafx.animation.ParallelTransition;
import javafx.animation.PauseTransition;
import javafx.animation.ScaleTransition;
import javafx.animation.TranslateTransition;
import javafx.application.Platform;
import javafx.concurrent.Task;
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
            settingsPage, analysisPage, resultPage, errorPage, permissionsPage, securityControlsPage;
    @FXML
    private BorderPane appShell;
    @FXML
    private TextField urlInput;
    @FXML
    private Label analysisUrl, analysisStage, resultTitle, resultSubtitle, resultScore, resultDecision, resultReason,
            dashboardScore, scannedCount, blockedCount, activityStatus, toast, errorMessageLabel;
    @FXML
    private ProgressIndicator analysisProgress;
    @FXML
    private ListView<String> threatList, activityList, featureList;
    @FXML
    private Button proceedButton, analyzeBtn;
    @FXML
    private VBox sidebar;

    private final ApiService apiService = new ApiService();
    private final com.aiwatchdog.service.BrowserMonitorService browser = new com.aiwatchdog.service.BrowserMonitorService();
    private int scanned = 0;
    private int blocked = 0;
    private final DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm");
    private boolean sidebarVisible = true;

    @FXML
    private void toggleSidebar() {
        if (sidebar != null) {
            sidebarVisible = !sidebarVisible;
            sidebar.setVisible(sidebarVisible);
            sidebar.setManaged(sidebarVisible);
        }
    }

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
    private void navigatePermissions() {
        if (permissionsPage != null)
            showPage(permissionsPage);
        else
            notifyUser("Permissions Center not yet implemented");
    }

    @FXML
    private void navigateSecurityControls() {
        if (securityControlsPage != null)
            showPage(securityControlsPage);
        else
            notifyUser("Security Controls not yet implemented");
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
        String url = urlInput.getText();
        if (url == null || url.isBlank()) {
            notifyUser("Enter a URL to analyze");
            return;
        }
        if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
            notifyUser("URL must start with http:// or https://");
            return;
        }
        analyze(url);
    }

    @FXML
    private void backToDashboard() {
        showPage(dashboardPage);
    }

    @FXML
    private void proceedAnyway() {
        notifyUser("Proceeding with caution...");
        showPage(dashboardPage);
    }

    @FXML
    private void retryConnection() {
        showPage(scannerPage);
    }

    private void analyze(String url) {
        if (analysisUrl != null)
            analysisUrl.setText(url);
        if (analysisProgress != null)
            analysisProgress.setProgress(ProgressIndicator.INDETERMINATE_PROGRESS);
        if (analysisStage != null)
            analysisStage.setText("Contacting Security API...");
        if (analyzeBtn != null)
            analyzeBtn.setDisable(true);
        showPage(analysisPage);

        Task<AnalyzeResponse> task = new Task<>() {
            @Override
            protected AnalyzeResponse call() throws Exception {
                updateMessage("Analyzing URL via Policy Engine...");
                return apiService.analyzeUrl(url);
            }
        };

        task.messageProperty().addListener((obs, oldMsg, newMsg) -> {
            if (analysisStage != null)
                analysisStage.setText(newMsg);
        });

        task.setOnSucceeded(e -> {
            if (analyzeBtn != null)
                analyzeBtn.setDisable(false);
            AnalyzeResponse response = task.getValue();
            showResult(response);
        });

        task.setOnFailed(e -> {
            if (analyzeBtn != null)
                analyzeBtn.setDisable(false);
            Throwable ex = task.getException();
            ex.printStackTrace();
            showError("Service Unavailable: " + ex.getMessage());
        });

        Thread th = new Thread(task);
        th.setDaemon(true);
        th.start();
    }

    private void showResult(AnalyzeResponse result) {
        if (analysisProgress != null)
            analysisProgress.setProgress(1);

        String decision = result.decision() != null ? result.decision().toUpperCase() : "UNKNOWN";
        String riskLevel = result.riskLevel() != null ? result.riskLevel().toUpperCase() : "UNKNOWN";

        if (resultTitle != null)
            resultTitle.setText(decision);
        if (resultSubtitle != null)
            resultSubtitle.setText(result.prediction() != null ? result.prediction() : "Analysis Complete");
        if (resultScore != null)
            resultScore.setText(String.format("%d / 100 (%s)", result.riskScore(), riskLevel));
        if (resultDecision != null)
            resultDecision.setText(String.format("Policy Decision: %s (Phishing Prob: %.1f%%)", decision,
                    result.phishingProbability() * 100));

        if (resultReason != null) {
            if (result.reasons() != null && !result.reasons().isEmpty()) {
                resultReason.setText(String.join("\n", result.reasons()));
            } else {
                resultReason.setText("No additional details provided by policy engine.");
            }
        }

        if (proceedButton != null)
            proceedButton.setVisible("WARN".equals(decision) || "REVIEW".equals(decision));

        scanned++;
        if ("BLOCK".equals(decision))
            blocked++;

        if (scannedCount != null)
            scannedCount.setText(String.format("%,d", scanned));
        if (blockedCount != null)
            blockedCount.setText(String.valueOf(blocked));
        if (dashboardScore != null)
            dashboardScore.setText(result.riskScore() + " / 100");

        String entry = timeFormat.format(LocalTime.now()) + " | " + result.url() + " | " + decision;
        if (activityList != null)
            activityList.getItems().add(0, entry);
        if (threatList != null && !"ALLOW".equals(decision))
            threatList.getItems().add(0, entry);

        if (activityStatus != null)
            activityStatus.setText("Analysis completed: " + decision);
        activityStatus.setText("Last analysis completed: " + decision);
        showPage(resultPage);

        if (resultTitle != null) {
            ScaleTransition reveal = new ScaleTransition(Duration.millis(260), resultTitle);
            reveal.setFromX(0.94);
            reveal.setFromY(0.94);
            reveal.setToX(1);
            reveal.setToY(1);
            reveal.play();
        }
    }

    private void showError(String errorMsg) {
        if (errorMessageLabel != null) {
            errorMessageLabel.setText(errorMsg);
        }
        if (errorPage != null) {
            showPage(errorPage);
        } else {
            notifyUser(errorMsg);
            showPage(scannerPage);
        }
    }

    private void showPage(Node page) {
        if (pageStack != null && page != null) {
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
    }

    private void showOnly(Node page) {
        if (root != null && page != null) {
            root.getChildren().forEach(child -> child.setVisible(child == page));
            page.toFront();
            page.setOpacity(0);
            FadeTransition fade = new FadeTransition(Duration.millis(300), page);
            fade.setToValue(1);
            fade.play();
        }
    }

    private void notifyUser(String message) {
        if (toast != null) {
            toast.setText(message);
            toast.setVisible(true);
            PauseTransition pause = new PauseTransition(Duration.seconds(2.5));
            pause.setOnFinished(e -> toast.setVisible(false));
            pause.play();
        }
    }
}
