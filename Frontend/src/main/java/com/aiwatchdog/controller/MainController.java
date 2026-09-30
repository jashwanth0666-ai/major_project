package com.aiwatchdog.controller;

import com.aiwatchdog.model.AnalyzeResponse;
import com.aiwatchdog.model.MonitorEvent;
import com.aiwatchdog.model.SecurityEvent;
import com.aiwatchdog.model.SecurityEventStats;
import com.aiwatchdog.model.ServiceHealth;
import com.aiwatchdog.service.ApiService;
import com.aiwatchdog.service.FileSystemMonitorService;
import com.aiwatchdog.service.ProcessMonitorService;
import com.aiwatchdog.util.ThemeManager;
import org.kordamp.ikonli.javafx.FontIcon;
import javafx.animation.FadeTransition;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.util.Duration;

import java.net.URI;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** JavaFX presentation layer; all analysis and history data comes from Spring REST. */
public class MainController {
    @FXML private StackPane pageStack;
    @FXML private ScrollPane dashboardPage, analysisPage, historyPage, monitoringPage, settingsPage;
    @FXML private Button navDashboardBtn, navAnalyzeBtn, navHistoryBtn, navMonitoringBtn, navSettingsBtn, analyzeBtn, monitoringToggleBtn;
    @FXML private Label pageTitle, pageSubtitle, connectionPill, backendStatus, mlStatus;
    @FXML private Region backendDot, mlDot, monitorBackendDot, monitorMlDot, fileMonitorDot, processMonitorDot;
    @FXML private Label systemStateTitle, systemStateDetail, monitoringSummary;
    @FXML private Label totalEventsValue, highRiskValue, blockedValue, dashboardMessage;
    @FXML private ListView<HistoryItem> recentList, historyList;
    @FXML private VBox recentEmptyState, historyEmptyState, analysisLoading, analysisError, analysisResult;
    @FXML private Label historyEmptyTitle, historyEmptyDetail, historyMessage, analysisErrorText;
    @FXML private ProgressIndicator dashboardLoading, historyLoading;
    @FXML private TextField urlInput;
    @FXML private Label resultDecision, resultRisk, resultUrl, resultScore, resultPrediction, resultProbability, resultReason;
    @FXML private ProgressBar resultScoreBar;
    @FXML private StackPane resultMark;
    @FXML private FontIcon resultIcon;
    @FXML private ComboBox<String> riskFilter, decisionFilter, themeChoice;
    @FXML private Label monitorBackendStatus, monitorMlStatus, fileMonitorDetail, fileMonitorStatus, processMonitorStatus;
    @FXML private Label monitorMessage, backendAddress, settingsConnectionState;

    private final ApiService apiService;
    private final ExecutorService io = Executors.newFixedThreadPool(4, task -> daemon(task, "aiwatchdog-ui-io"));
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(
            task -> daemon(task, "aiwatchdog-ui-refresh"));
    private final AtomicBoolean snapshotLoading = new AtomicBoolean();
    private final AtomicBoolean analysisRunning = new AtomicBoolean();
    private final AtomicBoolean monitoringChanging = new AtomicBoolean();
    private volatile boolean closed;
    private volatile FileSystemMonitorService fileMonitor;
    private volatile ProcessMonitorService processMonitor;
    private List<HistoryItem> allEvents = List.of();
    private String lastSubmittedUrl;
    private boolean hasSnapshot;

    public MainController() { this(new ApiService()); }

    MainController(ApiService apiService) { this.apiService = apiService; }

    @FXML
    private void initialize() {
        riskFilter.setItems(FXCollections.observableArrayList(
                "All risks", "SAFE", "LOW_RISK", "SUSPICIOUS", "HIGH_RISK"));
        decisionFilter.setItems(FXCollections.observableArrayList(
                "All decisions", "ALLOW", "REVIEW", "WARN", "BLOCK"));
        riskFilter.setValue("All risks");
        decisionFilter.setValue("All decisions");
        riskFilter.setOnAction(event -> renderHistory());
        decisionFilter.setOnAction(event -> renderHistory());

        themeChoice.setItems(FXCollections.observableArrayList("System", "Light", "Dark"));
        themeChoice.setValue(toDisplayName(ThemeManager.getCurrentMode()));
        themeChoice.setOnAction(event -> changeTheme());
        backendAddress.setText(apiService.getBaseUrl());
        recentList.setCellFactory(list -> new HistoryCell());
        historyList.setCellFactory(list -> new HistoryCell());
        activateNavigation(navDashboardBtn);
        setPage(dashboardPage, navDashboardBtn, "Dashboard", "Current service health and recent security events");

        backendStatus.setText("Checking");
        mlStatus.setText("Checking");
        fileMonitorStatus.setText("Not started");
        processMonitorStatus.setText("Not started");
        fileMonitorDetail.setText("Start local monitoring to watch configured folders");
        monitoringSummary.setText("Observers not started");
        refreshData();
        scheduler.scheduleAtFixedRate(this::refreshData, 15, 15, TimeUnit.SECONDS);
    }

    public void syncThemeSelection() {
        if (themeChoice != null) themeChoice.setValue(toDisplayName(ThemeManager.getCurrentMode()));
    }

    @FXML private void navigateDashboard() {
        setPage(dashboardPage, navDashboardBtn, "Dashboard", "Current service health and recent security events");
    }

    @FXML private void navigateAnalyze() {
        setPage(analysisPage, navAnalyzeBtn, "Analyze URL", "Review a link through the local security service");
    }

    @FXML private void navigateHistory() {
        setPage(historyPage, navHistoryBtn, "History", "Recent URL analyses and monitor events");
        renderHistory();
    }

    @FXML private void navigateMonitoring() {
        setPage(monitoringPage, navMonitoringBtn, "Monitoring", "Backend health and local observer state");
    }

    @FXML private void navigateSettings() {
        setPage(settingsPage, navSettingsBtn, "Settings", "Appearance and local service configuration");
    }

    private void setPage(Node page, Button active, String title, String subtitle) {
        if (pageStack == null || page == null) return;
        for (Node child : pageStack.getChildren()) {
            boolean selected = child == page;
            child.setManaged(selected);
            child.setVisible(selected);
        }
        activateNavigation(active);
        pageTitle.setText(title);
        pageSubtitle.setText(subtitle);
        page.setOpacity(0.96);
        FadeTransition fade = new FadeTransition(Duration.millis(150), page);
        fade.setToValue(1);
        fade.play();
    }

    private void activateNavigation(Button active) {
        for (Button button : List.of(navDashboardBtn, navAnalyzeBtn, navHistoryBtn, navMonitoringBtn, navSettingsBtn)) {
            button.getStyleClass().remove("nav-active");
        }
        if (active != null && !active.getStyleClass().contains("nav-active")) active.getStyleClass().add("nav-active");
    }

    @FXML
    private void refreshData() {
        if (closed || !snapshotLoading.compareAndSet(false, true)) return;
        Platform.runLater(() -> {
            setBusy(dashboardLoading, true);
            if (historyPage.isVisible()) setBusy(historyLoading, true);
        });
        io.execute(() -> {
            try {
                ServiceHealth health = apiService.getServiceHealth();
                try {
                    List<SecurityEvent> urlEvents = apiService.getRecentEvents();
                    List<MonitorEvent> monitorEvents = apiService.getRecentMonitorEvents();
                    SecurityEventStats stats = apiService.getSecurityEventStats();
                    UiSnapshot snapshot = new UiSnapshot(health, urlEvents, monitorEvents, stats);
                    Platform.runLater(() -> applySnapshot(snapshot));
                } catch (Exception dataException) {
                    Platform.runLater(() -> showDataUnavailable(health));
                }
            } catch (Exception exception) {
                Platform.runLater(() -> showBackendUnavailable());
            } finally {
                snapshotLoading.set(false);
                Platform.runLater(() -> {
                    setBusy(dashboardLoading, false);
                    setBusy(historyLoading, false);
                });
            }
        });
    }

    private void applySnapshot(UiSnapshot snapshot) {
        hasSnapshot = true;
        updateBackendStatus(snapshot.health());
        SecurityEventStats stats = snapshot.stats();
        totalEventsValue.setText(Long.toString(stats.totalEvents()));
        highRiskValue.setText(Long.toString(stats.highRiskCount()));
        blockedValue.setText(Long.toString(stats.blockCount()));

        List<HistoryItem> merged = new ArrayList<>();
        for (SecurityEvent event : snapshot.urlEvents()) merged.add(fromUrl(event));
        for (MonitorEvent event : snapshot.monitorEvents()) merged.add(fromMonitor(event));
        merged.sort(Comparator.comparing(HistoryItem::instant).reversed());
        allEvents = List.copyOf(merged);
        recentList.getItems().setAll(allEvents.stream().limit(6).toList());
        recentEmptyState.setVisible(allEvents.isEmpty());
        recentEmptyState.setManaged(allEvents.isEmpty());
        dashboardMessage.setText("");
        historyMessage.setText("");
        renderHistory();
    }

    private void updateBackendStatus(ServiceHealth health) {
        boolean backendUp = health.isBackendAvailable();
        boolean mlUp = health.isMlAvailable();
        setStatus(backendStatus, backendDot, backendUp ? "Connected" : "Unavailable", backendUp);
        setStatus(mlStatus, mlDot, mlUp ? "Available" : "Unavailable", mlUp);
        setStatus(monitorBackendStatus, monitorBackendDot, backendUp ? "Connected" : "Unavailable", backendUp);
        setStatus(monitorMlStatus, monitorMlDot, mlUp ? "Available" : "Unavailable", mlUp);
        settingsConnectionState.setText(backendUp ? (mlUp ? "Connected" : "ML unavailable") : "Unavailable");
        connectionPill.setText(backendUp && mlUp ? "CONNECTED" : backendUp ? "DEGRADED" : "UNAVAILABLE");
        connectionPill.getStyleClass().removeAll("status-online", "status-offline", "status-pending");
        connectionPill.getStyleClass().add(backendUp && mlUp ? "status-online" : "status-offline");
        if (backendUp && mlUp) {
            systemStateTitle.setText("Local security services are online");
            systemStateDetail.setText("Spring Boot and the ML service are responding to health checks.");
        } else if (backendUp) {
            systemStateTitle.setText("ML service is unavailable");
            systemStateDetail.setText("Spring Boot is reachable, but URL analysis may not be available.");
        } else {
            systemStateTitle.setText("Spring backend is unavailable");
            systemStateDetail.setText("Start the local services to load security history and analyze URLs.");
        }
    }

    private void showBackendUnavailable() {
        if (!hasSnapshot) {
            totalEventsValue.setText("—");
            highRiskValue.setText("—");
            blockedValue.setText("—");
            recentEmptyState.setVisible(true);
            recentEmptyState.setManaged(true);
            historyEmptyTitle.setText("History is unavailable");
            historyEmptyDetail.setText("Connect to Spring Boot to load recorded events.");
            historyEmptyState.setVisible(true);
            historyEmptyState.setManaged(true);
        }
        setStatus(backendStatus, backendDot, "Unavailable", false);
        setStatus(mlStatus, mlDot, "Unavailable", false);
        setStatus(monitorBackendStatus, monitorBackendDot, "Unavailable", false);
        setStatus(monitorMlStatus, monitorMlDot, "Unavailable", false);
        settingsConnectionState.setText("Unavailable");
        connectionPill.setText("UNAVAILABLE");
        connectionPill.getStyleClass().removeAll("status-online", "status-offline", "status-pending");
        connectionPill.getStyleClass().add("status-offline");
        systemStateTitle.setText("Spring backend is unavailable");
        systemStateDetail.setText("Start the local services to load security history and analyze URLs.");
        dashboardMessage.setText("Live backend data is currently unavailable.");
        if (historyPage.isVisible()) historyMessage.setText("Unable to refresh history. Check the local backend and retry.");
    }

    private void showDataUnavailable(ServiceHealth health) {
        updateBackendStatus(health);
        dashboardMessage.setText("Security event data could not be refreshed.");
        if (historyPage.isVisible()) historyMessage.setText("History could not be refreshed. Check the local backend and retry.");
        if (!hasSnapshot) {
            totalEventsValue.setText("—");
            highRiskValue.setText("—");
            blockedValue.setText("—");
            recentEmptyState.setVisible(true);
            recentEmptyState.setManaged(true);
            historyEmptyTitle.setText("History is unavailable");
            historyEmptyDetail.setText("Recorded events could not be loaded from Spring.");
            historyEmptyState.setVisible(true);
            historyEmptyState.setManaged(true);
        }
    }

    private void setStatus(Label label, Region dot, String text, boolean online) {
        label.setText(text);
        dot.getStyleClass().removeAll("status-online", "status-offline", "status-pending");
        dot.getStyleClass().add(online ? "status-online" : "status-offline");
    }

    private HistoryItem fromUrl(SecurityEvent event) {
        String probability = String.format(Locale.ROOT, "%.2f%% phishing probability", event.phishingProbability() * 100);
        return new HistoryItem(parseInstant(event.timestamp()), event.timestamp(), "URL", event.url(),
                event.prediction() + " · " + probability, event.riskLevel(), event.decision(), event.riskScore());
    }

    private HistoryItem fromMonitor(MonitorEvent event) {
        String detail = event.eventType() + " · " + event.action();
        if (event.processId() != null) detail += " · PID " + event.processId();
        if (event.sizeBytes() != null) detail += " · " + formatBytes(event.sizeBytes());
        return new HistoryItem(parseInstant(event.timestamp()), event.timestamp(), event.eventType(),
                event.resourceName(), detail, event.riskLevel(), event.decision(), event.riskScore());
    }

    private void renderHistory() {
        if (historyList == null || riskFilter == null || decisionFilter == null) return;
        String risk = riskFilter.getValue();
        String decision = decisionFilter.getValue();
        List<HistoryItem> filtered = allEvents.stream()
                .filter(event -> risk == null || risk.startsWith("All") || risk.equals(event.risk()))
                .filter(event -> decision == null || decision.startsWith("All") || decision.equals(event.decision()))
                .toList();
        historyList.getItems().setAll(filtered);
        boolean empty = filtered.isEmpty();
        historyEmptyState.setVisible(empty);
        historyEmptyState.setManaged(empty);
        if (empty) {
            boolean noEvents = allEvents.isEmpty();
            historyEmptyTitle.setText(noEvents ? "No security events yet" : "No matching events");
            historyEmptyDetail.setText(noEvents
                    ? "URL analyses and monitor events will appear here."
                    : "Try another risk or decision filter.");
        }
    }

    @FXML private void clearHistoryFilters() {
        riskFilter.setValue("All risks");
        decisionFilter.setValue("All decisions");
        renderHistory();
    }

    @FXML private void analyzeManual() {
        String candidate = urlInput.getText() == null ? "" : urlInput.getText().trim();
        if (candidate.isEmpty()) {
            showAnalysisValidation("Enter a URL to analyze.");
            return;
        }
        try {
            URI uri = URI.create(candidate);
            String scheme = uri.getScheme();
            if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))
                    || uri.getHost() == null) {
                showAnalysisValidation("Enter a valid HTTP or HTTPS URL.");
                return;
            }
        } catch (IllegalArgumentException exception) {
            showAnalysisValidation("Enter a valid HTTP or HTTPS URL.");
            return;
        }
        submitAnalysis(candidate);
    }

    @FXML private void retryAnalysis() {
        if (lastSubmittedUrl != null) submitAnalysis(lastSubmittedUrl);
        else navigateAnalyze();
    }

    private void showAnalysisValidation(String message) {
        lastSubmittedUrl = null;
        analysisErrorText.setText(message);
        setBusy(analysisError, true);
        setBusy(analysisLoading, false);
        setBusy(analysisResult, false);
        navigateAnalyze();
    }

    private void submitAnalysis(String url) {
        if (!analysisRunning.compareAndSet(false, true)) return;
        lastSubmittedUrl = url;
        urlInput.setText(url);
        setBusy(analysisError, false);
        setBusy(analysisResult, false);
        setBusy(analysisLoading, true);
        analyzeBtn.setDisable(true);
        setPage(analysisPage, navAnalyzeBtn, "Analyze URL", "Review a link through the local security service");

        Task<AnalyzeResponse> task = new Task<>() {
            @Override protected AnalyzeResponse call() throws Exception { return apiService.analyzeUrl(url); }
        };
        task.setOnSucceeded(event -> {
            analysisRunning.set(false);
            analyzeBtn.setDisable(false);
            setBusy(analysisLoading, false);
            showAnalysisResult(task.getValue());
            refreshData();
        });
        task.setOnFailed(event -> {
            analysisRunning.set(false);
            analyzeBtn.setDisable(false);
            setBusy(analysisLoading, false);
            setBusy(analysisResult, false);
            analysisErrorText.setText("Unable to connect to AI WatchDog. Check the Spring backend and ML service, then retry.");
            setBusy(analysisError, true);
        });
        io.execute(task);
    }

    private void showAnalysisResult(AnalyzeResponse result) {
        resultDecision.setText(valueOr(result.decision(), "UNKNOWN"));
        resultRisk.setText(valueOr(result.riskLevel(), "UNKNOWN"));
        resultUrl.setText(result.url());
        resultScore.setText(result.riskScore() + " / 100");
        resultPrediction.setText(valueOr(result.prediction(), "UNKNOWN"));
        resultProbability.setText(String.format(Locale.ROOT, "%.2f%%", result.phishingProbability() * 100));
        resultReason.setText(result.reasons() == null || result.reasons().isEmpty()
                ? "The backend returned no additional assessment details."
                : String.join("\n", result.reasons()));
        resultMark.getStyleClass().removeAll("result-safe", "result-warning", "result-danger");
        String decision = result.decision() == null ? "" : result.decision().toUpperCase(Locale.ROOT);
        String risk = result.riskLevel() == null ? "" : result.riskLevel().toUpperCase(Locale.ROOT);
        String statusClass = "BLOCK".equals(decision) || "HIGH_RISK".equals(risk) ? "result-danger"
                : "WARN".equals(decision) || "REVIEW".equals(decision) || "SUSPICIOUS".equals(risk)
                || "LOW_RISK".equals(risk) ? "result-warning" : "result-safe";
        resultMark.getStyleClass().add(statusClass);
        resultRisk.getStyleClass().removeAll("risk-safe", "risk-low", "risk-warning", "risk-danger");
        resultRisk.getStyleClass().add("SAFE".equals(risk) ? "risk-safe"
                : "LOW_RISK".equals(risk) ? "risk-low"
                : "SUSPICIOUS".equals(risk) ? "risk-warning" : "risk-danger");
        resultIcon.setIconLiteral("result-danger".equals(statusClass) ? "fth-alert-triangle"
                : "result-warning".equals(statusClass) ? "fth-alert-circle" : "fth-check");
        resultScoreBar.setProgress(0);
        setBusy(analysisResult, true);
        resultScoreBar.setProgress(0);
        Timeline scoreReveal = new Timeline(new KeyFrame(Duration.millis(420),
                new KeyValue(resultScoreBar.progressProperty(), result.riskScore() / 100.0)));
        scoreReveal.play();
        FadeTransition reveal = new FadeTransition(Duration.millis(180), analysisResult);
        reveal.setFromValue(0.82);
        reveal.setToValue(1);
        reveal.play();
    }

    @FXML private void toggleMonitoring() {
        if (!monitoringChanging.compareAndSet(false, true)) return;
        monitoringToggleBtn.setDisable(true);
        boolean wasRunning = (fileMonitor != null && fileMonitor.isRunning())
                || (processMonitor != null && processMonitor.isRunning());
        if (wasRunning) {
            io.execute(() -> {
                FileSystemMonitorService file = fileMonitor;
                ProcessMonitorService process = processMonitor;
                if (file != null) file.close();
                if (process != null) process.close();
                fileMonitor = null;
                processMonitor = null;
                Platform.runLater(() -> {
                    setStatus(fileMonitorStatus, fileMonitorDot, "Not started", false);
                    setStatus(processMonitorStatus, processMonitorDot, "Not started", false);
                    fileMonitorDetail.setText("Start local monitoring to watch configured folders");
                    monitoringSummary.setText("Observers not started");
                    monitoringToggleBtn.setText("Start local monitoring");
                    monitoringToggleBtn.setDisable(false);
                    monitoringChanging.set(false);
                });
            });
            return;
        }
        fileMonitorStatus.setText("Starting");
        processMonitorStatus.setText("Starting");
        fileMonitorDetail.setText("Registering configured directories");
        monitoringSummary.setText("Starting observers");
        io.execute(() -> {
            if (closed) { monitoringChanging.set(false); return; }
            FileSystemMonitorService file = new FileSystemMonitorService(apiService, this::handleMonitorEvent);
            ProcessMonitorService process = new ProcessMonitorService(apiService, this::handleMonitorEvent);
            fileMonitor = file;
            processMonitor = process;
            try {
                int directories = file.start();
                process.start();
                Platform.runLater(() -> {
                    updateMonitorStatus(file, process, directories, null);
                    monitoringToggleBtn.setDisable(false);
                    monitoringChanging.set(false);
                });
            } catch (Exception exception) {
                file.close();
                process.close();
                fileMonitor = null;
                processMonitor = null;
                Platform.runLater(() -> {
                    updateMonitorStatus(file, process, 0, exception.getMessage());
                    monitoringToggleBtn.setDisable(false);
                    monitoringToggleBtn.setText("Start local monitoring");
                    monitoringChanging.set(false);
                });
            }
        });
    }

    private void updateMonitorStatus(FileSystemMonitorService file, ProcessMonitorService process,
                                     int directories, String error) {
        boolean processUp = process.isRunning();
        boolean fileUp = file.isRunning();
        setStatus(processMonitorStatus, processMonitorDot, processUp ? "Active" : "Unavailable", processUp);
        setStatus(fileMonitorStatus, fileMonitorDot, fileUp ? "Active" : "Unavailable", fileUp);
        fileMonitorDetail.setText(fileUp
                ? "Watching " + directories + " configured directories"
                : error == null ? "No configured user directories are available" : "Unable to watch configured directories");
        monitoringSummary.setText(fileUp && processUp ? "Observers active"
                : processUp ? "Process observer active" : "Observers unavailable");
        monitoringToggleBtn.setText(fileUp || processUp ? "Stop local monitoring" : "Start local monitoring");
        monitorMessage.setText(error == null ? "" : "File observer could not start. Check the configured folders.");
    }

    private void handleMonitorEvent(MonitorEvent event) {
        if (closed) return;
        Platform.runLater(() -> monitorMessage.setText(
                event.eventType() + " event recorded: " + valueOr(event.decision(), "assessed")));
        scheduler.schedule(this::refreshData, 250, TimeUnit.MILLISECONDS);
    }

    private void changeTheme() {
        String selected = themeChoice.getValue();
        if (selected == null) return;
        ThemeManager.applyTheme(ThemeManager.ThemeMode.valueOf(selected.toUpperCase(Locale.ROOT)));
    }

    private static String toDisplayName(ThemeManager.ThemeMode mode) {
        return mode.name().substring(0, 1) + mode.name().substring(1).toLowerCase(Locale.ROOT);
    }

    private static String valueOr(String value, String fallback) { return value == null || value.isBlank() ? fallback : value; }

    private static Instant parseInstant(String value) {
        try { return Instant.parse(value); } catch (RuntimeException exception) { return Instant.EPOCH; }
    }

    private static String formatTime(String value) {
        try { return DateTimeFormatter.ofPattern("MMM d · HH:mm").withZone(ZoneId.systemDefault()).format(Instant.parse(value)); }
        catch (RuntimeException exception) { return value == null ? "Time unavailable" : value; }
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format(Locale.ROOT, "%.1f KB", bytes / 1024.0);
        return String.format(Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0));
    }

    private static void setBusy(Node node, boolean busy) {
        if (node == null) return;
        node.setVisible(busy);
        node.setManaged(busy);
    }

    private static Thread daemon(Runnable task, String name) {
        Thread thread = new Thread(task, name);
        thread.setDaemon(true);
        return thread;
    }

    public void close() {
        closed = true;
        scheduler.shutdownNow();
        io.shutdownNow();
        FileSystemMonitorService file = fileMonitor;
        ProcessMonitorService process = processMonitor;
        if (file != null) file.close();
        if (process != null) process.close();
        fileMonitor = null;
        processMonitor = null;
    }

    private record UiSnapshot(ServiceHealth health, List<SecurityEvent> urlEvents,
                              List<MonitorEvent> monitorEvents, SecurityEventStats stats) { }

    private record HistoryItem(Instant instant, String timestamp, String kind, String primary,
                               String secondary, String risk, String decision, int score) { }

    private static final class HistoryCell extends ListCell<HistoryItem> {
        private final HBox row = new HBox(12);
        private final VBox description = new VBox(4);
        private final Label primary = new Label();
        private final Label secondary = new Label();
        private final Label time = new Label();
        private final Label risk = new Label();
        private final Label decision = new Label();
        private final Region spacer = new Region();

        private HistoryCell() {
            row.getStyleClass().add("event-row");
            description.getStyleClass().add("event-description");
            primary.getStyleClass().add("event-primary");
            secondary.getStyleClass().add("event-secondary");
            secondary.setWrapText(true);
            secondary.setMaxWidth(400);
            time.getStyleClass().add("event-time");
            risk.getStyleClass().add("event-badge");
            decision.getStyleClass().add("event-badge");
            HBox.setHgrow(spacer, javafx.scene.layout.Priority.ALWAYS);
            description.getChildren().addAll(primary, secondary);
            row.setAlignment(javafx.geometry.Pos.CENTER_LEFT);
            row.getChildren().addAll(description, spacer, time, risk, decision);
            setContentDisplay(ContentDisplay.GRAPHIC_ONLY);
        }

        @Override protected void updateItem(HistoryItem item, boolean empty) {
            super.updateItem(item, empty);
            if (empty || item == null) { setGraphic(null); setText(null); return; }
            primary.setText(item.primary());
            secondary.setText(item.secondary());
            time.setText(formatTime(item.timestamp()));
            risk.setText(item.risk() + " · " + item.score());
            decision.setText(item.decision());
            risk.getStyleClass().removeAll("risk-safe", "risk-low", "risk-warning", "risk-danger");
            decision.getStyleClass().removeAll("decision-allow", "decision-review", "decision-warn", "decision-block");
            String riskName = item.risk() == null ? "" : item.risk().toUpperCase(Locale.ROOT);
            risk.getStyleClass().add("SAFE".equals(riskName) ? "risk-safe"
                    : "LOW_RISK".equals(riskName) ? "risk-low"
                    : "SUSPICIOUS".equals(riskName) ? "risk-warning" : "risk-danger");
            String decisionName = item.decision() == null ? "" : item.decision().toUpperCase(Locale.ROOT);
            decision.getStyleClass().add(switch (decisionName) {
                case "ALLOW" -> "decision-allow";
                case "REVIEW" -> "decision-review";
                case "WARN" -> "decision-warn";
                default -> "decision-block";
            });
            setAccessibleText(item.kind() + ", " + item.primary() + ", risk " + item.risk() + ", decision " + item.decision());
            setGraphic(row);
        }
    }
}
