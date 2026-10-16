package com.aiwatchdog.controller;

import com.aiwatchdog.model.FileShieldSettings;
import com.aiwatchdog.model.FileShieldSettingsUpdate;
import com.aiwatchdog.model.NotificationPreferences;
import com.aiwatchdog.model.WindowsTelemetrySettings;
import com.aiwatchdog.model.WindowsTelemetrySettingsUpdate;
import com.aiwatchdog.service.ApiService;
import com.aiwatchdog.util.DesktopMonitorPreferences;
import com.aiwatchdog.util.ThemeManager;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/** Settings that change real application behavior; backend changes are applied immediately. */
public final class SettingsController {
    @FXML private Button fileShieldTab, localMonitorTab, appearanceTab, aboutTab;
    @FXML private VBox fileShieldPane, localMonitorPane, appearancePane, aboutPane;
    @FXML private ListView<String> approvedRootsList, watchDirectoriesList, localMonitorRootsList;
    @FXML private TextField reputationDatabasePath;
    @FXML private CheckBox fileShieldEnabled, backendMonitoringEnabled, recursiveMonitoring;
    @FXML private Spinner<Integer> monitoringDepth, maxFilesPerScan, scanDepth;
    @FXML private Spinner<Integer> maxFileSizeMb;
    @FXML private Label backendSettingsStatus, reputationDatabaseStatus, settingsMessage;
    @FXML private CheckBox notificationsEnabled, warnNotificationsEnabled, blockNotificationsEnabled;
    @FXML private Label notificationPreferencesStatus;
    @FXML private Button saveNotificationPreferencesButton;
    @FXML private CheckBox windowsTelemetryEnabled;
    @FXML private CheckBox scriptMonitoringEnabled;
    @FXML private CheckBox processMonitoringEnabled;
    @FXML private Label windowsTelemetryStatus;
    @FXML private Button saveWindowsTelemetryButton;

    private final ApiService api = new ApiService();
    private final ExecutorService executor = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "aiwatchdog-settings");
        thread.setDaemon(true);
        return thread;
    });
    private Consumer<List<Path>> localMonitoringApply = paths -> { };
    private boolean backendFileWatcherActive;
    private WindowsTelemetrySettings confirmedWindowsTelemetrySettings;

    @FXML private Button themeLightBtn, themeDarkBtn, themeSystemBtn;
    @FXML private Label activeThemeLabel;

    @FXML
    private void initialize() {
        approvedRootsList.setItems(FXCollections.observableArrayList());
        watchDirectoriesList.setItems(FXCollections.observableArrayList());
        localMonitorRootsList.setItems(FXCollections.observableArrayList(loadLocalRoots()));
        monitoringDepth.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(0, 20, 5));
        maxFilesPerScan.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 10000, 500));
        scanDepth.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(0, 20, 5));
        maxFileSizeMb.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 1024, 100));
        fileShieldEnabled.selectedProperty().addListener((observable, oldValue, enabled) -> {
            backendMonitoringEnabled.setDisable(!enabled);
            if (!enabled) backendMonitoringEnabled.setSelected(false);
        });
        notificationsEnabled.selectedProperty().addListener((observable, oldValue, enabled) -> {
            warnNotificationsEnabled.setDisable(!enabled);
            blockNotificationsEnabled.setDisable(!enabled);
        });
        ThemeManager.ThemeMode mode = ThemeManager.getCurrentMode();
        if (mode == null) mode = ThemeManager.ThemeMode.LIGHT;
        updateThemeButtons(mode);
        loadBackendSettings();
        loadNotificationPreferences();
        loadWindowsTelemetrySettings();
    }

    public void setLocalMonitoringApplyHandler(Consumer<List<Path>> handler) {
        localMonitoringApply = handler == null ? paths -> { } : handler;
    }

    @FXML private void showFileShield() { show(fileShieldTab, fileShieldPane); }
    @FXML private void showLocalMonitor() { show(localMonitorTab, localMonitorPane); }
    @FXML private void showAppearance() { show(appearanceTab, appearancePane); }
    @FXML private void showAbout() { show(aboutTab, aboutPane); }

    private void show(Button button, VBox pane) {
        for (Button tab : List.of(fileShieldTab, localMonitorTab, appearanceTab, aboutTab))
            tab.getStyleClass().remove("settings-subnav-btn-active");
        button.getStyleClass().add("settings-subnav-btn-active");
        for (VBox candidate : List.of(fileShieldPane, localMonitorPane, appearancePane, aboutPane)) {
            boolean active = candidate == pane;
            candidate.setVisible(active);
            candidate.setManaged(active);
        }
    }

    @FXML private void addApprovedRoot() { chooseDirectory(approvedRootsList, "Choose an approved File Shield scan root"); }
    @FXML private void addWatchDirectory() { chooseDirectory(watchDirectoriesList, "Choose a backend monitored folder"); }
    @FXML private void addLocalMonitorRoot() { chooseDirectory(localMonitorRootsList, "Choose a desktop monitoring folder"); }
    @FXML private void removeApprovedRoot() { removeSelected(approvedRootsList); }
    @FXML private void removeWatchDirectory() { removeSelected(watchDirectoriesList); }
    @FXML private void removeLocalMonitorRoot() { removeSelected(localMonitorRootsList); }

    private void chooseDirectory(ListView<String> list, String title) {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle(title);
        File selected = chooser.showDialog(ownerWindow());
        if (selected != null) {
            String path = selected.toPath().toAbsolutePath().normalize().toString();
            if (!list.getItems().contains(path)) list.getItems().add(path);
        }
    }

    private void removeSelected(ListView<String> list) {
        int index = list.getSelectionModel().getSelectedIndex();
        if (index >= 0) list.getItems().remove(index);
    }

    @FXML private void browseReputationDatabase() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose the local hash reputation database");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("SQLite database", "*.db", "*.sqlite", "*.sqlite3"));
        File current = Path.of(reputationDatabasePath.getText().isBlank() ? "file_reputation.db" : reputationDatabasePath.getText()).toFile();
        if (current.getParentFile() != null && current.getParentFile().isDirectory()) chooser.setInitialDirectory(current.getParentFile());
        File selected = chooser.showOpenDialog(ownerWindow());
        if (selected != null) reputationDatabasePath.setText(selected.toPath().toAbsolutePath().normalize().toString());
    }

    private void loadBackendSettings() {
        backendSettingsStatus.setText("Loading settings from Spring Boot…");
        Task<FileShieldSettings> task = new Task<>() {
            @Override protected FileShieldSettings call() throws Exception { return api.getFileShieldSettings(); }
        };
        task.setOnSucceeded(event -> displayBackendSettings(task.getValue()));
        task.setOnFailed(event -> backendSettingsStatus.setText("Backend settings unavailable: " + message(task.getException())));
        executor.execute(task);
    }

    private void loadNotificationPreferences() {
        notificationPreferencesStatus.setText("Loading notification preferences from Spring Boot…");
        Task<NotificationPreferences> task = new Task<>() {
            @Override protected NotificationPreferences call() throws Exception { return api.getNotificationPreferences(); }
        };
        task.setOnSucceeded(event -> displayNotificationPreferences(task.getValue()));
        task.setOnFailed(event -> notificationPreferencesStatus.setText(
                "Notification preferences unavailable: " + message(task.getException())));
        executor.execute(task);
    }

    private void displayNotificationPreferences(NotificationPreferences preferences) {
        notificationsEnabled.setSelected(preferences.enabled());
        warnNotificationsEnabled.setSelected(preferences.warnEnabled());
        blockNotificationsEnabled.setSelected(preferences.blockEnabled());
        warnNotificationsEnabled.setDisable(!preferences.enabled());
        blockNotificationsEnabled.setDisable(!preferences.enabled());
        notificationsEnabled.setDisable(false);
        saveNotificationPreferencesButton.setDisable(false);
        notificationPreferencesStatus.setText("Preferences confirmed by Spring Boot and saved for this Windows user.");
    }

    private void loadWindowsTelemetrySettings() {
        windowsTelemetryStatus.setText("Loading Windows provider and collector state from Spring Boot…");
        Task<WindowsTelemetrySettings> task = new Task<>() {
            @Override protected WindowsTelemetrySettings call() throws Exception { return api.getWindowsTelemetrySettings(); }
        };
        task.setOnSucceeded(event -> displayWindowsTelemetrySettings(task.getValue()));
        task.setOnFailed(event -> windowsTelemetryStatus.setText(
                "Windows telemetry state unavailable: " + message(task.getException())));
        executor.execute(task);
    }

    private void displayWindowsTelemetrySettings(WindowsTelemetrySettings settings) {
        confirmedWindowsTelemetrySettings = settings;
        windowsTelemetryEnabled.setSelected(settings.windowsTelemetryEnabled());
        scriptMonitoringEnabled.setSelected(settings.scriptMonitoringEnabled());
        processMonitoringEnabled.setSelected(settings.processMonitoringEnabled());
        windowsTelemetryEnabled.setDisable(!settings.supported());
        scriptMonitoringEnabled.setDisable(!settings.supported());
        processMonitoringEnabled.setDisable(!settings.supported());
        saveWindowsTelemetryButton.setDisable(!settings.supported());
        windowsTelemetryStatus.setText(formatWindowsTelemetryStatus(settings));
    }

    private String formatWindowsTelemetryStatus(WindowsTelemetrySettings settings) {
        StringBuilder status = new StringBuilder(settings.state()).append(" · ").append(settings.message());
        for (var provider : settings.providers()) {
            status.append("\n").append(provider.provider()).append(": ").append(provider.state());
            if (provider.errorCategory() != null) status.append(" (").append(provider.errorCategory()).append(')');
            if (provider.lastEventTimestamp() != null) status.append(" · last event ").append(provider.lastEventTimestamp());
            else if (provider.eventsReceived() == 0 && "SUBSCRIBED".equals(provider.state())) status.append(" · no event received this session");
        }
        if (settings.droppedEvents() > 0) status.append("\nDropped telemetry events: ").append(settings.droppedEvents());
        if (settings.restartCount() > 0) status.append(" · collector restarts: ").append(settings.restartCount());
        if (settings.scriptMonitoringEnabled()) {
            status.append("\nScript analysis: PowerShell event subscription is separate from script block audit policy.");
            status.append(backendFileWatcherActive
                    ? " Static inspection follows the configured backend File Shield watch roots."
                    : " Static file inspection is UNAVAILABLE until backend File Shield folder monitoring is active.");
        }
        if (settings.processMonitoringEnabled()) {
            status.append("\nProcess correlation requires Windows process creation auditing to be enabled by an administrator; AI WatchDog does not change audit policy.");
        }
        return status.toString();
    }

    @FXML
    private void saveWindowsTelemetrySettings() {
        boolean requested = windowsTelemetryEnabled.isSelected();
        boolean scriptRequested = scriptMonitoringEnabled.isSelected();
        boolean processRequested = processMonitoringEnabled.isSelected();
        saveWindowsTelemetryButton.setDisable(true);
        windowsTelemetryStatus.setText("Applying Windows telemetry setting…");
        Task<WindowsTelemetrySettings> task = new Task<>() {
            @Override protected WindowsTelemetrySettings call() throws Exception {
                return api.updateWindowsTelemetrySettings(new WindowsTelemetrySettingsUpdate(requested,
                        scriptRequested, processRequested));
            }
        };
        task.setOnSucceeded(event -> displayWindowsTelemetrySettings(task.getValue()));
        task.setOnFailed(event -> {
            refreshWindowsTelemetryAfterFailure(message(task.getException()));
        });
        executor.execute(task);
    }

    private void refreshWindowsTelemetryAfterFailure(String failure) {
        windowsTelemetryEnabled.setDisable(true);
        scriptMonitoringEnabled.setDisable(true);
        processMonitoringEnabled.setDisable(true);
        saveWindowsTelemetryButton.setDisable(true);
        windowsTelemetryStatus.setText("Could not confirm the setting response. Refreshing actual backend state…");
        Task<WindowsTelemetrySettings> refresh = new Task<>() {
            @Override protected WindowsTelemetrySettings call() throws Exception { return api.getWindowsTelemetrySettings(); }
        };
        refresh.setOnSucceeded(event -> {
            displayWindowsTelemetrySettings(refresh.getValue());
            windowsTelemetryStatus.setText(formatWindowsTelemetryStatus(refresh.getValue())
                    + "\nApply response failed: " + failure + ". Displayed switches were reconciled with Spring Boot.");
        });
        refresh.setOnFailed(event -> {
            WindowsTelemetrySettings confirmed = confirmedWindowsTelemetrySettings;
            if (confirmed != null) {
                windowsTelemetryEnabled.setSelected(confirmed.windowsTelemetryEnabled());
                scriptMonitoringEnabled.setSelected(confirmed.scriptMonitoringEnabled());
                processMonitoringEnabled.setSelected(confirmed.processMonitoringEnabled());
            }
            windowsTelemetryEnabled.setDisable(true);
            scriptMonitoringEnabled.setDisable(true);
            processMonitoringEnabled.setDisable(true);
            saveWindowsTelemetryButton.setDisable(true);
            windowsTelemetryStatus.setText("Actual Windows telemetry state is unknown because Spring Boot could not be reached. "
                    + "Switches show the last backend-confirmed values and are disabled. Apply error: " + failure
                    + "; refresh error: " + message(refresh.getException()));
        });
        executor.execute(refresh);
    }

    @FXML
    private void saveNotificationPreferences() {
        NotificationPreferences requested = new NotificationPreferences(notificationsEnabled.isSelected(),
                warnNotificationsEnabled.isSelected(), blockNotificationsEnabled.isSelected());
        saveNotificationPreferencesButton.setDisable(true);
        notificationPreferencesStatus.setText("Applying notification preferences…");
        Task<NotificationPreferences> task = new Task<>() {
            @Override protected NotificationPreferences call() throws Exception {
                return api.updateNotificationPreferences(requested);
            }
        };
        task.setOnSucceeded(event -> displayNotificationPreferences(task.getValue()));
        task.setOnFailed(event -> {
            saveNotificationPreferencesButton.setDisable(false);
            notificationPreferencesStatus.setText("Preferences were not applied: " + message(task.getException()));
        });
        executor.execute(task);
    }

    private void displayBackendSettings(FileShieldSettings settings) {
        approvedRootsList.getItems().setAll(settings.allowedRoots());
        watchDirectoriesList.getItems().setAll(settings.watchDirectories());
        fileShieldEnabled.setSelected(settings.enabled());
        reputationDatabasePath.setText(settings.reputationDatabasePath());
        backendMonitoringEnabled.setSelected(settings.enabled() && settings.monitoringEnabled());
        backendMonitoringEnabled.setDisable(!settings.enabled());
        recursiveMonitoring.setSelected(settings.recursiveMonitoring());
        monitoringDepth.getValueFactory().setValue(settings.maxMonitoringDepth());
        maxFilesPerScan.getValueFactory().setValue(settings.maxFilesPerDirectoryScan());
        scanDepth.getValueFactory().setValue(settings.maxDirectoryDepth());
        maxFileSizeMb.getValueFactory().setValue((int) Math.max(1, Math.min(1024, settings.maxFileSizeBytes() / (1024 * 1024))));
        updateDatabaseStatus(settings.reputationDatabaseUsable(), settings.reputationDatabaseMessage());
        if (reputationDatabaseStatus != null) {
            String providers = settings.reputationProviders().stream()
                    .map(provider -> provider.provider() + ": " + provider.state()
                            + (provider.errorCategory() == null ? "" : " (" + provider.errorCategory() + ")"))
                    .reduce((a, b) -> a + " · " + b).orElse("No external threat-intelligence provider configured.");
            reputationDatabaseStatus.setText(settings.reputationDatabaseMessage() + "\nProviders: " + providers
                    + "\nQuarantine folder: " + (settings.quarantineDirectory() == null || settings.quarantineDirectory().isBlank()
                    ? "Configure an approved scan root" : settings.quarantineDirectory()));
            reputationDatabaseStatus.setStyle(settings.reputationDatabaseUsable()
                    ? "-fx-text-fill: #34775f;" : "-fx-text-fill: #a26c22;");
        }
        backendFileWatcherActive = settings.watcherActive();
        if (windowsTelemetryStatus != null) loadWindowsTelemetrySettings();
        backendSettingsStatus.setText(settings.watcherActive()
                ? "Spring Boot connected · File Shield watcher running"
                : "Spring Boot connected · File Shield watcher stopped");
    }

    @FXML
    private void saveSettings() {
        if (backendMonitoringEnabled.isSelected() && watchDirectoriesList.getItems().isEmpty()) {
            settingsMessage.setText("Add at least one backend monitored folder or turn monitoring off.");
            return;
        }
        if (reputationDatabasePath.getText().isBlank()) {
            settingsMessage.setText("Enter the path to a trusted SQLite reputation database. Without a readable database, scans return LOOKUP_ERROR.");
            return;
        }
        settingsMessage.setText("Applying settings…");
        FileShieldSettingsUpdate request = new FileShieldSettingsUpdate(
                fileShieldEnabled.isSelected(), List.copyOf(approvedRootsList.getItems()), List.copyOf(watchDirectoriesList.getItems()),
                reputationDatabasePath.getText().trim(), backendMonitoringEnabled.isSelected(),
                recursiveMonitoring.isSelected(), monitoringDepth.getValue(),
                maxFileSizeMb.getValue() * 1024L * 1024L, maxFilesPerScan.getValue(), scanDepth.getValue());
        saveLocalMonitorRoots();
        Task<FileShieldSettings> task = new Task<>() {
            @Override protected FileShieldSettings call() throws Exception { return api.updateFileShieldSettings(request); }
        };
        task.setOnSucceeded(event -> {
            FileShieldSettings applied = task.getValue();
            displayBackendSettings(applied);
            settingsMessage.setText(applied.reputationDatabaseUsable()
                    ? "Backend settings applied and desktop monitoring folders saved. Unlisted hashes show UNKNOWN."
                    : "Backend settings applied and desktop monitoring folders saved. Reputation lookup will show LOOKUP_ERROR until the selected database is readable and has the expected table.");
        });
        task.setOnFailed(event -> settingsMessage.setText("Desktop monitor folders were saved, but backend File Shield settings were not applied: " + message(task.getException())));
        executor.execute(task);
    }

    private void saveLocalMonitorRoots() {
        List<String> roots = List.copyOf(localMonitorRootsList.getItems());
        List<Path> paths = roots.stream().map(Path::of).toList();
        DesktopMonitorPreferences.setRoots(paths);
        localMonitoringApply.accept(paths);
    }

    private List<String> loadLocalRoots() {
        return DesktopMonitorPreferences.getRoots().stream().map(Path::toString).toList();
    }

    @FXML private void setThemeLight() { changeTheme(ThemeManager.ThemeMode.LIGHT); }
    @FXML private void setThemeDark() { changeTheme(ThemeManager.ThemeMode.DARK); }
    @FXML private void setThemeSystem() { changeTheme(ThemeManager.ThemeMode.SYSTEM); }

    private void changeTheme(ThemeManager.ThemeMode mode) {
        if (fileShieldPane.getScene() != null) ThemeManager.setScene(fileShieldPane.getScene());
        ThemeManager.applyTheme(mode);
        updateThemeButtons(mode);
    }

    private void updateThemeButtons(ThemeManager.ThemeMode mode) {
        for (var item : List.of(new Object[]{themeLightBtn, ThemeManager.ThemeMode.LIGHT},
                new Object[]{themeDarkBtn, ThemeManager.ThemeMode.DARK}, new Object[]{themeSystemBtn, ThemeManager.ThemeMode.SYSTEM})) {
            Button button = (Button) item[0];
            ThemeManager.ThemeMode itemMode = (ThemeManager.ThemeMode) item[1];
            button.getStyleClass().removeAll("theme-card-selected", "theme-card-unselected");
            button.getStyleClass().add(itemMode == mode ? "theme-card-selected" : "theme-card-unselected");
        }
        activeThemeLabel.setText("Active: " + mode.name() + " THEME");
    }

    private void updateDatabaseStatus(boolean usable, String message) {
        reputationDatabaseStatus.setText(message);
        reputationDatabaseStatus.setStyle(usable ? "-fx-text-fill: #34775f;" : "-fx-text-fill: #a26c22;");
    }

    private Window ownerWindow() {
        return fileShieldPane.getScene() == null ? null : fileShieldPane.getScene().getWindow();
    }

    private static String message(Throwable error) {
        String message = error == null ? null : error.getMessage();
        if (message == null || message.isBlank()) return "check the backend connection and try again";
        int marker = message.lastIndexOf(": ");
        return marker >= 0 && marker + 2 < message.length() ? message.substring(marker + 2) : message;
    }

    public void close() { executor.shutdownNow(); }
}
