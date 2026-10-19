package com.aiwatchdog.controller;

import com.aiwatchdog.model.FileShieldDirectoryResult;
import com.aiwatchdog.model.FileShieldScanResult;
import com.aiwatchdog.model.ThreatAssessmentResult;
import com.aiwatchdog.model.QuarantineHistory;
import com.aiwatchdog.model.QuarantineOperation;
import com.aiwatchdog.service.ApiService;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.layout.VBox;
import javafx.scene.control.TableCell;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.io.IOException;
import java.net.ConnectException;
import java.net.http.HttpConnectTimeoutException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Controller for the File Shield page. REST work always runs off the JavaFX Application Thread. */
public class FileShieldController {
    @FXML private Label scanStatusLabel;
    @FXML private Label scanSummaryLabel;
    @FXML private Label scanErrorLabel;
    @FXML private ProgressIndicator scanProgress;
    @FXML private Button scanFileButton;
    @FXML private Button scanDirectoryButton;
    @FXML private Button assessFileButton;
    @FXML private Label assessmentSummaryLabel;
    @FXML private TableView<FileShieldRow> resultsTable;
    @FXML private TableColumn<FileShieldRow, String> fileColumn;
    @FXML private TableColumn<FileShieldRow, String> hashColumn;
    @FXML private TableColumn<FileShieldRow, String> verdictColumn;
    @FXML private TableColumn<FileShieldRow, String> detailColumn;
    @FXML private TableColumn<FileShieldRow, FileShieldRow> actionColumn;
    @FXML private TableView<QuarantineOperation> quarantineTable;
    @FXML private TableColumn<QuarantineOperation, String> quarantineFileColumn;
    @FXML private TableColumn<QuarantineOperation, String> quarantineStateColumn;
    @FXML private TableColumn<QuarantineOperation, String> quarantineHashColumn;
    @FXML private TableColumn<QuarantineOperation, String> quarantineDetailColumn;
    @FXML private TableColumn<QuarantineOperation, QuarantineOperation> restoreColumn;
    @FXML private Label quarantineStatusLabel;

    private final ApiService api = new ApiService();
    private final ExecutorService scannerExecutor = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "aiwatchdog-file-shield-scan");
        thread.setDaemon(true);
        return thread;
    });
    private final ObservableList<FileShieldRow> rows = FXCollections.observableArrayList();
    private Task<List<FileShieldRow>> activeTask;

    @FXML
    private void initialize() {
        fileColumn.setCellValueFactory(cell -> new ReadOnlyStringWrapper(cell.getValue().filePath()));
        hashColumn.setCellValueFactory(cell -> new ReadOnlyStringWrapper(cell.getValue().sha256()));
        verdictColumn.setCellValueFactory(cell -> new ReadOnlyStringWrapper(cell.getValue().verdict()));
        detailColumn.setCellValueFactory(cell -> new ReadOnlyStringWrapper(cell.getValue().detail()));
        actionColumn.setCellValueFactory(cell -> new javafx.beans.property.ReadOnlyObjectWrapper<>(cell.getValue()));
        actionColumn.setCellFactory(column -> new TableCell<>() {
            private final Button quarantine = new Button("Quarantine…");
            { quarantine.setOnAction(event -> requestQuarantine(getItem())); }
            @Override protected void updateItem(FileShieldRow row, boolean empty) {
                super.updateItem(row, empty);
                setGraphic(empty || row == null || !row.quarantinable() ? null : quarantine);
                setText(null);
            }
        });
        verdictColumn.setCellFactory(column -> new TableCell<>() {
            @Override protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                getStyleClass().removeAll("verdict-malicious", "verdict-clean", "verdict-review", "verdict-error");
                if (empty || item == null) {
                    setText(null);
                    setGraphic(null);
                } else {
                    setText(item);
                    String normalized = item.toUpperCase(java.util.Locale.ROOT);
                    if (normalized.contains("MALICIOUS") || normalized.contains("BLOCK")) getStyleClass().add("verdict-malicious");
                    else if (normalized.contains("CLEAN") || normalized.contains("ALLOW")
                            || normalized.contains("ANALYZED") || normalized.contains("COMPLETED")) getStyleClass().add("verdict-clean");
                    else if (normalized.contains("UNKNOWN") || normalized.contains("REVIEW")
                            || normalized.contains("WARN") || normalized.contains("PARTIAL")
                            || normalized.contains("SUSPICIOUS")
                            || normalized.contains("LOOKUP_ERROR") || normalized.contains("UNAVAILABLE")
                            || normalized.contains("INVALID_PE") || normalized.contains("UNSUPPORTED"))
                        getStyleClass().add("verdict-review");
                    else getStyleClass().add("verdict-error");
                }
            }
        });
        resultsTable.setItems(rows);
        quarantineFileColumn.setCellValueFactory(cell -> new ReadOnlyStringWrapper(cell.getValue().fileName()));
        quarantineStateColumn.setCellValueFactory(cell -> new ReadOnlyStringWrapper(cell.getValue().state()));
        quarantineHashColumn.setCellValueFactory(cell -> new ReadOnlyStringWrapper(cell.getValue().sha256()));
        quarantineDetailColumn.setCellValueFactory(cell -> new ReadOnlyStringWrapper(cell.getValue().message()));
        restoreColumn.setCellValueFactory(cell -> new javafx.beans.property.ReadOnlyObjectWrapper<>(cell.getValue()));
        restoreColumn.setCellFactory(column -> new TableCell<>() {
            private final Button restore = new Button("Restore…");
            { restore.setOnAction(event -> requestRestore(getItem())); }
            @Override protected void updateItem(QuarantineOperation operation, boolean empty) {
                super.updateItem(operation, empty);
                boolean available = operation != null && java.util.Set.of("QUARANTINED", "RESTORE_FAILED", "RECOVERY_REQUIRED").contains(operation.state());
                setGraphic(empty || !available ? null : restore);
                setText(null);
            }
        });
        quarantineTable.setItems(FXCollections.observableArrayList());
        loadQuarantineHistory();
        resultsTable.setPlaceholder(new Label("No results yet. Choose a file or directory to begin."));
        scanProgress.setVisible(false);
        scanProgress.setManaged(false);
        scanErrorLabel.setVisible(false);
        scanErrorLabel.setManaged(false);
        scanSummaryLabel.setText("No scans yet");
        assessmentSummaryLabel.setText("");
    }

    @FXML
    private void chooseAndScanFile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose a file to scan");
        File selected = chooser.showOpenDialog(ownerWindow());
        if (selected != null) startScan(selected.toPath(), false);
    }

    @FXML
    private void chooseAndScanDirectory() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Choose a directory to scan");
        File selected = chooser.showDialog(ownerWindow());
        if (selected != null) startScan(selected.toPath(), true);
    }

    @FXML
    private void chooseAndAssessFile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose a file for unified threat assessment");
        File selected = chooser.showOpenDialog(ownerWindow());
        if (selected != null) startAssessment(selected.toPath());
    }

    private void startAssessment(Path selectedPath) {
        if (activeTask != null && activeTask.isRunning()) return;
        rows.clear(); assessmentSummaryLabel.setText("");
        scanErrorLabel.setText(""); scanErrorLabel.setVisible(false); scanErrorLabel.setManaged(false);
        scanStatusLabel.setText("Assessing file…");
        scanSummaryLabel.setText("Checking local SHA-256 reputation and requesting static PE analysis.");
        scanProgress.setVisible(true); scanProgress.setManaged(true);
        scanFileButton.setDisable(true); scanDirectoryButton.setDisable(true); assessFileButton.setDisable(true);
        activeTask = new Task<>() {
            @Override protected List<FileShieldRow> call() throws Exception {
                ThreatAssessmentResult assessment = api.assessFile(selectedPath.toAbsolutePath().toString());
                List<FileShieldRow> mapped = new ArrayList<>();
                String hash = assessment.sha256() == null ? "—" : assessment.sha256();
                String verdict = assessment.policyVerdict() + " · " + assessment.status();
                String evidence = String.join(" ", assessment.explanation());
                String errors = String.join(" ", assessment.errors());
                    String explanationSummary = assessment.explanationDetails() == null ? ""
                            : assessment.explanationDetails().summary();
                    mapped.add(new FileShieldRow(selectedPath.toString(), hash, verdict,
                            "Final policy verdict. " + evidence
                                    + (explanationSummary.isBlank() ? "" : " LLM explanation: " + explanationSummary)
                                    + (errors.isBlank() ? "" : " Errors: " + errors),
                                selectedPath.toAbsolutePath().toString(), "", false));
                if (assessment.sources() != null) assessment.sources().forEach((name, source) -> {
                    String sourceStatus = source.path("reputationStatus").asText("");
                    if (sourceStatus.isBlank()) sourceStatus = source.path("status").asText("");
                    if (sourceStatus.isBlank()) sourceStatus = source.path("scanStatus").asText("AVAILABLE");
                    String details = source.path("message").asText("");
                    if (details.isBlank() && source.path("risk_score").isNumber())
                        details = "Structural heuristic score " + source.path("risk_score").asInt()
                                + "; not a malware probability.";
                    mapped.add(new FileShieldRow(selectedPath.getFileName().toString(), hash,
                            name + ": " + sourceStatus, details, selectedPath.toAbsolutePath().toString(), sourceStatus,
                            name.equalsIgnoreCase("fileReputation") && (sourceStatus.equalsIgnoreCase("KNOWN_MALICIOUS") || sourceStatus.equalsIgnoreCase("SUSPICIOUS"))));
                });
                updateMessage("Assessment " + assessment.status() + " · policy " + assessment.policyVerdict());
                updateTitle(assessment.assessmentId());
                return mapped;
            }
        };
        activeTask.setOnSucceeded(event -> {
            rows.setAll(activeTask.getValue());
            scanStatusLabel.setText("Assessment complete");
            scanSummaryLabel.setText(activeTask.getMessage());
            assessmentSummaryLabel.setText("Source results are shown below. A PARTIAL assessment includes unavailable or failed analysis; UNKNOWN is not clean.");
            finishScan();
        });
        activeTask.setOnFailed(event -> {
            scanStatusLabel.setText("Assessment could not be completed");
            scanSummaryLabel.setText("No unified assessment was returned.");
            scanErrorLabel.setText(userMessage(activeTask.getException()));
            scanErrorLabel.setVisible(true); scanErrorLabel.setManaged(true); finishScan();
        });
        scannerExecutor.execute(activeTask);
    }

    private Window ownerWindow() {
        return resultsTable.getScene() == null ? null : resultsTable.getScene().getWindow();
    }

    private void startScan(Path selectedPath, boolean directory) {
        if (activeTask != null && activeTask.isRunning()) return;
        rows.clear();
        scanErrorLabel.setText("");
        scanErrorLabel.setVisible(false);
        scanErrorLabel.setManaged(false);
        scanStatusLabel.setText(directory ? "Scanning directory…" : "Scanning file…");
        scanSummaryLabel.setText(directory
                ? "Hashing and checking configured reputation providers. Signature inspection is skipped for bounded batch scans."
                : "Hashing, checking configured reputation providers, and inspecting Windows signature status.");
        scanProgress.setVisible(true);
        scanProgress.setManaged(true);
        scanFileButton.setDisable(true);
        scanDirectoryButton.setDisable(true);
        assessFileButton.setDisable(true);

        activeTask = new Task<>() {
            @Override protected List<FileShieldRow> call() throws Exception {
                if (directory) {
                    FileShieldDirectoryResult result = api.scanDirectory(selectedPath.toAbsolutePath().toString());
                    List<FileShieldRow> mapped = new ArrayList<>();
                    if (result.results() != null) {
                        for (FileShieldScanResult file : result.results()) {
                            mapped.add(toRow(file.fileName(), file));
                        }
                    }
                    updateMessage(directorySummary(result));
                    return mapped;
                }
                FileShieldScanResult result = api.scanFile(selectedPath.toAbsolutePath().toString());
                updateMessage("Single file scan complete");
                return List.of(toRow(selectedPath.toString(), result));
            }
        };

        activeTask.setOnSucceeded(event -> {
            rows.setAll(activeTask.getValue());
            scanStatusLabel.setText("Scan complete");
            scanSummaryLabel.setText(activeTask.getMessage());
            finishScan();
        });
        activeTask.setOnFailed(event -> {
            Throwable failure = activeTask.getException();
            scanStatusLabel.setText("Scan could not be completed");
            scanSummaryLabel.setText("No scan result was returned.");
            scanErrorLabel.setText(userMessage(failure));
            scanErrorLabel.setVisible(true);
            scanErrorLabel.setManaged(true);
            finishScan();
        });
        activeTask.setOnCancelled(event -> {
            scanStatusLabel.setText("Scan cancelled");
            scanSummaryLabel.setText("The request was cancelled before a result was received.");
            finishScan();
        });
        scannerExecutor.execute(activeTask);
    }

    private FileShieldRow toRow(String displayPath, FileShieldScanResult result) {
        String status = result.reputationStatus();
        String detail = result.message() == null ? "" : result.message();
        if (result.description() != null && !result.description().isBlank()) detail += " " + result.description();
        detail += signatureDetails(result);
        return new FileShieldRow(result.filePath() == null ? displayPath : result.filePath(),
                result.sha256() == null || result.sha256().isBlank() ? "—" : result.sha256(),
                verdict(result.reputationStatus(), result.scanStatus()),
                detail,
                result.filePath() == null ? displayPath : result.filePath(), status,
                status != null && (status.equalsIgnoreCase("KNOWN_MALICIOUS") || status.equalsIgnoreCase("SUSPICIOUS"))
                        && result.sha256() != null && result.filePath() != null);
    }

    private String signatureDetails(FileShieldScanResult result) {
        return result.signatureStatus() == null ? "" : " Signature: " + result.signatureStatus()
                + (result.signerSubject() == null ? "" : " (" + result.signerSubject() + ")")
                + (result.signatureMessage() == null ? "" : ". " + result.signatureMessage());
    }

    private void requestQuarantine(FileShieldRow row) {
        if (row == null || !row.quarantinable()) return;
        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION,
                "Move " + row.filePathForAction() + " into the restricted AI WatchDog quarantine?\nSHA-256: " + row.sha256()
                        + "\nThis changes the file's location and can affect running software.",
                ButtonType.CANCEL, ButtonType.OK);
        confirm.setHeaderText("Confirm file quarantine");
        if (confirm.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;
        runQuarantineTask(() -> api.quarantineFile(row.filePathForAction(), row.sha256()), "Quarantine request sent.");
    }

    private void requestRestore(QuarantineOperation operation) {
        if (operation == null) return;
        CheckBox reinspect = new CheckBox("Require a known-clean reputation result before restore (otherwise explicitly restore at my own risk)");
        reinspect.setSelected(true);
        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.getButtonTypes().setAll(ButtonType.CANCEL, ButtonType.OK);
        confirm.getDialogPane().setContent(new VBox(10,
                new Label("Restore " + operation.fileName() + " to a folder you choose? Existing files are never overwritten."), reinspect));
        confirm.setHeaderText("Confirm file restore");
        if (confirm.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Choose approved folder for restore");
        File selectedDirectory = chooser.showDialog(ownerWindow());
        if (selectedDirectory == null) return;
        String target = selectedDirectory.toPath().resolve(operation.fileName()).toString();
        boolean inspectBeforeRestore = reinspect.isSelected();
        runQuarantineTask(() -> api.restoreQuarantinedFile(operation.operationId(), target, inspectBeforeRestore), "Restore request sent.");
    }

    private void runQuarantineTask(java.util.concurrent.Callable<QuarantineOperation> action, String pending) {
        quarantineStatusLabel.setText(pending);
        Task<QuarantineOperation> task = new Task<>() { @Override protected QuarantineOperation call() throws Exception { return action.call(); } };
        task.setOnSucceeded(event -> {
            QuarantineOperation result = task.getValue();
            quarantineStatusLabel.setText(result.state() + ": " + result.message());
            loadQuarantineHistory();
        });
        task.setOnFailed(event -> { quarantineStatusLabel.setText(userMessage(task.getException())); loadQuarantineHistory(); });
        scannerExecutor.execute(task);
    }

    private void loadQuarantineHistory() {
        Task<QuarantineHistory> task = new Task<>() { @Override protected QuarantineHistory call() throws Exception { return api.getQuarantineHistory(); } };
        task.setOnSucceeded(event -> {
            QuarantineHistory history = task.getValue();
            quarantineTable.getItems().setAll(history.recent());
            quarantineStatusLabel.setText(history.active().size() + " active quarantined file(s) · showing "
                    + history.recent().size() + " recent operation(s)");
        });
        task.setOnFailed(event -> quarantineStatusLabel.setText("Quarantine history unavailable: " + userMessage(task.getException())));
        scannerExecutor.execute(task);
    }

    /** Refresh backend-owned quarantine history whenever this navigation section opens. */
    public void refreshPageData() {
        if (!scannerExecutor.isShutdown()) loadQuarantineHistory();
    }

    private String verdict(String reputationStatus, String scanStatus) {
        String scan = scanStatus == null ? "" : scanStatus.toUpperCase(java.util.Locale.ROOT);
        if (scan.equals("FAILED")) return "SCAN FAILED";
        if (scan.equals("REJECTED")) return "REJECTED";
        String reputation = reputationStatus == null ? "" : reputationStatus.toUpperCase(java.util.Locale.ROOT);
        if (reputation.endsWith("MALICIOUS")) return "MALICIOUS";
        if (reputation.endsWith("CLEAN")) return "CLEAN";
        if (reputation.endsWith("SUSPICIOUS")) return "SUSPICIOUS";
        if (reputation.endsWith("UNKNOWN")) return "UNKNOWN";
        if (reputation.endsWith("LOOKUP_ERROR")) return "LOOKUP ERROR";
        return scanStatus == null || scanStatus.isBlank() ? "SCAN ERROR" : scanStatus.replace('_', ' ');
    }

    private String directorySummary(FileShieldDirectoryResult result) {
        String summary = "Scanned " + result.scanned() + " of " + result.discovered()
                + " discovered files · " + result.knownMalicious() + " malicious · "
                + result.knownClean() + " clean · " + result.suspicious() + " suspicious · " + result.unknown() + " unknown · "
                + result.lookupErrors() + " lookup errors · " + result.failed() + " failed";
        return result.limitReached() ? summary + " · File limit reached" : summary;
    }

    private String userMessage(Throwable failure) {
        Throwable cause = failure;
        while (cause != null && cause.getCause() != null) cause = cause.getCause();
        if (cause instanceof ConnectException || cause instanceof HttpConnectTimeoutException) {
            return "Cannot connect to the local AI WatchDog backend. Start the Spring Boot backend and try again.";
        }
        if (failure instanceof IOException && failure.getMessage() != null && !failure.getMessage().isBlank()) {
            return failure.getMessage();
        }
        return "The local backend could not complete this scan. Check that it is running and that the selected path is approved.";
    }

    private void finishScan() {
        scanProgress.setVisible(false);
        scanProgress.setManaged(false);
        scanFileButton.setDisable(false);
        scanDirectoryButton.setDisable(false);
        assessFileButton.setDisable(false);
        activeTask = null;
    }

    /** Called by MainController when the application window closes. */
    public void close() {
        if (activeTask != null) activeTask.cancel(true);
        scannerExecutor.shutdownNow();
    }

    public record FileShieldRow(String filePath, String sha256, String verdict, String detail,
                                String filePathForAction, String reputationStatus, boolean quarantinable) { }
}
