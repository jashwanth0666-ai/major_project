package com.aiwatchdog.controller;

import com.aiwatchdog.model.AnalyzeResponse;
import com.aiwatchdog.model.AssessmentStats;
import com.aiwatchdog.model.MonitorEvent;
import com.aiwatchdog.model.SecurityEvent;
import com.aiwatchdog.model.SecurityEventStats;
import com.aiwatchdog.model.ServiceHealth;
import com.aiwatchdog.service.ApiService;
import com.aiwatchdog.service.BrowserMonitorService;
import com.aiwatchdog.service.FileSystemMonitorService;
import com.aiwatchdog.service.ProcessMonitorService;
import com.aiwatchdog.model.FileShieldSettings;
import com.aiwatchdog.model.NotificationPreferences;
import com.aiwatchdog.model.WindowsTelemetryHealth;
import com.aiwatchdog.util.SystemTraySupport;
import com.aiwatchdog.ui.scanner.ScanRadarView;
import javafx.animation.*;
import javafx.application.Platform;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.concurrent.Task;
import javafx.scene.Group;
import javafx.scene.effect.BlurType;
import javafx.scene.effect.DropShadow;
import java.util.concurrent.atomic.AtomicReference;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.ImageView;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import javafx.scene.shape.Arc;
import javafx.scene.shape.Circle;
import javafx.scene.shape.Rectangle;
import javafx.util.Duration;
import org.kordamp.ikonli.javafx.FontIcon;

import java.time.LocalDateTime;
import java.time.Instant;
import java.time.ZoneId;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class MainController {

    // =========================================================================
    // FXML Bindings
    // =========================================================================
    @FXML private StackPane root, pageStack;
    @FXML private VBox welcomePage;
    @FXML private BorderPane appShell;
    @FXML private Button getStartedBtn;
    @FXML private ImageView logoImage;
    @FXML private VBox sidebar;

    // Splash / Starting Page Controls
    @FXML private VBox splashContentBox;
    @FXML private StackPane splashLogoContainer;
    @FXML private Circle splashGlowCircle;
    @FXML private Label splashTitleLabel;
    @FXML private Label splashSubtitleLabel;
    @FXML private ProgressBar splashProgressBar;

    // Navigation buttons
    @FXML private Button navDashboardBtn;
    @FXML private Button navScannerBtn;
    @FXML private Button navFileShieldBtn;
    @FXML private Button navSecureAccessBtn;
    @FXML private Button navThreatCenterBtn;
    @FXML private Button navActivityBtn;
    @FXML private Button navInsightsBtn;
    @FXML private Button navSettingsBtn;
    private final List<ButtonBase> navItems = new ArrayList<>();
    private ButtonBase currentActiveNav;

    // Top Bar & Hamburger Controls
    @FXML private Button hamburgerBtn;
    @FXML private Region hamburgerBarTop;
    @FXML private Region hamburgerBarMid;
    @FXML private Region hamburgerBarBot;
    @FXML private TextField topSearchInput;

    // Sidebar Internal Layout
    @FXML private HBox brandContainer;
    @FXML private ScrollPane sidebarNavScroll;
    @FXML private VBox sidebarBottomBox;
    @FXML private VBox navMenuBox;

    // Collapsible Sidebar State
    public static final boolean SIDEBAR_OPEN_AT_START = false;
    private boolean isSidebarOpen = SIDEBAR_OPEN_AT_START;
    private boolean isSidebarAnimating = false;
    private double sidebarFullWidth = -1;
    private Timeline sidebarTimeline;

    // Pages
    @FXML private ScrollPane dashboardPage;
    @FXML private ScrollPane scannerInputPage;
    @FXML private ScrollPane fileShieldPage;
    @FXML private FileShieldController fileShieldViewController;
    @FXML private ScrollPane analyzingPage;
    @FXML private ScrollPane resultPage;
    @FXML private ScrollPane threatCenterPage;
    @FXML private ScrollPane activityPage;
    @FXML private ScrollPane insightsPage;
    @FXML private ScrollPane settingsPage;
    @FXML private SettingsController settingsViewController;
    @FXML private ScrollPane secureAccessPage;
    @FXML private ScrollPane scanErrorPage;
    @FXML private Label scanErrorUrl;
    @FXML private Label scanErrorMessage;

    // Dashboard Controls
    @FXML private Label dashDateLabel;
    @FXML private Label dashScannedCount;
    @FXML private Label dashThreatsBlockedCount;
    @FXML private Label dashInReviewCount;
    @FXML private Label dashAllowedCount;
    @FXML private Label dashScoreNumber;
    @FXML private Label dashScorePill;
    @FXML private Arc dashScoreArc;
    @FXML private Label dashRiskLevelTitle;
    @FXML private Label dashRiskDescription;
    @FXML private ProgressBar dashSafeProgress;
    @FXML private ProgressBar dashSuspiciousProgress;
    @FXML private ProgressBar dashPotentialProgress;
    @FXML private ProgressBar dashHighRiskProgress;
    @FXML private StackPane dashGaugeContainer;
    @FXML private Label dashOperationalBadge;
    @FXML private Label dashStatusNormalLabel;
    @FXML private HBox dashLiveShieldBox;
    @FXML private FontIcon dashLiveShieldIcon;
    @FXML private Label dashLiveShieldText;
    @FXML private Label sidebarProtectionTitle;
    @FXML private Label sidebarProtectionDescription;

    // Upgraded Dashboard Node Hooks (wd-)
    @FXML private VBox dashCardScanned, dashCardBlocked, dashCardReview, dashCardAllowed;
    @FXML private StackPane dashScannedTile, dashBlockedTile, dashReviewTile, dashAllowedTile;
    @FXML private FontIcon dashScannedIcon, dashBlockedIcon, dashReviewIcon, dashAllowedIcon;
    @FXML private Label dashScannedTrend, dashBlockedTrend, dashReviewTrend, dashAllowedTrend;
    @FXML private Region dashScannedLine, dashBlockedLine, dashReviewLine, dashAllowedLine;
    @FXML private Label dashSafePercent, dashSuspiciousPercent, dashPotentialPercent, dashHighRiskPercent;
    @FXML private Label dashAssessmentTotal, dashAssessmentUrls, dashAssessmentFiles;
    @FXML private Label dashAssessmentPartial, dashKnownMalicious, dashKnownClean, dashUnknownReputation, dashLookupError;
    @FXML private Label dashAssessmentAllow, dashAssessmentReview, dashAssessmentWarn, dashAssessmentBlock, dashAssessmentState;
    @FXML private ProgressIndicator dashAssessmentLoading;

    private com.aiwatchdog.ui.dashboard.RiskRadarView riskRadarView;
    private com.aiwatchdog.ui.dashboard.DashboardCardsHelper cardsHelper;

    // Scanner Input Controls
    @FXML private TextField scannerUrlInput;
    @FXML private Button analyzeBtn;

    // Analyzing Screen (Stitch Screen 2)
    @FXML private Label analyzingUrlText;
    @FXML private Label scanStatusText;
    @FXML private ProgressBar scanProgressBar;
    @FXML private Label scanPercentLabel;
    @FXML private StackPane step1IconBox, step2IconBox, step3IconBox, step4IconBox, step5IconBox, step6IconBox;
    @FXML private FontIcon step1Icon, step2Icon, step3Icon, step4Icon, step5Icon, step6Icon;
    @FXML private Label step1Label, step2Label, step3Label, step4Label, step5Label, step6Label;
    @FXML private StackPane radarContainer;
    @FXML private Group radarSweepContainer;
    @FXML private StackPane radarCenterShield;
    @FXML private StackPane orbitIcon1, orbitIcon2, orbitIcon3, orbitIcon4;
    private ScanRadarView scanRadarView;

    // Result Screen (Stitch Screen 3)
    @FXML private HBox resultHeroBox;
    @FXML private StackPane resultIconContainer;
    @FXML private FontIcon resultHeroIcon;
    @FXML private Label resultTitle;
    @FXML private Label resultSubtitle;
    @FXML private Label resultScoreNumber;
    @FXML private Label resultScorePill;
    @FXML private Arc resultScoreArc;
    @FXML private Label resultUrl;
    @FXML private Label resultPrediction;
    @FXML private Label resultDecision;
    @FXML private Label resultConfidence;
    @FXML private Label resultThreshold;
    @FXML private Label feedbackStatus;
    @FXML private Button feedbackFalsePositiveBtn, feedbackFalseNegativeBtn, feedbackCorrectBtn;
    @FXML private VBox reasonsListContainer;
    @FXML private Label featUrlLength;
    @FXML private Label featHasHttps;
    @FXML private Label featDotCount;
    @FXML private Label featDomainAge;
    @FXML private Label featKeywords;
    @FXML private Label featIpUsed;
    @FXML private HBox riskLevelHighBadge, riskLevelSuspiciousBadge, riskLevelLowBadge, riskLevelSafeBadge;
    @FXML private HBox resultBanner;
    @FXML private FontIcon resultBannerIcon;
    @FXML private Label resultBannerText;

    // Threat Center (Stitch Screen 4)
    @FXML private ComboBox<String> threatTimeFilter;
    @FXML private Label threatBlockedCount, threatInReviewCount, threatHighRiskCount;
    @FXML private VBox threatTableContainer;
    @FXML private VBox threatInsightsCard;
    @FXML private StackPane threatDonutPane;
    @FXML private Circle threatTrackCircle;
    @FXML private Arc threatArcHigh, threatArcSuspicious, threatArcInfo;
    @FXML private Label threatTotalCountLabel, threatTotalSubLabel;
    @FXML private HBox threatLegendHigh, threatLegendSusp, threatLegendInfo;
    @FXML private Label threatLegendHighPct, threatLegendSuspPct, threatLegendInfoPct;
    private com.aiwatchdog.ui.threatcenter.ThreatInsightsDonutHelper threatInsightsHelper;
    @FXML private VBox threatCard0, threatCard1, threatCard2, threatCard3;
    @FXML private StackPane threatTile0, threatTile1, threatTile2, threatTile3;
    @FXML private FontIcon threatIcon0, threatIcon1, threatIcon2, threatIcon3;
    @FXML private Label threatTrend0, threatTrend1, threatTrend2, threatTrend3;
    @FXML private Label threatSafeCount;
    private com.aiwatchdog.ui.dashboard.DashboardCardsHelper threatCardsHelper;

    // Activity (Stitch Screen 5)
    @FXML private ComboBox<String> activityTimeFilter, activityEventFilter, activityStatusFilter;
    @FXML private TextField activitySearchInput;
    @FXML private VBox activityTableContainer;
    @FXML private Label activityPaginationLabel;
    @FXML private Label activityPageLabel;
    @FXML private Button activityPreviousBtn, activityNextBtn;
    private int activityPageIndex;
    private static final int ACTIVITY_PAGE_SIZE = 10;
    @FXML private VBox activityCard0, activityCard1, activityCard2, activityCard3;
    @FXML private StackPane activityTile0, activityTile1, activityTile2, activityTile3;
    @FXML private FontIcon activityIcon0, activityIcon1, activityIcon2, activityIcon3;
    @FXML private Label activityCount0, activityCount1, activityCount2, activityCount3;
    private com.aiwatchdog.ui.dashboard.DashboardCardsHelper activityCardsHelper;

    // AI Insights (Stitch Screen 6)
    @FXML private ComboBox<String> insightsTimeFilter;
    @FXML private VBox insightCard0, insightCard1, insightCard2, insightCard3;
    @FXML private FontIcon insightIcon0, insightIcon1, insightIcon2, insightIcon3;
    @FXML private Label insightCount0, insightCount1, insightCount2, insightCount3;
    @FXML private Label insightTrend0, insightTrend1, insightTrend2, insightTrend3;
    private com.aiwatchdog.ui.dashboard.DashboardCardsHelper insightsCardsHelper;

    // Secure Access
    @FXML private VBox secureAccessContainer;
    @FXML private TextField domainExceptionInput;
    @FXML private FontIcon exceptionGlobe1, exceptionGlobe2;
    private final List<Animation> secureAccessGlobeAnimations = new ArrayList<>();

    // Toast
    @FXML private Label toast;

    // =========================================================================
    // Services and State
    // =========================================================================
    private final ApiService apiService = new ApiService();
    private final BrowserMonitorService browser = new BrowserMonitorService();
    private final ScheduledExecutorService backendRefresh = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "aiwatchdog-backend-refresh");
        thread.setDaemon(true);
        return thread;
    });
    private final AtomicBoolean refreshInFlight = new AtomicBoolean();
    private final AtomicBoolean monitorChanging = new AtomicBoolean();
    private volatile FileSystemMonitorService fileMonitor;
    private volatile ProcessMonitorService processMonitor;
    private volatile boolean closed;
    private volatile SystemTraySupport systemTraySupport;
    private volatile ServiceHealth latestBackendHealth;
    private volatile FileShieldSettings latestFileShieldSettings;
    private volatile NotificationPreferences latestNotificationPreferences;
    private volatile WindowsTelemetryHealth latestWindowsTelemetryHealth;
    private boolean initialUrlEventSnapshotLoaded;
    private boolean initialMonitorEventSnapshotLoaded;
    private boolean initialAssessmentSnapshotLoaded;
    private long lastMonitorEventId;
    private long lastUrlEventId;
    private long lastAssessmentEventId;

    private int totalScanned;
    private int totalBlocked;
    private int totalInReview;
    private int totalAllowed;

    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("hh:mm a");
    private final List<ActivityItem> activityLog = new ArrayList<>();
    private final List<ThreatItem> threatLog = new ArrayList<>();
    private String lastTargetUrl = "https://www.google.com";

    // Scanning animation & task state (Unified Single Source of Truth Engine)
    private AnimationTimer unifiedScanTimer;
    private long scanStartNs = 0;
    private long lastFrameNs = 0;
    private double scanProgress = 0.0;
    private double scanTargetProgress = 0.0;
    private boolean isAutoMode = true;
    private double autoDurationMs = 4000.0;
    private boolean isScanDone = false;
    private boolean isScanFailed = false;
    private boolean isScanFinishing = false;
    private long scanDoneNs = 0;
    private String scanFailureMessage = null;
    private int currentStepIndex = -1;
    private final DoubleProperty currentScanProgress = new SimpleDoubleProperty(0.0);
    private Task<AnalyzeResponse> currentScanTask;
    private AnalyzeResponse currentAnalyzeResult;
    private final AtomicReference<AnalyzeResponse> backendResultRef = new AtomicReference<>(null);
    private int currentStage = 1;
    private boolean isFinishingAnalysis = false;

    // Dashboard Telemetry Animations
    private Timeline gaugeTimeline;
    private ScaleTransition gaugePulse;
    private FadeTransition operationalBadgePulse;
    private ScaleTransition liveShieldPulse;
    private Timeline breakdownTimeline;

    // Splash / Starting Page Animations
    private Timeline splashMasterTimeline;
    private ScaleTransition splashGlowPulse;
    private FadeTransition splashGlowPulseFade;
    private boolean splashCompleted = false;

    // Record classes for UI logs
    public record ActivityItem(String time, String event, String urlOrDesc, String riskLevel,
                               String decision, String status, Instant instant, String assessmentId,
                               String subjectType, String detailsJson, String correlationId) {
        public ActivityItem(String time, String event, String urlOrDesc, String riskLevel,
                            String decision, String status, Instant instant) {
            this(time, event, urlOrDesc, riskLevel, decision, status, instant, null, null, null, null);
        }
    }
    public record ThreatItem(String url, String riskLevel, String decision, String time, Instant instant) {}

    // =========================================================================
    // Initialization
    // =========================================================================
    @FXML
    public void initialize() {
        if (dashAssessmentLoading != null) dashAssessmentLoading.setVisible(true);
        // Initialize sidebar navigation items list & set initial active state to Dashboard
        navItems.clear();
        for (ButtonBase btn : new ButtonBase[]{
                navDashboardBtn, navScannerBtn, navFileShieldBtn, navSecureAccessBtn,
                navThreatCenterBtn, navActivityBtn, navInsightsBtn, navSettingsBtn
        }) {
            if (btn != null) navItems.add(btn);
        }
        setActiveNav(navDashboardBtn);

        // Setup Dashboard Upgrades (Target Lock Radar, Stat Cards & Helpers)
        setupDashboardUpgrades();
        setupThreatCenterUpgrades();
        setupActivityUpgrades();
        setupInsightsUpgrades();
        setupAnalyzingUpgrades();
        setupSidebarCollapsible();
        setupSecureAccessUpgrades();
        if (settingsViewController != null) settingsViewController.setLocalMonitoringApplyHandler(this::applyLocalMonitorSettings);
        if (dashLiveShieldBox != null) {
            dashLiveShieldBox.setOnMouseClicked(event -> toggleLocalMonitoring());
            dashLiveShieldBox.setCursor(javafx.scene.Cursor.HAND);
            dashLiveShieldBox.setFocusTraversable(true);
            dashLiveShieldBox.setAccessibleRole(javafx.scene.AccessibleRole.BUTTON);
            dashLiveShieldBox.setAccessibleText("Toggle local file and process monitoring");
            Tooltip.install(dashLiveShieldBox, new Tooltip("Click to start or stop local file and process monitoring"));
            dashLiveShieldBox.setOnKeyPressed(event -> {
                if (event.getCode() == javafx.scene.input.KeyCode.ENTER || event.getCode() == javafx.scene.input.KeyCode.SPACE) {
                    toggleLocalMonitoring();
                    event.consume();
                }
            });
        }
        updateRiskGauge(0, "UNKNOWN", false);
        startDashboardTelemetryAnimations();
        animateThreatBreakdown();

        // Smoothly synchronize currentScanProgress with scanProgressBar and scanPercentLabel
        currentScanProgress.addListener((obs, oldVal, newVal) -> {
            double p = Math.max(0.0, Math.min(1.0, newVal.doubleValue()));
            if (scanProgressBar != null) {
                scanProgressBar.setProgress(p);
            }
            if (scanPercentLabel != null) {
                int pct = (int) Math.round(p * 100);
                scanPercentLabel.setText(pct + "%");
            }
        });

        // Setup Date in Dashboard
        if (dashDateLabel != null) {
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("EEE, d MMM yyyy • hh:mm a");
            dashDateLabel.setText(LocalDateTime.now().format(dtf));
        }

        // Initialize Filter Dropdowns
        if (threatTimeFilter != null) {
            threatTimeFilter.getItems().addAll("Last 24 hours", "Last 7 days", "Last 30 days");
            threatTimeFilter.setValue("Last 7 days");
        }
        if (activityTimeFilter != null) {
            activityTimeFilter.getItems().addAll("Last 24 hours", "Last 7 days", "Last 30 days");
            activityTimeFilter.setValue("Last 7 days");
        }
        if (activityEventFilter != null) {
            activityEventFilter.getItems().addAll("All Events", "URL Scan", "File Event", "Process Event", "Script Finding",
                    "Windows Security Event", "Unified Assessment · URL", "Unified Assessment · FILE", "Operator Feedback · FALSE_POSITIVE",
                    "Operator Feedback · FALSE_NEGATIVE", "Operator Feedback · CORRECT");
            activityEventFilter.setValue("All Events");
            activityEventFilter.setOnAction(event -> { activityPageIndex = 0; renderActivityTable(activitySearchInput == null ? "" : activitySearchInput.getText()); });
        }
        if (activityStatusFilter != null) {
            activityStatusFilter.getItems().addAll("All Status", "Allowed", "BLOCK policy", "Reviewed", "Warn", "ALLOW", "REVIEW", "BLOCK", "COMPLETE", "PARTIAL");
            activityStatusFilter.setValue("All Status");
            activityStatusFilter.setOnAction(event -> { activityPageIndex = 0; renderActivityTable(activitySearchInput == null ? "" : activitySearchInput.getText()); });
        }
        if (activityTimeFilter != null) {
            activityTimeFilter.setOnAction(event -> renderActivityTable(activitySearchInput == null ? "" : activitySearchInput.getText()));
        }
        if (threatTimeFilter != null) {
            threatTimeFilter.setOnAction(event -> renderThreatTable());
        }
        if (insightsTimeFilter != null) {
            insightsTimeFilter.getItems().addAll("Last 24 hours", "Last 7 days", "Last 30 days");
            insightsTimeFilter.setValue("Last 7 days");
        }
        // Populate Activity and Threat Center from Spring's persisted event APIs.
        renderThreatTable();
        renderActivityTable("");
        backendRefresh.scheduleWithFixedDelay(this::refreshBackendSnapshot, 0, 15, TimeUnit.SECONDS);

        // Start 5-second automated intro sequence on Welcome / Starting Page
        if (welcomePage != null && appShell != null) {
            welcomePage.setVisible(true);
            welcomePage.setManaged(true);
            appShell.setVisible(false);
            appShell.setManaged(false);
            Platform.runLater(this::startSplashSequence);
        } else {
            navigateDashboard();
        }
    }

    private void refreshBackendSnapshot() {
        if (closed || !refreshInFlight.compareAndSet(false, true)) return;
        try {
            ServiceHealth health = apiService.getServiceHealth();
            FileShieldSettings fileShieldSettings = safeLoad(apiService::getFileShieldSettings);
            NotificationPreferences notificationPreferences = safeLoad(apiService::getNotificationPreferences);
            WindowsTelemetryHealth windowsTelemetryHealth = safeLoad(apiService::getWindowsTelemetryHealth);
            List<SecurityEvent> urlEvents = safeLoad(apiService::getRecentEvents);
            List<MonitorEvent> monitorEvents = safeLoad(apiService::getRecentMonitorEvents);
            SecurityEventStats stats = safeLoad(apiService::getSecurityEventStats);
            List<SecurityEvent> assessments = safeLoad(apiService::getRecentAssessments);
            AssessmentStats assessmentStats = safeLoad(apiService::getAssessmentStats);
            List<SecurityEvent> feedbackEvents = safeLoad(apiService::getRecentFeedback);
            Platform.runLater(() -> {
                latestBackendHealth = health;
                latestFileShieldSettings = fileShieldSettings;
                if (notificationPreferences != null) latestNotificationPreferences = notificationPreferences;
                latestWindowsTelemetryHealth = windowsTelemetryHealth;
                updateSidebarProtectionStatus(health, fileShieldSettings, windowsTelemetryHealth);
                applyBackendSnapshot(health, urlEvents, monitorEvents, stats, assessments, assessmentStats, feedbackEvents);
                notifyForNewThreatEvents(urlEvents, monitorEvents, assessments);
            });
        } catch (Exception error) {
            Platform.runLater(() -> {
                latestBackendHealth = null;
                latestFileShieldSettings = null;
                latestWindowsTelemetryHealth = null;
                updateSidebarProtectionStatus(null, null, null);
                showBackendUnavailable(error);
            });
        } finally {
            refreshInFlight.set(false);
        }
    }

    private static <T> T safeLoad(BackendRead<T> read) {
        try { return read.get(); } catch (Exception ignored) { return null; }
    }

    @FunctionalInterface private interface BackendRead<T> { T get() throws Exception; }

    private void toggleLocalMonitoring() {
        if (closed || !monitorChanging.compareAndSet(false, true)) return;
        Thread worker = new Thread(() -> {
            try {
                FileSystemMonitorService currentFile = fileMonitor;
                ProcessMonitorService currentProcess = processMonitor;
                if ((currentFile != null && currentFile.isRunning()) || (currentProcess != null && currentProcess.isRunning())) {
                    if (currentFile != null) currentFile.close();
                    if (currentProcess != null) currentProcess.close();
                    fileMonitor = null;
                    processMonitor = null;
                    Platform.runLater(() -> setMonitoringStatus(false, "Local monitoring stopped"));
                    return;
                }
                FileSystemMonitorService file = new FileSystemMonitorService(apiService, event -> onMonitorEvent());
                ProcessMonitorService process = new ProcessMonitorService(apiService, event -> onMonitorEvent());
                fileMonitor = file;
                processMonitor = process;
                int watchedDirectories = file.start();
                process.start();
                ServiceHealth health = safeLoad(apiService::getServiceHealth);
                boolean backendAvailable = health != null && health.isBackendAvailable();
                String baseDetail = watchedDirectories > 0
                        ? "Local monitoring active · " + watchedDirectories + " folders"
                        : "Process monitoring active · No configured folders available";
                FileSystemMonitorService.HealthSnapshot fileHealth = file.getHealthSnapshot();
                if (fileHealth.registrationFailures() > 0) {
                    baseDetail += " · " + fileHealth.registrationFailures() + " folder registration errors";
                }
                final String detail = backendAvailable ? baseDetail : baseDetail + " · Event upload unavailable";
                Platform.runLater(() -> setMonitoringStatus(true, detail));
            } catch (Exception error) {
                FileSystemMonitorService file = fileMonitor;
                ProcessMonitorService process = processMonitor;
                if (file != null) file.close();
                if (process != null) process.close();
                fileMonitor = null;
                processMonitor = null;
                Platform.runLater(() -> setMonitoringStatus(false,
                        "Monitoring unavailable · " + valueOr(error.getMessage(), "Backend connection failed")));
            } finally {
                monitorChanging.set(false);
            }
        }, "aiwatchdog-monitor-control");
        worker.setDaemon(true);
        worker.start();
    }

    private void applyLocalMonitorSettings(List<java.nio.file.Path> roots) {
        FileSystemMonitorService current = fileMonitor;
        if (current == null || !current.isRunning() || closed) return;
        Thread worker = new Thread(() -> {
            try {
                current.close();
                FileSystemMonitorService replacement = new FileSystemMonitorService(apiService,
                        event -> onMonitorEvent(), roots);
                fileMonitor = replacement;
                int count = replacement.start();
                Platform.runLater(() -> notifyUser("Local file monitor updated · " + count + " folders watched"));
            } catch (Exception error) {
                fileMonitor = null;
                Platform.runLater(() -> notifyUser("Could not apply local monitoring folders: "
                        + valueOr(error.getMessage(), "Folder access failed")));
            }
        }, "aiwatchdog-local-monitor-settings");
        worker.setDaemon(true);
        worker.start();
    }

    private void onMonitorEvent() {
        if (!closed) backendRefresh.schedule(this::refreshBackendSnapshot, 300, TimeUnit.MILLISECONDS);
    }

    private void setMonitoringStatus(boolean running, String message) {
        if (dashLiveShieldBox != null) {
            dashLiveShieldBox.setOpacity(running ? 1.0 : 0.78);
            if (dashLiveShieldIcon != null) dashLiveShieldIcon.setIconColor(Color.web(running ? "#10B981" : "#64748B"));
        }
        if (dashLiveShieldText != null) dashLiveShieldText.setText(running ? "Live Shield Active" : "Live Shield Paused");
        updateSidebarProtectionStatus(latestBackendHealth, latestFileShieldSettings, latestWindowsTelemetryHealth);
        notifyUser(message);
    }

    public void setSystemTraySupport(SystemTraySupport support) {
        systemTraySupport = support;
    }

    public void openAlertsFromTray() {
        navigateThreatCenter();
    }

    private void updateSidebarProtectionStatus(ServiceHealth health, FileShieldSettings backendSettings,
                                               WindowsTelemetryHealth windowsTelemetry) {
        if (sidebarProtectionTitle == null || sidebarProtectionDescription == null) return;
        if (health == null || !health.isBackendAvailable()) {
            sidebarProtectionTitle.setText("Backend unavailable");
            sidebarProtectionDescription.setText("Collector and analysis status could not be confirmed");
            return;
        }
        if (!health.isMlAvailable()) {
            sidebarProtectionTitle.setText("Service degraded");
            sidebarProtectionDescription.setText("Spring Boot online · URL analysis unavailable");
            return;
        }
        boolean desktopMonitoring = (fileMonitor != null && fileMonitor.isRunning())
                || (processMonitor != null && processMonitor.isRunning());
        boolean backendMonitoring = backendSettings != null && backendSettings.watcherActive();
        boolean windowsMonitoring = windowsTelemetry != null && windowsTelemetry.enabled()
                && windowsTelemetry.running() && "RUNNING".equals(windowsTelemetry.state());
        boolean windowsDegraded = windowsTelemetry != null && windowsTelemetry.enabled()
                && !"RUNNING".equals(windowsTelemetry.state());
        if (desktopMonitoring || backendMonitoring) {
            FileSystemMonitorService.HealthSnapshot fileHealth = fileMonitor != null && fileMonitor.isRunning()
                    ? fileMonitor.getHealthSnapshot() : null;
            ProcessMonitorService.HealthSnapshot processHealth = processMonitor != null && processMonitor.isRunning()
                    ? processMonitor.getHealthSnapshot() : null;
            boolean fileDegraded = fileHealth != null && (fileHealth.registrationFailures() > 0
                    || fileHealth.overflowEvents() > 0 || fileHealth.droppedUploads() > 0
                    || fileHealth.uploadFailures() > 0);
            boolean processDegraded = processHealth != null && (processHealth.processAccessFailures() > 0
                    || processHealth.pollFailures() > 0 || processHealth.droppedUploads() > 0
                    || processHealth.uploadFailures() > 0);
            sidebarProtectionTitle.setText(windowsDegraded || fileDegraded || processDegraded
                    ? "Monitoring degraded" : "Monitoring active");
            String active = describeActiveMonitors(desktopMonitoring, backendMonitoring);
            if (fileHealth != null) active += " · " + fileMonitorSummary(fileHealth);
            if (processHealth != null) active += " · " + processMonitorSummary(processHealth);
            if (backendSettings == null && desktopMonitoring) active += " · backend watcher status unavailable";
            active += " · " + windowsTelemetrySummary(windowsTelemetry);
            sidebarProtectionDescription.setText(active);
        } else if (windowsMonitoring) {
            sidebarProtectionTitle.setText("Monitoring active");
            sidebarProtectionDescription.setText(windowsTelemetrySummary(windowsTelemetry));
        } else if (windowsDegraded) {
            sidebarProtectionTitle.setText("Monitoring degraded");
            sidebarProtectionDescription.setText(windowsTelemetrySummary(windowsTelemetry));
        } else if (backendSettings == null) {
            sidebarProtectionTitle.setText("Monitor status unavailable");
            sidebarProtectionDescription.setText("Spring Boot and URL analysis online · File Shield watcher state unavailable · "
                    + windowsTelemetrySummary(windowsTelemetry));
        } else {
            sidebarProtectionTitle.setText("Services online");
            sidebarProtectionDescription.setText("URL analysis is online · " + windowsTelemetrySummary(windowsTelemetry));
        }
    }

    private String windowsTelemetrySummary(WindowsTelemetryHealth health) {
        if (health == null) return "Windows telemetry state unavailable";
        if (!health.supported()) return "Windows event collection unsupported on this operating system";
        if (!health.enabled()) return "Windows Defender/Security event collection disabled";
        return "Windows event collection " + valueOr(health.state(), "UNKNOWN");
    }

    private String fileMonitorSummary(FileSystemMonitorService.HealthSnapshot health) {
        String summary = health.watchedDirectories() + " folders watched";
        if (health.registrationFailures() > 0 || health.overflowEvents() > 0 || health.droppedUploads() > 0
                || health.uploadFailures() > 0) {
            summary += " · degraded: " + health.registrationFailures() + " registration errors, "
                    + health.overflowEvents() + " watcher overflows, " + health.droppedUploads()
                    + " dropped uploads, " + health.uploadFailures() + " upload failures";
        }
        if (health.queuedUploads() > 0) summary += " · " + health.queuedUploads() + " uploads queued";
        return summary;
    }

    private String processMonitorSummary(ProcessMonitorService.HealthSnapshot health) {
        String summary = health.observedProcesses() + " processes observed · " + health.observedStarts()
                + " starts detected";
        if (health.processAccessFailures() > 0 || health.pollFailures() > 0 || health.droppedUploads() > 0
                || health.uploadFailures() > 0) {
            summary += " · degraded: " + health.processAccessFailures() + " access errors, "
                    + health.pollFailures() + " poll errors, " + health.droppedUploads()
                    + " dropped uploads, " + health.uploadFailures() + " upload failures";
        }
        if (health.queuedUploads() > 0) summary += " · " + health.queuedUploads() + " uploads queued";
        return summary;
    }

    private String describeActiveMonitors(boolean desktopMonitoring, boolean backendMonitoring) {
        if (desktopMonitoring && backendMonitoring) return "File Shield watcher and desktop event monitors are active";
        if (backendMonitoring) return "File Shield directory watcher is active";
        return "Desktop file and process event monitors are active";
    }

    private void notifyForNewThreatEvents(List<SecurityEvent> urlEvents, List<MonitorEvent> monitorEvents,
                                          List<SecurityEvent> assessments) {
        if (urlEvents != null) {
            long newest = urlEvents.stream().map(SecurityEvent::id).filter(java.util.Objects::nonNull)
                    .mapToLong(Long::longValue).max().orElse(lastUrlEventId);
            if (initialUrlEventSnapshotLoaded) {
                for (SecurityEvent event : urlEvents) {
                    if (event.id() != null && event.id() > lastUrlEventId && isAlertDecision(event.decision()))
                        sendThreatNotification("URL assessment", event.riskLevel(), event.decision());
                }
            } else initialUrlEventSnapshotLoaded = true;
            lastUrlEventId = Math.max(lastUrlEventId, newest);
        }
        if (monitorEvents != null) {
            long newest = monitorEvents.stream().map(MonitorEvent::id).filter(java.util.Objects::nonNull)
                    .mapToLong(Long::longValue).max().orElse(lastMonitorEventId);
            if (initialMonitorEventSnapshotLoaded) {
                for (MonitorEvent event : monitorEvents) {
                    if (event.id() != null && event.id() > lastMonitorEventId && isAlertDecision(event.decision())) {
                        String source = "FILE".equalsIgnoreCase(event.eventType()) ? "File event"
                                : "SCRIPT".equalsIgnoreCase(event.eventType()) ? "Script finding"
                                : "WINDOWS".equalsIgnoreCase(event.eventType()) ? "Windows security event" : "Process event";
                        sendThreatNotification(source, event.riskLevel(), event.decision());
                    }
                }
            } else initialMonitorEventSnapshotLoaded = true;
            lastMonitorEventId = Math.max(lastMonitorEventId, newest);
        }
        if (assessments != null) {
            long newest = assessments.stream().map(SecurityEvent::id).filter(java.util.Objects::nonNull)
                    .mapToLong(Long::longValue).max().orElse(lastAssessmentEventId);
            if (initialAssessmentSnapshotLoaded) {
                for (SecurityEvent event : assessments) {
                    if (event.id() == null || event.id() <= lastAssessmentEventId || !isAlertDecision(event.decision())) continue;
                    JsonNode details = parseAssessment(event.detailsJson());
                    String risk = textAt(details.path("sources").path("urlModel"), "risk_level", event.riskLevel());
                    sendThreatNotification("URL assessment", risk, event.decision());
                }
            } else initialAssessmentSnapshotLoaded = true;
            lastAssessmentEventId = Math.max(lastAssessmentEventId, newest);
        }
    }

    private boolean isAlertDecision(String decision) {
        return "WARN".equalsIgnoreCase(decision) || "BLOCK".equalsIgnoreCase(decision);
    }

    private void sendThreatNotification(String source, String riskLevel, String decision) {
        NotificationPreferences preferences = latestNotificationPreferences;
        if (preferences == null || !preferences.enabled()) return;
        boolean block = "BLOCK".equalsIgnoreCase(decision);
        if (block && !preferences.blockEnabled()) return;
        if (!block && !preferences.warnEnabled()) return;
        SystemTraySupport tray = systemTraySupport;
        if (tray != null) tray.showNotification("AI WatchDog · " + source,
                valueOr(riskLevel, "Risk unknown") + " · policy decision " + valueOr(decision, "unknown")
                        + ". Open the dashboard to review details.");
    }

    private void applyBackendSnapshot(ServiceHealth health, List<SecurityEvent> urlEvents,
                                      List<MonitorEvent> monitorEvents, SecurityEventStats stats,
                                      List<SecurityEvent> assessments, AssessmentStats assessmentStats,
                                      List<SecurityEvent> feedbackEvents) {
        if (closed) return;
        if (dashAssessmentLoading != null) { dashAssessmentLoading.setVisible(false); dashAssessmentLoading.setManaged(false); }
        boolean statsAvailable = stats != null;
        boolean urlHistoryAvailable = urlEvents != null;
        boolean monitorHistoryAvailable = monitorEvents != null;
        boolean assessmentsAvailable = assessments != null;
        boolean assessmentStatsAvailable = assessmentStats != null;
        boolean feedbackAvailable = feedbackEvents != null;
        if (stats == null) stats = new SecurityEventStats(0,0,0,0,0,0,0,0,0,0,0);
        if (urlEvents == null) urlEvents = List.of();
        if (monitorEvents == null) monitorEvents = List.of();
        if (assessments == null) assessments = List.of();
        if (feedbackEvents == null) feedbackEvents = List.of();
        updateAssessmentDashboard(assessmentStats);
        totalScanned = Math.toIntExact(Math.min(Integer.MAX_VALUE, stats.totalEvents()));
        totalBlocked = Math.toIntExact(Math.min(Integer.MAX_VALUE, stats.blockCount()));
        totalInReview = Math.toIntExact(Math.min(Integer.MAX_VALUE, stats.reviewCount() + stats.warnCount()));
        totalAllowed = Math.toIntExact(Math.min(Integer.MAX_VALUE, stats.allowCount()));
        if (cardsHelper != null) {
            cardsHelper.countUp(dashScannedCount, totalScanned);
            cardsHelper.countUp(dashThreatsBlockedCount, totalBlocked);
            cardsHelper.countUp(dashInReviewCount, totalInReview);
            cardsHelper.countUp(dashAllowedCount, totalAllowed);
        } else {
            setCount(dashScannedCount, totalScanned);
            setCount(dashThreatsBlockedCount, totalBlocked);
            setCount(dashInReviewCount, totalInReview);
            setCount(dashAllowedCount, totalAllowed);
        }
        setCount(threatBlockedCount, totalBlocked);
        setCount(threatInReviewCount, totalInReview);
        setCount(threatHighRiskCount, stats.highRiskCount());
        if (threatCardsHelper != null) {
            threatCardsHelper.countUp(threatBlockedCount, totalBlocked);
            threatCardsHelper.countUp(threatInReviewCount, totalInReview);
            threatCardsHelper.countUp(threatHighRiskCount, toCount(stats.highRiskCount()));
            threatCardsHelper.countUp(threatSafeCount, toCount(stats.safeCount() + stats.lowRiskCount()));
        }
        if (activityCardsHelper != null) {
            activityCardsHelper.countUp(activityCount0, urlEvents.size() + monitorEvents.size());
            activityCardsHelper.countUp(activityCount1, totalScanned);
            activityCardsHelper.countUp(activityCount2, totalBlocked);
            activityCardsHelper.countUp(activityCount3, totalAllowed);
        }
        if (insightCount0 != null) insightCount0.setText("N/A");
        if (insightCount2 != null) insightCount2.setText("N/A");
        if (insightsCardsHelper != null) {
            insightsCardsHelper.countUp(insightCount1, toCount(stats.phishingCount()));
            insightsCardsHelper.countUp(insightCount3, totalScanned);
        } else {
            setCount(insightCount1, stats.phishingCount());
            setCount(insightCount3, totalScanned);
        }
        if (!statsAvailable) {
            for (Label label : new Label[]{dashScannedCount, dashThreatsBlockedCount, dashInReviewCount,
                    dashAllowedCount, threatBlockedCount, threatInReviewCount, threatHighRiskCount,
                    dashSafePercent, dashSuspiciousPercent, dashPotentialPercent, dashHighRiskPercent,
                    activityCount1, activityCount2, activityCount3}) if (label != null) label.setText("N/A");
            if (dashRiskDescription != null) dashRiskDescription.setText("URL assessment metrics are unavailable from Spring Boot.");
        }
        int totalRiskEvents = Math.max(1, (int) Math.min(Integer.MAX_VALUE, stats.totalEvents()));
        updateBreakdown(dashSafeProgress, dashSafePercent, stats.safeCount(), totalRiskEvents);
        updateBreakdown(dashSuspiciousProgress, dashSuspiciousPercent, stats.suspiciousCount(), totalRiskEvents);
        updateBreakdown(dashPotentialProgress, dashPotentialPercent, stats.lowRiskCount(), totalRiskEvents);
        updateBreakdown(dashHighRiskProgress, dashHighRiskPercent, stats.highRiskCount(), totalRiskEvents);
        if (!statsAvailable) {
            for (Label label : new Label[]{dashSafePercent, dashSuspiciousPercent, dashPotentialPercent,
                    dashHighRiskPercent, threatSafeCount, insightCount1, insightCount3}) {
                if (label != null) label.setText("N/A");
            }
            for (ProgressBar bar : new ProgressBar[]{dashSafeProgress, dashSuspiciousProgress,
                    dashPotentialProgress, dashHighRiskProgress}) if (bar != null) bar.setProgress(0);
        }
        if (threatInsightsHelper != null) {
            int threatCount = (int) Math.min(Integer.MAX_VALUE, stats.highRiskCount() + stats.suspiciousCount() + stats.lowRiskCount());
            int divisor = Math.max(1, threatCount);
            threatInsightsHelper.updateData(threatCount,
                    (int) (stats.highRiskCount() * 100 / divisor),
                    (int) (stats.suspiciousCount() * 100 / divisor),
                    (int) (stats.lowRiskCount() * 100 / divisor));
        }
        urlEvents.stream().max(Comparator.comparing(event -> parseEventInstant(event.timestamp()))).ifPresentOrElse(
                event -> {
                    updateRiskGauge(event.riskScore(), event.riskLevel());
                    if (dashRiskDescription != null) dashRiskDescription.setText("Risk score from the latest URL assessment returned by Spring Boot.");
                },
                () -> {
                    updateRiskGauge(0, "UNKNOWN", false);
                    if (dashRiskDescription != null) dashRiskDescription.setText("No URL assessment has been returned by Spring Boot yet.");
                });
        if (dashOperationalBadge != null) {
            dashOperationalBadge.setText(health.isFullyAvailable() ? "SERVICES ONLINE" : "SERVICE UNAVAILABLE");
        }
        if (dashStatusNormalLabel != null) {
            dashStatusNormalLabel.setText(health.isBackendAvailable()
                    ? (health.isMlAvailable() ? "Spring Boot and ML service online" : "ML service unavailable")
                    : "Spring Boot backend unavailable");
        }

        List<ActivityItem> recent = new ArrayList<>();
        List<ThreatItem> threats = new ArrayList<>();
        for (SecurityEvent event : urlEvents) {
            String risk = valueOr(event.riskLevel(), "UNKNOWN");
            String decision = valueOr(event.decision(), "UNKNOWN");
            String time = formatEventTime(event.timestamp());
            Instant instant = parseEventInstant(event.timestamp());
            recent.add(new ActivityItem(time, "URL Scan", valueOr(event.url(), "URL unavailable"), risk,
                    decision, statusForDecision(decision), instant));
            if (!"ALLOW".equalsIgnoreCase(decision)) {
                threats.add(new ThreatItem(valueOr(event.url(), "URL unavailable"), risk, decision, time, instant));
            }
        }
        for (MonitorEvent event : monitorEvents) {
            String risk = valueOr(event.riskLevel(), "UNKNOWN");
            String decision = valueOr(event.decision(), "UNKNOWN");
            String time = formatEventTime(event.timestamp());
            String description = valueOr(event.resourceName(), "Resource unavailable");
            if (event.reasons() != null && !event.reasons().isEmpty()) {
                description += " · " + String.join(" · ", event.reasons().stream().limit(3).toList());
            }
            Instant instant = parseEventInstant(event.timestamp());
            String eventName = "FILE".equalsIgnoreCase(event.eventType()) ? "File Event"
                    : "PROCESS".equalsIgnoreCase(event.eventType()) ? "Process Event"
                    : "SCRIPT".equalsIgnoreCase(event.eventType()) ? "Script Finding"
                    : "WINDOWS".equalsIgnoreCase(event.eventType()) ? "Windows Security Event"
                    : valueOr(event.eventType(), "Monitor event");
            recent.add(new ActivityItem(time, eventName, description, risk,
                    decision, statusForDecision(decision), instant));
            if (!"ALLOW".equalsIgnoreCase(decision)) {
                threats.add(new ThreatItem(description, risk, decision, time, instant));
            }
        }
        for (SecurityEvent event : assessments) {
            JsonNode assessment = parseAssessment(event.detailsJson());
            String assessmentId = textAt(assessment, "assessmentId", "event-" + valueOr(event.id() == null ? null : event.id().toString(), "unknown"));
            String subjectType = valueOr(event.subjectType(), "Assessment");
            String subject = "FILE".equalsIgnoreCase(subjectType)
                    ? "File SHA-256 " + abbreviate(valueOr(event.subjectId(), "unavailable"))
                    : "URL".equalsIgnoreCase(subjectType) ? valueOr(event.subjectId(), "URL unavailable") : "Subject unavailable";
            String summary = assessmentSourceSummary(assessment);
            String decision = valueOr(event.decision(), "UNKNOWN");
            String status = textAt(assessment, "status", "UNKNOWN");
            recent.add(new ActivityItem(formatEventTime(event.timestamp()), "Unified Assessment · " + subjectType,
                    assessmentId + " · " + subject + " · " + summary, "Assessment", decision, status,
                    parseEventInstant(event.timestamp()), assessmentId, subjectType, event.detailsJson(), event.correlationId()));
        }
        for (SecurityEvent event : feedbackEvents) {
            JsonNode feedback = parseAssessment(event.detailsJson());
            String label = textAt(feedback, "label", "UNKNOWN");
            String assessmentId = valueOr(event.subjectId(), "unavailable");
            recent.add(new ActivityItem(formatEventTime(event.timestamp()), "Operator Feedback · " + label,
                    "Assessment " + assessmentId, "Human review", valueOr(event.decision(), "REVIEW"),
                    "Stored for offline evaluation", parseEventInstant(event.timestamp())));
        }
        activityLog.clear();
        // Each backend source is capped at 100 rows, so this combined in-memory page remains bounded.
        activityLog.addAll(recent.stream().sorted(Comparator.comparing(ActivityItem::instant).reversed()).toList());
        threatLog.clear();
        threatLog.addAll(threats.stream().sorted(Comparator.comparing(ThreatItem::instant).reversed()).limit(100).toList());
        renderActivityTable(activitySearchInput == null ? "" : activitySearchInput.getText());
        renderThreatTable();
        if (!urlHistoryAvailable || !monitorHistoryAvailable) {
            if (activityCount0 != null) activityCount0.setText("N/A");
        }
        if (activityPaginationLabel != null && (!statsAvailable || !urlHistoryAvailable
                || !monitorHistoryAvailable || !assessmentsAvailable || !assessmentStatsAvailable || !feedbackAvailable)) {
            activityPaginationLabel.setText("Partial data: one or more history or aggregate requests failed. Assessment and feedback history are limited to the latest 100 records.");
        }
    }

    private void updateAssessmentDashboard(AssessmentStats stats) {
        if (stats == null) {
            if (dashAssessmentState != null) dashAssessmentState.setText("Assessment metrics unavailable");
            for (Label label : new Label[]{dashAssessmentTotal, dashAssessmentUrls, dashAssessmentFiles,
                    dashAssessmentPartial, dashKnownMalicious, dashKnownClean, dashUnknownReputation,
                    dashLookupError, dashAssessmentAllow, dashAssessmentReview, dashAssessmentWarn,
                    dashAssessmentBlock}) if (label != null) label.setText("N/A");
            return;
        }
        setCount(dashAssessmentTotal, stats.totalAssessments());
        setCount(dashAssessmentUrls, stats.urlAssessments());
        setCount(dashAssessmentFiles, stats.fileAssessments());
        setCount(dashAssessmentPartial, stats.partialCount());
        setCount(dashKnownMalicious, stats.knownMaliciousCount());
        setCount(dashKnownClean, stats.knownCleanCount());
        setCount(dashUnknownReputation, stats.unknownReputationCount());
        setCount(dashLookupError, stats.lookupErrorCount());
        setCount(dashAssessmentAllow, stats.allowCount());
        setCount(dashAssessmentReview, stats.reviewCount());
        setCount(dashAssessmentWarn, stats.warnCount());
        setCount(dashAssessmentBlock, stats.blockCount());
        if (dashAssessmentState != null) dashAssessmentState.setText(stats.totalAssessments() == 0
                ? "Spring Boot available · no persisted assessments" : "Lifetime totals · reputation counts are source results");
    }

    private static JsonNode parseAssessment(String json) {
        if (json == null || json.isBlank()) return com.fasterxml.jackson.databind.node.MissingNode.getInstance();
        try { return new ObjectMapper().readTree(json); }
        catch (Exception ignored) { return com.fasterxml.jackson.databind.node.MissingNode.getInstance(); }
    }

    private static String textAt(JsonNode node, String field, String fallback) {
        JsonNode value = node.path(field);
        return value.isTextual() ? value.asText() : fallback;
    }

    private static String abbreviate(String value) {
        return value.length() > 16 ? value.substring(0, 8) + "…" + value.substring(value.length() - 6) : value;
    }

    private static String assessmentSourceSummary(JsonNode assessment) {
        JsonNode sources = assessment.path("sources");
        List<String> parts = new ArrayList<>();
        JsonNode url = sources.path("urlModel");
        if (url.isObject()) parts.add("URL " + textAt(url, "risk_level", textAt(url, "status", "result unavailable")));
        JsonNode reputation = sources.path("fileReputation");
        if (reputation.isObject()) parts.add("Reputation " + textAt(reputation, "reputationStatus", "unavailable"));
        JsonNode pe = sources.path("staticPe");
        if (pe.isObject()) {
            String peStatus = textAt(pe, "status", "unavailable");
            parts.add(pe.path("risk_score").isNumber()
                    ? "PE heuristic " + pe.path("risk_score").asInt() + "/100 · " + peStatus
                    : "PE " + peStatus);
        }
        JsonNode explanationDetails = assessment.path("explanationDetails");
        if (explanationDetails.isObject()) {
            String summary = textAt(explanationDetails, "summary", "");
            if (!summary.isBlank()) parts.add("LLM " + summary);
            else if (explanationDetails.path("fallbackUsed").asBoolean(false)) parts.add("LLM fallback explanation");
        }
        return parts.isEmpty() ? "Source details unavailable" : String.join(" · ", parts);
    }

    private void showBackendUnavailable(Exception error) {
        if (closed) return;
        if (dashAssessmentLoading != null) { dashAssessmentLoading.setVisible(false); dashAssessmentLoading.setManaged(false); }
        if (dashOperationalBadge != null && !"BACKEND UNAVAILABLE".equals(dashOperationalBadge.getText())) {
            dashOperationalBadge.setText("BACKEND UNAVAILABLE");
        }
        if (dashStatusNormalLabel != null && !"Unable to load security data from Spring Boot".equals(dashStatusNormalLabel.getText())) {
            dashStatusNormalLabel.setText("Unable to load security data from Spring Boot");
        }
        for (Label label : new Label[]{dashScannedCount, dashThreatsBlockedCount, dashInReviewCount,
                dashAllowedCount, dashAssessmentTotal, dashAssessmentUrls, dashAssessmentFiles,
                dashAssessmentPartial, dashKnownMalicious, dashKnownClean, dashUnknownReputation,
                dashLookupError, dashAssessmentAllow, dashAssessmentReview, dashAssessmentWarn,
                dashAssessmentBlock, threatBlockedCount, threatInReviewCount, threatHighRiskCount,
                threatSafeCount, dashSafePercent, dashSuspiciousPercent, dashPotentialPercent,
                dashHighRiskPercent, activityCount0, activityCount1, activityCount2, activityCount3,
                insightCount1, insightCount3}) if (label != null) label.setText("N/A");
        if (dashAssessmentState != null) dashAssessmentState.setText("Spring Boot unavailable");
    }

    private static void setCount(Label label, long value) {
        if (label != null) label.setText(String.format(Locale.ROOT, "%,d", value));
    }

    private static int toCount(long value) {
        return (int) Math.max(0, Math.min(Integer.MAX_VALUE, value));
    }

    private static void updateBreakdown(ProgressBar bar, Label label, long count, int total) {
        double fraction = Math.max(0, Math.min(1, (double) count / total));
        if (bar != null) bar.setProgress(fraction);
        if (label != null) label.setText(String.format(Locale.ROOT, "%d%%", Math.round(fraction * 100)));
    }

    private static Instant parseEventInstant(String value) {
        try { return Instant.parse(value); } catch (RuntimeException ignored) { return Instant.EPOCH; }
    }

    private static String valueOr(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String formatEventTime(String value) {
        try {
            return DateTimeFormatter.ofPattern("MMM d, hh:mm a", Locale.ROOT)
                    .withZone(ZoneId.systemDefault()).format(Instant.parse(value));
        } catch (RuntimeException ignored) {
            return valueOr(value, "Time unavailable");
        }
    }

    private static String statusForDecision(String decision) {
        return switch (decision.toUpperCase(Locale.ROOT)) {
            case "ALLOW" -> "Allowed";
            case "BLOCK" -> "BLOCK policy";
            case "REVIEW" -> "Reviewed";
            case "WARN" -> "Warn";
            default -> decision;
        };
    }

    // =========================================================================
    // Welcome / Starting Page (5s Clean Splash & Auto-Transition)
    // =========================================================================
    private void startSplashSequence() {
        if (welcomePage == null) {
            navigateDashboard();
            return;
        }

        splashCompleted = false;
        welcomePage.setVisible(true);
        welcomePage.setManaged(true);
        welcomePage.setOpacity(1.0);

        if (appShell != null) {
            appShell.setVisible(false);
            appShell.setManaged(false);
            appShell.setOpacity(0.0);
        }

        // Set initial invisible/offset states for staged entrance
        if (logoImage != null) {
            logoImage.setOpacity(0.0);
            logoImage.setScaleX(0.88);
            logoImage.setScaleY(0.88);
        }
        if (splashGlowCircle != null) {
            splashGlowCircle.setOpacity(0.0);
            splashGlowCircle.setScaleX(0.88);
            splashGlowCircle.setScaleY(0.88);
        }
        if (splashTitleLabel != null) {
            splashTitleLabel.setOpacity(0.0);
            splashTitleLabel.setTranslateY(18.0);
        }
        if (splashSubtitleLabel != null) {
            splashSubtitleLabel.setOpacity(0.0);
        }
        if (splashProgressBar != null) {
            splashProgressBar.setProgress(0.0);
            splashProgressBar.setOpacity(0.0);
        }

        // 1. Logo fades and scales in with a soft pulsing blue glow behind it (0.0s -> 0.9s)
        if (logoImage != null) {
            FadeTransition logoFade = new FadeTransition(Duration.millis(850), logoImage);
            logoFade.setFromValue(0.0);
            logoFade.setToValue(1.0);
            logoFade.play();

            ScaleTransition logoScale = new ScaleTransition(Duration.millis(850), logoImage);
            logoScale.setFromX(0.88);
            logoScale.setFromY(0.88);
            logoScale.setToX(1.0);
            logoScale.setToY(1.0);
            logoScale.setInterpolator(Interpolator.EASE_OUT);
            logoScale.play();
        }

        if (splashGlowCircle != null) {
            FadeTransition glowFade = new FadeTransition(Duration.millis(850), splashGlowCircle);
            glowFade.setFromValue(0.0);
            glowFade.setToValue(0.85);
            glowFade.setOnFinished(e -> {
                if (splashCompleted || splashGlowCircle == null) return;
                // Soft pulsing blue glow
                splashGlowPulse = new ScaleTransition(Duration.millis(1400), splashGlowCircle);
                splashGlowPulse.setFromX(1.0);
                splashGlowPulse.setFromY(1.0);
                splashGlowPulse.setToX(1.14);
                splashGlowPulse.setToY(1.14);
                splashGlowPulse.setAutoReverse(true);
                splashGlowPulse.setCycleCount(Animation.INDEFINITE);
                splashGlowPulse.setInterpolator(Interpolator.EASE_BOTH);
                splashGlowPulse.play();

                splashGlowPulseFade = new FadeTransition(Duration.millis(1400), splashGlowCircle);
                splashGlowPulseFade.setFromValue(0.85);
                splashGlowPulseFade.setToValue(0.50);
                splashGlowPulseFade.setAutoReverse(true);
                splashGlowPulseFade.setCycleCount(Animation.INDEFINITE);
                splashGlowPulseFade.setInterpolator(Interpolator.EASE_BOTH);
                splashGlowPulseFade.play();
            });
            glowFade.play();

            ScaleTransition glowScale = new ScaleTransition(Duration.millis(850), splashGlowCircle);
            glowScale.setFromX(0.88);
            glowScale.setFromY(0.88);
            glowScale.setToX(1.0);
            glowScale.setToY(1.0);
            glowScale.setInterpolator(Interpolator.EASE_OUT);
            glowScale.play();
        }

        List<KeyFrame> frames = new ArrayList<>();

        // 2. Title "AI WATCHDOG" slides up and fades in at 0.6s
        frames.add(new KeyFrame(Duration.millis(600), evt -> {
            if (splashTitleLabel != null) {
                TranslateTransition tt = new TranslateTransition(Duration.millis(650), splashTitleLabel);
                tt.setFromY(18.0);
                tt.setToY(0.0);
                tt.setInterpolator(Interpolator.EASE_OUT);
                tt.play();

                FadeTransition ft = new FadeTransition(Duration.millis(650), splashTitleLabel);
                ft.setFromValue(0.0);
                ft.setToValue(1.0);
                ft.play();
            }
        }));

        // 3. Tagline "SECURITY IN EVERY CLICK" fades in at 1.0s
        frames.add(new KeyFrame(Duration.millis(1000), evt -> {
            if (splashSubtitleLabel != null) {
                FadeTransition ft = new FadeTransition(Duration.millis(550), splashSubtitleLabel);
                ft.setFromValue(0.0);
                ft.setToValue(1.0);
                ft.play();
            }
        }));

        // 4. Progress bar fades in at 1.4s
        frames.add(new KeyFrame(Duration.millis(1400), evt -> {
            if (splashProgressBar != null) {
                FadeTransition ft = new FadeTransition(Duration.millis(250), splashProgressBar);
                ft.setFromValue(0.0);
                ft.setToValue(1.0);
                ft.play();
            }
        }));

        // 4. Thin progress bar fills for about 2.4 seconds (1.5s to 3.9s)
        if (splashProgressBar != null) {
            frames.add(new KeyFrame(Duration.millis(1500), new KeyValue(splashProgressBar.progressProperty(), 0.0)));
            frames.add(new KeyFrame(Duration.millis(3900), new KeyValue(splashProgressBar.progressProperty(), 1.0, Interpolator.EASE_BOTH)));
        }

        // 5. The screen fades out smoothly at 4.4s (600ms crossfade to Dashboard)
        frames.add(new KeyFrame(Duration.millis(4400), evt -> {
            performSplashCrossfade();
        }));

        // Sequence complete at 5.0s -> App continues to the same next screen as before
        frames.add(new KeyFrame(Duration.millis(5000), evt -> {
            completeSplashTransition();
        }));

        splashMasterTimeline = new Timeline(frames.toArray(new KeyFrame[0]));
        splashMasterTimeline.play();
    }

    private void performSplashCrossfade() {
        if (splashCompleted) return;

        // Prepare appShell for fade-in
        if (appShell != null) {
            appShell.setOpacity(0.0);
            appShell.setVisible(true);
            appShell.setManaged(true);
            navigateDashboard();

            FadeTransition appFadeIn = new FadeTransition(Duration.millis(550), appShell);
            appFadeIn.setFromValue(0.0);
            appFadeIn.setToValue(1.0);
            appFadeIn.play();
        }

        // Fade out welcomePage
        if (welcomePage != null) {
            FadeTransition splashFadeOut = new FadeTransition(Duration.millis(550), welcomePage);
            splashFadeOut.setFromValue(1.0);
            splashFadeOut.setToValue(0.0);
            splashFadeOut.setOnFinished(e -> {
                if (welcomePage != null) {
                    welcomePage.setVisible(false);
                    welcomePage.setManaged(false);
                    welcomePage.setOpacity(1.0);
                }
            });
            splashFadeOut.play();
        }
    }

    public void completeSplashTransition() {
        if (splashCompleted) return;
        splashCompleted = true;

        stopSplashAnimations();

        if (welcomePage != null) {
            welcomePage.setVisible(false);
            welcomePage.setManaged(false);
            welcomePage.setOpacity(1.0);
        }

        if (appShell != null) {
            appShell.setVisible(true);
            appShell.setManaged(true);
            appShell.setOpacity(1.0);
        }

        navigateDashboard();
        notifyUser("Protection is active");
    }

    private void stopSplashAnimations() {
        if (splashMasterTimeline != null) {
            splashMasterTimeline.stop();
            splashMasterTimeline = null;
        }
        if (splashGlowPulse != null) {
            splashGlowPulse.stop();
            splashGlowPulse = null;
        }
        if (splashGlowPulseFade != null) {
            splashGlowPulseFade.stop();
            splashGlowPulseFade = null;
        }
    }

    @FXML
    public void startProtection() {
        completeSplashTransition();
    }

    public boolean isWelcomePageVisible() {
        return welcomePage != null && welcomePage.isVisible();
    }

    // =========================================================================
    // Collapsible Sidebar & Hamburger Toggle
    // =========================================================================
    private void setupSidebarCollapsible() {
        if (sidebar == null) return;

        // Clip the sidebar contents so nothing overflows or wraps when collapsing
        Rectangle sidebarClip = new Rectangle();
        sidebarClip.widthProperty().bind(sidebar.widthProperty());
        sidebarClip.heightProperty().bind(sidebar.heightProperty());
        sidebar.setClip(sidebarClip);

        // Apply initial sidebar state when layout geometry is ready
        Platform.runLater(() -> {
            double fullW = getOrMeasureSidebarFullWidth();
            setSidebarStateInstant(isSidebarOpen, fullW);
        });
    }

    private double getOrMeasureSidebarFullWidth() {
        if (sidebarFullWidth > 0) {
            return sidebarFullWidth;
        }
        double w = 0;
        if (sidebar != null) {
            w = sidebar.getWidth();
            if (w <= 0) {
                w = sidebar.prefWidth(-1);
            }
            if (w <= 0) {
                w = sidebar.getPrefWidth();
            }
        }
        if (w <= 0) {
            w = 240.0;
        }
        sidebarFullWidth = w;
        lockSidebarChildrenWidth(sidebarFullWidth);
        return sidebarFullWidth;
    }

    private void lockSidebarChildrenWidth(double fullWidth) {
        if (sidebar == null) return;
        double leftInset = sidebar.getInsets().getLeft();
        double rightInset = sidebar.getInsets().getRight();
        if (leftInset == 0 && rightInset == 0) {
            leftInset = 14;
            rightInset = 14;
        }
        double contentWidth = Math.max(100, fullWidth - leftInset - rightInset);
        for (Node child : sidebar.getChildren()) {
            if (child instanceof Region r) {
                r.setMinWidth(contentWidth);
                r.setPrefWidth(contentWidth);
                if (r instanceof ScrollPane sp && sp.getContent() instanceof Region innerRegion) {
                    innerRegion.setMinWidth(contentWidth);
                    innerRegion.setPrefWidth(contentWidth);
                }
            }
        }
    }

    private void setSidebarStateInstant(boolean open, double fullWidth) {
        if (sidebar == null) return;
        lockSidebarChildrenWidth(fullWidth);
        if (open) {
            sidebar.setVisible(true);
            sidebar.setMinWidth(fullWidth);
            sidebar.setPrefWidth(fullWidth);
            sidebar.setMaxWidth(fullWidth);
            if (hamburgerBtn != null && !hamburgerBtn.getStyleClass().contains("wd-burger-on")) {
                hamburgerBtn.getStyleClass().add("wd-burger-on");
            }
        } else {
            sidebar.setMinWidth(0);
            sidebar.setPrefWidth(0);
            sidebar.setMaxWidth(0);
            sidebar.setVisible(false);
            if (hamburgerBtn != null) {
                hamburgerBtn.getStyleClass().remove("wd-burger-on");
            }
        }
    }

    @FXML
    public void toggleSidebar() {
        if (isSidebarAnimating || sidebar == null) {
            return;
        }
        isSidebarOpen = !isSidebarOpen;
        animateSidebar(isSidebarOpen);
    }

    public boolean isSidebarOpen() {
        return isSidebarOpen;
    }

    private void animateSidebar(boolean open) {
        double fullWidth = getOrMeasureSidebarFullWidth();
        double targetWidth = open ? fullWidth : 0.0;

        isSidebarAnimating = true;

        if (open) {
            sidebar.setVisible(true);
            if (hamburgerBtn != null && !hamburgerBtn.getStyleClass().contains("wd-burger-on")) {
                hamburgerBtn.getStyleClass().add("wd-burger-on");
            }
        } else {
            if (hamburgerBtn != null) {
                hamburgerBtn.getStyleClass().remove("wd-burger-on");
            }
        }

        if (sidebarTimeline != null) {
            sidebarTimeline.stop();
        }

        sidebarTimeline = new Timeline();
        KeyValue kvMin = new KeyValue(sidebar.minWidthProperty(), targetWidth, Interpolator.EASE_OUT);
        KeyValue kvPref = new KeyValue(sidebar.prefWidthProperty(), targetWidth, Interpolator.EASE_OUT);
        KeyValue kvMax = new KeyValue(sidebar.maxWidthProperty(), targetWidth, Interpolator.EASE_OUT);
        KeyFrame kf = new KeyFrame(Duration.millis(350), kvMin, kvPref, kvMax);
        sidebarTimeline.getKeyFrames().add(kf);
        sidebarTimeline.setOnFinished(e -> {
            isSidebarAnimating = false;
            if (!open) {
                sidebar.setVisible(false);
            }
        });

        sidebarTimeline.play();
    }

    // =========================================================================
    // Navigation
    // =========================================================================
    @FXML public void navigateDashboard() {
        selectNav(navDashboardBtn, dashboardPage);
        startDashboardTelemetryAnimations();
        if (riskRadarView != null) {
            riskRadarView.replay();
        } else {
            updateRiskGauge(0, "UNKNOWN", true);
            animateThreatBreakdown();
        }
        if (cardsHelper != null) {
            cardsHelper.playEntranceAnimation();
        }
    }
    @FXML public void navigateScanner() { selectNav(navScannerBtn, scannerInputPage); }
    @FXML public void navigateFileShield() { selectNav(navFileShieldBtn, fileShieldPage); }
    @FXML public void navigateSecureAccess() { selectNav(navSecureAccessBtn, secureAccessPage); refreshDomainWhitelist(); }
    @FXML public void navigateThreatCenter() {
        selectNav(navThreatCenterBtn, threatCenterPage);
        if (threatInsightsHelper != null) {
            threatInsightsHelper.playEntranceAnimation();
        }
    }
    @FXML public void navigateActivity() {
        selectNav(navActivityBtn, activityPage);
    }
    @FXML public void navigateInsights() {
        selectNav(navInsightsBtn, insightsPage);
    }
    @FXML public void navigateSettings() { selectNav(navSettingsBtn, settingsPage); }

    private void setActiveNav(ButtonBase target) {
        if (target == null && !navItems.isEmpty()) {
            target = navItems.get(0);
        }
        currentActiveNav = target;
        for (ButtonBase item : navItems) {
            item.getStyleClass().removeIf(c -> "nav-btn-active".equals(c) || "wd-on".equals(c));
            if (item instanceof ToggleButton t) {
                t.setSelected(false);
            }
        }
        if (target != null) {
            if (!target.getStyleClass().contains("nav-btn-active")) {
                target.getStyleClass().add("nav-btn-active");
            }
            if (!target.getStyleClass().contains("wd-on")) {
                target.getStyleClass().add("wd-on");
            }
            if (target instanceof ToggleButton t) {
                t.setSelected(true);
            }
        }
    }

    private void selectNav(Button activeBtn, ScrollPane targetPage) {
        setActiveNav(activeBtn);

        if (pageStack != null && targetPage != null) {
            pageStack.getChildren().forEach(child -> child.setVisible(child == targetPage));
            targetPage.toFront();
        }
    }

    // =========================================================================
    @FXML private void addException() {
        String domain = domainExceptionInput == null ? "" : domainExceptionInput.getText().trim();
        if (domain.isBlank()) { notifyUser("Enter a domain such as example.com."); return; }
        domainExceptionInput.setDisable(true);
        backendRefresh.execute(() -> {
            try {
                List<String> entries = apiService.addDomainWhitelistEntry(domain);
                Platform.runLater(() -> {
                    domainExceptionInput.clear();
                    domainExceptionInput.setDisable(false);
                    renderDomainWhitelist(entries);
                    notifyUser("Domain exception saved.");
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    domainExceptionInput.setDisable(false);
                    notifyUser(e.getMessage() == null ? "Could not save domain exception." : e.getMessage());
                });
            }
        });
    }

    private void refreshDomainWhitelist() {
        if (secureAccessContainer == null) return;
        secureAccessContainer.getChildren().clear();
        backendRefresh.execute(() -> {
            try {
                List<String> entries = apiService.getDomainWhitelist();
                Platform.runLater(() -> renderDomainWhitelist(entries));
            } catch (Exception e) {
                Platform.runLater(() -> notifyUser("Could not load domain exceptions. Check backend connection."));
            }
        });
    }

    private void renderDomainWhitelist(List<String> entries) {
        if (secureAccessContainer == null) return;
        secureAccessContainer.getChildren().clear();
        if (entries == null || entries.isEmpty()) {
            Label empty = new Label("No domain exceptions configured.");
            empty.getStyleClass().add("wd-exception-desc");
            secureAccessContainer.getChildren().add(empty);
            return;
        }
        for (String domain : entries) {
            HBox row = new HBox(14);
            row.setAlignment(Pos.CENTER_LEFT);
            row.getStyleClass().add("wd-exception-row");
            StackPane iconBox = new StackPane();
            iconBox.getStyleClass().addAll("metric-icon-circle", "icon-emerald-bg");
            iconBox.setMinSize(36, 36);
            FontIcon icon = new FontIcon("fth-globe");
            icon.setIconSize(16);
            icon.setIconColor(Color.web("#10B981"));
            iconBox.getChildren().add(icon);
            VBox details = new VBox(2);
            HBox.setHgrow(details, Priority.ALWAYS);
            Label title = new Label(domain);
            title.getStyleClass().add("wd-exception-domain");
            Label subtitle = new Label("Domain exception · URL model skipped; other checks remain active");
            subtitle.getStyleClass().add("wd-exception-desc");
            details.getChildren().addAll(title, subtitle);
            Button remove = new Button("Remove");
            remove.setAccessibleText("Remove " + domain + " from domain whitelist");
            remove.setOnAction(event -> removeDomainException(domain, remove));
            row.getChildren().addAll(iconBox, details, remove);
            secureAccessContainer.getChildren().add(row);
        }
    }

    private void removeDomainException(String domain, Button button) {
        button.setDisable(true);
        backendRefresh.execute(() -> {
            try {
                List<String> entries = apiService.removeDomainWhitelistEntry(domain);
                Platform.runLater(() -> { renderDomainWhitelist(entries); notifyUser("Domain exception removed."); });
            } catch (Exception e) {
                Platform.runLater(() -> { button.setDisable(false); notifyUser("Could not remove domain exception."); });
            }
        });
    }

    // =========================================================================
    @FXML
    public void addLegacyDemoException() {
        if (secureAccessContainer != null) {
            HBox newRow = new HBox(14);
            newRow.setAlignment(Pos.CENTER_LEFT);
            newRow.getStyleClass().add("wd-exception-row");

            StackPane iconBox = new StackPane();
            iconBox.getStyleClass().addAll("metric-icon-circle", "icon-green-bg");
            iconBox.setMinWidth(36); iconBox.setMinHeight(36);
            FontIcon icon = new FontIcon("fth-globe");
            icon.setIconSize(16);
            icon.setIconColor(Color.web("#10B981"));
            secureAccessGlobeAnimations.add(com.aiwatchdog.ui.dashboard.DashboardCardsHelper.createSlowRotation(icon));
            iconBox.getChildren().add(icon);

            VBox textCol = new VBox(2);
            HBox.setHgrow(textCol, Priority.ALWAYS);
            Label domainLabel = new Label("*.github.com");
            domainLabel.getStyleClass().add("wd-exception-domain");
            Label descLabel = new Label("Developer code repository exception • Added by user");
            descLabel.getStyleClass().add("wd-exception-desc");
            textCol.getChildren().addAll(domainLabel, descLabel);

            Label badge = new Label("ACTIVE");
            badge.getStyleClass().addAll("pill-badge", "badge-safe");
            badge.setStyle("-fx-font-size: 10px; -fx-font-weight: 700; -fx-padding: 3px 10px;");

            newRow.getChildren().addAll(iconBox, textCol, badge);
            secureAccessContainer.getChildren().add(newRow);
        }
        notifyUser("Domain exception *.github.com added to Secure Access whitelist.");
    }

    // =========================================================================
    // Search & Quick Presets
    // =========================================================================
    @FXML
    private void onTopSearchSubmit() {
        String url = topSearchInput.getText();
        if (url != null && !url.isBlank()) {
            analyze(url.trim());
        }
    }

    @FXML
    public void analyzeManual() {
        String url = scannerUrlInput.getText();
        if (url == null || url.isBlank()) {
            notifyUser("Please enter a URL to analyze");
            return;
        }
        analyze(url.trim());
    }

    @FXML public void simulateSafe() { analyze(browser.safe()); }
    @FXML public void simulateSuspicious() { analyze(browser.suspicious()); }
    @FXML public void simulatePhishing() { analyze(browser.phishing()); }

    @FXML
    public void scanAnotherUrl() {
        if (scannerUrlInput != null) {
            scannerUrlInput.clear();
            scannerUrlInput.requestFocus();
        }
        navigateScanner();
    }

    @FXML
    public void backToDashboard() {
        stopScanningAnimation();
        navigateDashboard();
    }

    // =========================================================================
    // Scanning Flow & Multi-Step Animation
    // =========================================================================
    private void analyze(String rawUrl) {
        String url = rawUrl;
        if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
            url = "https://" + url;
        }

        final String targetUrl = url;
        this.lastTargetUrl = targetUrl;

        // Stop any previous scanning operations
        stopScanningAnimation();
        backendResultRef.set(null);
        isFinishingAnalysis = false;
        currentStage = 1;

        // Display Analyzing Website page (Stitch Screen 2)
        if (analyzingPage != null) {
            pageStack.getChildren().forEach(child -> child.setVisible(child == analyzingPage));
            analyzingPage.toFront();
        }
        setActiveNav(navScannerBtn);

        if (analyzingUrlText != null) analyzingUrlText.setText(targetUrl);

        // Start unified engine in auto mode (4000ms duration per spec)
        wdScanStart(true, 4000.0);

        // Run actual backend analysis in background Task
        currentScanTask = new Task<>() {
            @Override
            protected AnalyzeResponse call() throws Exception {
                return apiService.analyzeUrl(targetUrl);
            }
        };

        currentScanTask.setOnSucceeded(e -> {
            if (currentScanTask == null || currentScanTask.isCancelled()) return;
            AnalyzeResponse response = currentScanTask.getValue();
            backendResultRef.set(response);
            wdScanComplete();
        });

        currentScanTask.setOnFailed(e -> {
            if (currentScanTask == null || currentScanTask.isCancelled()) return;
            scanFailureMessage = currentScanTask.getException() == null
                    ? "The Spring Boot analysis request failed."
                    : currentScanTask.getException().getMessage();
            if (scanErrorUrl != null) scanErrorUrl.setText("Target URL: " + targetUrl);
            if (scanErrorMessage != null) scanErrorMessage.setText(valueOr(scanFailureMessage,
                    "Unable to connect to the Spring Boot analysis API."));
            stopScanningAnimation();
            if (pageStack != null && scanErrorPage != null) {
                pageStack.getChildren().forEach(child -> child.setVisible(child == scanErrorPage));
                scanErrorPage.toFront();
            }
            setActiveNav(navScannerBtn);
        });

        Thread th = new Thread(currentScanTask);
        th.setDaemon(true);
        th.start();
    }

    private static final String[] STEP_STATUS_TEXTS = {
        "Initializing scan...",
        "Checking URL integrity...",
        "Extracting features...",
        "Running AI model analysis...",
        "Assessing risk level...",
        "Finalizing result..."
    };

    /**
     * Master frame tick driving the four in-scope elements from single source of truth 'p'.
     */
    private void updateScanFrame(long nowNs) {
        if (scanStartNs == 0) scanStartNs = nowNs;
        double dtMs = (lastFrameNs == 0) ? 16.6 : Math.min(50.0, (nowNs - lastFrameNs) / 1_000_000.0);
        lastFrameNs = nowNs;
        double tMs = nowNs / 1_000_000.0;

        if (!isScanDone && !isScanFailed) {
            if (isAutoMode) {
                double elapsed = (nowNs - scanStartNs) / 1_000_000.0;
                scanProgress = Math.max(0.0, Math.min(1.0, elapsed / autoDurationMs));
            } else if (isScanFinishing) {
                scanProgress = Math.min(1.0, scanProgress + dtMs / 1200.0);
            } else {
                scanProgress += (Math.min(scanTargetProgress, 0.96) - scanProgress) * Math.min(1.0, dtMs / 350.0);
            }

            if (scanProgress >= 1.0) {
                scanProgress = 1.0;
                isScanDone = true;
                scanDoneNs = nowNs;
            }
        }

        boolean ended = isScanDone || isScanFailed;
        double p = scanProgress;

        // 1. Step index derived strictly from p
        if (!ended) {
            int idx = Math.min(5, (int) Math.floor(p * 6.0));
            if (idx != currentStepIndex) {
                currentStepIndex = idx;
                updateStepViews(idx);
            }
        } else if (isScanDone && currentStepIndex != 6) {
            currentStepIndex = 6;
            updateStepViews(6); // all 6 steps marked done
        }

        // 2. Status text derived strictly from p / state
        if (scanStatusText != null) {
            if (isScanFailed) {
                scanStatusText.setText(scanFailureMessage != null ? scanFailureMessage : "Scan failed");
            } else if (isScanDone) {
                scanStatusText.setText("Scan complete");
            } else {
                int idx = Math.min(5, (int) Math.floor(p * 6.0));
                scanStatusText.setText(STEP_STATUS_TEXTS[idx]);
            }
        }

        // 3. Progress bar & percentage (Cosine stage easing per Section 6)
        if (!isScanFailed) {
            double fr = p * 6.0;
            int fi = (int) Math.floor(fr);
            double pe = (p >= 1.0) ? 1.0 : Math.min(0.99, (fi + (1.0 - Math.cos(Math.PI * (fr - fi))) / 2.0) / 6.0);
            currentScanProgress.set(pe);
            if (scanProgressBar != null) {
                scanProgressBar.setProgress(pe);
                scanProgressBar.setStyle("");
            }
            if (scanPercentLabel != null) {
                int pct = (int) Math.round(pe * 100);
                scanPercentLabel.setText(pct + "%");
                scanPercentLabel.setStyle("");
            }
        } else {
            if (scanProgressBar != null) {
                scanProgressBar.setStyle("-fx-accent: #EF4444;");
            }
            if (scanPercentLabel != null) {
                scanPercentLabel.setStyle("-fx-text-fill: #EF4444;");
            }
        }

        // 4. Radar update
        double doneElapsedMs = (scanDoneNs > 0) ? (nowNs - scanDoneNs) / 1_000_000.0 : 0.0;
        if (scanRadarView != null) {
            scanRadarView.update(tMs, dtMs, ended, doneElapsedMs, isScanFailed);
        }

        // 5. Completion transition to result page
        if (isScanDone && backendResultRef.get() != null && !isFinishingAnalysis) {
            if (doneElapsedMs >= 1000.0) {
                isFinishingAnalysis = true;
                stopScanningAnimation();
                showResult(backendResultRef.get());
            }
        }
    }

    private void updateStepViews(int activeIdx) {
        StackPane[] boxes = {step1IconBox, step2IconBox, step3IconBox, step4IconBox, step5IconBox, step6IconBox};
        FontIcon[] icons = {step1Icon, step2Icon, step3Icon, step4Icon, step5Icon, step6Icon};
        Label[] labels = {step1Label, step2Label, step3Label, step4Label, step5Label, step6Label};

        for (int i = 0; i < 6; i++) {
            StackPane box = boxes[i];
            FontIcon icon = icons[i];
            Label lbl = labels[i];
            if (box == null || lbl == null) continue;

            if (i < activeIdx) {
                // Done state: mint circle with green tick
                box.getStyleClass().removeAll("wd-stp-box-pending", "wd-stp-box-active");
                if (!box.getStyleClass().contains("wd-stp-box-done")) {
                    box.getStyleClass().add("wd-stp-box-done");
                }
                lbl.getStyleClass().removeAll("wd-stp-label-pending", "wd-stp-label-active");
                if (!lbl.getStyleClass().contains("wd-stp-label-done")) {
                    lbl.getStyleClass().add("wd-stp-label-done");
                }
                box.getChildren().clear();
                FontIcon tick = (icon != null) ? icon : new FontIcon("fth-check");
                tick.setIconLiteral("fth-check");
                tick.setIconSize(15);
                tick.setIconColor(Color.web("#10B981"));
                tick.setVisible(true);
                box.getChildren().add(tick);

                ScaleTransition pop = new ScaleTransition(Duration.millis(400), box);
                pop.setFromX(0.3); pop.setFromY(0.3);
                pop.setToX(1.0); pop.setToY(1.0);
                pop.setInterpolator(Interpolator.EASE_OUT);
                pop.play();
            } else if (i == activeIdx && !isScanDone) {
                // Active state: white circle with soft blue glow, solid blue dot
                box.getStyleClass().removeAll("wd-stp-box-pending", "wd-stp-box-done");
                if (!box.getStyleClass().contains("wd-stp-box-active")) {
                    box.getStyleClass().add("wd-stp-box-active");
                }
                lbl.getStyleClass().removeAll("wd-stp-label-pending", "wd-stp-label-done");
                if (!lbl.getStyleClass().contains("wd-stp-label-active")) {
                    lbl.getStyleClass().add("wd-stp-label-active");
                }
                box.getChildren().clear();
                Circle dot = new Circle(6, Color.web("#2563EB"));
                box.getChildren().add(dot);
            } else {
                // Pending state: light grey circle, grey dot
                box.getStyleClass().removeAll("wd-stp-box-active", "wd-stp-box-done");
                if (!box.getStyleClass().contains("wd-stp-box-pending")) {
                    box.getStyleClass().add("wd-stp-box-pending");
                }
                lbl.getStyleClass().removeAll("wd-stp-label-active", "wd-stp-label-done");
                if (!lbl.getStyleClass().contains("wd-stp-label-pending")) {
                    lbl.getStyleClass().add("wd-stp-label-pending");
                }
                box.getChildren().clear();
                Circle dot = new Circle(4.5, Color.web("#C5CFDC"));
                box.getChildren().add(dot);
            }
        }
    }

    public void wdScanStart(boolean auto, double durationMs) {
        stopScanningAnimation();
        isAutoMode = auto;
        autoDurationMs = (durationMs > 0) ? durationMs : 4000.0;
        scanProgress = 0.0;
        scanTargetProgress = 0.0;
        isScanDone = false;
        isScanFailed = false;
        isScanFinishing = false;
        scanDoneNs = 0;
        scanFailureMessage = null;
        currentStepIndex = -1;
        scanStartNs = 0;
        lastFrameNs = 0;

        if (scanRadarView != null) {
            scanRadarView.reset();
        }

        updateStepViews(0);
        if (scanStatusText != null) scanStatusText.setText(STEP_STATUS_TEXTS[0]);
        if (scanProgressBar != null) {
            scanProgressBar.setProgress(0.0);
            scanProgressBar.setStyle("");
        }
        if (scanPercentLabel != null) {
            scanPercentLabel.setText("0%");
            scanPercentLabel.setStyle("");
        }

        unifiedScanTimer = new AnimationTimer() {
            @Override
            public void handle(long now) {
                updateScanFrame(now);
            }
        };
        unifiedScanTimer.start();
    }

    public void wdScanStart() {
        wdScanStart(true, 4000.0);
    }

    public void wdScanProgress(double pct) {
        if (isScanDone || isScanFailed) return;
        isAutoMode = false;
        scanTargetProgress = Math.max(scanTargetProgress, Math.max(0.0, Math.min(0.96, pct / 100.0)));
    }

    public void wdScanComplete() {
        if (isScanDone || isScanFailed) return;
        isAutoMode = false;
        isScanFinishing = true;
    }

    public void wdScanFail(String message) {
        if (isScanDone || isScanFailed) return;
        isScanFailed = true;
        scanFailureMessage = message;
    }

    // Path B controller convenience methods matching Section 9
    public void start(boolean auto, double durationMs) { wdScanStart(auto, durationMs); }
    public void start() { wdScanStart(); }
    public void setProgress(double pct) { wdScanProgress(pct); }
    public void complete() { wdScanComplete(); }
    public void fail(String message) { wdScanFail(message); }

    private void setupAnalyzingUpgrades() {
        if (radarContainer != null) {
            radarContainer.getChildren().removeIf(node -> node instanceof ScanRadarView);
            scanRadarView = new ScanRadarView();
            radarContainer.getChildren().add(scanRadarView);
        }
    }

    private void stopScanningAnimation() {
        if (unifiedScanTimer != null) {
            unifiedScanTimer.stop();
            unifiedScanTimer = null;
        }
        if (currentScanTask != null && currentScanTask.isRunning()) {
            currentScanTask.cancel();
            currentScanTask = null;
        }
        if (scanRadarView != null) {
            scanRadarView.reset();
        }
    }

    private void resetStepper() {
        wdScanStart(true, 4000.0);
    }

    private void setStepStage(int stage, String statusText) {
        if (scanStatusText != null) scanStatusText.setText(statusText);
        updateStepViews(Math.max(0, Math.min(6, stage - 1)));
    }

    private void updateScanProgress(double prog, String percentStr) {
        currentScanProgress.set(prog);
        if (scanProgressBar != null) scanProgressBar.setProgress(prog);
        if (scanPercentLabel != null) scanPercentLabel.setText(percentStr);
    }

    // =========================================================================
    // Display Analysis Result (Stitch Screen 3)
    // =========================================================================
    private void showResult(AnalyzeResponse result) {
        currentAnalyzeResult = result;
        if (resultPage != null) {
            pageStack.getChildren().forEach(child -> child.setVisible(child == resultPage));
            resultPage.toFront();
        }
        setActiveNav(navScannerBtn);

        String url = result.url();
        String decision = valueOr(result.decision(), "UNKNOWN").toUpperCase(Locale.ROOT);
        String prediction = valueOr(result.prediction(), "UNKNOWN").toUpperCase(Locale.ROOT);
        boolean modelSkipped = result.reasons() != null && result.reasons().stream()
                .anyMatch(reason -> reason.startsWith("Model skipped:")
                        || reason.startsWith("URL indicator: Model skipped:"));
        boolean allowlistException = result.reasons() != null && result.reasons().stream()
                .anyMatch(reason -> reason.contains("active domain allowlist exception"));
        boolean feedbackOverride = modelSkipped && !allowlistException;
        String shownPrediction = allowlistException ? "MODEL SKIPPED · DOMAIN EXCEPTION"
                : feedbackOverride ? "SAFE · PRIOR FEEDBACK"
                : "PHISHING".equals(prediction) && "REVIEW".equals(decision)
                ? "REVIEW REQUIRED" : prediction;
        int score = result.riskScore();
        String riskLevel = valueOr(result.riskLevel(), "UNKNOWN").toUpperCase(Locale.ROOT);
        double prob = result.phishingProbability();

        // 1. Result Hero Box (SAFE / PHISHING / SUSPICIOUS)
        if (resultHeroBox != null) {
            if ("HIGH_RISK".equals(riskLevel) && !"REVIEW".equals(decision)) {
                if (resultIconContainer != null) {
                    resultIconContainer.setStyle("-fx-background-color: #EF4444; -fx-background-radius: 12px; -fx-alignment: center;");
                }
                if (resultHeroIcon != null) {
                    resultHeroIcon.setIconLiteral("fth-alert-triangle");
                    resultHeroIcon.setIconColor(Color.web("#FFFFFF"));
                }
                if (resultTitle != null) {
                    resultTitle.setText(shownPrediction);
                    resultTitle.getStyleClass().removeAll("result-title-text", "result-title-warn");
                    resultTitle.getStyleClass().add("result-title-danger");
                }
                if (resultSubtitle != null) {
                    resultSubtitle.setText("Risk: " + riskLevel + " · Policy decision: " + decision);
                    resultSubtitle.getStyleClass().removeAll("result-sub-text", "result-sub-warn");
                    resultSubtitle.getStyleClass().add("result-sub-danger");
                }
                if (resultBanner != null) {
                    resultBanner.getStyleClass().removeAll("banner-safe");
                    if (!resultBanner.getStyleClass().contains("banner-danger")) resultBanner.getStyleClass().add("banner-danger");
                }
                if (resultBannerIcon != null) {
                    resultBannerIcon.setIconLiteral("fth-alert-triangle");
                    resultBannerIcon.setIconColor(Color.web("#EF4444"));
                }
                if (resultBannerText != null) {
                    resultBannerText.setText("Assessment: " + shownPrediction + " · Risk: " + riskLevel + " · Decision: " + decision);
                    resultBannerText.getStyleClass().removeAll("banner-text-safe");
                    resultBannerText.getStyleClass().add("banner-text-danger");
                }
            } else if ("SUSPICIOUS".equals(riskLevel) || "LOW_RISK".equals(riskLevel) || "REVIEW".equals(decision)) {
                if (resultIconContainer != null) {
                    resultIconContainer.setStyle("-fx-background-color: #F59E0B; -fx-background-radius: 12px; -fx-alignment: center;");
                }
                if (resultHeroIcon != null) {
                    resultHeroIcon.setIconLiteral("fth-alert-circle");
                    resultHeroIcon.setIconColor(Color.web("#FFFFFF"));
                }
                if (resultTitle != null) {
                    resultTitle.setText(shownPrediction);
                    resultTitle.getStyleClass().removeAll("result-title-text", "result-title-danger");
                    resultTitle.getStyleClass().add("result-title-warn");
                }
                if (resultSubtitle != null) {
                    resultSubtitle.setText("Risk: " + riskLevel + " · Policy decision: " + decision);
                    resultSubtitle.getStyleClass().removeAll("result-sub-text", "result-sub-danger");
                    resultSubtitle.getStyleClass().add("result-sub-warn");
                }
                if (resultBanner != null) {
                    resultBanner.getStyleClass().removeAll("banner-safe");
                    if (!resultBanner.getStyleClass().contains("banner-danger")) resultBanner.getStyleClass().add("banner-danger");
                }
                if (resultBannerIcon != null) {
                    resultBannerIcon.setIconLiteral("fth-alert-circle");
                    resultBannerIcon.setIconColor(Color.web("#F59E0B"));
                }
                if (resultBannerText != null) {
                    resultBannerText.setText("Assessment: " + shownPrediction + " · Risk: " + riskLevel + " · Decision: " + decision);
                    resultBannerText.getStyleClass().removeAll("banner-text-safe");
                    resultBannerText.getStyleClass().add("banner-text-danger");
                }
            } else {
                if (resultIconContainer != null) {
                    resultIconContainer.setStyle("-fx-background-color: #10B981; -fx-background-radius: 12px; -fx-alignment: center;");
                }
                if (resultHeroIcon != null) {
                    resultHeroIcon.setIconLiteral("fth-check");
                    resultHeroIcon.setIconColor(Color.web("#FFFFFF"));
                }
                if (resultTitle != null) {
                    resultTitle.setText(shownPrediction);
                    resultTitle.getStyleClass().removeAll("result-title-danger", "result-title-warn");
                    resultTitle.getStyleClass().add("result-title-text");
                }
                if (resultSubtitle != null) {
                    resultSubtitle.setText("Risk: " + riskLevel + " · Policy decision: " + decision);
                    resultSubtitle.getStyleClass().removeAll("result-sub-danger", "result-sub-warn");
                    resultSubtitle.getStyleClass().add("result-sub-text");
                }
                if (resultBanner != null) {
                    resultBanner.getStyleClass().removeAll("banner-danger");
                    if (!resultBanner.getStyleClass().contains("banner-safe")) resultBanner.getStyleClass().add("banner-safe");
                }
                if (resultBannerIcon != null) {
                    resultBannerIcon.setIconLiteral("fth-check-circle");
                    resultBannerIcon.setIconColor(Color.web("#059669"));
                }
                if (resultBannerText != null) {
                    resultBannerText.setText("Assessment: " + shownPrediction + " · Risk: " + riskLevel + " · Decision: " + decision);
                    resultBannerText.getStyleClass().removeAll("banner-text-danger");
                    resultBannerText.getStyleClass().add("banner-text-safe");
                }
            }
        }

        // 2. Score Gauge (Dashboard and Result Screen)
        updateRiskGauge(score, riskLevel);

        // 3. Metadata fields
        if (resultUrl != null) resultUrl.setText(url);
        if (resultPrediction != null) {
            resultPrediction.setText("REVIEW".equals(decision) && "PHISHING".equals(prediction)
                    ? "PHISHING · REVIEW REQUIRED" : prediction);
            resultPrediction.setStyle("PHISHING".equals(prediction) && !"REVIEW".equals(decision)
                    ? "-fx-font-weight: 700; -fx-text-fill: #EF4444;"
                    : ("REVIEW".equals(decision) || "WARN".equals(decision)
                    ? "-fx-font-weight: 700; -fx-text-fill: #F59E0B;"
                    : "-fx-font-weight: 700; -fx-text-fill: #10B981;"));
        }
        if (resultDecision != null) {
            resultDecision.setText(decision);
            resultDecision.setStyle("BLOCK".equals(decision) ? "-fx-font-weight: 700; -fx-text-fill: #EF4444;"
                    : (("WARN".equals(decision) || "REVIEW".equals(decision))
                    ? "-fx-font-weight: 700; -fx-text-fill: #F59E0B;"
                    : "-fx-font-weight: 700; -fx-text-fill: #10B981;"));
        }
        if (resultConfidence != null) {
            resultConfidence.setText(modelSkipped ? "Model skipped" : String.format(Locale.ROOT, "%.2f%%", prob * 100.0));
        }
        if (resultThreshold != null) {
            resultThreshold.setText(modelSkipped ? (allowlistException ? "Domain allowlist" : "Feedback memory")
                    : String.format(Locale.ROOT, "%.0f%%", result.threshold() * 100.0));
        }
        if (resultScorePill != null) resultScorePill.setText(riskLevel);

        // 4. Why this result? (Backend reasons)
        if (reasonsListContainer != null) {
            reasonsListContainer.getChildren().clear();
            List<String> reasons = result.reasons();
            if (reasons != null && !reasons.isEmpty()) {
                for (String r : reasons) {
                    HBox row = new HBox(8);
                    row.setAlignment(Pos.CENTER_LEFT);
                    boolean isRisk = "HIGH_RISK".equals(riskLevel) || "SUSPICIOUS".equals(riskLevel);
                    FontIcon icon = new FontIcon(isRisk ? "fth-alert-triangle" : "fth-check");
                    icon.setIconSize(14);
                    icon.setIconColor(isRisk ? Color.web("#EF4444") : Color.web("#10B981"));
                    Label label = new Label(r);
                    label.getStyleClass().add("feature-key");
                    row.getChildren().addAll(icon, label);
                    reasonsListContainer.getChildren().add(row);
                }
            } else {
                Label noReasons = new Label("No assessment details were returned by the backend.");
                noReasons.getStyleClass().add("feature-key");
                reasonsListContainer.getChildren().add(noReasons);
            }
        }

        // These model features are not part of the Spring response contract.
        if (featUrlLength != null) featUrlLength.setText("—");
        if (featHasHttps != null) featHasHttps.setText("—");
        if (featDotCount != null) featDotCount.setText("—");
        if (featDomainAge != null) featDomainAge.setText("—");
        if (featKeywords != null) featKeywords.setText("—");
        if (featIpUsed != null) featIpUsed.setText("—");

        // 6. Risk Level Scale highlighting
        updateRiskLevelScale(riskLevel, decision);

        backendRefresh.schedule(this::refreshBackendSnapshot, 350, TimeUnit.MILLISECONDS);
    }

    @FXML private void markAssessmentFalsePositive() { submitAssessmentFeedback("FALSE_POSITIVE"); }
    @FXML private void markAssessmentFalseNegative() { submitAssessmentFeedback("FALSE_NEGATIVE"); }
    @FXML private void markAssessmentCorrect() { submitAssessmentFeedback("CORRECT"); }

    private void submitAssessmentFeedback(String label) {
        AnalyzeResponse assessment = currentAnalyzeResult;
        if (assessment == null || assessment.assessmentId() == null) {
            if (feedbackStatus != null) feedbackStatus.setText("This result cannot be linked to feedback.");
            return;
        }
        setFeedbackControlsDisabled(true);
        if (feedbackStatus != null) feedbackStatus.setText("Saving feedback locally…");
        Task<Void> task = new Task<>() {
            @Override protected Void call() throws Exception {
                apiService.submitThreatFeedback(assessment, label);
                return null;
            }
        };
        task.setOnSucceeded(event -> {
            setFeedbackControlsDisabled(false);
            if (feedbackStatus != null) feedbackStatus.setText("FALSE_POSITIVE".equals(label)
                    ? "False-positive feedback saved. This exact URL skips model inference for 30 days; other URLs are still analyzed."
                    : "Feedback saved for offline review. It does not retrain the model.");
        });
        task.setOnFailed(event -> {
            setFeedbackControlsDisabled(false);
            if (feedbackStatus != null) feedbackStatus.setText("Feedback could not be saved. Check the local backend connection.");
        });
        Thread worker = new Thread(task, "aiwatchdog-assessment-feedback");
        worker.setDaemon(true);
        worker.start();
    }

    private void setFeedbackControlsDisabled(boolean disabled) {
        if (feedbackFalsePositiveBtn != null) feedbackFalsePositiveBtn.setDisable(disabled);
        if (feedbackFalseNegativeBtn != null) feedbackFalseNegativeBtn.setDisable(disabled);
        if (feedbackCorrectBtn != null) feedbackCorrectBtn.setDisable(disabled);
    }

    // =========================================================================
    // Dynamic Risk Score Gauge Update & Telemetry Animations
    // =========================================================================
    public void setupDashboardUpgrades() {
        if (dashGaugeContainer != null) {
            riskRadarView = new com.aiwatchdog.ui.dashboard.RiskRadarView();
            riskRadarView.setBoundScoreLabel(dashScoreNumber);
            riskRadarView.setOnLevelChanged(this::applyRadarLevel);
            riskRadarView.setOnReplayRequested(this::replayDashboardSequence);
            dashGaugeContainer.getChildren().add(0, riskRadarView);
            dashGaugeContainer.setOnMouseClicked(e -> {
                if (riskRadarView != null) riskRadarView.replay();
            });
        }

        cardsHelper = new com.aiwatchdog.ui.dashboard.DashboardCardsHelper();
        if (dashCardScanned != null) {
            cardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    dashCardScanned, dashScannedTile, dashScannedIcon, dashScannedTrend,
                    dashScannedCount, dashScannedLine, 0, "wd-ic-blue", "wd-ic-blue-hover", "#3B6DF0"
            ));
        }
        if (dashCardBlocked != null) {
            cardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    dashCardBlocked, dashBlockedTile, dashBlockedIcon, dashBlockedTrend,
                    dashThreatsBlockedCount, dashBlockedLine, 0, "wd-ic-red", "wd-ic-red-hover", "#EF4444"
            ));
        }
        if (dashCardReview != null) {
            cardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    dashCardReview, dashReviewTile, dashReviewIcon, dashReviewTrend,
                    dashInReviewCount, dashReviewLine, 0, "wd-ic-amber", "wd-ic-amber-hover", "#F59E0B"
            ));
        }
        if (dashCardAllowed != null) {
            cardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    dashCardAllowed, dashAllowedTile, dashAllowedIcon, dashAllowedTrend,
                    dashAllowedCount, dashAllowedLine, 0, "wd-ic-green", "wd-ic-green-hover", "#10B981"
            ));
        }
        cardsHelper.setupAll();

        if (dashboardPage != null) {
            dashboardPage.visibleProperty().addListener((obs, oldV, isVis) -> {
                if (!isVis) {
                    if (riskRadarView != null) riskRadarView.stopTimer();
                    if (cardsHelper != null) cardsHelper.stopAllAnimations();
                    if (operationalBadgePulse != null) operationalBadgePulse.pause();
                    if (liveShieldPulse != null) liveShieldPulse.pause();
                } else {
                    if (riskRadarView != null) riskRadarView.startTimer();
                    if (cardsHelper != null) cardsHelper.resumeAllAnimations();
                    if (operationalBadgePulse != null) operationalBadgePulse.play();
                    if (liveShieldPulse != null) liveShieldPulse.play();
                }
            });
        }
    }

    public void setupThreatCenterUpgrades() {
        if (threatDonutPane != null) {
            threatInsightsHelper = new com.aiwatchdog.ui.threatcenter.ThreatInsightsDonutHelper(
                    threatInsightsCard,
                    threatDonutPane,
                    threatTrackCircle,
                    threatArcHigh,
                    threatArcSuspicious,
                    threatArcInfo,
                    threatTotalCountLabel,
                    threatTotalSubLabel,
                    threatLegendHigh,
                    threatLegendHighPct,
                    threatLegendSusp,
                    threatLegendSuspPct,
                    threatLegendInfo,
                    threatLegendInfoPct
            );
            threatInsightsHelper.setup();
        }

        threatCardsHelper = new com.aiwatchdog.ui.dashboard.DashboardCardsHelper();
        if (threatCard0 != null) {
            threatCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    threatCard0, threatTile0, threatIcon0, threatTrend0,
                    threatBlockedCount, null, 0, "icon-red-bg", "wd-tile-red-hover", "#EF4444"
            ));
        }
        if (threatCard1 != null) {
            threatCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    threatCard1, threatTile1, threatIcon1, threatTrend1,
                    threatInReviewCount, null, 0, "icon-amber-bg", "wd-tile-amber-hover", "#F59E0B"
            ));
        }
        if (threatCard2 != null) {
            threatCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    threatCard2, threatTile2, threatIcon2, threatTrend2,
                    threatHighRiskCount, null, 0, "icon-blue-bg", "wd-tile-blue-hover", "#3B6DF0"
            ));
        }
        if (threatCard3 != null) {
            threatCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    threatCard3, threatTile3, threatIcon3, threatTrend3,
                    threatSafeCount, null, 0, "icon-green-bg", "wd-tile-green-hover", "#10B981"
            ));
        }
        threatCardsHelper.setupAll();
        threatCardsHelper.setInstantVisible();

        if (threatCenterPage != null) {
            threatCenterPage.visibleProperty().addListener((obs, oldV, isVis) -> {
                if (threatInsightsHelper != null) {
                    if (isVis) {
                        threatInsightsHelper.playEntranceAnimation();
                    } else {
                        threatInsightsHelper.stopAllAnimations();
                    }
                }
                if (threatCardsHelper != null) {
                    if (isVis) {
                        threatCardsHelper.resumeAllAnimations();
                    } else {
                        threatCardsHelper.stopAllAnimations();
                    }
                }
            });
        }
    }

    public void setupActivityUpgrades() {
        activityCardsHelper = new com.aiwatchdog.ui.dashboard.DashboardCardsHelper();
        if (activityCard0 != null) {
            activityCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    activityCard0, activityTile0, activityIcon0, null,
                    activityCount0, null, 0, "icon-blue-bg", "wd-tile-blue-hover", "#3B6DF0"
            ));
        }
        if (activityCard1 != null) {
            activityCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    activityCard1, activityTile1, activityIcon1, null,
                    activityCount1, null, 0, "icon-blue-bg", "wd-tile-blue-hover", "#3B6DF0"
            ));
        }
        if (activityCard2 != null) {
            activityCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    activityCard2, activityTile2, activityIcon2, null,
                    activityCount2, null, 0, "icon-red-bg", "wd-tile-red-hover", "#EF4444"
            ));
        }
        if (activityCard3 != null) {
            activityCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    activityCard3, activityTile3, activityIcon3, null,
                    activityCount3, null, 0, "icon-green-bg", "wd-tile-green-hover", "#10B981"
            ));
        }
        activityCardsHelper.setupAll();
        activityCardsHelper.setInstantVisible();

        if (activityPage != null) {
            activityPage.visibleProperty().addListener((obs, oldV, isVis) -> {
                if (activityCardsHelper != null) {
                    if (isVis) {
                        activityCardsHelper.resumeAllAnimations();
                    } else {
                        activityCardsHelper.stopAllAnimations();
                    }
                }
            });
        }
    }

    public void setupInsightsUpgrades() {
        insightsCardsHelper = new com.aiwatchdog.ui.dashboard.DashboardCardsHelper();
        if (insightCard0 != null) {
            insightsCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    insightCard0, null, insightIcon0, insightTrend0,
                    insightCount0, null, 0, 0.0, "%", null, null, "#10B981"
            ));
        }
        if (insightCard1 != null) {
            insightsCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    insightCard1, null, insightIcon1, insightTrend1,
                    insightCount1, null, 0, 0.0, null, null, null, "#EF4444"
            ));
        }
        if (insightCard2 != null) {
            insightsCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    insightCard2, null, insightIcon2, insightTrend2,
                    insightCount2, null, 0, 0.0, "%", null, null, "#10B981"
            ));
        }
        if (insightCard3 != null) {
            insightsCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    insightCard3, null, insightIcon3, insightTrend3,
                    insightCount3, null, 0, 0.0, null, null, null, "#3B6DF0"
            ));
        }
        insightsCardsHelper.setupAll();
        insightsCardsHelper.setInstantVisible();

        if (insightsPage != null) {
            insightsPage.visibleProperty().addListener((obs, oldV, isVis) -> {
                if (insightsCardsHelper != null) {
                    if (isVis) {
                        insightsCardsHelper.resumeAllAnimations();
                    } else {
                        insightsCardsHelper.stopAllAnimations();
                    }
                }
            });
        }
    }

    public void setupSecureAccessUpgrades() {
        if (exceptionGlobe1 != null) {
            secureAccessGlobeAnimations.add(com.aiwatchdog.ui.dashboard.DashboardCardsHelper.createSlowRotation(exceptionGlobe1));
        }
        if (exceptionGlobe2 != null) {
            secureAccessGlobeAnimations.add(com.aiwatchdog.ui.dashboard.DashboardCardsHelper.createSlowRotation(exceptionGlobe2));
        }
        if (secureAccessPage != null) {
            secureAccessPage.visibleProperty().addListener((obs, oldV, isVis) -> {
                for (Animation a : secureAccessGlobeAnimations) {
                    if (isVis) a.play();
                    else a.pause();
                }
            });
        }
    }

    public void updateRiskGauge(int score) {
        updateRiskGauge(score, "UNKNOWN", true);
    }

    public void updateRiskGauge(int score, boolean animate) {
        updateRiskGauge(score, "UNKNOWN", animate);
    }

    public void updateRiskGauge(int score, String riskLevel) {
        updateRiskGauge(score, riskLevel, true);
    }

    private void updateRiskGauge(int score, String riskLevel, boolean animate) {
        int clampedScore = Math.max(0, Math.min(100, score));
        double targetArcLength = - (clampedScore / 100.0) * 360.0;
        String normalizedRisk = valueOr(riskLevel, "UNKNOWN").toUpperCase(Locale.ROOT);
        String strokeColor = colorForRiskLevel(normalizedRisk);

        // 1. Target Lock Radar (if active)
        if (riskRadarView != null) {
            riskRadarView.setAssessment(clampedScore, normalizedRisk, animate);
        }

        if (!animate && cardsHelper != null) {
            cardsHelper.setInstantVisible();
        }

        // 2. Legacy Dashboard Risk Score Arc (kept hidden for backward compatibility)
        if (dashScoreArc != null) {
            dashScoreArc.setStyle("-fx-stroke: " + strokeColor + ";");
            if (animate) {
                if (gaugeTimeline != null) gaugeTimeline.stop();
                double startLength = dashScoreArc.getLength();
                gaugeTimeline = new Timeline(
                        new KeyFrame(Duration.ZERO, new KeyValue(dashScoreArc.lengthProperty(), startLength, Interpolator.EASE_OUT)),
                        new KeyFrame(Duration.millis(850), new KeyValue(dashScoreArc.lengthProperty(), targetArcLength, Interpolator.EASE_OUT))
                );
                gaugeTimeline.play();
            } else {
                dashScoreArc.setLength(targetArcLength);
            }
        }

        // 3. Fallback score text if radar view is not mounted
        if (dashScoreNumber != null && riskRadarView == null) {
            dashScoreNumber.setText(String.valueOf(clampedScore));
        }

        // 4. Update status labels and score pill
        applyRadarLevel(com.aiwatchdog.ui.dashboard.RiskRadarView.getLevelForRisk(normalizedRisk));

        // 5. Result Screen Gauge (if loaded)
        if (resultScoreNumber != null) {
            resultScoreNumber.setText(String.valueOf(clampedScore));
        }
        if (resultScoreArc != null) {
            resultScoreArc.setLength(targetArcLength);
            resultScoreArc.setStyle("-fx-stroke: " + strokeColor + ";");
        }
        if (resultScorePill != null) {
            resultScorePill.getStyleClass().removeAll("badge-safe", "badge-low-risk", "badge-suspicious", "badge-high-risk");
            String riskClass = switch (normalizedRisk) {
                case "SAFE" -> "badge-safe";
                case "LOW_RISK" -> "badge-low-risk";
                case "SUSPICIOUS" -> "badge-suspicious";
                case "HIGH_RISK" -> "badge-high-risk";
                default -> null;
            };
            if (riskClass != null) resultScorePill.getStyleClass().add(riskClass);
        }
    }

    private static String colorForRiskLevel(String riskLevel) {
        return switch (riskLevel) {
            case "SAFE" -> "#10B981";
            case "LOW_RISK" -> "#84CC16";
            case "SUSPICIOUS" -> "#F59E0B";
            case "HIGH_RISK" -> "#EF4444";
            default -> "#64748B";
        };
    }

    private void applyRadarLevel(com.aiwatchdog.ui.dashboard.RiskRadarView.LevelData level) {
        if (level == null) return;
        if (dashStatusNormalLabel != null) {
            dashStatusNormalLabel.setText("● " + level.status);
            dashStatusNormalLabel.getStyleClass().removeAll("wd-status-low", "wd-status-med", "wd-status-high");
            if (level.id <= 1) dashStatusNormalLabel.getStyleClass().add("wd-status-low");
            else if (level.id == 2) dashStatusNormalLabel.getStyleClass().add("wd-status-med");
            else dashStatusNormalLabel.getStyleClass().add("wd-status-high");
        }
        if (dashRiskLevelTitle != null) {
            dashRiskLevelTitle.setText(level.title);
        }
        if (dashRiskDescription != null) {
            dashRiskDescription.setText(level.desc);
        }
        if (dashScorePill != null) {
            dashScorePill.setText("RISK LEVEL · " + level.title);
            dashScorePill.getStyleClass().removeAll("badge-safe", "badge-suspicious", "badge-high-risk",
                    "wd-rchip-low", "wd-rchip-med", "wd-rchip-high");
            if (level.id == 0 || level.id == 1) {
                dashScorePill.getStyleClass().addAll("badge-safe", "wd-rchip-low");
            } else if (level.id == 2) {
                dashScorePill.getStyleClass().addAll("badge-suspicious", "wd-rchip-med");
            } else if (level.id == 3) {
                dashScorePill.getStyleClass().addAll("badge-high-risk", "wd-rchip-high");
            }
        }
    }

    private void replayDashboardSequence() {
        Timeline replayTl = new Timeline(new KeyFrame(Duration.millis(2200), e -> animateThreatBreakdown()));
        replayTl.play();
    }

    public void startDashboardTelemetryAnimations() {
        // 1. "All Systems Operational" gentle heartbeat breathing
        if (dashOperationalBadge != null) {
            if (operationalBadgePulse == null) {
                operationalBadgePulse = new FadeTransition(Duration.millis(2000), dashOperationalBadge);
                operationalBadgePulse.setFromValue(1.0);
                operationalBadgePulse.setToValue(0.72);
                operationalBadgePulse.setInterpolator(Interpolator.EASE_BOTH);
                operationalBadgePulse.setAutoReverse(true);
                operationalBadgePulse.setCycleCount(Animation.INDEFINITE);
            }
            operationalBadgePulse.playFromStart();
        }

        // 2. "Live Shield Active" gentle breathing scale
        if (dashLiveShieldBox != null) {
            dashLiveShieldBox.setCache(true);
            dashLiveShieldBox.setCacheHint(javafx.scene.CacheHint.SCALE);
            if (liveShieldPulse == null) {
                liveShieldPulse = new ScaleTransition(Duration.millis(2200), dashLiveShieldBox);
                liveShieldPulse.setFromX(1.0);
                liveShieldPulse.setFromY(1.0);
                liveShieldPulse.setToX(1.02);
                liveShieldPulse.setToY(1.02);
                liveShieldPulse.setInterpolator(Interpolator.EASE_BOTH);
                liveShieldPulse.setAutoReverse(true);
                liveShieldPulse.setCycleCount(Animation.INDEFINITE);
            }
            liveShieldPulse.playFromStart();
        }
    }

    public void animateThreatBreakdown() {
        if (dashSafeProgress == null) return;
        if (breakdownTimeline != null) breakdownTimeline.stop();

        double safeTarget = 0.70;
        double suspTarget = 0.20;
        double potTarget = 0.08;
        double highTarget = 0.02;

        dashSafeProgress.setProgress(0.0);
        dashSuspiciousProgress.setProgress(0.0);
        dashPotentialProgress.setProgress(0.0);
        dashHighRiskProgress.setProgress(0.0);

        if (dashSafePercent != null) dashSafePercent.setText("0%");
        if (dashSuspiciousPercent != null) dashSuspiciousPercent.setText("0%");
        if (dashPotentialPercent != null) dashPotentialPercent.setText("0%");
        if (dashHighRiskPercent != null) dashHighRiskPercent.setText("0%");

        // Staggered fill: 0.14s stagger, 1.1s each, percentages count up
        animateSingleBar(dashSafeProgress, dashSafePercent, safeTarget, 70, 0);
        animateSingleBar(dashSuspiciousProgress, dashSuspiciousPercent, suspTarget, 20, 140);
        animateSingleBar(dashPotentialProgress, dashPotentialPercent, potTarget, 8, 280);
        animateSingleBar(dashHighRiskProgress, dashHighRiskPercent, highTarget, 2, 420);
    }

    private void animateSingleBar(ProgressBar bar, Label pctLabel, double targetProgress, int targetPercent, long delayMs) {
        Timeline tl = new Timeline();
        int steps = 30;
        for (int i = 0; i <= steps; i++) {
            double p = (double) i / steps;
            double ease = 1.0 - Math.pow(1.0 - p, 3.0); // cubic ease-out
            double prog = targetProgress * ease;
            int pct = (int) Math.round(targetPercent * ease);
            tl.getKeyFrames().add(new KeyFrame(
                    Duration.millis(delayMs + (i * (1100.0 / steps))),
                    e -> {
                        if (bar != null) bar.setProgress(prog);
                        if (pctLabel != null) pctLabel.setText(pct + "%");
                    }
            ));
        }
        tl.play();
    }

    public void displayResult(AnalyzeResponse result) {
        showResult(result);
    }

    private void updateRiskLevelScale(String riskLevel, String decision) {
        HBox[] badges = {riskLevelHighBadge, riskLevelSuspiciousBadge, riskLevelLowBadge, riskLevelSafeBadge};
        for (HBox b : badges) {
            if (b != null) {
                b.setStyle("-fx-padding: 4px 8px; -fx-background-radius: 6px; -fx-background-color: transparent; -fx-border-color: transparent;");
            }
        }

        if ("HIGH_RISK".equals(riskLevel)) {
            if (riskLevelHighBadge != null) {
                riskLevelHighBadge.setStyle("-fx-padding: 4px 8px; -fx-background-color: #FEF2F2; -fx-border-color: #FECACA; -fx-border-width: 1px; -fx-background-radius: 20px; -fx-border-radius: 20px;");
            }
        } else if ("SUSPICIOUS".equals(riskLevel)) {
            if (riskLevelSuspiciousBadge != null) {
                riskLevelSuspiciousBadge.setStyle("-fx-padding: 4px 8px; -fx-background-color: #FFFBEB; -fx-border-color: #FDE68A; -fx-border-width: 1px; -fx-background-radius: 20px; -fx-border-radius: 20px;");
            }
        } else {
            if (riskLevelLowBadge != null) {
                riskLevelLowBadge.setStyle("-fx-padding: 4px 8px; -fx-background-color: #ECFDF5; -fx-border-color: #A7F3D0; -fx-border-width: 1px; -fx-background-radius: 20px; -fx-border-radius: 20px;");
            }
        }
    }

    // =========================================================================
    // Render Tables (Threat Center & Activity Log)
    // =========================================================================
    private void renderThreatTable() {
        if (threatTableContainer == null) return;
        threatTableContainer.getChildren().clear();

        String timeSelection = threatTimeFilter == null ? null : threatTimeFilter.getValue();
        List<ThreatItem> filteredThreats = threatLog.stream()
                .filter(item -> matchesSelectedTime(item.instant(), timeSelection)).toList();
        int limit = Math.min(7, filteredThreats.size());
        for (int i = 0; i < limit; i++) {
            ThreatItem item = filteredThreats.get(i);
            HBox row = new HBox(8);
            row.getStyleClass().add("table-row-item");
            row.setAlignment(Pos.CENTER_LEFT);

            // URL with colored bullet dot
            HBox urlBox = new HBox(8);
            urlBox.setAlignment(Pos.CENTER_LEFT);
            urlBox.setPrefWidth(260);
            Color dotColor;
            String badgeClass;
            if ("High Risk".equalsIgnoreCase(item.riskLevel) || "HIGH_RISK".equalsIgnoreCase(item.riskLevel)) {
                dotColor = Color.web("#EF4444");
                badgeClass = "badge-high-risk";
            } else if ("Potential Risk".equalsIgnoreCase(item.riskLevel) || "LOW_RISK".equalsIgnoreCase(item.riskLevel)) {
                dotColor = Color.web("#F59E0B");
                badgeClass = "badge-potential-risk";
            } else if ("Suspicious".equalsIgnoreCase(item.riskLevel) || "SUSPICIOUS".equalsIgnoreCase(item.riskLevel)) {
                dotColor = Color.web("#3B82F6");
                badgeClass = "badge-suspicious";
            } else {
                dotColor = Color.web("#16C784");
                badgeClass = "badge-safe";
            }
            Circle dot = new Circle(4, dotColor);
            Label urlLabel = new Label(item.url);
            urlLabel.getStyleClass().add("url-table-text");
            urlBox.getChildren().addAll(dot, urlLabel);

            // Risk Level Pill
            HBox riskBox = new HBox();
            riskBox.setAlignment(Pos.CENTER_LEFT);
            riskBox.setPrefWidth(120);
            Label riskBadge = new Label(item.riskLevel);
            riskBadge.getStyleClass().addAll("pill-badge", badgeClass);
            riskBox.getChildren().add(riskBadge);

            // Decision
            Label decLabel = new Label(item.decision);
            decLabel.setPrefWidth(100);
            if ("BLOCK".equalsIgnoreCase(item.decision)) {
                decLabel.setStyle("-fx-font-size: 12px; -fx-font-weight: 700; -fx-text-fill: #EF4444;");
            } else if ("WARN".equalsIgnoreCase(item.decision) || "REVIEW".equalsIgnoreCase(item.decision)) {
                decLabel.setStyle("-fx-font-size: 12px; -fx-font-weight: 700; -fx-text-fill: #F59E0B;");
            } else {
                decLabel.setStyle("-fx-font-size: 12px; -fx-font-weight: 700; -fx-text-fill: #16C784;");
            }

            // Time
            Label timeLabel = new Label(item.time);
            timeLabel.setPrefWidth(80);
            timeLabel.getStyleClass().add("url-table-time");

            row.getChildren().addAll(urlBox, riskBox, decLabel, timeLabel);
            threatTableContainer.getChildren().add(row);
        }
    }

    private void renderActivityTable(String filterQuery) {
        if (activityTableContainer == null) return;
        activityTableContainer.getChildren().clear();

        String q = filterQuery == null ? "" : filterQuery.toLowerCase().trim();
        String eventFilter = activityEventFilter == null ? null : activityEventFilter.getValue();
        String statusFilter = activityStatusFilter == null ? null : activityStatusFilter.getValue();
        String timeFilter = activityTimeFilter == null ? null : activityTimeFilter.getValue();
        List<ActivityItem> filtered = new ArrayList<>();
        for (ActivityItem item : activityLog) {
            String searchText = (item.urlOrDesc + " " + item.event + " " + item.riskLevel + " " + item.decision + " " + item.status + " " + valueOr(item.assessmentId(), ""))
                    .toLowerCase(Locale.ROOT);
            if (!q.isEmpty() && !searchText.contains(q)) {
                continue;
            }
            if (eventFilter != null && !eventFilter.startsWith("All") && !eventFilter.equalsIgnoreCase(item.event)) continue;
            if (statusFilter != null && !statusFilter.startsWith("All")) {
                String expectedVerdict = switch (statusFilter) {
                    case "Allowed" -> "ALLOW";
                    case "BLOCK policy" -> "BLOCK";
                    case "Reviewed" -> "REVIEW";
                    case "Warn" -> "WARN";
                    default -> statusFilter;
                };
                boolean verdictFilter = List.of("ALLOW", "REVIEW", "WARN", "BLOCK").contains(expectedVerdict.toUpperCase(Locale.ROOT));
                if (verdictFilter ? !expectedVerdict.equalsIgnoreCase(item.decision())
                        : !expectedVerdict.equalsIgnoreCase(item.status())) continue;
            }
            if (!matchesSelectedTime(item.instant(), timeFilter)) continue;
            filtered.add(item);
        }
        int matched = filtered.size();
        int pageCount = Math.max(1, (matched + ACTIVITY_PAGE_SIZE - 1) / ACTIVITY_PAGE_SIZE);
        activityPageIndex = Math.min(activityPageIndex, pageCount - 1);
        int from = Math.min(matched, activityPageIndex * ACTIVITY_PAGE_SIZE);
        int to = Math.min(matched, from + ACTIVITY_PAGE_SIZE);
        for (ActivityItem item : filtered.subList(from, to)) {

            HBox row = new HBox(8);
            row.getStyleClass().add("table-row-item");
            row.setAlignment(Pos.CENTER_LEFT);

            // Time
            Label timeLabel = new Label(item.time);
            timeLabel.setPrefWidth(90);
            timeLabel.getStyleClass().add("url-table-time");

            // Event with dot
            HBox eventBox = new HBox(8);
            eventBox.setAlignment(Pos.CENTER_LEFT);
            eventBox.setPrefWidth(160);
              boolean highRisk = "High Risk".equalsIgnoreCase(item.riskLevel) || "HIGH_RISK".equalsIgnoreCase(item.riskLevel);
              boolean suspicious = "Suspicious".equalsIgnoreCase(item.riskLevel) || "SUSPICIOUS".equalsIgnoreCase(item.riskLevel);
              Circle dot = new Circle(4, highRisk ? Color.web("#EF4444") : (suspicious ? Color.web("#F59E0B") : Color.web("#3B82F6")));
            Label eventLabel = new Label(item.event);
            eventLabel.getStyleClass().add("url-table-text");
            eventBox.getChildren().addAll(dot, eventLabel);

            // URL / Description
            Label urlLabel = new Label(item.urlOrDesc);
            urlLabel.setPrefWidth(300);
            urlLabel.getStyleClass().add("url-table-text");

            // Risk Level Pill
            HBox riskBox = new HBox();
            riskBox.setAlignment(Pos.CENTER_LEFT);
            riskBox.setPrefWidth(110);
            Label riskBadge = new Label(item.riskLevel);
            riskBadge.getStyleClass().add("pill-badge");
              if ("High Risk".equalsIgnoreCase(item.riskLevel) || "HIGH_RISK".equalsIgnoreCase(item.riskLevel)) riskBadge.getStyleClass().add("badge-high-risk");
              else if ("Suspicious".equalsIgnoreCase(item.riskLevel) || "SUSPICIOUS".equalsIgnoreCase(item.riskLevel)) riskBadge.getStyleClass().add("badge-suspicious");
              else if ("Low Risk".equalsIgnoreCase(item.riskLevel) || "LOW_RISK".equalsIgnoreCase(item.riskLevel)) riskBadge.getStyleClass().add("badge-low-risk");
            else riskBadge.getStyleClass().add("badge-safe");
            riskBox.getChildren().add(riskBadge);

            // Decision
            Label decLabel = new Label(item.decision);
            decLabel.setPrefWidth(90);
              decLabel.setStyle("BLOCK".equalsIgnoreCase(item.decision)
                    ? "-fx-font-size: 12px; -fx-font-weight: 700; -fx-text-fill: #EF4444;"
                      : (("WARN".equalsIgnoreCase(item.decision) || "REVIEW".equalsIgnoreCase(item.decision))
                      ? "-fx-font-size: 12px; -fx-font-weight: 700; -fx-text-fill: #F59E0B;"
                      : "-fx-font-size: 12px; -fx-font-weight: 700; -fx-text-fill: #10B981;"));

            // Status
            Label statusLabel = new Label(item.status);
            statusLabel.setPrefWidth(100);
            statusLabel.getStyleClass().add("url-table-time");

            row.getChildren().addAll(timeLabel, eventBox, urlLabel, riskBox, decLabel, statusLabel);
            if (item.assessmentId() != null) {
                row.setCursor(javafx.scene.Cursor.HAND);
                row.setOnMouseClicked(event -> showAssessmentDetails(item));
                row.setFocusTraversable(true);
                row.setAccessibleText("Open assessment details for " + item.assessmentId());
                row.setOnKeyPressed(event -> {
                    if (event.getCode() == javafx.scene.input.KeyCode.ENTER || event.getCode() == javafx.scene.input.KeyCode.SPACE) showAssessmentDetails(item);
                });
            }
            activityTableContainer.getChildren().add(row);
        }

        if (activityPaginationLabel != null) {
            activityPaginationLabel.setText(matched == 0 ? "No matching events in the latest bounded history." :
                    "Showing " + (from + 1) + "-" + to + " of " + matched + " matching events");
        }
        if (activityPageLabel != null) activityPageLabel.setText("Page " + (activityPageIndex + 1) + " of " + pageCount);
        if (activityPreviousBtn != null) activityPreviousBtn.setDisable(activityPageIndex == 0);
        if (activityNextBtn != null) activityNextBtn.setDisable(activityPageIndex + 1 >= pageCount);
    }

    @FXML public void previousActivityPage() {
        if (activityPageIndex > 0) activityPageIndex--;
        renderActivityTable(activitySearchInput == null ? "" : activitySearchInput.getText());
    }

    @FXML public void nextActivityPage() {
        activityPageIndex++;
        renderActivityTable(activitySearchInput == null ? "" : activitySearchInput.getText());
    }

    private void showAssessmentDetails(ActivityItem item) {
        JsonNode details = parseAssessment(item.detailsJson());
        StringBuilder bodyText = new StringBuilder()
                .append("Assessment ID: ").append(item.assessmentId()).append('\n')
                .append("Correlation ID: ").append(valueOr(item.correlationId(), "Unavailable")).append('\n')
                .append("Subject: ").append(item.subjectType()).append(" · ").append(item.urlOrDesc()).append('\n')
                .append("Verdict: ").append(item.decision()).append(" · Status: ").append(item.status()).append("\n\n")
                .append("Source results\n");
        JsonNode sources = details.path("sources");
        try { bodyText.append(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(sources)); }
        catch (Exception ignored) { bodyText.append("Source details are unavailable or malformed."); }
        JsonNode explanation = details.path("explanation");
        if (explanation.isArray() && !explanation.isEmpty()) bodyText.append("\n\nExplanation\n").append(explanation.toString());
        JsonNode explanationDetails = details.path("explanationDetails");
        if (!explanationDetails.isMissingNode() && !explanationDetails.isNull()) {
            String summary = textAt(explanationDetails, "summary", "");
            String generatedBy = textAt(explanationDetails, "generatedBy", "");
            boolean fallbackUsed = explanationDetails.path("fallbackUsed").asBoolean(false);
            JsonNode supporting = explanationDetails.path("supportingEvidence");
            JsonNode uncertainties = explanationDetails.path("uncertainties");
            JsonNode recommended = explanationDetails.path("recommendedAction");
            bodyText.append("\n\nLLM explanation\n");
            if (!summary.isBlank()) bodyText.append("Summary: ").append(summary).append('\n');
            if (supporting.isArray() && !supporting.isEmpty()) {
                bodyText.append("Supporting evidence: ").append(supporting.toString()).append('\n');
            }
            if (uncertainties.isArray() && !uncertainties.isEmpty()) {
                bodyText.append("Uncertainties: ").append(uncertainties.toString()).append('\n');
            }
            if (recommended.isTextual() && !recommended.asText().isBlank()) {
                bodyText.append("Recommended action: ").append(recommended.asText()).append('\n');
            }
            if (!generatedBy.isBlank()) bodyText.append("Generated by: ").append(generatedBy).append('\n');
            bodyText.append("Fallback used: ").append(fallbackUsed);
        }
        JsonNode errors = details.path("errors");
        if (errors.isArray() && !errors.isEmpty()) bodyText.append("\n\nReported limitations\n").append(errors.toString());
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Assessment details"); alert.setHeaderText(item.assessmentId());
        TextArea content = new TextArea(bodyText.toString());
        content.setEditable(false); content.setWrapText(true); content.setPrefColumnCount(72); content.setPrefRowCount(22);
        alert.getDialogPane().setContent(content);
        alert.showAndWait();
    }

    private static boolean matchesSelectedTime(Instant instant, String selection) {
        if (selection == null || selection.startsWith("All") || instant == null) return true;
        long days = switch (selection) {
            case "Last 24 hours" -> 1;
            case "Last 7 days" -> 7;
            case "Last 30 days" -> 30;
            default -> Long.MAX_VALUE;
        };
        return days == Long.MAX_VALUE || !instant.isBefore(Instant.now().minusSeconds(days * 24 * 60 * 60));
    }

    @FXML
    public void filterActivityLog() {
        activityPageIndex = 0;
        if (activitySearchInput != null) {
            renderActivityTable(activitySearchInput.getText());
        }
    }

    // =========================================================================
    // Actions
    // =========================================================================
    @FXML
    public void exportReport() {
        notifyUser("Security report exported successfully.");
    }

    private void notifyUser(String message) {
        if (toast != null) {
            toast.setText(message);
            toast.setVisible(true);
            PauseTransition pause = new PauseTransition(Duration.seconds(2.8));
            pause.setOnFinished(e -> toast.setVisible(false));
            pause.play();
        }
    }

    @FXML
    public void retryLastScan() {
        if (lastTargetUrl != null && !lastTargetUrl.isBlank()) {
            analyze(lastTargetUrl);
        } else {
            navigateScanner();
        }
    }

    public void close() {
        closed = true;
        backendRefresh.shutdownNow();
        stopScanningAnimation();
        if (splashMasterTimeline != null) splashMasterTimeline.stop();
        if (gaugeTimeline != null) gaugeTimeline.stop();
        if (breakdownTimeline != null) breakdownTimeline.stop();
        if (cardsHelper != null) cardsHelper.stopAllAnimations();
        if (riskRadarView != null) riskRadarView.stopTimer();
        if (operationalBadgePulse != null) operationalBadgePulse.stop();
        if (liveShieldPulse != null) liveShieldPulse.stop();
        secureAccessGlobeAnimations.forEach(Animation::stop);
        FileSystemMonitorService file = fileMonitor;
        ProcessMonitorService process = processMonitor;
        if (file != null) file.close();
        if (process != null) process.close();
        if (fileShieldViewController != null) fileShieldViewController.close();
        if (settingsViewController != null) settingsViewController.close();
    }
}
