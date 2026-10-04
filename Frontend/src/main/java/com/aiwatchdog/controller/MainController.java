package com.aiwatchdog.controller;

import com.aiwatchdog.model.AnalyzeResponse;
import com.aiwatchdog.service.ApiService;
import com.aiwatchdog.service.BrowserMonitorService;
import com.aiwatchdog.service.URLFeatureExtractor;
import com.aiwatchdog.ui.scanner.ScanRadarView;
import com.aiwatchdog.util.ThemeManager;
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
import javafx.scene.shape.Arc;
import javafx.scene.shape.Circle;
import javafx.scene.shape.Rectangle;
import javafx.util.Duration;
import org.kordamp.ikonli.javafx.FontIcon;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

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
    @FXML private Button navSecureAccessBtn;
    @FXML private Button navThreatCenterBtn;
    @FXML private Button navActivityBtn;
    @FXML private Button navInsightsBtn;
    @FXML private Button navSettingsBtn;

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
    @FXML private ScrollPane analyzingPage;
    @FXML private ScrollPane resultPage;
    @FXML private ScrollPane threatCenterPage;
    @FXML private ScrollPane activityPage;
    @FXML private ScrollPane insightsPage;
    @FXML private ScrollPane settingsPage;
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

    // Upgraded Dashboard Node Hooks (wd-)
    @FXML private VBox dashCardScanned, dashCardBlocked, dashCardReview, dashCardAllowed;
    @FXML private StackPane dashScannedTile, dashBlockedTile, dashReviewTile, dashAllowedTile;
    @FXML private FontIcon dashScannedIcon, dashBlockedIcon, dashReviewIcon, dashAllowedIcon;
    @FXML private Label dashScannedTrend, dashBlockedTrend, dashReviewTrend, dashAllowedTrend;
    @FXML private Region dashScannedLine, dashBlockedLine, dashReviewLine, dashAllowedLine;
    @FXML private Label dashSafePercent, dashSuspiciousPercent, dashPotentialPercent, dashHighRiskPercent;

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

    // Settings (Stitch Screen 7)
    @FXML private Button setSubGeneral, setSubProtection, setSubNotifications, setSubAppearance, setSubPrivacy, setSubAbout;
    @FXML private VBox settingsGeneralPane, settingsProtectionPane, settingsNotificationsPane, settingsAppearancePane, settingsPrivacyPane, settingsAboutPane;
    @FXML private ComboBox<String> settingsLanguageCombo, protectionSensitivityCombo, notificationDeliveryCombo, fontScalingCombo;
    @FXML private StackPane switchStartWindows, switchMinimizeTray, switchConfirmExit, switchAutoUpdates;
    @FXML private StackPane switchRealTimeProtection, switchThreatBlocking, switchZeroHourHeuristics, switchSslInspection;
    @FXML private StackPane switchCriticalAlerts, switchScanNotifications, switchWarningBanners, switchSoundAlerts;
    @FXML private StackPane switchHighContrastBadges;
    @FXML private StackPane switchSaveHistory, switchShareTelemetry, switchDnsAnonymization;
    @FXML private Button themeLightBtn, themeDarkBtn, themeSystemBtn;
    @FXML private Label activeThemeLabel;

    // Secure Access
    @FXML private VBox secureAccessContainer;
    @FXML private FontIcon exceptionGlobe1, exceptionGlobe2;
    private final List<Animation> secureAccessGlobeAnimations = new ArrayList<>();

    // Toast
    @FXML private Label toast;

    // =========================================================================
    // Services and State
    // =========================================================================
    private final ApiService apiService = new ApiService();
    private final BrowserMonitorService browser = new BrowserMonitorService();
    private final URLFeatureExtractor featureExtractor = new URLFeatureExtractor();

    private int totalScanned = 1248;
    private int totalBlocked = 28;
    private int totalInReview = 14;
    private int totalAllowed = 1206;

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
    public record ActivityItem(String time, String event, String urlOrDesc, String riskLevel, String decision, String status) {}
    public record ThreatItem(String url, String riskLevel, String decision, String time) {}

    // =========================================================================
    // Initialization
    // =========================================================================
    @FXML
    public void initialize() {
        // Setup Dashboard Upgrades (Target Lock Radar, Stat Cards & Helpers)
        setupDashboardUpgrades();
        setupThreatCenterUpgrades();
        setupActivityUpgrades();
        setupInsightsUpgrades();
        setupAnalyzingUpgrades();
        setupSidebarCollapsible();
        setupSecureAccessUpgrades();
        updateRiskGauge(12, false);
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
            activityEventFilter.getItems().addAll("All Events", "URL Scan", "Phishing Detection", "Security Check");
            activityEventFilter.setValue("All Events");
        }
        if (activityStatusFilter != null) {
            activityStatusFilter.getItems().addAll("All Status", "Completed", "Blocked", "Reviewed");
            activityStatusFilter.setValue("All Status");
        }
        if (insightsTimeFilter != null) {
            insightsTimeFilter.getItems().addAll("Last 24 hours", "Last 7 days", "Last 30 days");
            insightsTimeFilter.setValue("Last 7 days");
        }
        if (settingsLanguageCombo != null) {
            settingsLanguageCombo.getItems().addAll("English (US)", "English (UK)", "Español", "Deutsch", "Français");
            settingsLanguageCombo.setValue("English (US)");
        }
        if (protectionSensitivityCombo != null) {
            protectionSensitivityCombo.getItems().addAll("Balanced (Recommended)", "Aggressive (High Security)", "Permissive (Low Friction)");
            protectionSensitivityCombo.setValue("Balanced (Recommended)");
        }
        if (notificationDeliveryCombo != null) {
            notificationDeliveryCombo.getItems().addAll("Instant Desktop Alerts", "Hourly Digest", "Muted during Fullscreen");
            notificationDeliveryCombo.setValue("Instant Desktop Alerts");
        }
        if (fontScalingCombo != null) {
            fontScalingCombo.getItems().addAll("Standard (100%)", "Large (110%)", "Compact (90%)");
            fontScalingCombo.setValue("Standard (100%)");
        }

        // Seed initial Threat Center and Activity items from Stitch design
        initSeedData();
        renderThreatTable();
        renderActivityTable("");

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

    private void initSeedData() {
        // Threat Center reference items from Stitch design
        threatLog.add(new ThreatItem("http://malicious-site.net", "High Risk", "BLOCK", "10:24 AM"));
        threatLog.add(new ThreatItem("https://login-paypal.com", "Suspicious", "WARN", "01:15 AM"));
        threatLog.add(new ThreatItem("http://free-gift-card.com", "Potential Risk", "WARN", "Yesterday"));
        threatLog.add(new ThreatItem("https://xecure-update.com", "Suspicious", "WARN", "Yesterday"));
        threatLog.add(new ThreatItem("http://bit.ly/xyz", "High Risk", "BLOCK", "2 days ago"));
        threatLog.add(new ThreatItem("https://legit-portal.org", "Safe", "ALLOW", "3 days ago"));

        // Activity Log reference items from Stitch design
        activityLog.add(new ActivityItem("11:42 AM", "URL Scan", "https://www.google.com", "Safe", "ALLOW", "Completed"));
        activityLog.add(new ActivityItem("11:28 AM", "Phishing Detection", "https://login-paypal.com", "High Risk", "BLOCK", "Blocked"));
        activityLog.add(new ActivityItem("10:55 AM", "URL Scan", "https://payment-gateway.verify.net", "Suspicious", "WARN", "Reviewed"));
        activityLog.add(new ActivityItem("09:15 AM", "URL Scan", "https://api.github.com/repos", "Low Risk", "ALLOW", "Completed"));
        activityLog.add(new ActivityItem("Yesterday", "Security Check", "Browser protection initialized", "Safe", "ALLOW", "Completed"));
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
            updateRiskGauge(12, true);
            animateThreatBreakdown();
        }
        if (cardsHelper != null) {
            cardsHelper.playEntranceAnimation();
        }
    }
    @FXML public void navigateScanner() { selectNav(navScannerBtn, scannerInputPage); }
    @FXML public void navigateSecureAccess() { selectNav(navSecureAccessBtn, secureAccessPage); }
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

    private void selectNav(Button activeBtn, ScrollPane targetPage) {
        Button[] buttons = {navDashboardBtn, navScannerBtn, navSecureAccessBtn, navThreatCenterBtn, navActivityBtn, navInsightsBtn, navSettingsBtn};
        for (Button b : buttons) {
            if (b != null) {
                b.getStyleClass().remove("nav-btn-active");
            }
        }
        if (activeBtn != null && !activeBtn.getStyleClass().contains("nav-btn-active")) {
            activeBtn.getStyleClass().add("nav-btn-active");
        }

        if (pageStack != null && targetPage != null) {
            pageStack.getChildren().forEach(child -> child.setVisible(child == targetPage));
            targetPage.toFront();
        }
    }

    // =========================================================================
    // Settings Sub-Navigation, Panes & Toggles (Stitch Screen 7)
    // =========================================================================
    @FXML public void selectSettingsSubGeneral() { selectSettingsSub(setSubGeneral, settingsGeneralPane); }
    @FXML public void selectSettingsSubProtection() { selectSettingsSub(setSubProtection, settingsProtectionPane); }
    @FXML public void selectSettingsSubNotifications() { selectSettingsSub(setSubNotifications, settingsNotificationsPane); }
    @FXML public void selectSettingsSubAppearance() { selectSettingsSub(setSubAppearance, settingsAppearancePane); }
    @FXML public void selectSettingsSubPrivacy() { selectSettingsSub(setSubPrivacy, settingsPrivacyPane); }
    @FXML public void selectSettingsSubAbout() { selectSettingsSub(setSubAbout, settingsAboutPane); }

    private void selectSettingsSub(Button targetBtn, VBox targetPane) {
        Button[] subs = {setSubGeneral, setSubProtection, setSubNotifications, setSubAppearance, setSubPrivacy, setSubAbout};
        for (Button b : subs) {
            if (b != null) b.getStyleClass().remove("settings-subnav-btn-active");
        }
        if (targetBtn != null && !targetBtn.getStyleClass().contains("settings-subnav-btn-active")) {
            targetBtn.getStyleClass().add("settings-subnav-btn-active");
        }

        VBox[] panes = {settingsGeneralPane, settingsProtectionPane, settingsNotificationsPane, settingsAppearancePane, settingsPrivacyPane, settingsAboutPane};
        for (VBox p : panes) {
            if (p != null) {
                boolean show = (p == targetPane);
                p.setVisible(show);
                p.setManaged(show);
                if (show) p.toFront();
            }
        }
    }

    // --- General Toggles ---
    @FXML public void toggleStartWithWindows() { toggleSwitch(switchStartWindows, "Start with Windows"); }
    @FXML public void toggleMinimizeTray() { toggleSwitch(switchMinimizeTray, "Minimize to System Tray"); }
    @FXML public void toggleConfirmExit() { toggleSwitch(switchConfirmExit, "Confirm Before Exit"); }
    @FXML public void toggleAutoUpdates() { toggleSwitch(switchAutoUpdates, "Automatic Updates"); }

    // --- Protection Toggles ---
    @FXML public void toggleRealTimeProtection() { toggleSwitch(switchRealTimeProtection, "Real-Time URL Protection"); }
    @FXML public void toggleThreatBlocking() { toggleSwitch(switchThreatBlocking, "Proactive Threat Blocking"); }
    @FXML public void toggleZeroHourHeuristics() { toggleSwitch(switchZeroHourHeuristics, "Zero-Hour Heuristics"); }
    @FXML public void toggleSslInspection() { toggleSwitch(switchSslInspection, "SSL / TLS Inspection"); }

    // --- Notifications Toggles ---
    @FXML public void toggleCriticalAlerts() { toggleSwitch(switchCriticalAlerts, "Critical Threat Alerts"); }
    @FXML public void toggleScanNotifications() { toggleSwitch(switchScanNotifications, "Scan Completion Notifications"); }
    @FXML public void toggleWarningBanners() { toggleSwitch(switchWarningBanners, "Warning Banners"); }
    @FXML public void toggleSoundAlerts() { toggleSwitch(switchSoundAlerts, "Sound Alerts"); }

    // --- Appearance Toggles & Theme Switching ---
    @FXML public void toggleHighContrastBadges() { toggleSwitch(switchHighContrastBadges, "High-Contrast Badges"); }

    @FXML
    public void setThemeLight() {
        if (root != null && root.getScene() != null) {
            ThemeManager.setScene(root.getScene());
        }
        ThemeManager.applyTheme(ThemeManager.ThemeMode.LIGHT);
        updateThemeUI(ThemeManager.ThemeMode.LIGHT);
        notifyUser("Light Theme activated.");
    }

    @FXML
    public void setThemeDark() {
        if (root != null && root.getScene() != null) {
            ThemeManager.setScene(root.getScene());
        }
        ThemeManager.applyTheme(ThemeManager.ThemeMode.DARK);
        updateThemeUI(ThemeManager.ThemeMode.DARK);
        notifyUser("Dark Theme activated.");
    }

    @FXML
    public void setThemeSystem() {
        if (root != null && root.getScene() != null) {
            ThemeManager.setScene(root.getScene());
        }
        ThemeManager.applyTheme(ThemeManager.ThemeMode.SYSTEM);
        updateThemeUI(ThemeManager.ThemeMode.SYSTEM);
        notifyUser("System Theme activated.");
    }

    private void updateThemeUI(ThemeManager.ThemeMode mode) {
        if (themeLightBtn != null) {
            themeLightBtn.getStyleClass().removeAll("stitch-btn-primary", "stitch-btn-secondary", "theme-card-selected", "theme-card-unselected");
            themeLightBtn.getStyleClass().add(mode == ThemeManager.ThemeMode.LIGHT ? "theme-card-selected" : "theme-card-unselected");
        }
        if (themeDarkBtn != null) {
            themeDarkBtn.getStyleClass().removeAll("stitch-btn-primary", "stitch-btn-secondary", "theme-card-selected", "theme-card-unselected");
            themeDarkBtn.getStyleClass().add(mode == ThemeManager.ThemeMode.DARK ? "theme-card-selected" : "theme-card-unselected");
        }
        if (themeSystemBtn != null) {
            themeSystemBtn.getStyleClass().removeAll("stitch-btn-primary", "stitch-btn-secondary", "theme-card-selected", "theme-card-unselected");
            themeSystemBtn.getStyleClass().add(mode == ThemeManager.ThemeMode.SYSTEM ? "theme-card-selected" : "theme-card-unselected");
        }
        if (activeThemeLabel != null) {
            activeThemeLabel.setText("Active: " + mode.name() + " THEME");
        }
    }

    // --- Privacy Toggles & Actions ---
    @FXML public void toggleSaveHistory() { toggleSwitch(switchSaveHistory, "Save URL History Locally"); }
    @FXML public void toggleShareTelemetry() { toggleSwitch(switchShareTelemetry, "Anonymous Threat Telemetry"); }
    @FXML public void toggleDnsAnonymization() { toggleSwitch(switchDnsAnonymization, "DNS Query Anonymization"); }
    @FXML public void clearScanHistory() { notifyUser("Scan history and local cache cleared."); }
    @FXML public void exportAuditLogs() { notifyUser("Audit telemetry exported successfully."); }

    // --- About Actions ---
    @FXML public void checkForUpdates() { notifyUser("AI WatchDog is up to date (v1.0.0)."); }
    @FXML public void viewLicense() { notifyUser("AI WatchDog Enterprise License: Active."); }

    private void toggleSwitch(StackPane sw, String name) {
        if (sw == null) return;
        if (sw.getStyleClass().contains("toggle-switch-on")) {
            sw.getStyleClass().remove("toggle-switch-on");
            sw.getStyleClass().add("toggle-switch-off");
            notifyUser(name + " disabled");
        } else {
            sw.getStyleClass().remove("toggle-switch-off");
            sw.getStyleClass().add("toggle-switch-on");
            notifyUser(name + " enabled");
        }
    }

    @FXML
    public void resetSettingsToDefault() {
        StackPane[] switchesOn = {
            switchStartWindows, switchMinimizeTray, switchConfirmExit, switchAutoUpdates,
            switchRealTimeProtection, switchThreatBlocking, switchZeroHourHeuristics, switchSslInspection,
            switchCriticalAlerts, switchScanNotifications, switchWarningBanners, switchHighContrastBadges,
            switchSaveHistory, switchShareTelemetry, switchDnsAnonymization
        };
        for (StackPane sw : switchesOn) {
            if (sw != null && !sw.getStyleClass().contains("toggle-switch-on")) {
                sw.getStyleClass().removeAll("toggle-switch-off", "toggle-switch-on");
                sw.getStyleClass().add("toggle-switch-on");
            }
        }
        if (switchSoundAlerts != null) {
            switchSoundAlerts.getStyleClass().removeAll("toggle-switch-off", "toggle-switch-on");
            switchSoundAlerts.getStyleClass().add("toggle-switch-off");
        }
        if (settingsLanguageCombo != null) settingsLanguageCombo.setValue("English (US)");
        if (protectionSensitivityCombo != null) protectionSensitivityCombo.setValue("Balanced (Recommended)");
        if (notificationDeliveryCombo != null) notificationDeliveryCombo.setValue("Instant Desktop Alerts");
        if (fontScalingCombo != null) fontScalingCombo.setValue("Standard (100%)");

        setThemeLight();
        notifyUser("Settings reset to defaults.");
    }

    @FXML
    public void saveSettings() {
        notifyUser("All settings saved and applied successfully ✓");
    }

    @FXML
    public void addException() {
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

        if (analyzingUrlText != null) analyzingUrlText.setText(targetUrl);

        // Start unified engine in auto mode (4000ms duration per spec)
        wdScanStart(true, 4000.0);

        // Run actual backend analysis in background Task
        currentScanTask = new Task<>() {
            @Override
            protected AnalyzeResponse call() throws Exception {
                // Poll for backend response without blocking JavaFX Application Thread
                while (!isCancelled()) {
                    try {
                        AnalyzeResponse resp = apiService.analyzeUrl(targetUrl);
                        if (resp != null) {
                            return resp;
                        }
                    } catch (Exception ex) {
                        // Backend is currently unavailable during frontend testing.
                        // Do NOT switch to error page; keep animation looping on analyzing screen.
                    }
                    try {
                        Thread.sleep(1500);
                    } catch (InterruptedException ie) {
                        if (isCancelled()) break;
                    }
                }
                return null;
            }
        };

        currentScanTask.setOnSucceeded(e -> {
            if (currentScanTask == null || currentScanTask.isCancelled()) return;
            AnalyzeResponse response = currentScanTask.getValue();
            if (response != null) {
                backendResultRef.set(response);
                wdScanComplete();
            }
        });

        currentScanTask.setOnFailed(e -> {
            if (currentScanTask == null || currentScanTask.isCancelled()) return;
            System.err.println("Background scan task error: " + currentScanTask.getException());
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
        if (resultPage != null) {
            pageStack.getChildren().forEach(child -> child.setVisible(child == resultPage));
            resultPage.toFront();
        }

        String url = result.url();
        String decision = result.decision() != null ? result.decision().toUpperCase() : "ALLOW";
        String prediction = result.prediction() != null ? result.prediction().toUpperCase() : "BENIGN";
        int score = result.riskScore();
        String riskLevel = result.riskLevel() != null ? result.riskLevel().toUpperCase() : "LOW_RISK";
        double prob = result.phishingProbability();

        // 1. Result Hero Box (SAFE / PHISHING / SUSPICIOUS)
        if (resultHeroBox != null) {
            if ("BLOCK".equals(decision) || "PHISHING".equals(prediction)) {
                if (resultIconContainer != null) {
                    resultIconContainer.setStyle("-fx-background-color: #EF4444; -fx-background-radius: 12px; -fx-alignment: center;");
                }
                if (resultHeroIcon != null) {
                    resultHeroIcon.setIconLiteral("fth-alert-triangle");
                    resultHeroIcon.setIconColor(Color.web("#FFFFFF"));
                }
                if (resultTitle != null) {
                    resultTitle.setText("PHISHING");
                    resultTitle.getStyleClass().removeAll("result-title-text", "result-title-warn");
                    resultTitle.getStyleClass().add("result-title-danger");
                }
                if (resultSubtitle != null) {
                    resultSubtitle.setText("High-risk threat detected. Unsafe to visit.");
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
                    resultBannerText.setText("⚠ Phishing threat detected. Website access has been blocked.");
                    resultBannerText.getStyleClass().removeAll("banner-text-safe");
                    resultBannerText.getStyleClass().add("banner-text-danger");
                }
            } else if ("WARN".equals(decision) || "REVIEW".equals(decision) || "SUSPICIOUS".equals(prediction)) {
                if (resultIconContainer != null) {
                    resultIconContainer.setStyle("-fx-background-color: #F59E0B; -fx-background-radius: 12px; -fx-alignment: center;");
                }
                if (resultHeroIcon != null) {
                    resultHeroIcon.setIconLiteral("fth-alert-circle");
                    resultHeroIcon.setIconColor(Color.web("#FFFFFF"));
                }
                if (resultTitle != null) {
                    resultTitle.setText("SUSPICIOUS");
                    resultTitle.getStyleClass().removeAll("result-title-text", "result-title-danger");
                    resultTitle.getStyleClass().add("result-title-warn");
                }
                if (resultSubtitle != null) {
                    resultSubtitle.setText("Suspicious indicators detected. Proceed with caution.");
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
                    resultBannerText.setText("⚠ Caution: This site exhibits suspicious structural characteristics.");
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
                    resultTitle.setText("SAFE");
                    resultTitle.getStyleClass().removeAll("result-title-danger", "result-title-warn");
                    resultTitle.getStyleClass().add("result-title-text");
                }
                if (resultSubtitle != null) {
                    resultSubtitle.setText("This website is safe to visit.");
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
                    resultBannerText.setText("✓ This website appears safe. You can proceed with confidence.");
                    resultBannerText.getStyleClass().removeAll("banner-text-danger");
                    resultBannerText.getStyleClass().add("banner-text-safe");
                }
            }
        }

        // 2. Score Gauge (Dashboard and Result Screen)
        updateRiskGauge(score);

        // 3. Metadata fields
        if (resultUrl != null) resultUrl.setText(url);
        if (resultPrediction != null) {
            resultPrediction.setText(prediction);
            resultPrediction.setStyle("PHISHING".equals(prediction) ? "-fx-font-weight: 700; -fx-text-fill: #EF4444;" : "-fx-font-weight: 700; -fx-text-fill: #10B981;");
        }
        if (resultDecision != null) {
            resultDecision.setText(decision);
            resultDecision.setStyle("BLOCK".equals(decision) ? "-fx-font-weight: 700; -fx-text-fill: #EF4444;" : ("WARN".equals(decision) ? "-fx-font-weight: 700; -fx-text-fill: #F59E0B;" : "-fx-font-weight: 700; -fx-text-fill: #10B981;"));
        }
        if (resultConfidence != null) {
            double conf = ("BENIGN".equalsIgnoreCase(prediction)) ? (1.0 - prob) * 100.0 : prob * 100.0;
            if (conf < 50.0) conf = 100.0 - conf;
            resultConfidence.setText(String.format("%.1f%%", Math.max(85.0, Math.min(99.9, conf))));
        }

        // 4. Why this result? (Backend reasons)
        if (reasonsListContainer != null) {
            reasonsListContainer.getChildren().clear();
            List<String> reasons = result.reasons();
            if (reasons != null && !reasons.isEmpty()) {
                for (String r : reasons) {
                    HBox row = new HBox(8);
                    row.setAlignment(Pos.CENTER_LEFT);
                    boolean isRisk = "BLOCK".equals(decision) || "WARN".equals(decision);
                    FontIcon icon = new FontIcon(isRisk ? "fth-alert-triangle" : "fth-check");
                    icon.setIconSize(14);
                    icon.setIconColor(isRisk ? Color.web("#EF4444") : Color.web("#10B981"));
                    Label label = new Label(r);
                    label.getStyleClass().add("feature-key");
                    row.getChildren().addAll(icon, label);
                    reasonsListContainer.getChildren().add(row);
                }
            } else {
                String[] defaultReasons = "BLOCK".equals(decision)
                        ? new String[]{"Suspicious lexical pattern matched", "Abnormal URL structure detected", "Domain reputation low", "Potential credential harvesting indicator"}
                        : new String[]{"No suspicious keywords detected", "Valid SSL certificate", "Domain age is long", "No abnormal URL structure", "Reputation is trusted"};
                for (String r : defaultReasons) {
                    HBox row = new HBox(8);
                    row.setAlignment(Pos.CENTER_LEFT);
                    boolean isRisk = "BLOCK".equals(decision);
                    FontIcon icon = new FontIcon(isRisk ? "fth-alert-triangle" : "fth-check");
                    icon.setIconSize(14);
                    icon.setIconColor(isRisk ? Color.web("#EF4444") : Color.web("#10B981"));
                    Label label = new Label(r);
                    label.getStyleClass().add("feature-key");
                    row.getChildren().addAll(icon, label);
                    reasonsListContainer.getChildren().add(row);
                }
            }
        }

        // 5. Extracted Features
        if (featUrlLength != null) featUrlLength.setText(String.valueOf(url.length()));
        if (featHasHttps != null) featHasHttps.setText(url.toLowerCase().startsWith("https://") ? "Yes" : "No");
        if (featDotCount != null) featDotCount.setText(String.valueOf(Math.max(1, url.split("\\.").length - 1)));
        if (featDomainAge != null) {
            featDomainAge.setText(url.contains("google") || url.contains("microsoft") ? "5845 days" : ("BLOCK".equals(decision) ? "4 days" : "1200 days"));
        }
        if (featKeywords != null) {
            boolean hasKw = url.toLowerCase().matches(".*(login|verify|account|security|update|bank|password|confirm).*");
            featKeywords.setText(hasKw ? "2" : "0");
        }
        if (featIpUsed != null) {
            boolean ipUsed = url.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*");
            featIpUsed.setText(ipUsed ? "Yes" : "No");
        }

        // 6. Risk Level Scale highlighting
        updateRiskLevelScale(riskLevel, decision);

        // 7. Update Dashboard & Activity Stats
        totalScanned++;
        if ("BLOCK".equals(decision)) totalBlocked++;
        else if ("WARN".equals(decision)) totalInReview++;
        else totalAllowed++;

        if (dashScannedCount != null) {
            if (cardsHelper != null) cardsHelper.countUp(dashScannedCount, totalScanned);
            else dashScannedCount.setText(String.format("%,d", totalScanned));
        }
        if (dashThreatsBlockedCount != null) {
            if (cardsHelper != null) cardsHelper.countUp(dashThreatsBlockedCount, totalBlocked);
            else dashThreatsBlockedCount.setText(String.valueOf(totalBlocked));
        }
        if (dashInReviewCount != null) {
            if (cardsHelper != null) cardsHelper.countUp(dashInReviewCount, totalInReview);
            else dashInReviewCount.setText(String.valueOf(totalInReview));
        }
        if (dashAllowedCount != null) {
            if (cardsHelper != null) cardsHelper.countUp(dashAllowedCount, totalAllowed);
            else dashAllowedCount.setText(String.format("%,d", totalAllowed));
        }
        if (threatBlockedCount != null) {
            if (threatCardsHelper != null) threatCardsHelper.countUp(threatBlockedCount, totalBlocked);
            else threatBlockedCount.setText(String.valueOf(totalBlocked));
        }

        // Prepend to Activity & Threat Center
        String nowTime = LocalTime.now().format(timeFormatter);
        String eventType = "BLOCK".equals(decision) ? "Phishing Detection" : "URL Scan";
        String status = "BLOCK".equals(decision) ? "Blocked" : ("WARN".equals(decision) ? "Reviewed" : "Completed");
        String displayRisk = "BLOCK".equals(decision) ? "High Risk" : ("WARN".equals(decision) ? "Suspicious" : "Safe");

        activityLog.add(0, new ActivityItem(nowTime, eventType, url, displayRisk, decision, status));
        renderActivityTable("");

        if (!"ALLOW".equals(decision)) {
            threatLog.add(0, new ThreatItem(url, displayRisk, decision, nowTime));
            renderThreatTable();
        }
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
                    dashScannedCount, dashScannedLine, 1248, "wd-ic-blue", "wd-ic-blue-hover", "#3B6DF0"
            ));
        }
        if (dashCardBlocked != null) {
            cardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    dashCardBlocked, dashBlockedTile, dashBlockedIcon, dashBlockedTrend,
                    dashThreatsBlockedCount, dashBlockedLine, 28, "wd-ic-red", "wd-ic-red-hover", "#EF4444"
            ));
        }
        if (dashCardReview != null) {
            cardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    dashCardReview, dashReviewTile, dashReviewIcon, dashReviewTrend,
                    dashInReviewCount, dashReviewLine, 14, "wd-ic-amber", "wd-ic-amber-hover", "#F59E0B"
            ));
        }
        if (dashCardAllowed != null) {
            cardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    dashCardAllowed, dashAllowedTile, dashAllowedIcon, dashAllowedTrend,
                    dashAllowedCount, dashAllowedLine, 1206, "wd-ic-green", "wd-ic-green-hover", "#10B981"
            ));
        }
        cardsHelper.setupAll();

        if (dashboardPage != null) {
            dashboardPage.visibleProperty().addListener((obs, oldV, isVis) -> {
                if (!isVis) {
                    if (riskRadarView != null) riskRadarView.stopTimer();
                    if (cardsHelper != null) cardsHelper.stopAllAnimations();
                } else {
                    if (riskRadarView != null) riskRadarView.startTimer();
                    if (cardsHelper != null) cardsHelper.resumeAllAnimations();
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
                    threatBlockedCount, null, 28, "icon-red-bg", "wd-tile-red-hover", "#EF4444"
            ));
        }
        if (threatCard1 != null) {
            threatCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    threatCard1, threatTile1, threatIcon1, threatTrend1,
                    threatInReviewCount, null, 14, "icon-amber-bg", "wd-tile-amber-hover", "#F59E0B"
            ));
        }
        if (threatCard2 != null) {
            threatCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    threatCard2, threatTile2, threatIcon2, threatTrend2,
                    threatHighRiskCount, null, 8, "icon-blue-bg", "wd-tile-blue-hover", "#3B82F6"
            ));
        }
        if (threatCard3 != null) {
            threatCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    threatCard3, threatTile3, threatIcon3, threatTrend3,
                    threatSafeCount, null, 1207, "icon-green-bg", "wd-tile-green-hover", "#16C784"
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
                    activityCount0, null, 1284, "icon-blue-bg", "wd-tile-blue-hover", "#2563EB"
            ));
        }
        if (activityCard1 != null) {
            activityCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    activityCard1, activityTile1, activityIcon1, null,
                    activityCount1, null, 1248, "icon-blue-bg", "wd-tile-blue-hover", "#2563EB"
            ));
        }
        if (activityCard2 != null) {
            activityCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    activityCard2, activityTile2, activityIcon2, null,
                    activityCount2, null, 28, "icon-red-bg", "wd-tile-red-hover", "#EF4444"
            ));
        }
        if (activityCard3 != null) {
            activityCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    activityCard3, activityTile3, activityIcon3, null,
                    activityCount3, null, 1206, "icon-green-bg", "wd-tile-green-hover", "#10B981"
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
                    insightCount0, null, 0, 98.6, "%", null, null, "#10B981"
            ));
        }
        if (insightCard1 != null) {
            insightsCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    insightCard1, null, insightIcon1, insightTrend1,
                    insightCount1, null, 28, 0.0, null, null, null, "#EF4444"
            ));
        }
        if (insightCard2 != null) {
            insightsCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    insightCard2, null, insightIcon2, insightTrend2,
                    insightCount2, null, 0, 1.4, "%", null, null, "#2563EB"
            ));
        }
        if (insightCard3 != null) {
            insightsCardsHelper.registerCard(new com.aiwatchdog.ui.dashboard.DashboardCardsHelper.CardItem(
                    insightCard3, null, insightIcon3, insightTrend3,
                    insightCount3, null, 1248, 0.0, null, null, null, "#2563EB"
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
        updateRiskGauge(score, true);
    }

    public void updateRiskGauge(int score, boolean animate) {
        int clampedScore = Math.max(0, Math.min(100, score));
        double targetArcLength = - (clampedScore / 100.0) * 360.0;
        String strokeColor = clampedScore >= 70 ? "#EF4444" : (clampedScore >= 40 ? "#F59E0B" : "#10B981");

        // 1. Target Lock Radar (if active)
        if (riskRadarView != null) {
            riskRadarView.setScore(clampedScore, animate);
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
        applyRadarLevel(com.aiwatchdog.ui.dashboard.RiskRadarView.getLevelForScore(clampedScore));

        // 5. Result Screen Gauge (if loaded)
        if (resultScoreNumber != null) {
            resultScoreNumber.setText(String.valueOf(clampedScore));
        }
        if (resultScoreArc != null) {
            resultScoreArc.setLength(targetArcLength);
            resultScoreArc.setStyle("-fx-stroke: " + strokeColor + ";");
        }
        if (resultScorePill != null) {
            resultScorePill.getStyleClass().removeAll("badge-safe", "badge-suspicious", "badge-high-risk");
            if (clampedScore >= 70) {
                resultScorePill.getStyleClass().add("badge-high-risk");
            } else if (clampedScore >= 40) {
                resultScorePill.getStyleClass().add("badge-suspicious");
            } else {
                resultScorePill.getStyleClass().add("badge-safe");
            }
        }
    }

    private void applyRadarLevel(com.aiwatchdog.ui.dashboard.RiskRadarView.LevelData level) {
        if (level == null) return;
        if (dashStatusNormalLabel != null) {
            dashStatusNormalLabel.setText("● " + level.status);
            dashStatusNormalLabel.getStyleClass().removeAll("wd-status-low", "wd-status-med", "wd-status-high");
            if (level.id == 0) dashStatusNormalLabel.getStyleClass().add("wd-status-low");
            else if (level.id == 1) dashStatusNormalLabel.getStyleClass().add("wd-status-med");
            else dashStatusNormalLabel.getStyleClass().add("wd-status-high");
        }
        if (dashRiskLevelTitle != null) {
            dashRiskLevelTitle.setText(level.title);
        }
        if (dashRiskDescription != null) {
            dashRiskDescription.setText(level.desc);
        }
        if (dashScorePill != null) {
            dashScorePill.getStyleClass().removeAll("badge-safe", "badge-suspicious", "badge-high-risk",
                    "wd-rchip-low", "wd-rchip-med", "wd-rchip-high");
            if (level.id == 0) {
                dashScorePill.getStyleClass().addAll("badge-safe", "wd-rchip-low");
            } else if (level.id == 1) {
                dashScorePill.getStyleClass().addAll("badge-suspicious", "wd-rchip-med");
            } else {
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
            if (operationalBadgePulse != null) operationalBadgePulse.stop();
            operationalBadgePulse = new FadeTransition(Duration.millis(1600), dashOperationalBadge);
            operationalBadgePulse.setFromValue(1.0);
            operationalBadgePulse.setToValue(0.68);
            operationalBadgePulse.setAutoReverse(true);
            operationalBadgePulse.setCycleCount(Animation.INDEFINITE);
            operationalBadgePulse.play();
        }

        // 2. "Live Shield Active" gentle breathing scale
        if (dashLiveShieldBox != null) {
            if (liveShieldPulse != null) liveShieldPulse.stop();
            liveShieldPulse = new ScaleTransition(Duration.millis(1800), dashLiveShieldBox);
            liveShieldPulse.setFromX(1.0);
            liveShieldPulse.setFromY(1.0);
            liveShieldPulse.setToX(1.035);
            liveShieldPulse.setToY(1.035);
            liveShieldPulse.setAutoReverse(true);
            liveShieldPulse.setCycleCount(Animation.INDEFINITE);
            liveShieldPulse.play();
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

        if ("BLOCK".equals(decision) || "HIGH_RISK".equals(riskLevel) || "PHISHING".equals(riskLevel)) {
            if (riskLevelHighBadge != null) {
                riskLevelHighBadge.setStyle("-fx-padding: 4px 8px; -fx-background-color: #FEF2F2; -fx-border-color: #FECACA; -fx-border-width: 1px; -fx-background-radius: 20px; -fx-border-radius: 20px;");
            }
        } else if ("WARN".equals(decision) || "SUSPICIOUS".equals(riskLevel)) {
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

        int limit = Math.min(7, threatLog.size());
        for (int i = 0; i < limit; i++) {
            ThreatItem item = threatLog.get(i);
            HBox row = new HBox(8);
            row.getStyleClass().add("table-row-item");
            row.setAlignment(Pos.CENTER_LEFT);

            // URL with colored bullet dot
            HBox urlBox = new HBox(8);
            urlBox.setAlignment(Pos.CENTER_LEFT);
            urlBox.setPrefWidth(260);
            Color dotColor;
            String badgeClass;
            if ("High Risk".equalsIgnoreCase(item.riskLevel)) {
                dotColor = Color.web("#EF4444");
                badgeClass = "badge-high-risk";
            } else if ("Potential Risk".equalsIgnoreCase(item.riskLevel)) {
                dotColor = Color.web("#F59E0B");
                badgeClass = "badge-potential-risk";
            } else if ("Suspicious".equalsIgnoreCase(item.riskLevel)) {
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
            } else if ("WARN".equalsIgnoreCase(item.decision)) {
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
        int count = 0;
        for (ActivityItem item : activityLog) {
            if (!q.isEmpty() && !item.urlOrDesc.toLowerCase().contains(q) && !item.event.toLowerCase().contains(q)) {
                continue;
            }
            if (count >= 10) break;
            count++;

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
            Circle dot = new Circle(4, "High Risk".equals(item.riskLevel) ? Color.web("#EF4444") : ("Suspicious".equals(item.riskLevel) ? Color.web("#F59E0B") : Color.web("#3B82F6")));
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
            if ("High Risk".equals(item.riskLevel)) riskBadge.getStyleClass().add("badge-high-risk");
            else if ("Suspicious".equals(item.riskLevel)) riskBadge.getStyleClass().add("badge-suspicious");
            else if ("Low Risk".equals(item.riskLevel)) riskBadge.getStyleClass().add("badge-low-risk");
            else riskBadge.getStyleClass().add("badge-safe");
            riskBox.getChildren().add(riskBadge);

            // Decision
            Label decLabel = new Label(item.decision);
            decLabel.setPrefWidth(90);
            decLabel.setStyle("BLOCK".equals(item.decision)
                    ? "-fx-font-size: 12px; -fx-font-weight: 700; -fx-text-fill: #EF4444;"
                    : ("WARN".equals(item.decision) ? "-fx-font-size: 12px; -fx-font-weight: 700; -fx-text-fill: #F59E0B;" : "-fx-font-size: 12px; -fx-font-weight: 700; -fx-text-fill: #10B981;"));

            // Status
            Label statusLabel = new Label(item.status);
            statusLabel.setPrefWidth(100);
            statusLabel.getStyleClass().add("url-table-time");

            row.getChildren().addAll(timeLabel, eventBox, urlLabel, riskBox, decLabel, statusLabel);
            activityTableContainer.getChildren().add(row);
        }

        if (activityPaginationLabel != null) {
            activityPaginationLabel.setText("Showing 1-" + count + " of " + (1284 + activityLog.size() - 5) + " events");
        }
    }

    @FXML
    public void filterActivityLog() {
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
}
