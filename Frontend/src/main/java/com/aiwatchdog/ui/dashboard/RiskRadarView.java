package com.aiwatchdog.ui.dashboard;

import com.aiwatchdog.util.ThemeManager;
import javafx.animation.AnimationTimer;
import javafx.application.Platform;
import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.control.Label;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.ArcType;
import javafx.scene.shape.StrokeLineCap;
import javafx.scene.shape.StrokeLineJoin;

import java.util.function.Consumer;

/**
 * Animated Target Lock Radar (210x210) for AI WatchDog Dashboard.
 * Driven by an AnimationTimer at 60fps.
 * Renders:
 * - Clockwise outer score arc
 * - Rotating tick bezel (72 ticks)
 * - Dashed inner range rings and crosshairs
 * - Sweeping beam (3.2s / rev) with 10 trailing wedges
 * - Active blips with snapping lock-on brackets
 * - Center disc with live score value
 */
public class RiskRadarView extends StackPane {

    public static class LevelData {
        public final int id;
        public final String hexColor;
        public final Color color;
        public final String status;
        public final String title;
        public final String desc;
        public final int blipLimit;

        public LevelData(int id, String hexColor, String status, String title, String desc, int blipLimit) {
            this.id = id;
            this.hexColor = hexColor;
            this.color = Color.web(hexColor);
            this.status = status;
            this.title = title;
            this.desc = desc;
            this.blipLimit = blipLimit;
        }
    }

    public static final LevelData LEVEL_SAFE = new LevelData(
            0, "#10b981", "SAFE", "SAFE",
            "Risk level supplied by the Spring Boot backend.", 2
    );
    public static final LevelData LEVEL_LOW = new LevelData(
            1, "#84cc16", "LOW_RISK", "LOW_RISK",
            "Risk level supplied by the Spring Boot backend.", 3
    );
    public static final LevelData LEVEL_MED = new LevelData(
            2, "#f59e0b", "SUSPICIOUS", "SUSPICIOUS",
            "Risk level supplied by the Spring Boot backend.", 5
    );
    public static final LevelData LEVEL_HIGH = new LevelData(
            3, "#ef4444", "HIGH_RISK", "HIGH_RISK",
            "Risk level supplied by the Spring Boot backend.", 9
    );
    public static final LevelData LEVEL_UNKNOWN = new LevelData(
            4, "#64748b", "UNKNOWN", "UNKNOWN",
            "Waiting for a risk level from the Spring Boot backend.", 1
    );

    public static LevelData getLevelForRisk(String riskLevel) {
        if (riskLevel == null) return LEVEL_UNKNOWN;
        return switch (riskLevel.trim().toUpperCase(java.util.Locale.ROOT)) {
            case "SAFE" -> LEVEL_SAFE;
            case "LOW_RISK" -> LEVEL_LOW;
            case "SUSPICIOUS" -> LEVEL_MED;
            case "HIGH_RISK" -> LEVEL_HIGH;
            default -> LEVEL_UNKNOWN;
        };
    }

    private static class Blip {
        final double angle;
        final double radius;
        final double x;
        final double y;
        double life = 0.0;

        Blip(int index) {
            this.angle = (index * 137.5) % 360.0;
            this.radius = 22.0 + (index * 11) % 28;
            double rad = Math.toRadians(this.angle);
            this.x = 80.0 + Math.cos(rad) * this.radius;
            this.y = 80.0 + Math.sin(rad) * this.radius;
        }
    }

    private final Canvas canvas;
    private final Blip[] blips = new Blip[10];

    // Animation state
    private double currentScore = 12.0;
    private double animFrom = 0.0;
    private double animTo = 12.0;
    private long animStartNs = -1;
    private long animDurationMs = 2200;
    private long animDelayMs = 0;
    private boolean animating = false;

    private double prevSweepAngle = 0.0;
    private long lastFrameNs = 0;
    private LevelData currentLevel = LEVEL_UNKNOWN;

    private Consumer<LevelData> onLevelChanged;
    private Runnable onReplayRequested;
    private Label boundScoreLabel;

    private final AnimationTimer timer;
    private boolean timerRunning = false;

    public RiskRadarView() {
        this.setMinSize(210, 210);
        this.setPrefSize(210, 210);
        this.setMaxSize(210, 210);

        canvas = new Canvas(210, 210);
        getChildren().add(canvas);

        for (int i = 0; i < 10; i++) {
            blips[i] = new Blip(i);
        }

        timer = new AnimationTimer() {
            @Override
            public void handle(long nowNs) {
                render(nowNs);
            }
        };

        // Lifecycle & visibility management to prevent leaks
        sceneProperty().addListener((obs, oldScene, newScene) -> {
            if (newScene != null) {
                if (isVisible()) startTimer();
            } else {
                stopTimer();
            }
        });

        visibleProperty().addListener((obs, wasVisible, isNowVisible) -> {
            if (isNowVisible && getScene() != null) {
                startTimer();
            } else {
                stopTimer();
            }
        });

        setOnMouseClicked((MouseEvent e) -> {
            replay();
        });
    }

    public void setBoundScoreLabel(Label label) {
        this.boundScoreLabel = label;
        if (boundScoreLabel != null) {
            boundScoreLabel.setText(String.valueOf(Math.round(currentScore)));
        }
    }

    public void setOnLevelChanged(Consumer<LevelData> callback) {
        this.onLevelChanged = callback;
        if (onLevelChanged != null) {
            onLevelChanged.accept(currentLevel);
        }
    }

    public void setOnReplayRequested(Runnable callback) {
        this.onReplayRequested = callback;
    }

    public void startTimer() {
        if (!timerRunning) {
            lastFrameNs = System.nanoTime();
            timer.start();
            timerRunning = true;
        }
    }

    public void stopTimer() {
        if (timerRunning) {
            timer.stop();
            timerRunning = false;
        }
    }

    /**
     * Sets risk score with animation.
     */
    public void setScore(int score) {
        setScore(score, this.currentScore, 0, 2200);
    }

    public void setScore(int score, boolean animate) {
        if (animate) {
            setScore(score, this.currentScore, 0, 2200);
        } else {
            this.currentScore = Math.max(0, Math.min(100, score));
            this.animFrom = this.currentScore;
            this.animTo = this.currentScore;
            this.animating = false;
            if (boundScoreLabel != null) {
                boundScoreLabel.setText(String.valueOf(Math.round(this.currentScore)));
            }
            renderStatic();
        }
    }

    public void setScore(int score, double from, long delayMs, long durationMs) {
        int target = Math.max(0, Math.min(100, score));
        this.animFrom = from;
        this.animTo = target;
        this.animDelayMs = delayMs;
        this.animDurationMs = durationMs;
        this.animStartNs = -1;
        this.animating = true;
        startTimer();
    }

    /** Updates the visualization with a backend score and its backend-assigned risk level. */
    public void setAssessment(int score, String riskLevel, boolean animate) {
        LevelData level = getLevelForRisk(riskLevel);
        updateLevel(level);
        setScore(score, animate);
    }

    public void replay() {
        setScore((int) Math.round(animTo), this.currentScore, 0, 2200);
        if (onReplayRequested != null) {
            onReplayRequested.run();
        }
    }

    public double getCurrentScore() {
        return currentScore;
    }

    public LevelData getCurrentLevel() {
        return currentLevel;
    }

    private static double cubicEaseInOut(double p) {
        return p < 0.5 ? 4.0 * p * p * p : 1.0 - Math.pow(-2.0 * p + 2.0, 3) / 2.0;
    }

    private static boolean anglePassed(double angle, double prevAngle, double currAngle) {
        return currAngle >= prevAngle
                ? (angle > prevAngle && angle <= currAngle)
                : (angle > prevAngle || angle <= currAngle);
    }

    private void updateLevel(LevelData newLevel) {
        if (currentLevel != newLevel) {
            currentLevel = newLevel;
            if (onLevelChanged != null) {
                Platform.runLater(() -> onLevelChanged.accept(newLevel));
            }
        }
    }

    private boolean isDarkTheme() {
        if (getScene() != null && getScene().getStylesheets() != null) {
            for (String css : getScene().getStylesheets()) {
                if (css.contains("app-dark.css")) return true;
            }
        }
        return ThemeManager.getCurrentMode() == ThemeManager.ThemeMode.DARK;
    }

    private void render(long nowNs) {
        if (lastFrameNs == 0) lastFrameNs = nowNs;
        double dtMs = (nowNs - lastFrameNs) / 1_000_000.0;
        lastFrameNs = nowNs;

        // Score interpolation
        if (animating) {
            if (animStartNs < 0) animStartNs = nowNs;
            long elapsedMs = (nowNs - animStartNs) / 1_000_000L;
            if (elapsedMs >= animDelayMs) {
                double progress = Math.min(1.0, (double) (elapsedMs - animDelayMs) / animDurationMs);
                double ease = cubicEaseInOut(progress);
                currentScore = animFrom + (animTo - animFrom) * ease;
                if (progress >= 1.0) {
                    currentScore = animTo;
                    animating = false;
                }
            }
        }

        LevelData level = currentLevel;

        if (boundScoreLabel != null) {
            boundScoreLabel.setText(String.valueOf(Math.round(currentScore)));
        }

        // Draw radar
        drawFrame(nowNs / 1_000_000.0, dtMs, level);
    }

    private void renderStatic() {
        drawFrame(System.currentTimeMillis(), 16.6, currentLevel);
    }

    private void drawFrame(double tMs, double dtMs, LevelData level) {
        GraphicsContext gc = canvas.getGraphicsContext2D();
        gc.clearRect(0, 0, 210, 210);

        boolean dark = isDarkTheme();
        Color trackColor = dark ? Color.web("#252525") : Color.web("#e9eef6");
        Color bezelBg = dark ? Color.web("#0A0A0A") : Color.web("#f8fafd");
        Color bezelBorder = dark ? Color.web("#252525") : Color.web("#e6ecf5");
        Color dashRing = dark ? Color.web("#1E1E1E") : Color.web("#dbe3ee");
        Color crosshair = dark ? Color.web("#181818") : Color.web("#eef2f8");
        Color centerDiscFill = dark ? Color.web("#0A0A0A") : Color.web("#ffffff");

        gc.save();
        // Scale 160x160 design coordinate system to 210x210
        double scale = 210.0 / 160.0;
        gc.scale(scale, scale);

        // 1. Outer Track Ring (cx=80, cy=80, r=71, stroke-width=5)
        gc.setStroke(trackColor);
        gc.setLineWidth(5.0);
        gc.strokeOval(80 - 71, 80 - 71, 142, 142);

        // 2. Outer Score Arc (fills clockwise from 12 o'clock / -90 deg)
        if (currentScore > 0) {
            gc.setStroke(level.color);
            gc.setLineWidth(5.0);
            gc.setLineCap(StrokeLineCap.ROUND);
            double arcExtent = -(currentScore / 100.0) * 360.0;
            gc.strokeArc(80 - 71, 80 - 71, 142, 142, 90, arcExtent, ArcType.OPEN);
        }

        // 3. Bezel Background (r=56)
        gc.setFill(bezelBg);
        gc.setStroke(bezelBorder);
        gc.setLineWidth(1.0);
        gc.fillOval(80 - 56, 80 - 56, 112, 112);
        gc.strokeOval(80 - 56, 80 - 56, 112, 112);

        // 4. Dashed Range Rings (r=42, r=28)
        gc.setStroke(dashRing);
        gc.setLineWidth(1.0);
        gc.setLineDashes(2, 3);
        gc.strokeOval(80 - 42, 80 - 42, 84, 84);
        gc.strokeOval(80 - 28, 80 - 28, 56, 56);
        gc.setLineDashes((double[]) null);

        // 5. Crosshair Lines
        gc.setStroke(crosshair);
        gc.setLineWidth(1.0);
        gc.strokeLine(80, 26, 80, 134);
        gc.strokeLine(26, 80, 134, 80);

        // 6. Rotating Tick Bezel (72 ticks, rotates at -t / 90)
        double bezelRot = -(tMs / 90.0) % 360.0;
        gc.save();
        gc.translate(80, 80);
        gc.rotate(bezelRot);
        gc.translate(-80, -80);
        for (int i = 0; i < 72; i++) {
            double rad = Math.toRadians(i * 5.0);
            boolean lg = (i % 6 == 0);
            double r1 = lg ? 57.0 : 59.5;
            double r2 = 62.0;
            gc.setLineWidth(lg ? 1.6 : 1.0);
            Color tickCol = lg
                    ? (dark ? Color.web("#404040") : Color.web("#b6c3d6"))
                    : (dark ? Color.web("#262626") : Color.web("#d3dce9"));
            gc.setStroke(tickCol);
            gc.strokeLine(80 + Math.cos(rad) * r1, 80 + Math.sin(rad) * r1,
                          80 + Math.cos(rad) * r2, 80 + Math.sin(rad) * r2);
        }
        gc.restore();

        // 7. Sweep Beam (one turn every 3.2s = 3200ms)
        double currSweepAngle = (tMs / 3200.0 * 360.0) % 360.0;
        gc.save();
        gc.translate(80, 80);
        gc.rotate(currSweepAngle);
        gc.translate(-80, -80);

        // 10 Trailing Wedges behind beam
        for (int k = 0; k < 10; k++) {
            double a1 = Math.toRadians(-(k + 1) * 6.0);
            double a2 = Math.toRadians(-k * 6.0);
            double op = 0.24 * (1.0 - (double) k / 10.0);
            Color wedgeCol = Color.color(level.color.getRed(), level.color.getGreen(), level.color.getBlue(), op);
            gc.setFill(wedgeCol);

            gc.beginPath();
            gc.moveTo(80, 80);
            for (int s = 0; s <= 6; s++) {
                double a = a1 + (a2 - a1) * ((double) s / 6.0);
                gc.lineTo(80 + 54.0 * Math.cos(a), 80 + 54.0 * Math.sin(a));
            }
            gc.closePath();
            gc.fill();
        }

        // Leading beam line
        gc.setStroke(level.color);
        gc.setLineWidth(1.6);
        gc.setLineCap(StrokeLineCap.ROUND);
        gc.strokeLine(80, 80, 134, 80);
        gc.restore();

        // 8. Blips with Corner Lock-on Brackets
        for (int b = 0; b < 10; b++) {
            Blip blip = blips[b];
            if (b >= level.blipLimit) {
                blip.life = 0.0;
            } else if (anglePassed(blip.angle, prevSweepAngle, currSweepAngle)) {
                blip.life = 1.0;
            } else {
                blip.life = Math.max(0.0, blip.life - dtMs / 2400.0);
            }

            if (blip.life > 0.0) {
                double life = blip.life;
                // Center dot
                Color dotCol = Color.color(level.color.getRed(), level.color.getGreen(), level.color.getBlue(), life);
                gc.setFill(dotCol);
                gc.fillOval(blip.x - 2.6, blip.y - 2.6, 5.2, 5.2);

                // Corner lock-on brackets
                double age = 1.0 - life;
                double sc = 1.0 + Math.max(0.0, 1.0 - age * 5.0) * 1.1;

                gc.save();
                gc.translate(blip.x, blip.y);
                gc.scale(sc, sc);
                gc.setStroke(dotCol);
                gc.setLineWidth(1.4);
                gc.setLineCap(StrokeLineCap.ROUND);
                gc.setLineJoin(StrokeLineJoin.MITER);

                gc.beginPath();
                // Top-left
                gc.moveTo(-6, -3); gc.lineTo(-6, -6); gc.lineTo(-3, -6);
                // Top-right
                gc.moveTo(3, -6); gc.lineTo(6, -6); gc.lineTo(6, -3);
                // Bottom-right
                gc.moveTo(6, 3); gc.lineTo(6, 6); gc.lineTo(3, 6);
                // Bottom-left
                gc.moveTo(-3, 6); gc.lineTo(-6, 6); gc.lineTo(-6, 3);
                gc.stroke();
                gc.restore();
            }
        }
        prevSweepAngle = currSweepAngle;

        // 9. Center Disc (r=26)
        gc.setFill(centerDiscFill);
        gc.setStroke(bezelBorder);
        gc.setLineWidth(1.0);
        gc.fillOval(80 - 26, 80 - 26, 52, 52);
        gc.strokeOval(80 - 26, 80 - 26, 52, 52);

        gc.restore();
    }
}
