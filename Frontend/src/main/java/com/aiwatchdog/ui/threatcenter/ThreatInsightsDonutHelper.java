package com.aiwatchdog.ui.threatcenter;

import javafx.animation.*;
import javafx.application.Platform;
import javafx.scene.Cursor;
import javafx.scene.effect.BlurType;
import javafx.scene.effect.DropShadow;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.Arc;
import javafx.scene.shape.Circle;
import javafx.util.Duration;

/**
 * Modern, high-performance UI helper driving the Threat Insights Risk Score donut chart
 * on the Threat Center page.
 *
 * Features:
 * - Cascading clockwise ribbon draw-in for the 3 arc segments (High Risk, Suspicious, Info)
 * - Cubic ease-out count-up animation for the center threat count (45) with micro-scale pop
 * - Staggered cascade and percentage count-up for legend rows
 * - Segment-level interactive hover expansion, soft glow, depth-of-field dimming on sibling arcs,
 *   and dynamic center metric focus
 * - Ambient living breathing vigilance glow on the High Risk segment
 * - Interactive replay on click
 * - Safe lifecycle management to eliminate background CPU overhead when hidden
 */
public class ThreatInsightsDonutHelper {

    private final Pane cardPane;
    private final StackPane donutPane;
    private final Circle trackCircle;
    private final Arc arcHigh;
    private final Arc arcSuspicious;
    private final Arc arcInfo;
    private final Label totalCountLabel;
    private final Label totalSubLabel;
    private final HBox legendHigh;
    private final Label legendHighPct;
    private final HBox legendSusp;
    private final Label legendSuspPct;
    private final HBox legendInfo;
    private final Label legendInfoPct;

    // Data is supplied by Spring event statistics after the view loads.
    private int targetTotal;
    private int targetHighPct;
    private int targetSuspPct;
    private int targetInfoPct;

    // Target arc sweep angles (clockwise negative degrees in JavaFX coordinates)
    private double highTargetLen() { return -360.0 * targetHighPct / 100.0; }
    private double suspiciousTargetLen() { return -360.0 * targetSuspPct / 100.0; }
    private double infoTargetLen() { return -360.0 * targetInfoPct / 100.0; }

    // Animation controllers
    private Timeline entranceTimeline;
    private Timeline pulseTimeline;
    private boolean isHovered = false;
    private boolean isAnimating = false;

    private static final String DEFAULT_SUB_LABEL = "Total threats";

    public ThreatInsightsDonutHelper(
            Pane cardPane,
            StackPane donutPane,
            Circle trackCircle,
            Arc arcHigh,
            Arc arcSuspicious,
            Arc arcInfo,
            Label totalCountLabel,
            Label totalSubLabel,
            HBox legendHigh,
            Label legendHighPct,
            HBox legendSusp,
            Label legendSuspPct,
            HBox legendInfo,
            Label legendInfoPct
    ) {
        this.cardPane = cardPane;
        this.donutPane = donutPane;
        this.trackCircle = trackCircle;
        this.arcHigh = arcHigh;
        this.arcSuspicious = arcSuspicious;
        this.arcInfo = arcInfo;
        this.totalCountLabel = totalCountLabel;
        this.totalSubLabel = totalSubLabel;
        this.legendHigh = legendHigh;
        this.legendHighPct = legendHighPct;
        this.legendSusp = legendSusp;
        this.legendSuspPct = legendSuspPct;
        this.legendInfo = legendInfo;
        this.legendInfoPct = legendInfoPct;
    }

    /**
     * Initializes cursors, hover micro-interactions, resting state, and replay listeners.
     */
    public void setup() {
        setInstantVisible();

        if (donutPane != null) {
            donutPane.setCursor(Cursor.HAND);
            donutPane.setOnMouseClicked(e -> {
                e.consume();
                playEntranceAnimation();
            });
        }

        if (cardPane != null) {
            cardPane.setOnMouseClicked(e -> {
                playEntranceAnimation();
            });
        }

        setupHoverInteractions();
    }

    /**
     * Sets the donut and legend elements to their fully-rendered resting values.
     */
    public void setInstantVisible() {
        stopAllAnimations();

        if (arcHigh != null) {
            arcHigh.setStartAngle(90.0);
            arcHigh.setLength(highTargetLen());
            arcHigh.setStrokeWidth(14.0);
            arcHigh.setOpacity(1.0);
            arcHigh.setEffect(null);
        }
        if (arcSuspicious != null) {
            arcSuspicious.setStartAngle(90.0 + highTargetLen());
            arcSuspicious.setLength(suspiciousTargetLen());
            arcSuspicious.setStrokeWidth(14.0);
            arcSuspicious.setOpacity(1.0);
            arcSuspicious.setEffect(null);
        }
        if (arcInfo != null) {
            arcInfo.setStartAngle(90.0 + highTargetLen() + suspiciousTargetLen());
            arcInfo.setLength(infoTargetLen());
            arcInfo.setStrokeWidth(14.0);
            arcInfo.setOpacity(1.0);
            arcInfo.setEffect(null);
        }

        if (totalCountLabel != null) {
            totalCountLabel.setText(String.valueOf(targetTotal));
            totalCountLabel.setScaleX(1.0);
            totalCountLabel.setScaleY(1.0);
        }
        if (totalSubLabel != null) {
            totalSubLabel.setText(DEFAULT_SUB_LABEL);
            totalSubLabel.setOpacity(1.0);
            totalSubLabel.setTranslateY(0.0);
        }

        if (legendHigh != null) {
            legendHigh.setOpacity(1.0);
            legendHigh.setTranslateX(0.0);
            legendHigh.getStyleClass().remove("wd-threat-legend-hover");
        }
        if (legendHighPct != null) legendHighPct.setText(targetHighPct + "%");

        if (legendSusp != null) {
            legendSusp.setOpacity(1.0);
            legendSusp.setTranslateX(0.0);
            legendSusp.getStyleClass().remove("wd-threat-legend-hover");
        }
        if (legendSuspPct != null) legendSuspPct.setText(targetSuspPct + "%");

        if (legendInfo != null) {
            legendInfo.setOpacity(1.0);
            legendInfo.setTranslateX(0.0);
            legendInfo.getStyleClass().remove("wd-threat-legend-hover");
        }
        if (legendInfoPct != null) legendInfoPct.setText(targetInfoPct + "%");

        startPulse();
    }

    private void setupHoverInteractions() {
        if (arcHigh != null && legendHigh != null) {
            setupSegmentHover(arcHigh, legendHigh, Color.web("#EF4444"), "18", "High Risk (40%)");
        }
        if (arcSuspicious != null && legendSusp != null) {
            setupSegmentHover(arcSuspicious, legendSusp, Color.web("#F59E0B"), "16", "Suspicious (35%)");
        }
        if (arcInfo != null && legendInfo != null) {
            setupSegmentHover(arcInfo, legendInfo, Color.web("#3B82F6"), "11", "Info (25%)");
        }
    }

    private void setupSegmentHover(Arc targetArc, HBox targetLegend, Color color, String countStr, String labelStr) {
        targetArc.setCursor(Cursor.HAND);
        if (targetLegend != null) {
            targetLegend.setCursor(Cursor.HAND);
        }

        Runnable onEnter = () -> {
            if (isAnimating) return;
            isHovered = true;
            stopPulse();

            // 1. Thicken & glow the inspected segment
            targetArc.setStrokeWidth(17.5);
            DropShadow glow = new DropShadow(BlurType.GAUSSIAN, color.deriveColor(0, 1, 1, 0.45), 14, 0.25, 0, 0);
            targetArc.setEffect(glow);

            // 2. Gently soften sibling arcs to draw focus
            if (arcHigh != null && arcHigh != targetArc) arcHigh.setOpacity(0.35);
            if (arcSuspicious != null && arcSuspicious != targetArc) arcSuspicious.setOpacity(0.35);
            if (arcInfo != null && arcInfo != targetArc) arcInfo.setOpacity(0.35);

            // 3. Highlight legend row
            if (targetLegend != null && !targetLegend.getStyleClass().contains("wd-threat-legend-hover")) {
                targetLegend.getStyleClass().add("wd-threat-legend-hover");
            }

            // 4. Update center metrics to inspected segment
            if (totalCountLabel != null) {
                totalCountLabel.setText(countStr);
            }
            if (totalSubLabel != null) {
                totalSubLabel.setText(labelStr);
            }
        };

        Runnable onExit = () -> {
            if (isAnimating) return;
            isHovered = false;

            // 1. Restore segment stroke and effect
            targetArc.setStrokeWidth(14.0);
            targetArc.setEffect(null);

            // 2. Restore sibling arcs opacity
            if (arcHigh != null) arcHigh.setOpacity(1.0);
            if (arcSuspicious != null) arcSuspicious.setOpacity(1.0);
            if (arcInfo != null) arcInfo.setOpacity(1.0);

            // 3. Remove legend highlight
            if (targetLegend != null) {
                targetLegend.getStyleClass().remove("wd-threat-legend-hover");
            }

            // 4. Restore center metrics
            if (totalCountLabel != null) {
                totalCountLabel.setText(String.valueOf(targetTotal));
            }
            if (totalSubLabel != null) {
                totalSubLabel.setText(DEFAULT_SUB_LABEL);
            }

            // 5. Resume ambient vigilance pulse
            startPulse();
        };

        targetArc.setOnMouseEntered(e -> onEnter.run());
        targetArc.setOnMouseExited(e -> onExit.run());
        if (targetLegend != null) {
            targetLegend.setOnMouseEntered(e -> onEnter.run());
            targetLegend.setOnMouseExited(e -> onExit.run());
        }
    }

    /**
     * Plays the entrance sequence:
     * - Cascading clockwise ribbon sweep of the 3 arc segments (High Risk, Suspicious, Info)
     * - Total count-up from 0 to 45 with cubic ease-out and soft scale pop
     * - Staggered cascade for legend rows and percentage counters
     */
    public void playEntranceAnimation() {
        stopAllAnimations();
        isAnimating = true;
        isHovered = false;

        entranceTimeline = new Timeline();
        int totalFrames = 40;

        // KeyFrame 0: reset starting values at the very beginning of timeline playback
        entranceTimeline.getKeyFrames().add(new KeyFrame(Duration.ZERO, evt -> {
            if (arcHigh != null) {
                arcHigh.setLength(0.0);
                arcHigh.setStrokeWidth(14.0);
                arcHigh.setOpacity(1.0);
                arcHigh.setEffect(null);
            }
            if (arcSuspicious != null) {
                arcSuspicious.setLength(0.0);
                arcSuspicious.setStrokeWidth(14.0);
                arcSuspicious.setOpacity(1.0);
                arcSuspicious.setEffect(null);
            }
            if (arcInfo != null) {
                arcInfo.setLength(0.0);
                arcInfo.setStrokeWidth(14.0);
                arcInfo.setOpacity(1.0);
                arcInfo.setEffect(null);
            }

            if (totalCountLabel != null) {
                totalCountLabel.setText("0");
                totalCountLabel.setScaleX(1.0);
                totalCountLabel.setScaleY(1.0);
            }
            if (totalSubLabel != null) {
                totalSubLabel.setText(DEFAULT_SUB_LABEL);
                totalSubLabel.setOpacity(0.0);
                totalSubLabel.setTranslateY(5.0);
            }

            if (legendHigh != null) {
                legendHigh.setOpacity(0.0);
                legendHigh.setTranslateX(14.0);
                legendHigh.getStyleClass().remove("wd-threat-legend-hover");
            }
            if (legendHighPct != null) legendHighPct.setText("0%");

            if (legendSusp != null) {
                legendSusp.setOpacity(0.0);
                legendSusp.setTranslateX(14.0);
                legendSusp.getStyleClass().remove("wd-threat-legend-hover");
            }
            if (legendSuspPct != null) legendSuspPct.setText("0%");

            if (legendInfo != null) {
                legendInfo.setOpacity(0.0);
                legendInfo.setTranslateX(14.0);
                legendInfo.getStyleClass().remove("wd-threat-legend-hover");
            }
            if (legendInfoPct != null) legendInfoPct.setText("0%");
        }));

        // 1. Cascading Arcs Sweep
        // High Risk: 0ms -> 650ms
        // Suspicious: 200ms -> 850ms
        // Info: 400ms -> 1050ms
        for (int i = 1; i <= totalFrames; i++) {
            double p = (double) i / totalFrames;
            double ease = 1.0 - Math.pow(1.0 - p, 3.0); // cubic ease-out
            long t = Math.max(16, Math.round(p * 1100.0));

            // Arc 1: High Risk (0 to 650ms)
            double pHigh = Math.min(1.0, (double) t / 650.0);
            double easeHigh = 1.0 - Math.pow(1.0 - pHigh, 3.0);
            double lenHigh = highTargetLen() * easeHigh;

            // Arc 2: Suspicious (200ms to 850ms)
            double pSusp = Math.max(0.0, Math.min(1.0, (t - 200.0) / 650.0));
            double easeSusp = 1.0 - Math.pow(1.0 - pSusp, 3.0);
            double lenSusp = suspiciousTargetLen() * easeSusp;

            // Arc 3: Info (400ms to 1050ms)
            double pInfo = Math.max(0.0, Math.min(1.0, (t - 400.0) / 650.0));
            double easeInfo = 1.0 - Math.pow(1.0 - pInfo, 3.0);
            double lenInfo = infoTargetLen() * easeInfo;

            // Center count-up: 50ms to 1000ms
            double pCount = Math.max(0.0, Math.min(1.0, (t - 50.0) / 950.0));
            double easeCount = 1.0 - Math.pow(1.0 - pCount, 3.0);
            int countVal = (int) Math.round(targetTotal * easeCount);

            // Subtitle fade: 350ms to 850ms
            double pSub = Math.max(0.0, Math.min(1.0, (t - 350.0) / 500.0));
            double subOp = pSub;
            double subTy = 5.0 * (1.0 - pSub);

            // Legend 1 (High Risk): 150ms to 600ms
            double pLeg1 = Math.max(0.0, Math.min(1.0, (t - 150.0) / 450.0));
            double easeLeg1 = 1.0 - Math.pow(1.0 - pLeg1, 3.0);
            int pct1 = (int) Math.round(targetHighPct * easeLeg1);

            // Legend 2 (Suspicious): 300ms to 750ms
            double pLeg2 = Math.max(0.0, Math.min(1.0, (t - 300.0) / 450.0));
            double easeLeg2 = 1.0 - Math.pow(1.0 - pLeg2, 3.0);
            int pct2 = (int) Math.round(targetSuspPct * easeLeg2);

            // Legend 3 (Info): 450ms to 900ms
            double pLeg3 = Math.max(0.0, Math.min(1.0, (t - 450.0) / 450.0));
            double easeLeg3 = 1.0 - Math.pow(1.0 - pLeg3, 3.0);
            int pct3 = (int) Math.round(targetInfoPct * easeLeg3);

            entranceTimeline.getKeyFrames().add(new KeyFrame(Duration.millis(t), evt -> {
                if (arcHigh != null) { arcHigh.setStartAngle(90.0); arcHigh.setLength(lenHigh); }
                if (arcSuspicious != null) { arcSuspicious.setStartAngle(90.0 + lenHigh); arcSuspicious.setLength(lenSusp); }
                if (arcInfo != null) { arcInfo.setStartAngle(90.0 + lenHigh + lenSusp); arcInfo.setLength(lenInfo); }

                if (totalCountLabel != null) totalCountLabel.setText(String.valueOf(countVal));
                if (totalSubLabel != null) {
                    totalSubLabel.setOpacity(subOp);
                    totalSubLabel.setTranslateY(subTy);
                }

                if (legendHigh != null) {
                    legendHigh.setOpacity(easeLeg1);
                    legendHigh.setTranslateX(14.0 * (1.0 - easeLeg1));
                }
                if (legendHighPct != null) legendHighPct.setText(pct1 + "%");

                if (legendSusp != null) {
                    legendSusp.setOpacity(easeLeg2);
                    legendSusp.setTranslateX(14.0 * (1.0 - easeLeg2));
                }
                if (legendSuspPct != null) legendSuspPct.setText(pct2 + "%");

                if (legendInfo != null) {
                    legendInfo.setOpacity(easeLeg3);
                    legendInfo.setTranslateX(14.0 * (1.0 - easeLeg3));
                }
                if (legendInfoPct != null) legendInfoPct.setText(pct3 + "%");
            }));
        }

        entranceTimeline.setOnFinished(e -> {
            isAnimating = false;
            // Pop the center number softly on completion
            if (totalCountLabel != null) {
                totalCountLabel.setText(String.valueOf(targetTotal));
                ScaleTransition pop = new ScaleTransition(Duration.millis(140), totalCountLabel);
                pop.setFromX(1.0);
                pop.setFromY(1.0);
                pop.setToX(1.08);
                pop.setToY(1.08);
                pop.setAutoReverse(true);
                pop.setCycleCount(2);
                pop.play();
            }
            if (totalSubLabel != null) {
                totalSubLabel.setOpacity(1.0);
                totalSubLabel.setTranslateY(0.0);
            }
            startPulse();
        });

        entranceTimeline.play();
    }

    /**
     * Ambient living pulse: creates a subtle, elegant vigilance breathing effect on the
     * High Risk segment to convey continuous live protection.
     */
    private void startPulse() {
        stopPulse();
        if (arcHigh == null || isHovered) return;

        DropShadow ambientShadow = new DropShadow();
        ambientShadow.setBlurType(BlurType.GAUSSIAN);
        ambientShadow.setColor(Color.web("#EF4444", 0.0));
        ambientShadow.setRadius(0);
        ambientShadow.setSpread(0.2);
        arcHigh.setEffect(ambientShadow);

        pulseTimeline = new Timeline(
                new KeyFrame(Duration.ZERO,
                        new KeyValue(ambientShadow.colorProperty(), Color.web("#EF4444", 0.0)),
                        new KeyValue(ambientShadow.radiusProperty(), 0.0)
                ),
                new KeyFrame(Duration.millis(1400),
                        new KeyValue(ambientShadow.colorProperty(), Color.web("#EF4444", 0.35), Interpolator.EASE_BOTH),
                        new KeyValue(ambientShadow.radiusProperty(), 8.0, Interpolator.EASE_BOTH)
                ),
                new KeyFrame(Duration.millis(2800),
                        new KeyValue(ambientShadow.colorProperty(), Color.web("#EF4444", 0.0), Interpolator.EASE_BOTH),
                        new KeyValue(ambientShadow.radiusProperty(), 0.0, Interpolator.EASE_BOTH)
                )
        );
        pulseTimeline.setCycleCount(Animation.INDEFINITE);
        pulseTimeline.play();
    }

    private void stopPulse() {
        if (pulseTimeline != null) {
            pulseTimeline.stop();
            pulseTimeline = null;
        }
        if (arcHigh != null && !isHovered) {
            arcHigh.setEffect(null);
        }
    }

    /**
     * Stops all active transitions and timers to avoid CPU usage when the page is inactive.
     */
    public void stopAllAnimations() {
        if (entranceTimeline != null) {
            entranceTimeline.stop();
            entranceTimeline = null;
        }
        stopPulse();
        isAnimating = false;
    }

    /**
     * Updates target metrics if live telemetry changes, smoothly triggering the counters.
     */
    public void updateData(int total, int highPct, int suspPct, int infoPct) {
        this.targetTotal = Math.max(0, total);
        int normalizedTotal = Math.max(0, highPct) + Math.max(0, suspPct) + Math.max(0, infoPct);
        this.targetHighPct = normalizedTotal == 0 ? 0 : Math.max(0, highPct) * 100 / normalizedTotal;
        this.targetSuspPct = normalizedTotal == 0 ? 0 : Math.max(0, suspPct) * 100 / normalizedTotal;
        this.targetInfoPct = Math.max(0, 100 - this.targetHighPct - this.targetSuspPct);
        if (!isAnimating && !isHovered) {
            if (arcHigh != null) { arcHigh.setStartAngle(90.0); arcHigh.setLength(highTargetLen()); }
            if (arcSuspicious != null) { arcSuspicious.setStartAngle(90.0 + highTargetLen()); arcSuspicious.setLength(suspiciousTargetLen()); }
            if (arcInfo != null) { arcInfo.setStartAngle(90.0 + highTargetLen() + suspiciousTargetLen()); arcInfo.setLength(infoTargetLen()); }
            if (totalCountLabel != null) totalCountLabel.setText(String.valueOf(targetTotal));
            if (legendHighPct != null) legendHighPct.setText(targetHighPct + "%");
            if (legendSuspPct != null) legendSuspPct.setText(targetSuspPct + "%");
            if (legendInfoPct != null) legendInfoPct.setText(targetInfoPct + "%");
        }
    }
}
