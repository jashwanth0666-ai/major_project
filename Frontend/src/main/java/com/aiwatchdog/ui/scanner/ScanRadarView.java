package com.aiwatchdog.ui.scanner;

import javafx.animation.Interpolator;
import javafx.geometry.Point2D;
import javafx.scene.Group;
import javafx.scene.effect.BlurType;
import javafx.scene.effect.DropShadow;
import javafx.scene.effect.GaussianBlur;
import javafx.scene.layout.Pane;
import javafx.scene.paint.Color;
import javafx.scene.paint.CycleMethod;
import javafx.scene.paint.LinearGradient;
import javafx.scene.paint.Stop;
import javafx.scene.shape.Circle;
import javafx.scene.shape.SVGPath;
import javafx.scene.shape.StrokeLineCap;
import javafx.scene.shape.StrokeLineJoin;
import javafx.scene.transform.Rotate;
import javafx.scene.transform.Scale;
import javafx.scene.transform.Translate;

/**
 * Native JavaFX Radar visualization for the "Analyzing Website" screen.
 * Implements Section 5, 6, and 9 specifications:
 * - 300x300 container with center (150, 150)
 * - Three rings: radii 138, 100, 63 (stroke #b3ead2, width 1.6)
 * - 53° sweep rotating clockwise at 80°/s (one turn every 4.5s)
 * - Four telemetry nodes with idle drift (+/-2.2° angle, +/-1.8px radius)
 * - Hot-node scaling (1.14) and glow rise (0.20 to 0.55) when wedge passes
 * - Breathing core glow, finish state (white tick), and failure state (red core with "!")
 */
public class ScanRadarView extends Pane {

    private static final double C0 = 150.0;
    private static final double DEG2RAD = Math.PI / 180.0;

    private static final Color SWEEP_GREEN = Color.web("#10B981");
    private static final Color CORE_GREEN_1 = Color.web("#34D399");
    private static final Color CORE_GREEN_2 = Color.web("#10B981");
    private static final Color CORE_FAIL_1 = Color.web("#F87171");
    private static final Color CORE_FAIL_2 = Color.web("#EF4444");

    // Rings
    private final Circle ringOuter;
    private final Circle ringMid;
    private final Circle ringInner;

    // Sweep Group
    private final Group sweepGroup;
    private final Rotate sweepRotate;
    private final SVGPath sweepWedge;
    private final SVGPath sweepArc;
    private final Circle sweepDot;

    // Core
    private final Circle coreGlow;
    private final Circle coreCircle;
    private final SVGPath shieldIcon;
    private final SVGPath tickIcon;
    private final SVGPath bangIcon;

    // Nodes
    private static class NodeData {
        final double baseAngle;
        final double phase;
        final Color borderColor;
        final Color glowColor;
        final Group group;
        final Circle glow;
        final Circle circle;
        final SVGPath icon;
        double scale = 1.0;

        NodeData(double angle, double phase, Color borderColor, Color glowColor,
                 String iconPath, boolean dark) {
            this.baseAngle = angle;
            this.phase = phase;
            this.borderColor = borderColor;
            this.glowColor = glowColor;

            this.group = new Group();

            this.glow = new Circle(0, 0, 23);
            this.glow.setFill(glowColor);
            this.glow.setOpacity(0.20);
            this.glow.setEffect(new GaussianBlur(6));

            this.circle = new Circle(0, 0, 19.5);
            this.circle.setFill(dark ? Color.web("#141414") : Color.WHITE);
            this.circle.setStroke(borderColor);
            this.circle.setStrokeWidth(2.4);

            this.icon = new SVGPath();
            this.icon.setContent(iconPath);
            this.icon.setFill(Color.TRANSPARENT);
            this.icon.setStroke(dark ? Color.web("#F5F5F5") : Color.web("#1E293B"));
            this.icon.setStrokeWidth(1.8);
            this.icon.setStrokeLineCap(StrokeLineCap.ROUND);
            this.icon.setStrokeLineJoin(StrokeLineJoin.ROUND);
            this.icon.getTransforms().addAll(new Scale(0.74, 0.74), new Translate(-12, -12));

            this.group.getChildren().addAll(this.glow, this.circle, this.icon);
        }
    }

    private final NodeData[] nodes = new NodeData[4];
    private double currentRot = 0.0;

    public ScanRadarView() {
        setPrefSize(300, 300);
        setMinSize(300, 300);
        setMaxSize(300, 300);
        setScaleX(0.92);
        setScaleY(0.92);

        boolean dark = isDark();

        // 1. Concentric rings (radii 138, 100, 63)
        Color ringColor = dark ? Color.web("#1C3A2E") : Color.web("#B3EAD2");
        ringOuter = new Circle(C0, C0, 138);
        ringOuter.setFill(Color.TRANSPARENT);
        ringOuter.setStroke(ringColor);
        ringOuter.setStrokeWidth(1.6);

        ringMid = new Circle(C0, C0, 100);
        ringMid.setFill(Color.TRANSPARENT);
        ringMid.setStroke(ringColor);
        ringMid.setStrokeWidth(1.6);

        ringInner = new Circle(C0, C0, 63);
        ringInner.setFill(Color.TRANSPARENT);
        ringInner.setStroke(ringColor);
        ringInner.setStrokeWidth(1.6);

        getChildren().addAll(ringOuter, ringMid, ringInner);

        // 2. Sweep: 53° wedge (26° to 79°), 3px arc on radius 138, green dot on 26° edge
        sweepGroup = new Group();
        sweepRotate = new Rotate(0, C0, C0);
        sweepGroup.getTransforms().add(sweepRotate);

        Point2D p26 = polarToXY(26.0, 138.0);
        Point2D p79 = polarToXY(79.0, 138.0);

        sweepWedge = new SVGPath();
        sweepWedge.setContent(String.format(java.util.Locale.US,
                "M %.2f %.2f L %.2f %.2f A 138 138 0 0 1 %.2f %.2f Z",
                C0, C0, p26.getX(), p26.getY(), p79.getX(), p79.getY()));
        sweepWedge.setFill(Color.color(SWEEP_GREEN.getRed(), SWEEP_GREEN.getGreen(), SWEEP_GREEN.getBlue(), 0.16));

        sweepArc = new SVGPath();
        sweepArc.setContent(String.format(java.util.Locale.US,
                "M %.2f %.2f A 138 138 0 0 0 %.2f %.2f",
                p79.getX(), p79.getY(), p26.getX(), p26.getY()));
        sweepArc.setFill(Color.TRANSPARENT);
        sweepArc.setStroke(SWEEP_GREEN);
        sweepArc.setStrokeWidth(3.0);
        sweepArc.setStrokeLineCap(StrokeLineCap.ROUND);

        sweepDot = new Circle(p26.getX(), p26.getY(), 5.8);
        sweepDot.setFill(SWEEP_GREEN);
        sweepDot.setStroke(Color.WHITE);
        sweepDot.setStrokeWidth(2.2);

        sweepGroup.getChildren().addAll(sweepWedge, sweepArc, sweepDot);
        getChildren().add(sweepGroup);

        // 3. Four telemetry nodes at radius ~104
        // Document: 205.3°, #bcd0ff
        nodes[0] = new NodeData(205.3, 0.0 * 1.7, Color.web("#BCD0FF"), Color.web("#7AA2FF"),
                "M7 3h7l4 4v14H7z M14 3v4h4 M10 12h5 M10 16h5", dark);
        // Cloud: -23.3°, #b5e8e0
        nodes[1] = new NodeData(-23.3, 1.0 * 1.7, Color.web("#B5E8E0"), Color.web("#5FD3C4"),
                "M7 18a4 4 0 010-8 5.5 5.5 0 0110.5 1.5A3.3 3.3 0 0117 18z", dark);
        // Shield: 128.3°, #a9e3cb
        nodes[2] = new NodeData(128.3, 2.0 * 1.7, Color.web("#A9E3CB"), Color.web("#34D399"),
                "M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z", dark);
        // Clock: 49.2°, #fbd9a0
        nodes[3] = new NodeData(49.2, 3.0 * 1.7, Color.web("#FBD9A0"), Color.web("#F6AD3C"),
                "M12 3a9 9 0 100 18 9 9 0 000-18z M12 7v5l3 2", dark);

        for (NodeData nd : nodes) {
            getChildren().add(nd.group);
        }

        // 4. Central Core: radius 46, gradient #34d399 to #10b981, soft green glow
        coreGlow = new Circle(C0, C0, 50);
        coreGlow.setFill(SWEEP_GREEN);
        coreGlow.setOpacity(0.28);
        coreGlow.setEffect(new GaussianBlur(8));

        coreCircle = new Circle(C0, C0, 46);
        updateCoreGradient(false);
        coreCircle.setEffect(new DropShadow(BlurType.GAUSSIAN, Color.color(SWEEP_GREEN.getRed(), SWEEP_GREEN.getGreen(), SWEEP_GREEN.getBlue(), 0.35), 22, 0.15, 0, 0));

        // Core icon 1: Shield (default)
        shieldIcon = new SVGPath();
        shieldIcon.setContent("M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z");
        shieldIcon.setFill(Color.TRANSPARENT);
        shieldIcon.setStroke(Color.WHITE);
        shieldIcon.setStrokeWidth(1.8);
        shieldIcon.setStrokeLineJoin(StrokeLineJoin.ROUND);
        shieldIcon.getTransforms().addAll(new Translate(C0, C0), new Scale(1.15, 1.15), new Translate(-12, -12));

        // Core icon 2: Tick (finish)
        tickIcon = new SVGPath();
        tickIcon.setContent("M5 12.5l4.5 4.5L19 7.5");
        tickIcon.setFill(Color.TRANSPARENT);
        tickIcon.setStroke(Color.WHITE);
        tickIcon.setStrokeWidth(2.4);
        tickIcon.setStrokeLineCap(StrokeLineCap.ROUND);
        tickIcon.setStrokeLineJoin(StrokeLineJoin.ROUND);
        tickIcon.getTransforms().addAll(new Translate(C0, C0), new Scale(1.5, 1.5), new Translate(-12, -12));
        tickIcon.setOpacity(0.0);

        // Core icon 3: Exclamation / Bang (failure)
        bangIcon = new SVGPath();
        bangIcon.setContent("M12 7v6.2M12 16.6v.1");
        bangIcon.setFill(Color.TRANSPARENT);
        bangIcon.setStroke(Color.WHITE);
        bangIcon.setStrokeWidth(2.6);
        bangIcon.setStrokeLineCap(StrokeLineCap.ROUND);
        bangIcon.getTransforms().addAll(new Translate(C0, C0), new Scale(1.5, 1.5), new Translate(-12, -12));
        bangIcon.setOpacity(0.0);

        getChildren().addAll(coreGlow, coreCircle, shieldIcon, tickIcon, bangIcon);

        reset();
    }

    public void reset() {
        currentRot = 0.0;
        sweepRotate.setAngle(0.0);
        sweepGroup.setOpacity(1.0);
        shieldIcon.setOpacity(1.0);
        tickIcon.setOpacity(0.0);
        bangIcon.setOpacity(0.0);
        updateCoreGradient(false);
        coreGlow.setFill(SWEEP_GREEN);

        for (NodeData nd : nodes) {
            nd.scale = 1.0;
            Point2D pt = polarToXY(nd.baseAngle, 104.0);
            nd.group.setTranslateX(pt.getX());
            nd.group.setTranslateY(pt.getY());
            nd.group.setScaleX(1.0);
            nd.group.setScaleY(1.0);
            nd.glow.setOpacity(0.20);
        }
    }

    /**
     * Called on each frame by the master AnimationTimer.
     * @param tMs timestamp in milliseconds
     * @param dtMs elapsed milliseconds since previous frame
     * @param ended true if completed or failed
     * @param doneElapsedMs milliseconds elapsed since completion
     * @param failed true if scan failed
     */
    public void update(double tMs, double dtMs, boolean ended, double doneElapsedMs, boolean failed) {
        if (failed) {
            shieldIcon.setOpacity(0.0);
            tickIcon.setOpacity(0.0);
            bangIcon.setOpacity(1.0);
            updateCoreGradient(true);
            coreGlow.setFill(CORE_FAIL_2);
            return; // Sweep stops on failure
        }

        // 1. Clockwise sweep rotation (+80 deg/s)
        double f = ended ? Math.max(0.15, 1.0 - doneElapsedMs / 900.0) : 1.0;
        currentRot += dtMs * 0.08 * (ended ? f * 0.3 : 1.0);
        sweepRotate.setAngle(currentRot);

        // Sweep fade out on completion (over 700ms)
        if (ended) {
            double swOp = Math.max(0.0, 1.0 - doneElapsedMs / 700.0);
            sweepGroup.setOpacity(swOp);
            shieldIcon.setOpacity(0.0);
            tickIcon.setOpacity(1.0);
            bangIcon.setOpacity(0.0);
        } else {
            sweepGroup.setOpacity(1.0);
            shieldIcon.setOpacity(1.0);
            tickIcon.setOpacity(0.0);
            bangIcon.setOpacity(0.0);
        }

        // 2. Core glow breathing (period ~3.8s)
        coreGlow.setOpacity(0.22 + 0.10 * Math.sin(tMs / 600.0));

        // 3. Telemetry nodes idle drift and hot-node scaling
        double head = (((26.0 + currentRot) % 360.0) + 360.0) % 360.0;

        for (NodeData n : nodes) {
            // Idle drift: +/-2.2 deg angle, +/-1.8 px radius
            double a = n.baseAngle + 2.2 * Math.sin(tMs / 1300.0 + n.phase);
            double r = 104.0 + 1.8 * Math.sin(tMs / 900.0 + n.phase * 2.0);
            Point2D pt = polarToXY(a, r);
            n.group.setTranslateX(pt.getX());
            n.group.setTranslateY(pt.getY());

            // Wedge containment test (53° wedge clockwise from head)
            double rel = (((n.baseAngle - head) % 360.0) + 360.0) % 360.0;
            boolean hot = !ended && (rel <= 53.0);

            // Eased scale (target 1.14 when hot, 1.0 when idle)
            double targetScale = hot ? 1.14 : 1.0;
            n.scale += (targetScale - n.scale) * Math.min(1.0, dtMs / 120.0);
            n.group.setScaleX(n.scale);
            n.group.setScaleY(n.scale);

            // Glow opacity (0.55 when hot, 0.20 when idle)
            n.glow.setOpacity(hot ? 0.55 : 0.20);
        }
    }

    private void updateCoreGradient(boolean bad) {
        Color c1 = bad ? CORE_FAIL_1 : CORE_GREEN_1;
        Color c2 = bad ? CORE_FAIL_2 : CORE_GREEN_2;
        LinearGradient grad = new LinearGradient(0, 0, 1, 1, true, CycleMethod.NO_CYCLE,
                new Stop(0, c1), new Stop(1, c2));
        coreCircle.setFill(grad);
    }

    private Point2D polarToXY(double angleDeg, double radius) {
        double rad = angleDeg * DEG2RAD;
        return new Point2D(C0 + radius * Math.cos(rad), C0 + radius * Math.sin(rad));
    }

    private boolean isDark() {
        if (getScene() != null && getScene().getStylesheets() != null) {
            for (String css : getScene().getStylesheets()) {
                if (css.contains("app-dark.css")) return true;
            }
        }
        return false;
    }
}
