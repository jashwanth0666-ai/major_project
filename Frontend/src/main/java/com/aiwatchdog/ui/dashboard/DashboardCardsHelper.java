package com.aiwatchdog.ui.dashboard;

import javafx.animation.*;
import javafx.application.Platform;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import javafx.scene.transform.Scale;
import javafx.util.Duration;
import org.kordamp.ikonli.javafx.FontIcon;

import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * UI Helper managing the 4 Stat Cards:
 * - Entrance staggered slide-up and fade-in
 * - Icon animations (Globe rotation, Warning shake, Target/Tick pop, Arrow float)
 * - Number count-up with cubic ease-out
 * - Hover elevation, icon tile fill transition, and bottom line draw
 */
public class DashboardCardsHelper {

    private static final NumberFormat NUMBER_FORMAT = NumberFormat.getIntegerInstance(Locale.US);

    public static class CardItem {
        public final Pane cardPane;
        public final StackPane iconTile;
        public final FontIcon fontIcon;
        public final Label trendArrow;
        public final Label countLabel;
        public final Region bottomLine;
        public final int targetCount;
        public final double decimalTarget;
        public final String decimalSuffix;
        public final String baseTileStyle;
        public final String hoverTileStyle;
        public final String baseIconColor;

        public CardItem(Pane cardPane, StackPane iconTile, FontIcon fontIcon,
                        Label trendArrow, Label countLabel, Region bottomLine,
                        int targetCount, String baseTileStyle, String hoverTileStyle, String baseIconColor) {
            this(cardPane, iconTile, fontIcon, trendArrow, countLabel, bottomLine, targetCount, 0.0, null, baseTileStyle, hoverTileStyle, baseIconColor);
        }

        public CardItem(Pane cardPane, StackPane iconTile, FontIcon fontIcon,
                        Label trendArrow, Label countLabel, Region bottomLine,
                        int targetCount, double decimalTarget, String decimalSuffix,
                        String baseTileStyle, String hoverTileStyle, String baseIconColor) {
            this.cardPane = cardPane;
            this.iconTile = iconTile;
            this.fontIcon = fontIcon;
            this.trendArrow = trendArrow;
            this.countLabel = countLabel;
            this.bottomLine = bottomLine;
            this.targetCount = targetCount;
            this.decimalTarget = decimalTarget;
            this.decimalSuffix = decimalSuffix;
            this.baseTileStyle = baseTileStyle;
            this.hoverTileStyle = hoverTileStyle;
            this.baseIconColor = baseIconColor;
        }
    }

    private final List<Animation> runningAnimations = new ArrayList<>();
    private final List<CardItem> cards = new ArrayList<>();

    public void registerCard(CardItem card) {
        cards.add(card);
    }

    public void setupAll() {
        for (int i = 0; i < cards.size(); i++) {
            CardItem c = cards.get(i);
            setupHoverAndBottomLine(c);
            setupIconAnimation(c.fontIcon, i);
        }
    }

    public void setInstantVisible() {
        for (CardItem item : cards) {
            if (item.cardPane != null) {
                item.cardPane.setOpacity(1.0);
                item.cardPane.setTranslateY(0.0);
            }
        }
    }

    /**
     * Staggered entrance animation for cards (0, 80, 160, 240 ms).
     */
    public void playEntranceAnimation() {
        for (int i = 0; i < cards.size(); i++) {
            CardItem item = cards.get(i);
            Pane card = item.cardPane;
            int delayMs = i * 80;

            card.setOpacity(0.0);
            card.setTranslateY(12.0);

            FadeTransition ft = new FadeTransition(Duration.millis(550), card);
            ft.setFromValue(0.0);
            ft.setToValue(1.0);
            ft.setInterpolator(Interpolator.EASE_BOTH);

            TranslateTransition tt = new TranslateTransition(Duration.millis(550), card);
            tt.setFromY(12.0);
            tt.setToY(0.0);
            tt.setInterpolator(Interpolator.EASE_OUT);

            ParallelTransition pt = new ParallelTransition(ft, tt);
            pt.setDelay(Duration.millis(delayMs));
            pt.play();

            // Count-up staggered by 100ms
            if (item.countLabel != null) {
                int countDelayMs = i * 100;
                if (item.decimalTarget > 0) {
                    animateCountUpDecimal(item.countLabel, 0.0, item.decimalTarget, item.decimalSuffix != null ? item.decimalSuffix : "", 1400, countDelayMs);
                } else if (item.targetCount > 0) {
                    animateCountUp(item.countLabel, 0, item.targetCount, 1400, countDelayMs);
                }
            }
        }
    }

    /**
     * Re-runs count-up for a specific label to a new value.
     */
    public void countUp(Label label, int targetValue) {
        int from = 0;
        try {
            if (label != null && label.getText() != null) {
                from = Integer.parseInt(label.getText().replaceAll("[^0-9]", ""));
            }
        } catch (Exception ignored) {}
        animateCountUp(label, from, targetValue, 1400, 0);
    }

    public static void animateCountUp(Label label, int fromVal, int toVal, long durationMs, long delayMs) {
        if (label == null) return;
        Timeline tl = new Timeline();
        int steps = Math.min(60, Math.max(1, Math.abs(toVal - fromVal)));
        for (int i = 0; i <= steps; i++) {
            double p = (double) i / steps;
            double ease = 1.0 - Math.pow(1.0 - p, 3.0); // cubic ease-out
            final int current = fromVal + (int) Math.round((toVal - fromVal) * ease);
            tl.getKeyFrames().add(new KeyFrame(
                    Duration.millis(delayMs + (i * ((double) durationMs / steps))),
                    e -> label.setText(NUMBER_FORMAT.format(current))
            ));
        }
        tl.play();
    }

    public static void animateCountUpDecimal(Label label, double fromVal, double toVal, String suffix, long durationMs, long delayMs) {
        if (label == null) return;
        Timeline tl = new Timeline();
        int steps = 50;
        for (int i = 0; i <= steps; i++) {
            double p = (double) i / steps;
            double ease = 1.0 - Math.pow(1.0 - p, 3.0); // cubic ease-out
            final double current = fromVal + (toVal - fromVal) * ease;
            tl.getKeyFrames().add(new KeyFrame(
                    Duration.millis(delayMs + (i * ((double) durationMs / steps))),
                    e -> label.setText(String.format(Locale.US, "%.1f%s", current, suffix))
            ));
        }
        tl.play();
    }

    private void setupHoverAndBottomLine(CardItem item) {
        Pane card = item.cardPane;
        Region line = item.bottomLine;
        StackPane tile = item.iconTile;
        FontIcon icon = item.fontIcon;

        if (card == null) return;

        TranslateTransition lift = new TranslateTransition(Duration.millis(250), card);
        TranslateTransition drop = new TranslateTransition(Duration.millis(250), card);

        final Scale lineScale;
        final Timeline drawLine;
        final Timeline retractLine;

        if (line != null) {
            // Bottom line starts hidden at scaleX 0, anchored at the left edge
            line.setPrefHeight(3.0);
            line.setMinHeight(3.0);
            line.setMaxHeight(3.0);
            line.setMaxWidth(Double.MAX_VALUE);

            lineScale = new Scale(0.0, 1.0, 0.0, 0.0);
            line.getTransforms().add(lineScale);

            drawLine = new Timeline();
            retractLine = new Timeline();
        } else {
            lineScale = null;
            drawLine = null;
            retractLine = null;
        }

        card.setOnMouseEntered(e -> {
            card.getStyleClass().add("wd-card-hover");
            lift.stop();
            lift.setFromY(card.getTranslateY());
            lift.setToY(-3.0);
            lift.play();

            if (tile != null && item.baseTileStyle != null && item.hoverTileStyle != null) {
                tile.getStyleClass().remove(item.baseTileStyle);
                if (!tile.getStyleClass().contains(item.hoverTileStyle)) {
                    tile.getStyleClass().add(item.hoverTileStyle);
                }
            }
            if (icon != null && item.hoverTileStyle != null) {
                icon.setIconColor(Color.WHITE);
            }

            if (line != null && drawLine != null && retractLine != null && lineScale != null) {
                retractLine.stop();
                drawLine.stop();
                drawLine.getKeyFrames().setAll(
                        new KeyFrame(Duration.ZERO, new KeyValue(lineScale.xProperty(), lineScale.getX())),
                        new KeyFrame(Duration.millis(450), new KeyValue(lineScale.xProperty(), 1.0, Interpolator.EASE_OUT))
                );
                drawLine.play();
            }
        });

        card.setOnMouseExited(e -> {
            card.getStyleClass().remove("wd-card-hover");
            drop.stop();
            drop.setFromY(card.getTranslateY());
            drop.setToY(0.0);
            drop.play();

            if (tile != null && item.baseTileStyle != null && item.hoverTileStyle != null) {
                tile.getStyleClass().remove(item.hoverTileStyle);
                if (!tile.getStyleClass().contains(item.baseTileStyle)) {
                    tile.getStyleClass().add(item.baseTileStyle);
                }
            }
            if (icon != null && item.baseIconColor != null) {
                icon.setIconColor(Color.web(item.baseIconColor));
            }

            if (line != null && drawLine != null && retractLine != null && lineScale != null) {
                drawLine.stop();
                retractLine.stop();
                retractLine.getKeyFrames().setAll(
                        new KeyFrame(Duration.ZERO, new KeyValue(lineScale.xProperty(), lineScale.getX())),
                        new KeyFrame(Duration.millis(250), new KeyValue(lineScale.xProperty(), 0.0, Interpolator.EASE_OUT))
                );
                retractLine.play();
            }
        });
    }

    private void setupIconAnimation(FontIcon icon, int index) {
        if (icon == null) return;
        String literal = icon.getIconLiteral();
        if (literal == null) literal = "";

        if (literal.contains("globe") || literal.contains("target")) {
            // Slow, serene rotation (12 seconds per full turn) as in security overview
            setupGlobeRotation(icon);
        } else {
            // Gentle, slow popup (scale up to 1.08 with 2800ms-3400ms cycle, no vibrate)
            long cycle = 2800 + ((index % 4) * 200L);
            setupSlowPopup(icon, cycle);
        }
    }

    public static RotateTransition createSlowRotation(Node node) {
        if (node instanceof javafx.scene.text.Text) {
            ((javafx.scene.text.Text) node).setBoundsType(javafx.scene.text.TextBoundsType.VISUAL);
        }
        node.setCache(true);
        node.setCacheHint(javafx.scene.CacheHint.ROTATE);
        if (node.getParent() instanceof javafx.scene.layout.Region) {
            ((javafx.scene.layout.Region) node.getParent()).setSnapToPixel(false);
        } else {
            node.parentProperty().addListener((obs, oldP, newP) -> {
                if (newP instanceof javafx.scene.layout.Region) {
                    ((javafx.scene.layout.Region) newP).setSnapToPixel(false);
                }
            });
        }

        RotateTransition rt = new RotateTransition(Duration.seconds(12), node);
        rt.setByAngle(360);
        rt.setInterpolator(Interpolator.LINEAR);
        rt.setCycleCount(Animation.INDEFINITE);
        rt.play();
        return rt;
    }

    private void setupGlobeRotation(Node globe) {
        RotateTransition rt = createSlowRotation(globe);
        runningAnimations.add(rt);
    }

    private void setupSlowPopup(Node node, long cycleMs) {
        ScaleTransition st = new ScaleTransition(Duration.millis(cycleMs), node);
        st.setFromX(1.0);
        st.setFromY(1.0);
        st.setToX(1.08);
        st.setToY(1.08);
        st.setAutoReverse(true);
        st.setCycleCount(Animation.INDEFINITE);
        st.setInterpolator(Interpolator.EASE_BOTH);
        st.play();
        runningAnimations.add(st);
    }

    private void setupTrendArrowAnimation(Node arrow) {
        // Disabled: keep arrows completely static so nothing vibrates
    }

    public void stopAllAnimations() {
        for (Animation a : runningAnimations) {
            a.stop();
        }
    }

    public void resumeAllAnimations() {
        for (Animation a : runningAnimations) {
            a.play();
        }
    }
}
