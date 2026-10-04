package com.aiwatchdog.ui;

import javafx.animation.RotateTransition;
import javafx.animation.ScaleTransition;
import javafx.animation.SequentialTransition;
import javafx.animation.TranslateTransition;
import javafx.collections.ListChangeListener;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.control.ButtonBase;
import javafx.util.Duration;

/**
 * UI-only motion helper for native JavaFX buttons per Section B9.
 * Smooth 120-160ms transitions for hover and press states without modifying
 * button handlers or business logic.
 */
public class WdButtonFx {

    public static void installAll(Parent root) {
        if (root == null) return;
        findAndInstall(root);
        root.getChildrenUnmodifiable().addListener((ListChangeListener<Node>) c -> {
            while (c.next()) {
                if (c.wasAdded()) {
                    for (Node n : c.getAddedSubList()) {
                        if (n instanceof Parent) {
                            findAndInstall((Parent) n);
                        } else if (n instanceof ButtonBase) {
                            install((ButtonBase) n);
                        }
                    }
                }
            }
        });
    }

    private static void findAndInstall(Parent parent) {
        for (Node child : parent.getChildrenUnmodifiable()) {
            if (child instanceof ButtonBase) {
                install((ButtonBase) child);
            } else if (child.getStyleClass().contains("icon-btn-round")) {
                installIconRound(child);
            }
            if (child instanceof Parent) {
                findAndInstall((Parent) child);
            }
        }
    }

    public static void install(ButtonBase b) {
        if (b == null) return;
        if (Boolean.TRUE.equals(b.getProperties().get("wd-fx-installed"))) return;
        b.getProperties().put("wd-fx-installed", true);

        boolean isStatic = b.getStyleClass().contains("wd-btn--static");

        if (!isStatic) {
            TranslateTransition tt = new TranslateTransition(Duration.millis(140), b);
            ScaleTransition st = new ScaleTransition(Duration.millis(120), b);

            b.hoverProperty().addListener((obs, oldVal, hovered) -> {
                if (b.isPressed()) return;
                tt.stop();
                if (hovered) {
                    tt.setToY(-1.0);
                } else {
                    tt.setToY(0.0);
                }
                tt.play();
            });

            b.pressedProperty().addListener((obs, oldVal, pressed) -> {
                st.stop();
                tt.stop();
                if (pressed) {
                    st.setDuration(Duration.millis(90));
                    st.setToX(0.97);
                    st.setToY(0.97);
                    tt.setToY(0.0);
                } else {
                    st.setDuration(Duration.millis(120));
                    st.setToX(1.0);
                    st.setToY(1.0);
                    if (b.isHover()) {
                        tt.setToY(-1.0);
                    } else {
                        tt.setToY(0.0);
                    }
                }
                st.play();
                tt.play();
            });
        }

        // Icon animations:
        // wd-btn--spin: rotate icon/graphic 180 degrees on hover
        if (b.getStyleClass().contains("wd-btn--spin")) {
            Node target = b.getGraphic() != null ? b.getGraphic() : b;
            RotateTransition rt = new RotateTransition(Duration.millis(250), target);
            b.hoverProperty().addListener((obs, oldVal, hovered) -> {
                rt.stop();
                if (hovered) {
                    rt.setToAngle(180);
                } else {
                    rt.setToAngle(0);
                }
                rt.play();
            });
        }

        // wd-btn--back: nudge graphic or button -3px left on hover
        if (b.getStyleClass().contains("wd-btn--back")) {
            Node target = b.getGraphic() != null ? b.getGraphic() : b;
            TranslateTransition lt = new TranslateTransition(Duration.millis(160), target);
            b.hoverProperty().addListener((obs, oldVal, hovered) -> {
                lt.stop();
                if (hovered) {
                    lt.setToX(-3.0);
                } else {
                    lt.setToX(0.0);
                }
                lt.play();
            });
        }
    }

    private static void installIconRound(Node node) {
        if (Boolean.TRUE.equals(node.getProperties().get("wd-fx-installed"))) return;
        node.getProperties().put("wd-fx-installed", true);

        if (node.getStyleClass().contains("wd-btn--bell")) {
            Node bellIcon = node;
            if (node instanceof Parent) {
                Parent p = (Parent) node;
                if (!p.getChildrenUnmodifiable().isEmpty()) {
                    bellIcon = p.getChildrenUnmodifiable().get(0);
                }
            }
            final Node animTarget = bellIcon;
            node.hoverProperty().addListener((obs, oldVal, hovered) -> {
                if (hovered) {
                    RotateTransition rt1 = new RotateTransition(Duration.millis(120), animTarget);
                    rt1.setToAngle(14);
                    RotateTransition rt2 = new RotateTransition(Duration.millis(140), animTarget);
                    rt2.setToAngle(-10);
                    RotateTransition rt3 = new RotateTransition(Duration.millis(100), animTarget);
                    rt3.setToAngle(5);
                    RotateTransition rt4 = new RotateTransition(Duration.millis(80), animTarget);
                    rt4.setToAngle(0);

                    SequentialTransition seq = new SequentialTransition(rt1, rt2, rt3, rt4);
                    seq.play();
                } else {
                    animTarget.setRotate(0);
                }
            });
        }
    }
}
