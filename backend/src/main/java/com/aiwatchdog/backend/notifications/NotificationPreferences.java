package com.aiwatchdog.backend.notifications;

/** Per-user local notification policy for findings already written to the audit history. */
public record NotificationPreferences(boolean enabled, boolean warnEnabled, boolean blockEnabled) {
    public static NotificationPreferences defaults() {
        return new NotificationPreferences(true, true, true);
    }
}
