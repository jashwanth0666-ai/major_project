package com.aiwatchdog.model;

import java.time.Instant;
import java.util.List;

public record WindowsTelemetrySettings(boolean enabled, boolean windowsTelemetryEnabled, boolean scriptMonitoringEnabled,
                                       boolean processMonitoringEnabled, boolean supported, boolean running, String state, String errorCategory,
                                       String message, Instant startedAt, long droppedEvents, int restartCount,
                                       List<WindowsTelemetryProviderStatus> providers) {
    public WindowsTelemetrySettings {
        providers = providers == null ? List.of() : List.copyOf(providers);
    }

    public WindowsTelemetryHealth health() {
        return new WindowsTelemetryHealth(enabled, windowsTelemetryEnabled, scriptMonitoringEnabled, processMonitoringEnabled,
                supported, running, state, errorCategory,
                message, startedAt, droppedEvents, restartCount, providers);
    }
}
