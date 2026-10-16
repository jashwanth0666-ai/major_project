package com.aiwatchdog.backend.windowstelemetry;

import java.time.Instant;
import java.util.List;

public record WindowsTelemetryHealth(
        boolean enabled,
        boolean windowsTelemetryEnabled,
        boolean scriptMonitoringEnabled,
        boolean processMonitoringEnabled,
        boolean supported,
        boolean running,
        String state,
        String errorCategory,
        String message,
        Instant startedAt,
        long droppedEvents,
        int restartCount,
        List<WindowsTelemetryProviderStatus> providers) {
    public WindowsTelemetryHealth {
        providers = providers == null ? List.of() : List.copyOf(providers);
    }
}
