package com.aiwatchdog.backend.windowstelemetry;

import java.time.Instant;
import java.util.List;

public record WindowsTelemetrySettingsResponse(
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
    public WindowsTelemetrySettingsResponse {
        providers = providers == null ? List.of() : List.copyOf(providers);
    }

    public static WindowsTelemetrySettingsResponse from(WindowsTelemetryHealth health) {
        return new WindowsTelemetrySettingsResponse(health.enabled(), health.windowsTelemetryEnabled(),
                health.scriptMonitoringEnabled(), health.processMonitoringEnabled(), health.supported(), health.running(), health.state(),
                health.errorCategory(), health.message(), health.startedAt(), health.droppedEvents(),
                health.restartCount(), health.providers());
    }
}
