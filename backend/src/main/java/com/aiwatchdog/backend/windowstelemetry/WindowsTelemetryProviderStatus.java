package com.aiwatchdog.backend.windowstelemetry;

import java.time.Instant;

public record WindowsTelemetryProviderStatus(
        String provider,
        String state,
        String errorCategory,
        String message,
        Instant lastEventTimestamp,
        long eventsReceived) { }
