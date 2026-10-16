package com.aiwatchdog.model;

import java.time.Instant;

public record WindowsTelemetryProviderStatus(String provider, String state, String errorCategory,
                                             String message, Instant lastEventTimestamp, long eventsReceived) { }
