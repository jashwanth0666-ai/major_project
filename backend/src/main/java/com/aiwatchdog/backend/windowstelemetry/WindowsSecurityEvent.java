package com.aiwatchdog.backend.windowstelemetry;

import java.time.Instant;

/** Allowlisted Windows event metadata; raw event XML and message text are never retained. */
public record WindowsSecurityEvent(
        String logName,
        String providerName,
        int eventId,
        long recordId,
        Instant timestamp,
        String processName,
        Long processId,
        String parentProcessName,
        Long parentProcessId,
        String transientContent,
        String scriptBlockId,
        int scriptMessageNumber,
        int scriptMessageTotal) {

    /** Compatibility constructor for security events whose payload is not needed for analysis. */
    public WindowsSecurityEvent(String logName, String providerName, int eventId, long recordId, Instant timestamp) {
        this(logName, providerName, eventId, recordId, timestamp, null, null, null, null, null, null, 0, 0);
    }
}
