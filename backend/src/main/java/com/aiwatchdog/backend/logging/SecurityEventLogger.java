package com.aiwatchdog.backend.logging;

public interface SecurityEventLogger {

    void log(SecurityEvent event);

    /** Store a structured assessment in the same canonical security event history. */
    void logAssessment(SecurityEvent event);

    /** Persists a file-shield operation in the existing structured security_events table. */
    default void logOperation(SecurityEvent event) { logAssessment(event); }
}
