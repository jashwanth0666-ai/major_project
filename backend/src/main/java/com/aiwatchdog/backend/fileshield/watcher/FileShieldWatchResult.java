package com.aiwatchdog.backend.fileshield.watcher;

import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.aiwatchdog.backend.fileshield.model.ScanStatus;

import java.time.Instant;

/** Safe, structured observation of an automatic read-only scan. Full local paths are omitted. */
public record FileShieldWatchResult(
        String fileName,
        String eventType,
        String sha256,
        ReputationStatus reputationStatus,
        ScanStatus scanStatus,
        String message,
        Instant observedAt) { }
