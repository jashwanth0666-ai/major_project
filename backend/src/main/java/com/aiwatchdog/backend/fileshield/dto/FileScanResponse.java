package com.aiwatchdog.backend.fileshield.dto;

import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.aiwatchdog.backend.fileshield.model.ScanStatus;
import java.time.Instant;

public record FileScanResponse(String fileName, String sha256, ReputationStatus reputationStatus,
                               ScanStatus scanStatus, String message, long sizeBytes,
                               String reputationSource, String description, String filePath,
                               String extension, Instant createdAt, Instant lastModifiedAt,
                               String signatureStatus, String signerSubject, String signatureMessage) {
    public FileScanResponse(String fileName, String sha256, ReputationStatus reputationStatus,
                            ScanStatus scanStatus, String message, long sizeBytes,
                            String reputationSource, String description) {
        this(fileName, sha256, reputationStatus, scanStatus, message, sizeBytes,
                reputationSource, description, null, null, null, null, null, null, null);
    }
}
