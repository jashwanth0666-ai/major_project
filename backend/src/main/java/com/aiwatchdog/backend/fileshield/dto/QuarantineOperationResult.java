package com.aiwatchdog.backend.fileshield.dto;

import java.time.Instant;

public record QuarantineOperationResult(String operationId, String state, boolean success,
                                        String fileName, String sha256, String originalPath,
                                        String quarantinePath, String destinationPath,
                                        String signatureStatus, Instant timestamp, String message) { }
