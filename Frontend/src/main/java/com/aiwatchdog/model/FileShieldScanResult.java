package com.aiwatchdog.model;

/** Mirrors the Spring File Shield scan response. Statuses stay strings for forward compatibility. */
public record FileShieldScanResult(
        String fileName,
        String sha256,
        String reputationStatus,
        String scanStatus,
        String message,
        long sizeBytes,
        String reputationSource,
        String description,
        String filePath,
        String extension,
        String createdAt,
        String lastModifiedAt,
        String signatureStatus,
        String signerSubject,
        String signatureMessage) { }
