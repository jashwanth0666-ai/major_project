package com.aiwatchdog.model;

public record QuarantineOperation(String operationId, String state, boolean success, String fileName,
                                  String sha256, String originalPath, String quarantinePath,
                                  String destinationPath, String signatureStatus, String timestamp, String message) { }
