package com.aiwatchdog.backend.fileshield.service;

import java.nio.file.attribute.FileTime;

/** Internal stable identity snapshot used to recheck a file before sensitive operations. */
public record FileInspectionSnapshot(String sha256, long sizeBytes, String extension,
                                     FileTime createdAt, FileTime modifiedAt, String fileKey,
                                     SignatureInspection signature) { }
