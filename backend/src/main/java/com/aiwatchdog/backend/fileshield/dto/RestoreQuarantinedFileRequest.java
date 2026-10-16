package com.aiwatchdog.backend.fileshield.dto;

public record RestoreQuarantinedFileRequest(String destinationPath, boolean confirmed, boolean reinspect) { }
