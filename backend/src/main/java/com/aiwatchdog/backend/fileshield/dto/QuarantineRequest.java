package com.aiwatchdog.backend.fileshield.dto;

public record QuarantineRequest(String path, String expectedSha256, boolean confirmed) { }
