package com.aiwatchdog.backend.fileshield.dto;

import jakarta.validation.constraints.NotBlank;

public record FileScanRequest(@NotBlank String path) { }
