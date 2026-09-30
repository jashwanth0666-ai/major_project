package com.aiwatchdog.backend.monitor;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record MonitorEventRequest(
        @NotBlank String eventType,
        @NotBlank String action,
        @NotBlank String resourceName,
        Long processId,
        Long sizeBytes) {
}
