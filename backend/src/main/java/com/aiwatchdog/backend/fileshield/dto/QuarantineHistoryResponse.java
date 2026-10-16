package com.aiwatchdog.backend.fileshield.dto;

import java.util.List;

public record QuarantineHistoryResponse(List<QuarantineOperationResult> active, List<QuarantineOperationResult> recent) {
    public QuarantineHistoryResponse {
        active = active == null ? List.of() : List.copyOf(active);
        recent = recent == null ? List.of() : List.copyOf(recent);
    }
}
