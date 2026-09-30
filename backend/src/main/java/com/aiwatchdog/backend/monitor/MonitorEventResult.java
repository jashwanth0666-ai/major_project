package com.aiwatchdog.backend.monitor;

import java.time.Instant;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonFormat;

public record MonitorEventResult(
        Long id,
        Instant timestamp,
        String eventType,
        String action,
        String resourceName,
        Long processId,
        Long sizeBytes,
        int riskScore,
        String riskLevel,
        String decision,
        @JsonFormat(without = JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED) List<String> reasons) {
}
