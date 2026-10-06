package com.aiwatchdog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record MonitorEvent(
        Long id,
        String timestamp,
        String eventType,
        String action,
        String resourceName,
        Long processId,
        Long sizeBytes,
        int riskScore,
        String riskLevel,
        String decision,
        List<String> reasons) {
}
