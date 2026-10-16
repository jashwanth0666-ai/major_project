package com.aiwatchdog.model;

import java.util.List;

public record QuarantineHistory(List<QuarantineOperation> active, List<QuarantineOperation> recent) {
    public QuarantineHistory {
        active = active == null ? List.of() : List.copyOf(active);
        recent = recent == null ? List.of() : List.copyOf(recent);
    }
}
