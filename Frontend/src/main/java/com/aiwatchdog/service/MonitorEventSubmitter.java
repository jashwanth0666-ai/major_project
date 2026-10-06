package com.aiwatchdog.service;

import com.aiwatchdog.model.MonitorEvent;

@FunctionalInterface
public interface MonitorEventSubmitter {
    MonitorEvent submit(String eventType, String action, String resourceName,
                        Long processId, Long sizeBytes) throws Exception;
}
