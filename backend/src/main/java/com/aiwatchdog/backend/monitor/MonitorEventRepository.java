package com.aiwatchdog.backend.monitor;

import java.util.List;

public interface MonitorEventRepository {
    MonitorEventResult save(MonitorEventResult event);
    List<MonitorEventResult> findRecent(int limit);
}
