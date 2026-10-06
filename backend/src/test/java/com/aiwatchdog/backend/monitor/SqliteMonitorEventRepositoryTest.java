package com.aiwatchdog.backend.monitor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SqliteMonitorEventRepositoryTest {
    @TempDir Path temporaryDirectory;

    @Test
    void persistsAndReadsMonitorEventsUsingConfiguredDatabase() {
        SqliteMonitorEventRepository repository = new SqliteMonitorEventRepository(
                temporaryDirectory.resolve("monitor-events.db").toString());
        MonitorEventResult input = new MonitorEventResult(null, Instant.now(), "FILE", "FILE_CREATED",
                "setup.exe", null, 512L, 85, "HIGH_RISK", "BLOCK", List.of("name rule"));

        MonitorEventResult saved = repository.save(input);
        List<MonitorEventResult> recent = repository.findRecent(10);

        assertNotNull(saved.id());
        assertEquals(1, recent.size());
        assertEquals("setup.exe", recent.getFirst().resourceName());
        assertEquals(input.timestamp(), recent.getFirst().timestamp());
        assertEquals(List.of("name rule"), recent.getFirst().reasons());
    }
}
