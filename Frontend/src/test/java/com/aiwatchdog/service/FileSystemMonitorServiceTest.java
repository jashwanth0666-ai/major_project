package com.aiwatchdog.service;

import com.aiwatchdog.model.MonitorEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class FileSystemMonitorServiceTest {
    @TempDir Path temporaryDirectory;

    @Test
    void watchesConfiguredFolderAndSubmitsOnlyTheBasename() throws Exception {
        CompletableFuture<MonitorEvent> received = new CompletableFuture<>();
        MonitorEventSubmitter sink = (type, action, name, pid, size) ->
                new MonitorEvent(1L, Instant.now().toString(), type, action, name, pid, size,
                        0, "SAFE", "ALLOW", List.of("test"));
        Path nested = Files.createDirectories(temporaryDirectory.resolve("nested"));
        try (FileSystemMonitorService monitor = new FileSystemMonitorService(
                sink, received::complete, List.of(temporaryDirectory), List.of())) {
            assertTrue(monitor.start() >= 2);
            Files.writeString(nested.resolve("notes.txt"), "controlled test event");

            MonitorEvent event = received.get(5, TimeUnit.SECONDS);
            assertEquals("FILE", event.eventType());
            assertEquals("notes.txt", event.resourceName());
            assertFalse(event.resourceName().contains(temporaryDirectory.toString()));
            assertTrue(List.of("FILE_CREATED", "FILE_MODIFIED").contains(event.action()));
        }
    }
}
