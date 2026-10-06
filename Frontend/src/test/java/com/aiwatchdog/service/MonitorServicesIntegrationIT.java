package com.aiwatchdog.service;

import com.aiwatchdog.model.MonitorEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Run explicitly with FastAPI and Spring Boot running: mvn -Dtest=MonitorServicesIntegrationIT test. */
class MonitorServicesIntegrationIT {
    @TempDir Path temporaryDirectory;
    private final ApiService api = new ApiService();

    @Test
    void fileWatcherEventPassesThroughSpringPolicyAndSqlite() throws Exception {
        CompletableFuture<MonitorEvent> received = new CompletableFuture<>();
        try (FileSystemMonitorService monitor = new FileSystemMonitorService(
                api, received::complete, List.of(temporaryDirectory), List.of())) {
            assertTrue(monitor.start() >= 1);
            Files.writeString(temporaryDirectory.resolve("controlled-event.exe"), "metadata test only");
            MonitorEvent event = received.get(10, TimeUnit.SECONDS);

            assertEquals("FILE", event.eventType());
            assertEquals("controlled-event.exe", event.resourceName());
            assertEquals("HIGH_RISK", event.riskLevel());
            assertEquals("BLOCK", event.decision());
            assertTrue(api.getRecentMonitorEvents().stream()
                    .anyMatch(saved -> event.id().equals(saved.id())));
        }
    }

    @Test
    void processStartPassesThroughSpringPolicyAndSqlite() throws Exception {
        LinkedBlockingQueue<MonitorEvent> received = new LinkedBlockingQueue<>();
        String java = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString();
        String classpath = System.getProperty("java.class.path");
        try (ProcessMonitorService monitor = new ProcessMonitorService(api, received::offer)) {
            monitor.start();
            Process child = new ProcessBuilder(java, "-cp", classpath,
                    ProcessMonitorServiceTest.SleepProcess.class.getName()).start();
            try {
                MonitorEvent event = null;
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(12);
                while (System.nanoTime() < deadline) {
                    MonitorEvent candidate = received.poll(500, TimeUnit.MILLISECONDS);
                    if (candidate != null && candidate.processId().equals(child.pid())) {
                        event = candidate;
                        break;
                    }
                }
                assertNotNull(event, "expected to observe the controlled Java child process");
                MonitorEvent savedEvent = event;
                assertEquals("PROCESS", savedEvent.eventType());
                assertEquals("PROCESS_STARTED", savedEvent.action());
                assertEquals(child.pid(), savedEvent.processId());
                assertTrue(api.getRecentMonitorEvents().stream()
                        .anyMatch(saved -> savedEvent.id().equals(saved.id())));
            } finally {
                child.destroyForcibly();
            }
        }
    }
}
