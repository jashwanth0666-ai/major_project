package com.aiwatchdog.service;

import com.aiwatchdog.model.MonitorEvent;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class ProcessMonitorServiceTest {
    @Test
    void reportsNewProcessNameAndPidWithoutArguments() throws Exception {
        LinkedBlockingQueue<MonitorEvent> observed = new LinkedBlockingQueue<>();
        MonitorEventSubmitter sink = (type, action, name, pid, size) -> {
            MonitorEvent event = new MonitorEvent(1L, Instant.now().toString(), type, action, name, pid, size,
                    0, "SAFE", "ALLOW", List.of("test"));
            observed.offer(event);
            return event;
        };
        String java = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString();
        String classpath = System.getProperty("java.class.path");
        try (ProcessMonitorService monitor = new ProcessMonitorService(sink, observed::offer)) {
            monitor.start();
            Process child = new ProcessBuilder(java, "-cp", classpath,
                    ProcessMonitorServiceTest.SleepProcess.class.getName()).start();
            try {
                MonitorEvent event = null;
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(12);
                while (System.nanoTime() < deadline) {
                    MonitorEvent candidate = observed.poll(500, TimeUnit.MILLISECONDS);
                    if (candidate != null && candidate.processId().equals(child.pid())) {
                        event = candidate;
                        break;
                    }
                }
                assertNotNull(event, "expected to observe the controlled child process");
                assertEquals("PROCESS", event.eventType());
                assertEquals("PROCESS_STARTED", event.action());
                assertTrue(event.processId() > 0);
                assertTrue(event.resourceName().toLowerCase().endsWith("java.exe"));
            } finally {
                child.destroyForcibly();
            }
        }
    }

    public static class SleepProcess {
        public static void main(String[] args) throws InterruptedException {
            Thread.sleep(10_000);
        }
    }
}
