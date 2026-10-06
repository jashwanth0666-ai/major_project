package com.aiwatchdog.backend.monitor;

import com.aiwatchdog.backend.policy.PolicyEngineImpl;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MonitorEventAnalyzerTest {
    @Test
    void executableFileIsAssessedByRulesAndPolicy() {
        InMemoryRepository repository = new InMemoryRepository();
        MonitorEventAnalyzer analyzer = analyzer(repository);

        MonitorEventResult result = analyzer.analyze(
                new MonitorEventRequest("FILE", "FILE_CREATED", "invoice.exe", null, 1234L));

        assertEquals("HIGH_RISK", result.riskLevel());
        assertEquals("BLOCK", result.decision());
        assertTrue(result.reasons().getFirst().contains("content was not inspected"));
        assertEquals(result, repository.saved);
    }

    @Test
    void ordinaryFileDoesNotReceiveAThreatVerdict() {
        MonitorEventAnalyzer analyzer = analyzer(new InMemoryRepository());

        MonitorEventResult result = analyzer.analyze(
                new MonitorEventRequest("FILE", "FILE_CREATED", "notes.txt", null, 50L));

        assertEquals("SAFE", result.riskLevel());
        assertEquals("ALLOW", result.decision());
        assertTrue(result.reasons().getFirst().contains("not a malware verdict"));
    }

    @Test
    void pathDataIsRejectedSoOnlyBasenamesCanBeLogged() {
        MonitorEventAnalyzer analyzer = analyzer(new InMemoryRepository());

        assertThrows(IllegalArgumentException.class, () -> analyzer.analyze(
                new MonitorEventRequest("FILE", "FILE_CREATED", "C:\\Users\\person\\invoice.exe", null, 4L)));
    }

    @Test
    void dualUseProcessIsWarnedWithoutInspectingArguments() {
        MonitorEventAnalyzer analyzer = analyzer(new InMemoryRepository());
        MonitorEventResult result = analyzer.analyze(
                new MonitorEventRequest("PROCESS", "PROCESS_STARTED", "powershell.exe", 1234L, null));

        assertEquals("SUSPICIOUS", result.riskLevel());
        assertEquals("WARN", result.decision());
        assertTrue(result.reasons().getFirst().contains("command line and process behavior were not inspected"));
    }

    private static class InMemoryRepository implements MonitorEventRepository {
        private MonitorEventResult saved;
        @Override public MonitorEventResult save(MonitorEventResult event) {
            saved = new MonitorEventResult(1L, event.timestamp(), event.eventType(), event.action(),
                    event.resourceName(), event.processId(), event.sizeBytes(), event.riskScore(),
                    event.riskLevel(), event.decision(), event.reasons());
            return saved;
        }
        @Override public List<MonitorEventResult> findRecent(int limit) { return new ArrayList<>(); }
    }

    private MonitorEventAnalyzer analyzer(MonitorEventRepository repository) {
        return new MonitorEventAnalyzer(new FileEngine(), new ProcessEngine(), new HeuristicRiskEngine(),
                new PolicyEngineImpl(), repository);
    }
}
