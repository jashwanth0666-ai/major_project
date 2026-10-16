package com.aiwatchdog.backend.windowstelemetry;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProcessBehaviorCorrelatorTest {
    @Test
    void reportsOfficeToScriptHostCorrelationAndDeduplicatesEvent() {
        ProcessBehaviorCorrelator correlator = new ProcessBehaviorCorrelator(new ScriptThreatAnalyzer());
        WindowsSecurityEvent event = new WindowsSecurityEvent("Security", "Microsoft-Windows-Security-Auditing",
                4688, 42, Instant.parse("2026-01-01T00:00:00Z"),
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 900L,
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", 300L,
                null, null, 0, 0);

        var finding = correlator.accept(event);

        assertTrue(finding.isPresent());
        assertEquals("OFFICE_PARENT_STARTED_SCRIPT_HOST", finding.orElseThrow().evidence());
        assertEquals(900L, finding.orElseThrow().processId());
        assertTrue(correlator.accept(event).isEmpty());
    }

    @Test
    void ignoresUnrelatedProcessCreation() {
        ProcessBehaviorCorrelator correlator = new ProcessBehaviorCorrelator(new ScriptThreatAnalyzer());
        WindowsSecurityEvent event = new WindowsSecurityEvent("Security", "Microsoft-Windows-Security-Auditing",
                4688, 43, Instant.parse("2026-01-01T00:00:01Z"), "C:\\Windows\\System32\\notepad.exe", 901L,
                "C:\\Windows\\explorer.exe", 500L, null, null, 0, 0);

        assertTrue(correlator.accept(event).isEmpty());
    }
}
