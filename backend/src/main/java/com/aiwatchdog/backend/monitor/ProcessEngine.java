package com.aiwatchdog.backend.monitor;

import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
public class ProcessEngine {
    private static final Set<String> DUAL_USE_WINDOWS_TOOLS = Set.of(
            "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe");

    public AnalysisSignals analyze(MonitorEventRequest request) {
        if (!"PROCESS_STARTED".equals(canonical(request.action()))) {
            throw new IllegalArgumentException("Unsupported process action: " + request.action());
        }
        if (request.processId() == null || request.processId() < 0) {
            throw new IllegalArgumentException("process_id is required");
        }
        String name = request.resourceName();
        if (name == null || name.isBlank() || name.length() > 260 || name.contains("/") || name.contains("\\")) {
            throw new IllegalArgumentException("resource_name must be an executable basename");
        }
        if (DUAL_USE_WINDOWS_TOOLS.contains(name.trim().toLowerCase(Locale.ROOT))) {
            return new AnalysisSignals(55,
                    List.of("Dual-use Windows utility started; command line and process behavior were not inspected"));
        }
        return new AnalysisSignals(0, List.of());
    }

    private String canonical(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("action is required");
        return value.trim().toUpperCase(Locale.ROOT);
    }
}
