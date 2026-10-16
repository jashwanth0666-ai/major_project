package com.aiwatchdog.backend.windowstelemetry;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/** Bounded, in-memory correlation for Security 4688/4689 events; it does not keep command lines. */
@Component
public class ProcessBehaviorCorrelator {
    private static final int MAX_PROCESSES = 8192;
    private static final int MAX_DEDUP = 16384;
    private static final Duration RETENTION = Duration.ofMinutes(30);
    private static final Set<String> SCRIPT_HOSTS = Set.of("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe");
    private static final Set<String> DUAL_USE_TOOLS = Set.of("certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe");
    private static final Set<String> OFFICE = Set.of("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe");
    private final LinkedHashMap<Long, ProcessSnapshot> processes = new LinkedHashMap<>();
    private final LinkedHashMap<String, Boolean> seenRecords = new LinkedHashMap<>();
    private final ScriptThreatAnalyzer scriptAnalyzer;

    public ProcessBehaviorCorrelator(ScriptThreatAnalyzer scriptAnalyzer) { this.scriptAnalyzer = scriptAnalyzer; }

    public synchronized Optional<ProcessFinding> accept(WindowsSecurityEvent event) {
        if (event == null || event.timestamp() == null || !"Security".equalsIgnoreCase(event.logName())) return Optional.empty();
        String identity = event.logName() + ":" + event.eventId() + ":" + event.recordId() + ":" + event.timestamp();
        if (seenRecords.putIfAbsent(identity, Boolean.TRUE) != null) return Optional.empty();
        trimDedup();
        Instant timestamp = event.timestamp();
        processes.entrySet().removeIf(entry -> entry.getValue().timestamp().isBefore(timestamp.minus(RETENTION)));

        if (event.eventId() == 4689) {
            if (event.processId() != null) {
                ProcessSnapshot prior = processes.get(event.processId());
                if (prior != null && !timestamp.isBefore(prior.timestamp())) processes.remove(event.processId());
            }
            return Optional.empty();
        }
        if (event.eventId() != 4688 || event.processId() == null || event.processId() <= 0) return Optional.empty();

        String name = basename(event.processName());
        if (name.isBlank()) return Optional.empty();
        String parent = basename(event.parentProcessName());
        if (parent.isBlank() && event.parentProcessId() != null) {
            ProcessSnapshot parentSnapshot = processes.get(event.parentProcessId());
            if (parentSnapshot != null && !timestamp.isBefore(parentSnapshot.timestamp())) parent = parentSnapshot.name();
        }
        ProcessSnapshot previous = processes.get(event.processId());
        if (previous == null || !timestamp.isBefore(previous.timestamp())) {
            if (processes.size() >= MAX_PROCESSES) processes.remove(processes.keySet().iterator().next());
            processes.put(event.processId(), new ProcessSnapshot(name, event.parentProcessId(), parent, timestamp));
        }

        List<String> commandIndicators = scriptAnalyzer.inspectText(event.transientContent());
        String reason = null;
        if (OFFICE.contains(parent) && SCRIPT_HOSTS.contains(name)) {
            reason = "OFFICE_PARENT_STARTED_SCRIPT_HOST";
        } else if (SCRIPT_HOSTS.contains(parent) && DUAL_USE_TOOLS.contains(name)) {
            reason = "SCRIPT_HOST_STARTED_DUAL_USE_UTILITY";
        } else if (!commandIndicators.isEmpty()) {
            reason = "PROCESS_COMMAND_MATCHED_SCRIPT_RULES:" + String.join(",", commandIndicators);
        }
        if (reason == null) return Optional.empty();
        return Optional.of(new ProcessFinding(event.processId(), name, timestamp,
                parent.isBlank() ? "Parent process unavailable" : "Parent process: " + parent,
                reason));
    }

    private String basename(String value) {
        if (value == null || value.isBlank()) return "";
        String normalized = value.replace('/', '\\');
        int separator = normalized.lastIndexOf('\\');
        String result = separator >= 0 ? normalized.substring(separator + 1) : normalized;
        return result.toLowerCase(Locale.ROOT);
    }

    private void trimDedup() {
        while (seenRecords.size() > MAX_DEDUP) seenRecords.remove(seenRecords.keySet().iterator().next());
    }

    private record ProcessSnapshot(String name, Long parentPid, String parentName, Instant timestamp) { }
    public record ProcessFinding(Long processId, String processName, Instant timestamp, String parentSummary, String evidence) { }
}
