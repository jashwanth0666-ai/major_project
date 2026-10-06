package com.aiwatchdog.backend.monitor;

import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
public class FileEngine {
    private static final Set<String> EXECUTABLE_EXTENSIONS = Set.of(
            "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "js", "msi", "com", "jar", "lnk");
    private static final Set<String> ACTIVE_OR_DISK_EXTENSIONS = Set.of("docm", "xlsm", "iso", "img", "vhd");

    public AnalysisSignals analyze(MonitorEventRequest request) {
        String action = canonical(request.action());
        if (!Set.of("FILE_CREATED", "FILE_MODIFIED", "FILE_RENAMED").contains(action)) {
            throw new IllegalArgumentException("Unsupported file action: " + action);
        }
        String name = safeBasename(request.resourceName());
        if (request.sizeBytes() != null && request.sizeBytes() < 0) {
            throw new IllegalArgumentException("size_bytes must not be negative");
        }
        int score = 0;
        List<String> reasons = new ArrayList<>();
        int dot = name.lastIndexOf('.');
        String extension = dot < 0 ? "" : name.substring(dot + 1).toLowerCase(Locale.ROOT);
        if (EXECUTABLE_EXTENSIONS.contains(extension)) {
            score = 85;
            reasons.add("File has an executable or script extension; content was not inspected");
        } else if (ACTIVE_OR_DISK_EXTENSIONS.contains(extension)) {
            score = 55;
            reasons.add("File type can contain active content or mounted images; content was not inspected");
        }
        return new AnalysisSignals(score, List.copyOf(reasons));
    }

    private String safeBasename(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("resource_name is required");
        String name = value.trim();
        if (name.length() > 260 || name.contains("/") || name.contains("\\") || name.equals(".") || name.equals("..")) {
            throw new IllegalArgumentException("resource_name must be a basename of at most 260 characters");
        }
        return name;
    }

    private String canonical(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("action is required");
        return value.trim().toUpperCase(Locale.ROOT);
    }
}
