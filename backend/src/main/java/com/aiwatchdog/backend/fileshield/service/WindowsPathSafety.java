package com.aiwatchdog.backend.fileshield.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Rejects Windows reparse points, including junctions that Java's symbolic-link check alone may miss. */
@Component
public class WindowsPathSafety {
    private static final String SCRIPT = "$ErrorActionPreference='Stop'; $paths=ConvertFrom-Json -InputObject $env:AIWD_PATHS_JSON; "
            + "foreach($p in $paths){$i=Get-Item -Force -LiteralPath ([string]$p) -ErrorAction Stop; "
            + "$r=($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0; "
            + "[Console]::Out.WriteLine([string]$r)}";
    private final ObjectMapper mapper = new ObjectMapper();

    public void rejectReparseComponents(Path path) throws IOException {
        Path normalized = path.toAbsolutePath().normalize();
        List<String> existing = new ArrayList<>();
        Path cursor = normalized.getRoot();
        if (cursor != null && Files.exists(cursor, java.nio.file.LinkOption.NOFOLLOW_LINKS)) existing.add(cursor.toString());
        for (Path part : normalized) {
            cursor = cursor == null ? part : cursor.resolve(part);
            if (Files.exists(cursor, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(cursor)) throw new IOException("Symbolic link or reparse point rejected.");
                existing.add(cursor.toString());
            }
        }
        if (!System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win")) return;
        String root = System.getenv("SystemRoot");
        if (root == null || root.isBlank()) throw new IOException("Windows path safety provider is unavailable.");
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(Path.of(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe").toString(),
                    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-");
            builder.redirectError(ProcessBuilder.Redirect.DISCARD);
            builder.environment().put("AIWD_PATHS_JSON", mapper.writeValueAsString(existing));
            process = builder.start();
            try (var input = process.getOutputStream()) { input.write(SCRIPT.getBytes(StandardCharsets.UTF_8)); }
            if (!process.waitFor(3, TimeUnit.SECONDS)) {
                process.destroyForcibly(); throw new IOException("Windows reparse-point inspection timed out.");
            }
            byte[] bytes;
            try (var output = process.getInputStream()) { bytes = output.readNBytes(8193); }
            if (process.exitValue() != 0 || bytes.length > 8192) throw new IOException("Windows reparse-point inspection failed.");
            String[] lines = new String(bytes, StandardCharsets.UTF_8).trim().split("\\R");
            if (existing.isEmpty() && lines.length == 1 && lines[0].isEmpty()) return;
            if (lines.length != existing.size()) throw new IOException("Windows reparse-point inspection returned incomplete results.");
            for (String line : lines) if (Boolean.parseBoolean(line.trim())) throw new IOException("Windows reparse point rejected.");
        } catch (InterruptedException interrupted) {
            if (process != null) process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new IOException("Windows reparse-point inspection was interrupted.", interrupted);
        } catch (RuntimeException exception) {
            if (process != null) process.destroyForcibly();
            throw new IOException("Windows reparse-point inspection failed.", exception);
        }
    }
}
