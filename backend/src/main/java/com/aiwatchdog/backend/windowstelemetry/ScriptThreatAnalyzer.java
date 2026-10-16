package com.aiwatchdog.backend.windowstelemetry;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/** Bounded static inspection. Input text is analyzed in memory and never returned or logged. */
@Component
public class ScriptThreatAnalyzer {
    public static final int MAX_SCRIPT_BYTES = 1_048_576;
    public static final int MAX_TELEMETRY_TEXT_CHARS = 262_144;
    public static final int MAX_SCRIPT_FRAGMENT_CHARS = 32_768;
    private static final int MAX_SCRIPT_FRAGMENTS = 8;
    private static final Set<String> SCRIPT_EXTENSIONS = Set.of(
            ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta");
    private static final Pattern ENCODED = Pattern.compile("(?i)(?:-enc(?:odedcommand)?\\s+|frombase64string\\s*\\()([a-z0-9+/]{80,}={0,2})?");
    private static final Pattern DOWNLOAD = Pattern.compile("(?is)(?:downloadstring|downloadfile|invoke-webrequest|\\biwr\\b|\\bcurl\\b|\\bbitsadmin\\b).{0,500}(?:invoke-expression|\\biex\\b|start-process|\\s-i\\s)");
    private static final Pattern EXECUTE_DOWNLOAD = Pattern.compile("(?is)(?:invoke-expression|\\biex\\b|start-process).{0,500}(?:downloadstring|downloadfile|invoke-webrequest|\\biwr\\b|\\bcurl\\b)");
    private static final Pattern PERSISTENCE = Pattern.compile("(?is)(?:schtasks(?:\\.exe)?\\s+.{0,80}/create|register-scheduledtask|new-service|sc(?:\\.exe)?\\s+create|currentversion\\\\run|\\bstartup\\b).{0,200}(?:powershell|wscript|cscript|mshta|\\.ps1|\\.vbs|\\.js)?");
    private static final Pattern INJECTION = Pattern.compile("(?is)(?:virtualalloc|writeprocessmemory).{0,500}(?:createremotethread|ntqueueapcthread)|(?:createremotethread|ntqueueapcthread).{0,500}(?:virtualalloc|writeprocessmemory)");
    private static final Pattern DUAL_USE = Pattern.compile("(?i)(?:powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32).{0,160}(?:certutil|bitsadmin|mshta|rundll32|regsvr32)");
    private static final Pattern KNOWN_TOOL_MARKER = Pattern.compile("(?i)\\b(?:invoke-mimikatz|invoke-reflectivepeinjection|invoke-shellcode|empire\\.ps|mimikatz\\.exe)\\b");
    private static final Pattern COMPLEXITY_TOKEN = Pattern.compile("(?i)(?:frombase64string|\\[char\\]|-join|convertfrom-base64)");
    private final ConcurrentHashMap<String, Instant> recentFindings = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ScriptAssembly> scriptAssemblies = new ConcurrentHashMap<>();

    public Optional<ScriptAnalysis> inspectFile(Path path) throws IOException {
        if (path == null || Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
        String name = path.getFileName() == null ? "" : path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        if (dot < 0 || !SCRIPT_EXTENSIONS.contains(name.substring(dot).toLowerCase(Locale.ROOT))) return Optional.empty();
        long size = Files.size(path);
        if (size < 1 || size > MAX_SCRIPT_BYTES) return Optional.empty();
        byte[] bytes;
        try (var input = Files.newInputStream(path)) { bytes = input.readNBytes(MAX_SCRIPT_BYTES + 1); }
        if (bytes.length == 0 || bytes.length > MAX_SCRIPT_BYTES) return Optional.empty();
        String text = decode(bytes);
        List<String> evidence = inspectText(text);
        if (evidence.isEmpty()) return Optional.empty();
        String digest = digest(bytes);
        Instant now = Instant.now();
        recentFindings.entrySet().removeIf(entry -> entry.getValue().isBefore(now.minusSeconds(1800)));
        if (recentFindings.size() > 4096) recentFindings.clear();
        String pathKey = digest(path.toAbsolutePath().normalize().toString().getBytes(StandardCharsets.UTF_8));
        String key = digest + ":" + pathKey + ":" + evidence;
        if (recentFindings.putIfAbsent(key, now) != null) return Optional.empty();
        return Optional.of(new ScriptAnalysis("STATIC_SCRIPT_FILE", evidence, 65, now));
    }

    /** Accepts transient event text only; callers must persist the returned rule labels, never this input. */
    public List<String> inspectText(String text) {
        if (text == null || text.isBlank() || text.length() > MAX_TELEMETRY_TEXT_CHARS) return List.of();
        String sample = text.toLowerCase(Locale.ROOT);
        List<String> findings = new ArrayList<>(4);
        if (ENCODED.matcher(sample).find()) findings.add("ENCODED_OR_BASE64_SCRIPT_CONTENT");
        if (DOWNLOAD.matcher(sample).find() || EXECUTE_DOWNLOAD.matcher(sample).find()) findings.add("DOWNLOAD_AND_EXECUTE_PATTERN");
        if (PERSISTENCE.matcher(sample).find()) findings.add("SCRIPT_PERSISTENCE_PATTERN");
        if (INJECTION.matcher(sample).find()) findings.add("PROCESS_INJECTION_API_COMBINATION");
        if (DUAL_USE.matcher(sample).find()) findings.add("SCRIPT_AND_ADMIN_UTILITY_COMBINATION");
        if (KNOWN_TOOL_MARKER.matcher(sample).find()) findings.add("KNOWN_OFFENSIVE_TOOL_MARKER");
        if (sample.length() >= 4096 && countComplexityTokens(sample) >= 12) findings.add("HIGH_COMPLEXITY_OBFUSCATION_PATTERN");
        return List.copyOf(findings);
    }

    private int countComplexityTokens(String text) {
        var matcher = COMPLEXITY_TOKEN.matcher(text);
        int count = 0;
        while (matcher.find() && count < 12) count++;
        return count;
    }

    private String decode(byte[] bytes) {
        if (bytes.length >= 2 && bytes[0] == (byte) 0xff && bytes[1] == (byte) 0xfe)
            return new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_16LE);
        if (bytes.length >= 2 && bytes[0] == (byte) 0xfe && bytes[1] == (byte) 0xff)
            return new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_16BE);
        if (bytes.length >= 3 && bytes[0] == (byte) 0xef && bytes[1] == (byte) 0xbb && bytes[2] == (byte) 0xbf)
            return new String(bytes, 3, bytes.length - 3, StandardCharsets.UTF_8);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public Optional<ScriptAnalysis> inspectObservedText(String source, String text, Instant timestamp) {
        List<String> evidence = inspectText(text);
        if (evidence.isEmpty()) return Optional.empty();
        return Optional.of(new ScriptAnalysis(source, evidence, 70, timestamp == null ? Instant.now() : timestamp));
    }

    public Optional<ScriptAnalysis> inspectObservedFragment(String source, String blockId, int messageNumber,
                                                             int messageTotal, String fragment, Instant timestamp) {
        if (fragment == null || fragment.length() > MAX_SCRIPT_FRAGMENT_CHARS) return Optional.empty();
        if (blockId == null || blockId.isBlank() || messageNumber < 1 || messageTotal < 1
                || messageTotal > MAX_SCRIPT_FRAGMENTS || messageNumber > messageTotal) {
            return inspectObservedText(source, fragment, timestamp);
        }
        scriptAssemblies.entrySet().removeIf(entry -> entry.getValue().createdAt.isBefore(Instant.now().minusSeconds(120)));
        if (scriptAssemblies.size() >= 256 && !scriptAssemblies.containsKey(blockId)) scriptAssemblies.clear();
        ScriptAssembly assembly = scriptAssemblies.computeIfAbsent(blockId, ignored -> new ScriptAssembly(messageTotal, Instant.now()));
        String complete = assembly.add(messageNumber, messageTotal, fragment);
        if (complete == null) return Optional.empty();
        scriptAssemblies.remove(blockId, assembly);
        return inspectObservedText(source, complete, timestamp);
    }

    private String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    public record ScriptAnalysis(String source, List<String> evidence, int score, Instant observedAt) {
        public ScriptAnalysis { evidence = List.copyOf(evidence); }
    }

    private static final class ScriptAssembly {
        private final int total;
        private final Instant createdAt;
        private final String[] parts;
        private int size;
        private int received;

        private ScriptAssembly(int total, Instant createdAt) { this.total = total; this.createdAt = createdAt; this.parts = new String[total]; }

        private synchronized String add(int number, int declaredTotal, String fragment) {
            if (declaredTotal != total || size + fragment.length() > MAX_TELEMETRY_TEXT_CHARS) return null;
            int index = number - 1;
            if (parts[index] == null) { parts[index] = fragment; size += fragment.length(); received++; }
            else if (!parts[index].equals(fragment)) return null;
            if (received != total) return null;
            StringBuilder text = new StringBuilder(size);
            for (String part : parts) text.append(part);
            return text.toString();
        }
    }
}
