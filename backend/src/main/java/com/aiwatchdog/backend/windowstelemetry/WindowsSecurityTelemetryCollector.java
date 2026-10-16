package com.aiwatchdog.backend.windowstelemetry;

import com.aiwatchdog.backend.monitor.MonitorEventAnalyzer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Subscribes to allowlisted Windows event IDs using the built-in EventLogWatcher API via fixed PowerShell code. */
@Component
public class WindowsSecurityTelemetryCollector implements SmartLifecycle, AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(WindowsSecurityTelemetryCollector.class);
    private static final String DEFENDER_LOG = "Microsoft-Windows-Windows Defender/Operational";
    private static final String SECURITY_LOG = "Security";
    private static final String POWERSHELL_LOG = "Microsoft-Windows-PowerShell/Operational";
    private static final int MAX_JSON_LINE_LENGTH = 262_144;

    private final WindowsTelemetryProperties properties;
    private final MonitorEventAnalyzer analyzer;
    private final ScriptThreatAnalyzer scriptAnalyzer;
    private final ProcessBehaviorCorrelator processCorrelator;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, ProviderState> providers = new ConcurrentHashMap<>();
    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicLong droppedEvents = new AtomicLong();
    private final AtomicInteger restartCount = new AtomicInteger();
    private final AtomicLong lifecycleGeneration = new AtomicLong();
    private volatile Process process;
    private volatile Thread supervisor;
    private volatile ThreadPoolExecutor eventWorkers;
    private volatile Instant startedAt;
    private volatile String collectorError;

    public WindowsSecurityTelemetryCollector(WindowsTelemetryProperties properties, MonitorEventAnalyzer analyzer,
                                             ScriptThreatAnalyzer scriptAnalyzer,
                                             ProcessBehaviorCorrelator processCorrelator) {
        this.properties = properties;
        this.analyzer = analyzer;
        this.scriptAnalyzer = scriptAnalyzer;
        this.processCorrelator = processCorrelator;
        providers.put("Defender Operational", new ProviderState("STARTING", null,
                "Waiting for the Windows event provider."));
        providers.put("Windows Security", new ProviderState("STARTING", null,
                "Waiting for Windows Security log access."));
        providers.put("PowerShell Operational", new ProviderState("DISABLED", null,
                "PowerShell script block logging is not enabled."));
        providers.put("Defender Antivirus service", new ProviderState("STARTING", null,
                "Waiting for Defender service status."));
    }

    @Override
    public synchronized void start() {
        if (running.get()) return;
        if (!isAnyFeatureEnabled()) {
            setAllProviderState("DISABLED", null, "Windows telemetry collection is turned off in Settings.");
            return;
        }
        if (!isWindows()) {
            setAllProviderState("UNSUPPORTED", "UNSUPPORTED_PLATFORM", "Windows Event Log collection is available only on Windows.");
            return;
        }
        long generation = lifecycleGeneration.incrementAndGet();
        running.set(true);
        startedAt = Instant.now();
        collectorError = null;
        providers.replaceAll((name, state) -> new ProviderState("STARTING", null, "Starting Windows event subscription."));
        ThreadPoolExecutor oldWorkers = eventWorkers;
        if (oldWorkers != null) oldWorkers.shutdownNow();
        eventWorkers = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(properties.getQueueCapacity()), task -> {
            Thread thread = new Thread(task, "aiwatchdog-windows-event-ingestion");
            thread.setDaemon(true);
            return thread;
        }, new ThreadPoolExecutor.AbortPolicy());
        supervisor = new Thread(() -> supervise(generation), "aiwatchdog-windows-event-subscriber");
        supervisor.setDaemon(true);
        supervisor.start();
    }

    private void supervise(long generation) {
        while (isCurrent(generation)) {
            Process child = null;
            Thread errorDrain = null;
            AtomicReference<String> diagnosticCategory = new AtomicReference<>();
            try {
                Path executable = powershellExecutable();
                ProcessBuilder builder = new ProcessBuilder(executable.toString(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-")
                        .redirectErrorStream(false);
                builder.environment().put("AIWD_SCRIPT_ENABLED", Boolean.toString(properties.isScriptMonitoringEnabled()));
                builder.environment().put("AIWD_PROCESS_ENABLED", Boolean.toString(properties.isProcessMonitoringEnabled()));
                builder.environment().put("AIWD_WINDOWS_ENABLED", Boolean.toString(properties.isEnabled()));
                child = builder.start();
                process = child;
                Process monitoredProcess = child;
                errorDrain = new Thread(() -> drainErrors(monitoredProcess, diagnosticCategory), "aiwatchdog-windows-event-stderr");
                errorDrain.setDaemon(true);
                errorDrain.start();
                try (OutputStream input = child.getOutputStream()) {
                    ClassPathResource script = new ClassPathResource("windows-telemetry/Collect-WindowsSecurityEvents.ps1");
                    try (var stream = script.getInputStream()) { stream.transferTo(input); }
                    input.flush();
                }
                try (BufferedReader output = new BufferedReader(new InputStreamReader(child.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while (isCurrent(generation) && (line = output.readLine()) != null) processLine(line);
                }
                if (isCurrent(generation)) {
                    int exitCode = child.waitFor();
                    throw new IOException("Windows event subscriber exited with code " + exitCode);
                }
            } catch (Exception exception) {
                if (isCurrent(generation)) {
                    if (errorDrain != null) {
                        try { errorDrain.join(500); }
                        catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                    }
                    collectorError = diagnosticCategory.get() == null
                            ? classifyError(exception) : diagnosticCategory.get();
                    log.warn("Windows event collector unavailable: category={}", collectorError);
                    providers.replaceAll((name, state) -> !isProviderRequired(name)
                            ? new ProviderState("DISABLED", null, "This provider is not enabled in Settings.")
                            : new ProviderState("DEGRADED", collectorError, "Event subscription process stopped; retrying."));
                }
            } finally {
                if (process == child) process = null;
                if (child != null && child.isAlive()) child.destroyForcibly();
            }
            if (isCurrent(generation)) {
                restartCount.incrementAndGet();
                try { Thread.sleep(properties.getRestartDelayMs()); }
                catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private boolean isCurrent(long generation) {
        return running.get() && lifecycleGeneration.get() == generation;
    }

    private void drainErrors(Process child, AtomicReference<String> diagnosticCategory) {
        try (BufferedReader errors = new BufferedReader(new InputStreamReader(child.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = errors.readLine()) != null) {
                String category = classifyPowerShellDiagnostic(line);
                if (!"SUBSCRIBER_PROCESS_ERROR".equals(category)) diagnosticCategory.compareAndSet(null, category);
            }
        } catch (IOException ignored) { }
    }

    /** Converts PowerShell diagnostics to fixed categories; raw stderr is deliberately discarded. */
    private String classifyPowerShellDiagnostic(String diagnostic) {
        String value = diagnostic == null ? "" : diagnostic.toLowerCase(java.util.Locale.ROOT);
        if (value.contains("access is denied") || value.contains("unauthorizedaccess")
                || value.contains("securityexception")) return "EVENT_LOG_ACCESS_DENIED";
        if (value.contains("execution policy") || value.contains("running scripts is disabled")) return "POWERSHELL_POLICY_RESTRICTION";
        if (value.contains("parsererror") || value.contains("parseexception") || value.contains("unexpected token")) return "POWERSHELL_SCRIPT_ERROR";
        if (value.contains("cannot find path") || value.contains("not recognized as the name")
                || value.contains("commandnotfoundexception")) return "POWERSHELL_COMPONENT_UNAVAILABLE";
        return "SUBSCRIBER_PROCESS_ERROR";
    }

    private void processLine(String line) {
        if (line == null || line.isBlank()) return;
        if (line.length() > MAX_JSON_LINE_LENGTH) {
            droppedEvents.incrementAndGet();
            return;
        }
        try {
            JsonNode json = mapper.readTree(line);
            String kind = json.path("kind").asText();
            switch (kind) {
                case "provider" -> updateProvider(json);
                case "provider-error" -> updateProviderError(json);
                case "collector" -> droppedEvents.accumulateAndGet(json.path("droppedEvents").asLong(), Math::max);
                case "event" -> acceptEvent(json);
                default -> { }
            }
        } catch (Exception exception) {
            log.warn("Ignoring malformed Windows event collector output");
        }
    }

    private void updateProvider(JsonNode json) {
        String name = boundedText(json.path("provider").asText(), 80);
        if (!providers.containsKey(name)) return;
        String state = boundedText(json.path("state").asText("UNKNOWN"), 32).toUpperCase();
        String error = nullableText(json.path("errorCategory").asText(null), 64);
        String message = boundedText(json.path("message").asText("Provider status received."), 180);
        providers.computeIfPresent(name, (key, current) -> new ProviderState(state, error, message,
                current.lastEventTimestamp(), current.eventsReceived()));
        if (allRequiredSubscriptionsReady()) collectorError = null;
    }

    private void updateProviderError(JsonNode json) {
        String name = boundedText(json.path("provider").asText(), 80);
        providers.computeIfPresent(name, (key, current) -> new ProviderState("DEGRADED",
                boundedText(json.path("errorCategory").asText("EVENT_DELIVERY_ERROR"), 64),
                "The event provider reported a delivery error.", current.lastEventTimestamp(), current.eventsReceived()));
    }

    private void acceptEvent(JsonNode json) {
        String logName = boundedText(json.path("logName").asText(), 160);
        int eventId = json.path("eventId").asInt(-1);
        long recordId = json.path("recordId").asLong(-1);
        if (recordId < 0 || !isAllowlistedEvent(logName, eventId)) return;
        Instant parsedTimestamp;
        try { parsedTimestamp = Instant.parse(json.path("timestampUtc").asText()); }
        catch (RuntimeException exception) { parsedTimestamp = Instant.now(); }
        final Instant timestamp = parsedTimestamp;
        Long processId = positiveLong(json.path("processId").asLong(0));
        Long parentProcessId = positiveLong(json.path("parentProcessId").asLong(0));
        String scriptBlockId = nullableText(json.path("scriptBlockId").asText(null), 128);
        int scriptMessageNumber = json.path("scriptMessageNumber").asInt(0);
        int scriptMessageTotal = json.path("scriptMessageTotal").asInt(0);
        WindowsSecurityEvent event = new WindowsSecurityEvent(logName,
                boundedText(json.path("providerName").asText(), 128), eventId, recordId, timestamp,
                nullableText(json.path("processName").asText(null), 512), processId,
                nullableText(json.path("parentProcessName").asText(null), 512), parentProcessId,
                nullableText(json.path("transientContent").asText(null), ScriptThreatAnalyzer.MAX_SCRIPT_FRAGMENT_CHARS),
                scriptBlockId, scriptMessageNumber, scriptMessageTotal);
        String provider = DEFENDER_LOG.equals(logName) ? "Defender Operational"
                : POWERSHELL_LOG.equals(logName) ? "PowerShell Operational" : "Windows Security";
        providers.computeIfPresent(provider, (key, current) -> new ProviderState(current.state(), current.errorCategory(),
                current.message(), timestamp, current.eventsReceived() + 1));
        ThreadPoolExecutor workers = eventWorkers;
        if (workers == null || workers.isShutdown()) return;
        try {
            workers.execute(() -> {
                try {
                    if (POWERSHELL_LOG.equals(event.logName()) && event.eventId() == 4104) {
                        scriptAnalyzer.inspectObservedFragment("OBSERVED_POWERSHELL_SCRIPT_BLOCK", event.scriptBlockId(),
                                event.scriptMessageNumber(), event.scriptMessageTotal(), event.transientContent(), event.timestamp())
                                .ifPresent(analysis -> analyzer.recordScriptFinding("PowerShell Script Block", analysis, event.processId()));
                    } else if (SECURITY_LOG.equalsIgnoreCase(event.logName()) && (event.eventId() == 4688 || event.eventId() == 4689)) {
                        processCorrelator.accept(event).ifPresent(analyzer::recordProcessFinding);
                    } else analyzer.analyzeWindowsEvent(event);
                }
                catch (RuntimeException exception) {
                    log.warn("Windows event could not be added to monitor history: category={}", exception.getClass().getSimpleName());
                }
            });
        } catch (java.util.concurrent.RejectedExecutionException exception) {
            droppedEvents.incrementAndGet();
        }
    }

    private boolean isAllowlistedEvent(String logName, int eventId) {
        if (DEFENDER_LOG.equals(logName)) return eventId == 1116 || eventId == 1117 || eventId == 1118 || eventId == 5007;
        if (POWERSHELL_LOG.equals(logName)) return properties.isScriptMonitoringEnabled() && eventId == 4104;
        return SECURITY_LOG.equalsIgnoreCase(logName)
                && ((properties.isProcessMonitoringEnabled() && (eventId == 4688 || eventId == 4689))
                || (properties.isEnabled() && (eventId == 1102 || eventId == 4697 || eventId == 4698 || eventId == 4719)));
    }

    private WindowsTelemetryProviderStatus providerStatus(String name, ProviderState state) {
        return new WindowsTelemetryProviderStatus(name, state.state(), state.errorCategory(), state.message(),
                state.lastEventTimestamp(), state.eventsReceived());
    }

    public WindowsTelemetryHealth getHealth() {
        boolean supported = isWindows();
        List<WindowsTelemetryProviderStatus> snapshot = providers.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> providerStatus(entry.getKey(), entry.getValue())).toList();
        String state;
        String message;
        if (!isAnyFeatureEnabled()) {
            state = "DISABLED";
            message = "Windows telemetry, script monitoring, and process monitoring are disabled.";
        } else if (!supported) {
            state = "UNSUPPORTED";
            message = "Windows Event Log collection is available only on Windows.";
        } else {
            boolean providersReady = (!properties.isEnabled() || (isProviderSubscribed(snapshot, "Defender Operational")
                    && isProviderSubscribed(snapshot, "Windows Security") && isProviderState(snapshot, "Defender Antivirus service", "RUNNING")))
                    && (!properties.isScriptMonitoringEnabled() || isProviderSubscribed(snapshot, "PowerShell Operational"))
                    && (!properties.isProcessMonitoringEnabled() || isProviderSubscribed(snapshot, "Windows Security"));
            boolean anySubscribed = snapshot.stream().anyMatch(p -> "SUBSCRIBED".equals(p.state()));
            state = !running.get() ? "STARTING" : providersReady ? "RUNNING" : anySubscribed ? "DEGRADED" : "UNAVAILABLE";
            message = switch (state) {
                case "RUNNING" -> "All enabled Windows event subscriptions are active.";
                case "DEGRADED" -> "Some enabled Windows event providers are unavailable; review provider states and permissions.";
                case "UNAVAILABLE" -> "None of the enabled Windows event providers are currently subscribed.";
                default -> "Windows event collector is starting.";
            };
        }
        return new WindowsTelemetryHealth(isAnyFeatureEnabled(), properties.isEnabled(), properties.isScriptMonitoringEnabled(),
                properties.isProcessMonitoringEnabled(), supported, running.get(), state, collectorError,
                message, startedAt, droppedEvents.get(), restartCount.get(), snapshot);
    }

    private boolean isAnyFeatureEnabled() {
        return properties.isEnabled() || properties.isScriptMonitoringEnabled() || properties.isProcessMonitoringEnabled();
    }

    private boolean isProviderRequired(String provider) {
        return switch (provider) {
            case "Defender Operational", "Defender Antivirus service" -> properties.isEnabled();
            case "PowerShell Operational" -> properties.isScriptMonitoringEnabled();
            case "Windows Security" -> properties.isEnabled() || properties.isProcessMonitoringEnabled();
            default -> false;
        };
    }

    private boolean allRequiredSubscriptionsReady() {
        return (!properties.isEnabled() || ("SUBSCRIBED".equals(providerState("Defender Operational").state())
                && "SUBSCRIBED".equals(providerState("Windows Security").state())
                && "RUNNING".equals(providerState("Defender Antivirus service").state())))
                && (!properties.isScriptMonitoringEnabled() || "SUBSCRIBED".equals(providerState("PowerShell Operational").state()))
                && (!properties.isProcessMonitoringEnabled() || "SUBSCRIBED".equals(providerState("Windows Security").state()));
    }

    private boolean isProviderSubscribed(List<WindowsTelemetryProviderStatus> snapshot, String name) {
        return isProviderState(snapshot, name, "SUBSCRIBED");
    }

    private boolean isProviderState(List<WindowsTelemetryProviderStatus> snapshot, String name, String state) {
        return snapshot.stream().anyMatch(provider -> name.equals(provider.provider()) && state.equals(provider.state()));
    }

    private Long positiveLong(long value) { return value > 0 ? value : null; }

    private void setAllProviderState(String state, String error, String message) {
        providers.replaceAll((name, current) -> new ProviderState(state, error, message,
                current.lastEventTimestamp(), current.eventsReceived()));
    }

    private Path powershellExecutable() throws IOException {
        String systemRoot = System.getenv("SystemRoot");
        if (systemRoot == null || systemRoot.isBlank()) throw new java.nio.file.NoSuchFileException("SystemRoot");
        Path executable = Path.of(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!Files.isRegularFile(executable)) throw new java.nio.file.NoSuchFileException(executable.toString());
        return executable;
    }

    private ProviderState providerState(String name) {
        return providers.getOrDefault(name, new ProviderState("UNKNOWN", null, "Provider status unavailable."));
    }

    private String classifyError(Exception exception) {
        if (exception instanceof java.nio.file.NoSuchFileException) return "POWERSHELL_UNAVAILABLE";
        if (exception instanceof SecurityException) return "PROCESS_START_DENIED";
        if (exception instanceof IOException && exception.getMessage() != null
                && exception.getMessage().startsWith("Windows event subscriber exited with code ")) {
            return "SUBSCRIBER_EXIT_" + exception.getMessage().substring("Windows event subscriber exited with code ".length());
        }
        return "SUBSCRIBER_PROCESS_ERROR";
    }

    private String boundedText(String value, int max) {
        if (value == null || value.isBlank()) return "UNKNOWN";
        return value.length() <= max ? value : value.substring(0, max);
    }

    private String nullableText(String value, int max) {
        return value == null || value.isBlank() ? null : boundedText(value, max);
    }

    private boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    @Override public boolean isRunning() { return running.get(); }
    @Override public boolean isAutoStartup() { return true; }
    @Override public int getPhase() { return Integer.MAX_VALUE - 50; }

    @Override public void stop(Runnable callback) {
        try { close(); } finally { callback.run(); }
    }

    @Override public synchronized void stop() { close(); }

    @Override
    public synchronized void close() {
        lifecycleGeneration.incrementAndGet();
        running.set(false);
        Process child = process;
        if (child != null) child.destroy();
        Thread thread = supervisor;
        if (thread != null) thread.interrupt();
        ThreadPoolExecutor workers = eventWorkers;
        if (workers != null) {
            workers.shutdown();
            try {
                if (!workers.awaitTermination(2, TimeUnit.SECONDS)) workers.shutdownNow();
            } catch (InterruptedException exception) {
                workers.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        if (!isAnyFeatureEnabled()) {
            collectorError = null;
            setAllProviderState("DISABLED", null, "Windows monitoring is turned off in Settings.");
        }
        else if (!isWindows()) setAllProviderState("UNSUPPORTED", "UNSUPPORTED_PLATFORM", "Windows Event Log collection is available only on Windows.");
        supervisor = null;
        eventWorkers = null;
    }

    private record ProviderState(String state, String errorCategory, String message,
                                 Instant lastEventTimestamp, long eventsReceived) {
        private ProviderState(String state, String errorCategory, String message) {
            this(state, errorCategory, message, null, 0);
        }
    }
}
