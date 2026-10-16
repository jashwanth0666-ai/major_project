package com.aiwatchdog.backend.windowstelemetry;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Owns the desired collector state and reports the separately observed provider state. */
@Service
public class WindowsTelemetrySettingsService {
    private static final Logger log = LoggerFactory.getLogger(WindowsTelemetrySettingsService.class);
    private final WindowsTelemetryProperties properties;
    private final WindowsSecurityTelemetryCollector collector;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Path settingsFile;

    public WindowsTelemetrySettingsService(WindowsTelemetryProperties properties,
                                           WindowsSecurityTelemetryCollector collector,
                                           @Value("${ai-watchdog.windows-telemetry.settings-path:}") String configuredPath) {
        this.properties = properties;
        this.collector = collector;
        this.settingsFile = configuredPath == null || configuredPath.isBlank()
                ? defaultSettingsPath() : Path.of(configuredPath).toAbsolutePath().normalize();
    }

    @PostConstruct
    synchronized void load() {
        if (!Files.isRegularFile(settingsFile)) return;
        try {
            WindowsTelemetrySettingsRequest saved = mapper.readValue(settingsFile.toFile(), WindowsTelemetrySettingsRequest.class);
            if (saved != null) {
                if (saved.enabled() != null) properties.setEnabled(saved.enabled());
                if (saved.scriptMonitoringEnabled() != null) properties.setScriptMonitoringEnabled(saved.scriptMonitoringEnabled());
                if (saved.processMonitoringEnabled() != null) properties.setProcessMonitoringEnabled(saved.processMonitoringEnabled());
            }
        } catch (IOException | RuntimeException exception) {
            properties.setEnabled(false);
            properties.setScriptMonitoringEnabled(false);
            properties.setProcessMonitoringEnabled(false);
            log.warn("Windows telemetry settings could not be read; collection remains disabled (category={})",
                    exception.getClass().getSimpleName());
        }
    }

    public synchronized WindowsTelemetrySettingsResponse get() {
        return WindowsTelemetrySettingsResponse.from(collector.getHealth());
    }

    public synchronized WindowsTelemetrySettingsResponse update(WindowsTelemetrySettingsRequest request) {
        if (request == null || (request.enabled() == null && request.scriptMonitoringEnabled() == null
                && request.processMonitoringEnabled() == null)) {
            throw new IllegalArgumentException("At least one monitoring setting is required.");
        }
        WindowsTelemetrySettingsRequest applied = new WindowsTelemetrySettingsRequest(
                request.enabled() == null ? properties.isEnabled() : request.enabled(),
                request.scriptMonitoringEnabled() == null ? properties.isScriptMonitoringEnabled() : request.scriptMonitoringEnabled(),
                request.processMonitoringEnabled() == null ? properties.isProcessMonitoringEnabled() : request.processMonitoringEnabled());
        persist(applied);
        properties.setEnabled(applied.enabled());
        properties.setScriptMonitoringEnabled(applied.scriptMonitoringEnabled());
        properties.setProcessMonitoringEnabled(applied.processMonitoringEnabled());
        collector.stop();
        collector.start();
        return get();
    }

    private void persist(WindowsTelemetrySettingsRequest request) {
        Path temporary = settingsFile.resolveSibling(settingsFile.getFileName() + ".tmp");
        try {
            Path parent = settingsFile.getParent();
            if (parent != null) Files.createDirectories(parent);
            mapper.writeValue(temporary.toFile(), request);
            try {
                Files.move(temporary, settingsFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException unsupportedAtomicMove) {
                Files.move(temporary, settingsFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException exception) {
            try { Files.deleteIfExists(temporary); } catch (IOException ignored) { }
            throw new IllegalStateException("Could not persist Windows telemetry settings for this user.");
        }
    }

    private static Path defaultSettingsPath() {
        String appData = System.getenv("APPDATA");
        Path base = appData == null || appData.isBlank()
                ? Path.of(System.getProperty("user.home"), ".aiwatchdog")
                : Path.of(appData, "AIWatchDog");
        return base.resolve("windows-telemetry-settings.json");
    }
}
