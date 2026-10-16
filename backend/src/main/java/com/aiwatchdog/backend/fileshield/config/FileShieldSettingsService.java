package com.aiwatchdog.backend.fileshield.config;

import com.aiwatchdog.backend.fileshield.watcher.FileShieldDirectoryWatcher;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.sqlite.SQLiteConfig;
import org.springframework.stereotype.Service;
import com.aiwatchdog.backend.fileshield.reputation.HashReputationService;
import com.aiwatchdog.backend.fileshield.service.FileQuarantineService;
import com.aiwatchdog.backend.fileshield.reputation.ReputationProviderStatus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.List;

/** Applies and persists local File Shield configuration without requiring a backend restart. */
@Service
public class FileShieldSettingsService {
    private static final long MIN_FILE_SIZE = 1024;
    private static final long MAX_FILE_SIZE = 1024L * 1024 * 1024;
    private final FileShieldProperties properties;
    private final FileShieldDirectoryWatcher watcher;
    private final ObjectMapper mapper;
    private final Path settingsFile;
    private final HashReputationService reputation;
    private final FileQuarantineService quarantine;

    @Autowired
    public FileShieldSettingsService(FileShieldProperties properties, FileShieldDirectoryWatcher watcher,
                                     HashReputationService reputation, FileQuarantineService quarantine,
                                     @Value("${ai-watchdog.file-shield.settings-path:}") String configuredPath) {
        this(properties, watcher, new ObjectMapper(), configuredPath == null || configuredPath.isBlank()
                ? defaultSettingsPath() : Path.of(configuredPath), reputation, quarantine);
    }

    FileShieldSettingsService(FileShieldProperties properties, FileShieldDirectoryWatcher watcher,
                              ObjectMapper mapper, Path settingsFile) {
        this(properties, watcher, mapper, settingsFile, null, null);
    }
    FileShieldSettingsService(FileShieldProperties properties, FileShieldDirectoryWatcher watcher,
                              ObjectMapper mapper, Path settingsFile, HashReputationService reputation,
                              FileQuarantineService quarantine) {
        this.properties = properties;
        this.watcher = watcher;
        this.mapper = mapper;
        this.settingsFile = settingsFile;
        this.reputation = reputation;
        this.quarantine = quarantine;
    }

    @PostConstruct
    void loadPersistedSettings() {
        if (!Files.isRegularFile(settingsFile)) {
            normalizeConfiguredDirectories();
            return;
        }
        try {
            apply(mapper.readValue(settingsFile.toFile(), FileShieldSettingsRequest.class), false);
        } catch (Exception exception) {
            // Keep the validated Spring configuration if a saved user file is corrupt or stale.
            normalizeConfiguredDirectories();
        }
    }

    private void normalizeConfiguredDirectories() {
        try {
            List<Path> roots = validateDirectories(properties.getAllowedRoots().stream().map(Path::toString).toList(), "approved scan root");
            List<Path> watches = validateDirectories(properties.getWatchDirectories().stream().map(Path::toString).toList(), "watch directory");
            if (watches.stream().anyMatch(watch -> roots.stream().noneMatch(watch::startsWith) || isQuarantinePath(watch, roots))) return;
            properties.setAllowedRoots(roots);
            properties.setWatchDirectories(watches);
        } catch (RuntimeException ignored) {
            // Keep the original properties so the watcher can report invalid/missing configuration at startup.
        }
    }

    public synchronized FileShieldSettingsResponse get() {
        return response();
    }

    public synchronized FileShieldSettingsResponse update(FileShieldSettingsRequest request) {
        apply(request, true);
        return response();
    }

    private void apply(FileShieldSettingsRequest request, boolean persist) {
        if (request == null) throw new IllegalArgumentException("File Shield settings are required.");
        if (request.maxFileSizeBytes() < MIN_FILE_SIZE || request.maxFileSizeBytes() > MAX_FILE_SIZE)
            throw new IllegalArgumentException("Maximum file size must be between 1 KiB and 1 GiB.");
        if (request.maxFilesPerDirectoryScan() < 1 || request.maxFilesPerDirectoryScan() > 10000)
            throw new IllegalArgumentException("Directory scan file limit must be between 1 and 10000.");
        if (request.maxDirectoryDepth() < 0 || request.maxDirectoryDepth() > 20)
            throw new IllegalArgumentException("Directory scan depth must be between 0 and 20.");
        if (request.maxMonitoringDepth() < 0 || request.maxMonitoringDepth() > 20)
            throw new IllegalArgumentException("Monitoring depth must be between 0 and 20.");
        if (request.reputationDatabasePath() == null || request.reputationDatabasePath().isBlank())
            throw new IllegalArgumentException("Choose a reputation database path.");

        List<Path> roots = validateDirectories(request.allowedRoots(), "approved scan root");
        List<Path> watches = validateDirectories(request.watchDirectories(), "watch directory");
        for (Path watch : watches) {
            if (roots.stream().noneMatch(watch::startsWith))
                throw new IllegalArgumentException("Every monitored folder must be inside an approved scan root.");
            if (isQuarantinePath(watch, roots))
                throw new IllegalArgumentException("Quarantine storage cannot be selected as a monitored folder.");
        }
        if (request.monitoringEnabled() && watches.isEmpty())
            throw new IllegalArgumentException("Choose at least one monitored folder or turn monitoring off.");
        if (!request.enabled() && request.monitoringEnabled())
            throw new IllegalArgumentException("Enable File Shield before enabling continuous File Shield monitoring.");
        Path database = Path.of(request.reputationDatabasePath().trim()).toAbsolutePath().normalize();

        // Validate everything before changing active settings.
        FileShieldSettingsRequest normalized = new FileShieldSettingsRequest(
                request.enabled(), roots.stream().map(Path::toString).toList(), watches.stream().map(Path::toString).toList(),
                database.toString(), request.monitoringEnabled(), request.recursiveMonitoring(),
                request.maxMonitoringDepth(), request.maxFileSizeBytes(), request.maxFilesPerDirectoryScan(),
                request.maxDirectoryDepth());
        if (persist) persist(normalized);

        watcher.close();
        properties.setEnabled(request.enabled());
        properties.setAllowedRoots(roots);
        properties.setWatchDirectories(watches);
        properties.setReputationDatabasePath(database);
        properties.setMonitoringEnabled(request.monitoringEnabled());
        properties.setRecursiveMonitoring(request.recursiveMonitoring());
        properties.setMaxMonitoringDepth(request.maxMonitoringDepth());
        properties.setMaxFileSize(request.maxFileSizeBytes());
        properties.setMaxFilesPerDirectoryScan(request.maxFilesPerDirectoryScan());
        properties.setMaxDirectoryDepth(request.maxDirectoryDepth());
        watcher.start();
    }

    private List<Path> validateDirectories(List<String> configured, String description) {
        List<Path> result = new ArrayList<>();
        if (configured == null) return result;
        for (String value : configured) {
            if (value == null || value.isBlank()) continue;
            try {
                Path candidate = Path.of(value.trim()).toAbsolutePath().normalize();
                if (!Files.exists(candidate))
                    throw new IllegalArgumentException("The selected " + description + " must exist and be accessible.");
                Path real = candidate.toRealPath();
                if (!Files.isDirectory(real, LinkOption.NOFOLLOW_LINKS))
                    throw new IllegalArgumentException("The selected " + description + " must be a directory.");
                if (!result.contains(real)) result.add(real);
            } catch (IOException | SecurityException exception) {
                throw new IllegalArgumentException("The selected " + description + " cannot be accessed.");
            }
        }
        return List.copyOf(result);
    }

    private boolean isQuarantinePath(Path path, List<Path> roots) {
        Path target = path.toAbsolutePath().normalize();
        return roots.stream().map(root -> root.resolve(".aiwatchdog-quarantine").toAbsolutePath().normalize())
                .anyMatch(target::startsWith);
    }

    private void persist(FileShieldSettingsRequest request) {
        try {
            Path parent = settingsFile.getParent();
            if (parent != null) Files.createDirectories(parent);
            Path temporary = settingsFile.resolveSibling(settingsFile.getFileName() + ".tmp");
            mapper.writeValue(temporary.toFile(), request);
            try { Files.move(temporary, settingsFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
            catch (IOException unsupportedAtomicMove) { Files.move(temporary, settingsFile, StandardCopyOption.REPLACE_EXISTING); }
        } catch (IOException exception) {
            throw new IllegalStateException("Could not save File Shield settings to the user configuration folder.");
        }
    }

    private FileShieldSettingsResponse response() {
        Path database = properties.getReputationDatabasePath().toAbsolutePath().normalize();
        String message = "Reputation database is unavailable.";
        boolean usable = false;
        if (Files.isRegularFile(database)) {
            SQLiteConfig config = new SQLiteConfig();
            config.setReadOnly(true);
            try (var connection = DriverManager.getConnection("jdbc:sqlite:" + database, config.toProperties());
                 var query = connection.prepareStatement("SELECT sha256, reputation, source, description FROM hash_reputation LIMIT 0")) {
                query.executeQuery().close();
                usable = true;
                message = "Database is readable and has the expected table. Hashes absent from it may be checked against enabled providers; UNKNOWN is not a clean verdict.";
            } catch (Exception ignored) {
                message = "Database is missing, unreadable, or does not have the expected hash_reputation table and columns.";
            }
        }
        List<ReputationProviderStatus> providers;
        try { providers = reputation == null ? List.of() : reputation.providerStatuses(); }
        catch (RuntimeException failure) {
            providers = List.of(new ReputationProviderStatus("reputation-status", "UNAVAILABLE",
                    failure.getClass().getSimpleName(), java.time.Instant.now()));
        }
        return new FileShieldSettingsResponse(
                properties.isEnabled(),
                properties.getAllowedRoots().stream().map(Path::toString).toList(),
                properties.getWatchDirectories().stream().map(Path::toString).toList(),
                database.toString(), properties.isMonitoringEnabled(), properties.isRecursiveMonitoring(),
                properties.getMaxMonitoringDepth(), properties.getMaxFileSize(),
                properties.getMaxFilesPerDirectoryScan(), properties.getMaxDirectoryDepth(), watcher.isRunning(),
                usable, message, quarantine == null ? "" : quarantine.defaultDirectory(), providers);
    }

    private static Path defaultSettingsPath() {
        String appData = System.getenv("APPDATA");
        Path base = appData == null || appData.isBlank()
                ? Path.of(System.getProperty("user.home"), ".aiwatchdog")
                : Path.of(appData, "AIWatchDog");
        return base.resolve("file-shield-settings.json");
    }
}
