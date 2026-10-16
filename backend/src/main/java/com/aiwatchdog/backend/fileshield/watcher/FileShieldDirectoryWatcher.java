package com.aiwatchdog.backend.fileshield.watcher;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import com.aiwatchdog.backend.fileshield.dto.DirectoryScanResponse;
import com.aiwatchdog.backend.fileshield.dto.FileScanResponse;
import com.aiwatchdog.backend.fileshield.exception.FileShieldException;
import com.aiwatchdog.backend.fileshield.service.FileShieldService;
import com.aiwatchdog.backend.monitor.MonitorEventAnalyzer;
import com.aiwatchdog.backend.windowstelemetry.ScriptThreatAnalyzer;
import com.aiwatchdog.backend.windowstelemetry.WindowsTelemetryProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.SmartLifecycle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Watches only explicitly configured directories approved by File Shield roots.
 * WatchService observes metadata events; all hashing and reputation work runs in a bounded pool.
 */
@Component
public class FileShieldDirectoryWatcher implements SmartLifecycle, AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(FileShieldDirectoryWatcher.class);
    private static final WatchEvent.Kind<?>[] WATCH_KINDS = {
            StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY
    };

    private final FileShieldProperties properties;
    private final FileShieldService fileShieldService;
    private final ScriptThreatAnalyzer scriptThreatAnalyzer;
    private final MonitorEventAnalyzer monitorEventAnalyzer;
    private final WindowsTelemetryProperties telemetryProperties;
    private final ApplicationEventPublisher eventPublisher;
    private final Map<WatchKey, Registration> registrations = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Path, ScanWork> pendingScans = new ConcurrentHashMap<>();
    private final AtomicBoolean running = new AtomicBoolean();
    private volatile WatchService watchService;
    private volatile ThreadPoolExecutor workers;
    private volatile Thread watcherThread;

    @Autowired
    public FileShieldDirectoryWatcher(FileShieldProperties properties,
                                      FileShieldService fileShieldService,
                                      ScriptThreatAnalyzer scriptThreatAnalyzer,
                                      MonitorEventAnalyzer monitorEventAnalyzer,
                                      WindowsTelemetryProperties telemetryProperties,
                                      ApplicationEventPublisher eventPublisher) {
        this.properties = properties;
        this.fileShieldService = fileShieldService;
        this.scriptThreatAnalyzer = scriptThreatAnalyzer;
        this.monitorEventAnalyzer = monitorEventAnalyzer;
        this.telemetryProperties = telemetryProperties;
        this.eventPublisher = eventPublisher;
    }

    /** Retains the existing construction contract used by isolated watcher fixtures. */
    public FileShieldDirectoryWatcher(FileShieldProperties properties, FileShieldService fileShieldService,
                                      ApplicationEventPublisher eventPublisher) {
        this(properties, fileShieldService, null, null, new WindowsTelemetryProperties(), eventPublisher);
    }

    @Override
    public synchronized void start() {
        if (running.get() || !properties.isMonitoringEnabled()) return;
        if (properties.getWatchDirectories().isEmpty()) {
            log.info("File Shield monitoring is enabled but no watch directories are configured");
            return;
        }
        try {
            WatchService candidate = FileSystems.getDefault().newWatchService();
            ThreadPoolExecutor pool = createWorkerPool();
            watchService = candidate;
            workers = pool;
            int registeredRoots = 0;
            for (Path configured : properties.getWatchDirectories()) {
                Path root = validateWatchRoot(configured);
                if (root == null) continue;
                int before = registrations.size();
                registerTree(root, root);
                if (registrations.size() > before) registeredRoots++;
            }
            if (registeredRoots == 0) {
                log.warn("File Shield monitoring is enabled but no configured directory is approved and accessible");
                closeResources();
                return;
            }
            running.set(true);
            watcherThread = new Thread(this::watchLoop, "aiwatchdog-file-shield-watcher");
            watcherThread.setDaemon(true);
            watcherThread.start();
            log.info("File Shield directory monitoring started for {} configured root(s)", registeredRoots);
        } catch (IOException | RuntimeException exception) {
            log.warn("File Shield directory monitoring could not start: category={}", exception.getClass().getSimpleName());
            closeResources();
        }
    }

    private ThreadPoolExecutor createWorkerPool() {
        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, "aiwatchdog-file-shield-worker");
            thread.setDaemon(true);
            return thread;
        };
        return new ThreadPoolExecutor(properties.getMonitoringWorkerCount(),
                properties.getMonitoringWorkerCount(), 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(properties.getMonitoringQueueCapacity()), factory,
                new ThreadPoolExecutor.AbortPolicy());
    }

    private Path validateWatchRoot(Path configured) {
        try {
            Path normalized = configured.toAbsolutePath().normalize();
            if (isQuarantinePath(normalized) || hasSymlinkComponent(normalized) || !Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
                log.warn("Skipping configured File Shield watch directory: invalid or redirected path");
                return null;
            }
            Path real = normalized.toRealPath();
            if (!withinAllowedRoots(real)) {
                log.warn("Skipping configured File Shield watch directory outside approved roots");
                return null;
            }
            return real;
        } catch (IOException | SecurityException exception) {
            log.warn("Skipping inaccessible File Shield watch directory: category={}", exception.getClass().getSimpleName());
            return null;
        }
    }

    private void registerTree(Path root, Path start) throws IOException {
        if (!properties.isRecursiveMonitoring()) {
            registerDirectory(root, root, 0);
            return;
        }
        int maxDepth = properties.getMaxMonitoringDepth();
        Files.walkFileTree(start, Set.of(), maxDepth + 1, new SimpleFileVisitor<>() {
            @Override public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attrs) {
                if (isQuarantinePath(directory) || Files.isSymbolicLink(directory) || !isWithinRoot(directory, root)) return FileVisitResult.SKIP_SUBTREE;
                Path relative = root.relativize(directory);
                int depth = relative.toString().isEmpty() ? 0 : relative.getNameCount();
                if (depth <= maxDepth) {
                    try { registerDirectory(root, directory, depth); }
                    catch (IOException exception) { log.warn("Could not register a File Shield watch directory: category={}", exception.getClass().getSimpleName()); }
                }
                if (depth >= maxDepth) return FileVisitResult.SKIP_SUBTREE;
                return FileVisitResult.CONTINUE;
            }

            @Override public FileVisitResult visitFileFailed(Path file, IOException exception) {
                log.debug("Skipping inaccessible path while registering File Shield monitoring");
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void registerDirectory(Path root, Path directory, int depth) throws IOException {
        if (isQuarantinePath(directory) || !isWithinRoot(directory, root)) return;
        WatchKey key = directory.register(watchService, WATCH_KINDS);
        registrations.put(key, new Registration(root, directory, depth));
    }

    private void watchLoop() {
        while (running.get()) {
            WatchKey key;
            try { key = watchService.take(); }
            catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                break;
            } catch (ClosedWatchServiceException closedException) { break; }
            Registration registration = registrations.get(key);
            if (registration == null) {
                key.reset();
                continue;
            }
            for (WatchEvent<?> event : key.pollEvents()) {
                if (event.kind() == StandardWatchEventKinds.OVERFLOW) {
                    enqueueDirectoryRescan(registration.root());
                    continue;
                }
                Object context = event.context();
                if (!(context instanceof Path relative)) continue;
                Path changed = registration.directory().resolve(relative).normalize();
                if (!isWithinRoot(changed, registration.root()) || hasSymlinkComponent(changed)) continue;
                if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE
                        && Files.isDirectory(changed, LinkOption.NOFOLLOW_LINKS)) {
                    registerNewDirectory(registration, changed);
                } else if (Files.isRegularFile(changed, LinkOption.NOFOLLOW_LINKS)) {
                    queueFileEvent(changed, event.kind().name());
                }
            }
            if (!key.reset()) {
                registrations.remove(key);
                log.warn("File Shield watch registration became invalid");
            }
        }
        running.set(false);
    }

    private void registerNewDirectory(Registration parent, Path child) {
        if (!properties.isRecursiveMonitoring()) return;
        try {
            Path real = child.toRealPath();
            int depth = parent.root().relativize(real).getNameCount();
            if (depth > properties.getMaxMonitoringDepth() || !isWithinRoot(real, parent.root())) return;
            registerTree(parent.root(), real);
        } catch (IOException | SecurityException exception) {
            log.debug("Ignoring unavailable new directory during File Shield registration");
        }
    }

    /** Package-visible so event coalescing can be exercised deterministically in tests. */
    void queueFileEvent(Path file, String eventType) {
        Path path = file.toAbsolutePath().normalize();
        if (!running.get() || hasSymlinkComponent(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return;
        ScanWork work = pendingScans.computeIfAbsent(path, ignored -> new ScanWork(eventType));
        if (StandardWatchEventKinds.ENTRY_CREATE.name().equals(eventType)) work.eventType.set(eventType);
        else work.eventType.compareAndSet(null, eventType);
        work.dirty.set(true);
        submitIfNeeded(path, work);
    }

    private void submitIfNeeded(Path path, ScanWork work) {
        ThreadPoolExecutor pool = workers;
        if (pool == null || pool.isShutdown() || !work.scheduled.compareAndSet(false, true)) return;
        try {
            pool.execute(() -> runScanWork(path, work));
        } catch (RejectedExecutionException rejected) {
            work.scheduled.set(false);
            pendingScans.remove(path, work);
            log.warn("File Shield scan queue is full; dropping event type={} for file={}", work.eventType.get(), path.getFileName());
        }
    }

    private void runScanWork(Path path, ScanWork work) {
        try {
            for (int pass = 0; pass < 2 && running.get(); pass++) {
                work.dirty.set(false);
                String eventType = work.eventType.getAndSet("ENTRY_MODIFY");
                if (!awaitStableFile(path)) {
                    log.info("File Shield skipped unstable or unavailable file: eventType={}, file={}", eventType, path.getFileName());
                } else {
                    try {
                        inspectScript(path);
                        FileScanResponse result = fileShieldService.scanFileForMonitoring(path);
                        publishResult(eventType, result);
                    } catch (FileShieldException exception) {
                        log.info("File Shield rejected watch event: eventType={}, file={}, reason={}", eventType,
                                path.getFileName(), exception.code());
                    } catch (RuntimeException exception) {
                        log.warn("File Shield watch scan failed: eventType={}, file={}, category={}", eventType,
                                path.getFileName(), exception.getClass().getSimpleName());
                    }
                }
                if (!work.dirty.get()) break;
            }
        } finally {
            work.scheduled.set(false);
            if (work.dirty.get() && running.get()) submitIfNeeded(path, work);
            else pendingScans.remove(path, work);
        }
    }

    private void inspectScript(Path path) {
        if (scriptThreatAnalyzer == null || monitorEventAnalyzer == null
                || !telemetryProperties.isScriptMonitoringEnabled()) return;
        try {
            scriptThreatAnalyzer.inspectFile(path).ifPresent(analysis ->
                    monitorEventAnalyzer.recordScriptFinding(path.getFileName().toString(), analysis));
        } catch (IOException | RuntimeException exception) {
            log.debug("Static script inspection skipped: category={}", exception.getClass().getSimpleName());
        }
    }

    private boolean awaitStableFile(Path path) {
        BasicFileAttributes previous = null;
        int stableObservations = 0;
        for (int attempt = 0; attempt < properties.getStabilityCheckAttempts() && running.get(); attempt++) {
            try {
                if (hasSymlinkComponent(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return false;
                BasicFileAttributes current = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (current.size() > properties.getMaxFileSize()) return false;
                if (previous != null && current.size() == previous.size()
                        && current.lastModifiedTime().equals(previous.lastModifiedTime())
                        && (current.fileKey() == null || previous.fileKey() == null || current.fileKey().equals(previous.fileKey()))) {
                    stableObservations++;
                    if (stableObservations >= 2) return true;
                } else stableObservations = 0;
                previous = current;
                Thread.sleep(properties.getStabilityCheckIntervalMs());
            } catch (IOException | SecurityException exception) {
                return false;
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    private void enqueueDirectoryRescan(Path root) {
        ThreadPoolExecutor pool = workers;
        if (pool == null || pool.isShutdown()) return;
        try {
            pool.execute(() -> {
                try {
                    DirectoryScanResponse response = fileShieldService.scanDirectory(root);
                    if (response.results() != null) {
                        for (FileScanResponse result : response.results()) publishResult("OVERFLOW_RESYNC", result);
                    }
                    log.info("File Shield overflow rescan completed: files={}, limitReached={}", response.scanned(), response.limitReached());
                } catch (RuntimeException exception) {
                    log.warn("File Shield overflow rescan failed: category={}", exception.getClass().getSimpleName());
                }
            });
        } catch (RejectedExecutionException rejected) {
            log.warn("File Shield scan queue is full; skipping controlled overflow rescan");
        }
    }

    private void publishResult(String eventType, FileScanResponse result) {
        String name = result.fileName() == null ? "[unknown]" : result.fileName();
        FileShieldWatchResult event = new FileShieldWatchResult(name, eventType, result.sha256(),
                result.reputationStatus(), result.scanStatus(), result.message(), Instant.now());
        eventPublisher.publishEvent(event);
        log.info("File Shield watch result: eventType={}, file={}, reputation={}, scanStatus={}, sha256={}",
                event.eventType(), event.fileName(), event.reputationStatus(), event.scanStatus(), event.sha256());
    }

    private boolean withinAllowedRoots(Path path) {
        for (Path approvedRoot : properties.getAllowedRoots()) {
            try {
                Path realRoot = approvedRoot.toAbsolutePath().normalize().toRealPath();
                if (path.toAbsolutePath().normalize().startsWith(realRoot)) return true;
            } catch (IOException | SecurityException ignored) { }
        }
        return false;
    }

    private boolean isWithinRoot(Path path, Path root) {
        try { return path.toRealPath().startsWith(root.toRealPath()) && path.toAbsolutePath().normalize().startsWith(root); }
        catch (IOException | SecurityException exception) { return false; }
    }

    private boolean isQuarantinePath(Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        return properties.getAllowedRoots().stream().map(root -> root.toAbsolutePath().normalize().resolve(".aiwatchdog-quarantine"))
                .anyMatch(normalized::startsWith);
    }

    private boolean hasSymlinkComponent(Path path) {
        Path cursor = path.getRoot();
        for (Path component : path) {
            cursor = cursor == null ? component : cursor.resolve(component);
            if (Files.isSymbolicLink(cursor)) return true;
        }
        return false;
    }

    @Override public boolean isRunning() { return running.get(); }
    @Override public boolean isAutoStartup() { return true; }
    @Override public int getPhase() { return Integer.MAX_VALUE - 100; }
    @Override public void stop(Runnable callback) { try { close(); } finally { callback.run(); } }

    @Override
    public synchronized void stop() { close(); }

    @Override
    public synchronized void close() {
        running.set(false);
        Thread thread = watcherThread;
        if (thread != null) thread.interrupt();
        closeResources();
        ThreadPoolExecutor pool = workers;
        if (pool != null) {
            pool.shutdownNow();
            try { pool.awaitTermination(2, TimeUnit.SECONDS); }
            catch (InterruptedException exception) { Thread.currentThread().interrupt(); }
        }
        watcherThread = null;
        workers = null;
        watchService = null;
        registrations.clear();
        pendingScans.clear();
    }

    private void closeResources() {
        WatchService service = watchService;
        if (service != null) try { service.close(); } catch (IOException ignored) { }
        ThreadPoolExecutor pool = workers;
        if (pool != null) pool.shutdownNow();
    }

    private record Registration(Path root, Path directory, int depth) { }

    private static final class ScanWork {
        private final AtomicReference<String> eventType;
        private final AtomicBoolean dirty = new AtomicBoolean();
        private final AtomicBoolean scheduled = new AtomicBoolean();
        private ScanWork(String eventType) { this.eventType = new AtomicReference<>(eventType); }
    }
}
