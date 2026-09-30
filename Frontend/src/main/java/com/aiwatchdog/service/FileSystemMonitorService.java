package com.aiwatchdog.service;

import com.aiwatchdog.model.MonitorEvent;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Stream;

/** Watches explicitly configured user directories and reports basename-only metadata. */
public final class FileSystemMonitorService implements AutoCloseable {
    private static final long DEBOUNCE_MILLIS = 1500;
    private final MonitorEventSubmitter eventSubmitter;
    private final Consumer<MonitorEvent> eventConsumer;
    private final Map<WatchKey, Path> directories = new ConcurrentHashMap<>();
    private final Map<String, Long> lastSeen = new ConcurrentHashMap<>();
    private final Map<Path, Long> recentDeletes = new ConcurrentHashMap<>();
    private final List<Path> exclusions;
    private final List<Path> roots;
    private final ExecutorService sender = new ThreadPoolExecutor(2, 2, 0, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(256), task -> {
        Thread thread = new Thread(task, "aiwatchdog-file-event-sender");
        thread.setDaemon(true);
        return thread;
    }, new ThreadPoolExecutor.DiscardOldestPolicy());
    private WatchService watcher;
    private Thread worker;
    private volatile boolean running;

    public boolean isRunning() { return running; }

    public FileSystemMonitorService(MonitorEventSubmitter eventSubmitter, Consumer<MonitorEvent> eventConsumer) {
        this(eventSubmitter, eventConsumer, configuredRoots(),
                configuredPaths("AI_WATCHDOG_MONITOR_EXCLUDE", List.of()));
    }

    FileSystemMonitorService(MonitorEventSubmitter eventSubmitter, Consumer<MonitorEvent> eventConsumer,
                             List<Path> roots, List<Path> exclusions) {
        this.eventSubmitter = eventSubmitter;
        this.eventConsumer = eventConsumer;
        this.roots = roots.stream().map(path -> path.toAbsolutePath().normalize()).toList();
        this.exclusions = exclusions.stream().map(path -> path.toAbsolutePath().normalize()).toList();
    }

    public synchronized int start() throws IOException {
        if (running) return directories.size();
        watcher = Path.of(System.getProperty("user.home")).getFileSystem().newWatchService();
        for (Path root : roots) {
            if (!Files.isDirectory(root) || excluded(root)) continue;
            try (Stream<Path> paths = Files.walk(root)) {
                paths.filter(Files::isDirectory).filter(path -> !excluded(path)).forEach(path -> {
                    try { register(path); } catch (IOException ignored) { }
                });
            }
        }
        if (directories.isEmpty()) {
            watcher.close();
            watcher = null;
            return 0;
        }
        running = true;
        worker = new Thread(this::watchLoop, "aiwatchdog-file-monitor");
        worker.setDaemon(true);
        worker.start();
        return directories.size();
    }

    private void watchLoop() {
        while (running) {
            WatchKey key;
            try { key = watcher.take(); }
            catch (InterruptedException exception) { Thread.currentThread().interrupt(); break; }
            catch (java.nio.file.ClosedWatchServiceException exception) { break; }
            Path directory = directories.get(key);
            if (directory != null) {
                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.OVERFLOW) continue;
                    Object context = event.context();
                    if (!(context instanceof Path relative)) continue;
                    Path path = directory.resolve(relative).normalize();
                    if (event.kind() == StandardWatchEventKinds.ENTRY_DELETE) {
                        long now = System.currentTimeMillis();
                        recentDeletes.put(path, System.currentTimeMillis());
                        if (recentDeletes.size() > 1024) {
                            recentDeletes.entrySet().removeIf(entry -> now - entry.getValue() > 2000);
                        }
                        continue;
                    }
                    if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE && Files.isDirectory(path)) {
                        registerTree(path);
                    } else if (Files.isRegularFile(path) && !excluded(path) && !hidden(path)) {
                        String action = event.kind() == StandardWatchEventKinds.ENTRY_CREATE
                                ? inferCreateOrRename(path) : "FILE_MODIFIED";
                        dispatch(path, action);
                    }
                }
            }
            if (!key.reset()) directories.remove(key);
        }
    }

    private String inferCreateOrRename(Path createdPath) {
        long now = System.currentTimeMillis();
        recentDeletes.entrySet().removeIf(entry -> now - entry.getValue() > 2000);
        Path parent = createdPath.getParent();
        Path deletedPath = recentDeletes.entrySet().stream()
                .filter(entry -> entry.getKey().getParent().equals(parent))
                .filter(entry -> now - entry.getValue() <= 2000)
                .map(Map.Entry::getKey)
                .findFirst().orElse(null);
        if (deletedPath != null) {
            recentDeletes.remove(deletedPath);
            return "FILE_RENAMED";
        }
        return "FILE_CREATED";
    }

    private void registerTree(Path root) {
        if (excluded(root)) return;
        try (Stream<Path> paths = Files.walk(root)) {
            paths.filter(Files::isDirectory).filter(path -> !excluded(path)).forEach(path -> {
                try { register(path); } catch (IOException ignored) { }
            });
        } catch (IOException ignored) { }
    }

    private void register(Path directory) throws IOException {
        WatchKey key = directory.register(watcher,
                StandardWatchEventKinds.ENTRY_CREATE,
                StandardWatchEventKinds.ENTRY_MODIFY,
                StandardWatchEventKinds.ENTRY_DELETE);
        directories.put(key, directory);
    }

    private void dispatch(Path path, String action) {
        long now = System.currentTimeMillis();
        String key = action + ":" + path.toAbsolutePath().normalize();
        Long previous = lastSeen.put(key, now);
        if (previous != null && now - previous < DEBOUNCE_MILLIS) return;
        if (lastSeen.size() > 10_000) {
            lastSeen.entrySet().removeIf(entry -> now - entry.getValue() > 300_000);
        }
        String name = path.getFileName().toString();
        Long size = null;
        try { size = Files.readAttributes(path, BasicFileAttributes.class).size(); }
        catch (IOException ignored) { }
        Long fileSize = size;
        sender.submit(() -> {
            try {
                MonitorEvent result = eventSubmitter.submit("FILE", action, name, null, fileSize);
                eventConsumer.accept(result);
            } catch (Exception ignored) {
                // The next event is retried normally; the UI reports service state separately.
            }
        });
    }

    private boolean excluded(Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        return exclusions.stream().anyMatch(normalized::startsWith);
    }

    private boolean hidden(Path path) {
        try { return Files.isHidden(path); } catch (IOException exception) { return true; }
    }

    private static List<Path> configuredRoots() {
        String configured = System.getenv("AI_WATCHDOG_MONITOR_DIRS");
        if (configured != null && !configured.isBlank()) return configuredPaths("AI_WATCHDOG_MONITOR_DIRS", List.of());
        Path home = Path.of(System.getProperty("user.home"));
        return List.of(home.resolve("Downloads"), home.resolve("Desktop"), home.resolve("Documents"));
    }

    private static List<Path> configuredPaths(String variable, List<Path> fallback) {
        String configured = System.getenv(variable);
        if (configured == null || configured.isBlank()) return fallback;
        List<Path> paths = new ArrayList<>();
        for (String part : configured.split(",")) {
            if (!part.isBlank()) paths.add(Path.of(part.trim()).toAbsolutePath().normalize());
        }
        return List.copyOf(paths);
    }

    @Override public synchronized void close() {
        running = false;
        if (watcher != null) {
            try { watcher.close(); } catch (IOException ignored) { }
            watcher = null;
        }
        if (worker != null) worker.interrupt();
        sender.shutdown();
        try {
            if (!sender.awaitTermination(2, TimeUnit.SECONDS)) sender.shutdownNow();
        } catch (InterruptedException exception) {
            sender.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
