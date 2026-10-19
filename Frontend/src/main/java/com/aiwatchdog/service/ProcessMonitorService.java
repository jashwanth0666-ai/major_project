package com.aiwatchdog.service;

import com.aiwatchdog.model.MonitorEvent;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/** Polls ProcessHandle metadata without collecting command-line arguments or killing processes. */
public final class ProcessMonitorService implements AutoCloseable {
    private final MonitorEventSubmitter eventSubmitter;
    private final Consumer<MonitorEvent> eventConsumer;
    private final Map<Long, Instant> knownProcesses = new ConcurrentHashMap<>();
    private final ThreadPoolExecutor sender = new ThreadPoolExecutor(2, 2, 0, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(256), task -> {
        Thread thread = new Thread(task, "aiwatchdog-process-event-sender");
        thread.setDaemon(true);
        return thread;
    }, new ThreadPoolExecutor.AbortPolicy());
    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicLong observedProcesses = new AtomicLong();
    private final AtomicLong observedStarts = new AtomicLong();
    private final AtomicLong processAccessFailures = new AtomicLong();
    private final AtomicLong pollFailures = new AtomicLong();
    private final AtomicLong uploadFailures = new AtomicLong();
    private final AtomicLong droppedUploads = new AtomicLong();
    private final AtomicLong lastPollEpochMillis = new AtomicLong();
    private Thread worker;

    public boolean isRunning() { return running.get(); }

    public HealthSnapshot getHealthSnapshot() {
        return new HealthSnapshot(running.get(), observedProcesses.get(), observedStarts.get(),
                processAccessFailures.get(), pollFailures.get(), uploadFailures.get(), droppedUploads.get(),
                sender.getQueue().size(), 256, lastPollEpochMillis.get());
    }

    public record HealthSnapshot(boolean running, long observedProcesses, long observedStarts,
                                 long processAccessFailures, long pollFailures, long uploadFailures,
                                 long droppedUploads, int queuedUploads, int uploadQueueCapacity,
                                 long lastPollEpochMillis) {}

    public ProcessMonitorService(MonitorEventSubmitter eventSubmitter, Consumer<MonitorEvent> eventConsumer) {
        this.eventSubmitter = eventSubmitter;
        this.eventConsumer = eventConsumer;
    }

    public synchronized void start() {
        if (running.get()) return;
        snapshotExistingProcesses();
        running.set(true);
        worker = new Thread(this::poll, "aiwatchdog-process-monitor");
        worker.setDaemon(true);
        worker.start();
    }

    private void snapshotExistingProcesses() {
        try {
            ProcessHandle.allProcesses().forEach(process -> {
                try { knownProcesses.put(process.pid(), process.info().startInstant().orElse(Instant.EPOCH)); }
                catch (RuntimeException ignored) { processAccessFailures.incrementAndGet(); }
            });
        } catch (RuntimeException ignored) {
            // Process enumeration can be restricted by the OS; file monitoring should still start.
            pollFailures.incrementAndGet();
        }
        observedProcesses.set(knownProcesses.size());
        lastPollEpochMillis.set(System.currentTimeMillis());
    }

    private void poll() {
        long interval = pollIntervalMillis();
        while (running.get()) {
            try {
                Map<Long, Instant> observed = new ConcurrentHashMap<>();
                ProcessHandle.allProcesses().forEach(process -> {
                    try {
                        long pid = process.pid();
                        Instant started = process.info().startInstant().orElse(Instant.EPOCH);
                        observed.put(pid, started);
                        Instant knownStart = knownProcesses.putIfAbsent(pid, started);
                        if (knownStart == null || (!knownStart.equals(Instant.EPOCH) && !knownStart.equals(started))) {
                            report(process, pid);
                        }
                    } catch (RuntimeException ignored) { processAccessFailures.incrementAndGet(); }
                });
                knownProcesses.keySet().removeIf(pid -> !observed.containsKey(pid));
                observedProcesses.set(observed.size());
                lastPollEpochMillis.set(System.currentTimeMillis());
                Thread.sleep(interval);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                break;
            } catch (RuntimeException exception) {
                pollFailures.incrementAndGet();
                try { Thread.sleep(interval); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); break; }
            }
        }
    }

    private void report(ProcessHandle process, long pid) {
        String command = process.info().command().orElse("");
        String name;
        try { name = command.isBlank() ? "unknown-process" : Path.of(command).getFileName().toString(); }
        catch (RuntimeException exception) { name = "unknown-process"; }
        String processName = name;
        observedStarts.incrementAndGet();
        try {
            sender.execute(() -> {
            try {
                MonitorEvent result = eventSubmitter.submit("PROCESS", "PROCESS_STARTED",
                        processName, pid, null);
                eventConsumer.accept(result);
            } catch (Exception ignored) {
                uploadFailures.incrementAndGet();
            }
            });
        } catch (RejectedExecutionException ignored) {
            droppedUploads.incrementAndGet();
        }
    }

    private long pollIntervalMillis() {
        String configured = System.getenv("AI_WATCHDOG_PROCESS_POLL_MS");
        if (configured == null) configured = System.getProperty("aiwatchdog.process.poll-ms", "2000");
        try { return Math.max(1000, Math.min(60_000, Long.parseLong(configured))); }
        catch (NumberFormatException exception) { return 2000; }
    }

    @Override public synchronized void close() {
        running.set(false);
        if (worker != null) worker.interrupt();
        sender.shutdownNow();
        knownProcesses.clear();
    }
}
