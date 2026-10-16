package com.aiwatchdog.backend.fileshield.watcher;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import com.aiwatchdog.backend.fileshield.dto.FileScanResponse;
import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.aiwatchdog.backend.fileshield.model.ScanStatus;
import com.aiwatchdog.backend.fileshield.reputation.HashReputation;
import com.aiwatchdog.backend.fileshield.service.DefaultSha256Scanner;
import com.aiwatchdog.backend.fileshield.service.FileShieldService;
import com.aiwatchdog.backend.fileshield.service.FileShieldServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.PayloadApplicationEvent;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class FileShieldDirectoryWatcherTest {
    @TempDir Path root;
    private static final String ABC_HASH = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    @Test void monitoringIsDisabledByDefault() throws Exception {
        FileShieldProperties properties = new FileShieldProperties();
        assertFalse(properties.isMonitoringEnabled());
        FileShieldDirectoryWatcher watcher = new FileShieldDirectoryWatcher(properties, mock(FileShieldService.class), mockPublisher(new CopyOnWriteArrayList<>()));
        watcher.start();
        assertFalse(watcher.isRunning());
        watcher.close();
    }

    @Test void approvedDirectoryCreateAndModifyEventsUseExistingScanner() throws Exception {
        FileShieldProperties properties = propertiesFor(root);
        List<FileShieldWatchResult> events = new CopyOnWriteArrayList<>();
        FileShieldService service = new FileShieldServiceImpl(properties, new DefaultSha256Scanner(),
                hash -> new HashReputation(ReputationStatus.UNKNOWN, "test-empty-provider", null));
        FileShieldDirectoryWatcher watcher = new FileShieldDirectoryWatcher(properties, service, mockPublisher(events));
        try {
            watcher.start();
            assertTrue(watcher.isRunning());
            Path file = root.resolve("sample.txt");
            Files.writeString(file, "abc");
            await(() -> events.stream().anyMatch(e -> ABC_HASH.equals(e.sha256())), 5_000);
            assertTrue(events.stream().anyMatch(e -> "sample.txt".equals(e.fileName())
                    && "ENTRY_CREATE".equals(e.eventType())
                    && ABC_HASH.equals(e.sha256())
                    && e.reputationStatus() == ReputationStatus.UNKNOWN));

            String updatedHash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest("updated".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            Files.writeString(file, "updated");
            await(() -> events.stream().anyMatch(e -> updatedHash.equals(e.sha256())), 5_000);
            assertTrue(events.stream().anyMatch(e -> "ENTRY_MODIFY".equals(e.eventType()) && updatedHash.equals(e.sha256())));
        } finally { watcher.close(); }
        assertFalse(watcher.isRunning());
    }

    @Test void configuredDirectoriesOutsideApprovedRootsAreNotWatched() throws Exception {
        Path approved = Files.createDirectory(root.resolve("approved"));
        Path outside = Files.createDirectory(root.resolve("outside"));
        FileShieldProperties properties = propertiesFor(outside);
        properties.setAllowedRoots(List.of(approved));
        FileShieldDirectoryWatcher watcher = new FileShieldDirectoryWatcher(properties, mock(FileShieldService.class), mockPublisher(new CopyOnWriteArrayList<>()));
        watcher.start();
        assertFalse(watcher.isRunning());
        watcher.close();
    }

    @Test void reputationLookupFailureIsPublishedAsLookupError() throws Exception {
        FileShieldProperties properties = propertiesFor(root);
        List<FileShieldWatchResult> events = new CopyOnWriteArrayList<>();
        FileShieldService service = new FileShieldServiceImpl(properties, new DefaultSha256Scanner(), hash -> {
            throw new IllegalStateException("test lookup failure");
        });
        FileShieldDirectoryWatcher watcher = new FileShieldDirectoryWatcher(properties, service, mockPublisher(events));
        try {
            watcher.start();
            Files.writeString(root.resolve("lookup-error.txt"), "abc");
            await(() -> events.stream().anyMatch(event -> event.reputationStatus() == ReputationStatus.LOOKUP_ERROR), 5_000);
            FileShieldWatchResult result = events.stream()
                    .filter(event -> event.reputationStatus() == ReputationStatus.LOOKUP_ERROR)
                    .findFirst().orElseThrow();
            assertEquals(ABC_HASH, result.sha256());
            assertEquals(ScanStatus.PARTIAL, result.scanStatus());
        } finally { watcher.close(); }
    }

    @Test void waitsForAnActivelyWrittenFileAndHonorsDepthAndSizeLimits() throws Exception {
        FileShieldProperties properties = propertiesFor(root);
        properties.setStabilityCheckIntervalMs(300);
        properties.setStabilityCheckAttempts(4);
        properties.setMaxMonitoringDepth(0);
        properties.setMaxFileSize(32);
        List<FileShieldWatchResult> events = new CopyOnWriteArrayList<>();
        FileShieldService service = new FileShieldServiceImpl(properties, new DefaultSha256Scanner(),
                hash -> new HashReputation(ReputationStatus.UNKNOWN, "test-empty-provider", null));
        FileShieldDirectoryWatcher watcher = new FileShieldDirectoryWatcher(properties, service, mockPublisher(events));
        try {
            watcher.start();
            Path growingFile = Files.writeString(root.resolve("growing.txt"), "start");
            watcher.queueFileEvent(growingFile, "ENTRY_CREATE");
            Thread.sleep(100);
            Files.writeString(growingFile, "finished", java.nio.file.StandardOpenOption.APPEND);
            String finalHash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest("startfinished".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            await(() -> events.stream().anyMatch(event -> finalHash.equals(event.sha256())), 5_000);

            Path nested = Files.createDirectory(root.resolve("nested"));
            Files.writeString(nested.resolve("ignored.txt"), "abc");
            Path tooLarge = Files.writeString(root.resolve("too-large.txt"), "x".repeat(33));
            watcher.queueFileEvent(tooLarge, "ENTRY_CREATE");
            Thread.sleep(500);
            assertTrue(events.stream().noneMatch(event -> event.fileName().equals("ignored.txt")
                    || event.fileName().equals("too-large.txt")));
        } finally { watcher.close(); }
    }

    @Test void deletedFilesAreIgnoredWithoutCallingTheScanner() throws Exception {
        FileShieldProperties properties = propertiesFor(root);
        FileShieldService service = mock(FileShieldService.class);
        FileShieldDirectoryWatcher watcher = new FileShieldDirectoryWatcher(properties, service,
                mockPublisher(new CopyOnWriteArrayList<>()));
        Path file = Files.writeString(root.resolve("deleted.txt"), "abc");
        watcher.start();
        try {
            Files.delete(file);
            watcher.queueFileEvent(file, "ENTRY_MODIFY");
            Thread.sleep(100);
            verifyNoInteractions(service);
        } finally { watcher.close(); }
    }

    @Test void anInvalidWatchKeyIsRemovedWithoutStoppingOtherRoots() throws Exception {
        Path removedRoot = Files.createDirectory(root.resolve("removed-root"));
        Path healthyRoot = Files.createDirectory(root.resolve("healthy-root"));
        FileShieldProperties properties = propertiesFor(removedRoot);
        properties.setAllowedRoots(List.of(removedRoot, healthyRoot));
        properties.setWatchDirectories(List.of(removedRoot, healthyRoot));
        List<FileShieldWatchResult> events = new CopyOnWriteArrayList<>();
        FileShieldService service = new FileShieldServiceImpl(properties, new DefaultSha256Scanner(),
                hash -> new HashReputation(ReputationStatus.UNKNOWN, "test-empty-provider", null));
        FileShieldDirectoryWatcher watcher = new FileShieldDirectoryWatcher(properties, service, mockPublisher(events));
        try {
            watcher.start();
            Files.delete(removedRoot);
            Path survivingFile = Files.writeString(healthyRoot.resolve("surviving.txt"), "abc");
            await(() -> events.stream().anyMatch(event -> "surviving.txt".equals(event.fileName())), 5_000);
            assertTrue(watcher.isRunning());
        } finally { watcher.close(); }
    }

    @Test void duplicateEventsCoalesceAndQueueSaturationStaysBounded() throws Exception {
        FileShieldProperties properties = propertiesFor(root);
        properties.setMonitoringWorkerCount(1);
        properties.setMonitoringQueueCapacity(1);
        Path first = Files.writeString(root.resolve("first.txt"), "first");
        Path second = Files.writeString(root.resolve("second.txt"), "second");
        Path third = Files.writeString(root.resolve("third.txt"), "third");
        CountDownLatch firstEntered = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch scansFinished = new CountDownLatch(3);
        AtomicInteger calls = new AtomicInteger();
        FileShieldService service = mock(FileShieldService.class);
        when(service.scanFile(any(Path.class))).thenAnswer(invocation -> {
            Path path = invocation.getArgument(0);
            calls.incrementAndGet();
            if (path.equals(first)) {
                firstEntered.countDown();
                assertTrue(releaseFirst.await(3, TimeUnit.SECONDS));
            }
            scansFinished.countDown();
            return response(path.getFileName().toString());
        });
        FileShieldDirectoryWatcher watcher = new FileShieldDirectoryWatcher(properties, service, mockPublisher(new CopyOnWriteArrayList<>()));
        try {
            watcher.start();
            watcher.queueFileEvent(first, "ENTRY_CREATE");
            assertTrue(firstEntered.await(3, TimeUnit.SECONDS));
            for (int index = 0; index < 12; index++) watcher.queueFileEvent(first, "ENTRY_MODIFY");
            watcher.queueFileEvent(second, "ENTRY_CREATE");
            watcher.queueFileEvent(third, "ENTRY_CREATE");
            releaseFirst.countDown();
            assertTrue(scansFinished.await(5, TimeUnit.SECONDS));
            assertEquals(3, calls.get(), "same-path events coalesce to one follow-up, and only the single queued item is accepted");
            verify(service, never()).scanFile(third);
        } finally {
            releaseFirst.countDown();
            watcher.close();
        }
    }

    @Test void shutdownClosesWatcherAndStopsAcceptingEvents() throws Exception {
        FileShieldProperties properties = propertiesFor(root);
        FileShieldService service = mock(FileShieldService.class);
        FileShieldDirectoryWatcher watcher = new FileShieldDirectoryWatcher(properties, service, mockPublisher(new CopyOnWriteArrayList<>()));
        watcher.start();
        assertTrue(watcher.isRunning());
        watcher.stop();
        assertFalse(watcher.isRunning());
        watcher.queueFileEvent(root.resolve("later.txt"), "ENTRY_CREATE");
        verifyNoInteractions(service);
    }

    private FileShieldProperties propertiesFor(Path directory) {
        FileShieldProperties properties = new FileShieldProperties();
        properties.setEnabled(true);
        properties.setAllowedRoots(List.of(directory));
        properties.setMonitoringEnabled(true);
        properties.setWatchDirectories(List.of(directory));
        properties.setRecursiveMonitoring(true);
        properties.setMaxMonitoringDepth(2);
        properties.setStabilityCheckIntervalMs(50);
        properties.setStabilityCheckAttempts(5);
        return properties;
    }

    private ApplicationEventPublisher mockPublisher(List<FileShieldWatchResult> events) {
        return event -> {
            if (event instanceof FileShieldWatchResult result) {
                events.add(result);
            } else if (event instanceof PayloadApplicationEvent<?> payload && payload.getPayload() instanceof FileShieldWatchResult result) {
                events.add(result);
            }
        };
    }

    private FileScanResponse response(String fileName) {
        return new FileScanResponse(fileName, ABC_HASH, ReputationStatus.UNKNOWN, ScanStatus.COMPLETED,
                "Unknown hash", 3, "test", null);
    }

    private void await(java.util.function.BooleanSupplier condition, long timeoutMs) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(25);
        assertTrue(condition.getAsBoolean(), "condition did not become true before timeout");
    }
}
