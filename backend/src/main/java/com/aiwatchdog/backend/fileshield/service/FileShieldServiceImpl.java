package com.aiwatchdog.backend.fileshield.service;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import com.aiwatchdog.backend.fileshield.dto.DirectoryScanResponse;
import com.aiwatchdog.backend.fileshield.dto.FileScanResponse;
import com.aiwatchdog.backend.fileshield.exception.FileShieldException;
import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.aiwatchdog.backend.fileshield.model.ScanStatus;
import com.aiwatchdog.backend.fileshield.reputation.HashReputation;
import com.aiwatchdog.backend.fileshield.reputation.HashReputationService;
import com.aiwatchdog.backend.monitor.MonitorEventAnalyzer;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

@Service
public class FileShieldServiceImpl implements FileShieldService {
    private static final Logger log = LoggerFactory.getLogger(FileShieldServiceImpl.class);
    private final FileShieldProperties properties;
    private final Sha256Scanner scanner;
    private final HashReputationService reputation;
    private final FileInspectionService inspection;
    private final MonitorEventAnalyzer monitorEvents;

    @Autowired
    public FileShieldServiceImpl(FileShieldProperties properties, Sha256Scanner scanner,
                                 HashReputationService reputation, FileInspectionService inspection,
                                 MonitorEventAnalyzer monitorEvents) {
        this.properties = properties; this.scanner = scanner; this.reputation = reputation;
        this.inspection = inspection; this.monitorEvents = monitorEvents;
    }

    /** Compatibility constructor for direct service fixtures. */
    public FileShieldServiceImpl(FileShieldProperties properties, Sha256Scanner scanner,
                                 HashReputationService reputation) {
        this(properties, scanner, reputation, new FileInspectionService(properties, scanner,
                new com.aiwatchdog.backend.fileshield.service.AuthenticodeSignatureInspector()), null);
    }

    @Override
    public FileScanResponse scanFile(Path requested) {
        return scanFile(requested, true);
    }

    @Override
    public FileScanResponse scanFileForMonitoring(Path requested) {
        return scanFile(requested, false);
    }

    private FileScanResponse scanFile(Path requested, boolean includeSignature) {
        Path file = validatePath(requested, false);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
            throw new FileShieldException(HttpStatus.BAD_REQUEST, "NOT_A_REGULAR_FILE", "The selected path is not a regular file.");
        long size;
        try { size = Files.size(file); }
        catch (IOException e) { throw new FileShieldException(HttpStatus.FORBIDDEN, "FILE_UNREADABLE", "The selected file cannot be read."); }
        if (size > properties.getMaxFileSize())
            throw new FileShieldException(HttpStatus.PAYLOAD_TOO_LARGE, "FILE_TOO_LARGE", "The selected file exceeds the configured scan size limit.");
        long started = System.nanoTime();
        try {
            FileInspectionSnapshot snapshot = inspection.inspect(file, includeSignature);
            HashReputation result;
            try { result = reputation.lookup(snapshot.sha256()); }
            catch (RuntimeException lookupFailure) {
                log.warn("File reputation lookup failed: category={}", lookupFailure.getClass().getSimpleName());
                result = new HashReputation(ReputationStatus.LOOKUP_ERROR, "local-provider", "Reputation lookup failed.");
            }
            ScanStatus status = result.status() == ReputationStatus.LOOKUP_ERROR
                    || (includeSignature && snapshot.signature().status() == com.aiwatchdog.backend.fileshield.service.SignatureStatus.INSPECTION_ERROR)
                    ? ScanStatus.PARTIAL : ScanStatus.COMPLETED;
            String message = switch (result.status()) {
                case KNOWN_MALICIOUS -> "A configured reputation source lists this SHA-256 as known malicious.";
                case KNOWN_CLEAN -> "A configured reputation source lists this SHA-256 as known clean.";
                case SUSPICIOUS -> "A configured reputation source reported suspicious indicators; this is not a malware verdict.";
                case UNKNOWN -> "Hash is not listed; this does not establish that the file is safe.";
                case LOOKUP_ERROR -> "Hash calculated, but configured reputation lookups failed.";
            };
            String signatureMessage = includeSignature ? snapshot.signature().message()
                    : "Signature not inspected during bounded directory scan; use single-file scan for signature details.";
            if (status == ScanStatus.PARTIAL && result.status() != ReputationStatus.LOOKUP_ERROR)
                message += " " + signatureMessage;
            log.info("File scan completed: outcome={}, durationMs={}", result.status(), (System.nanoTime() - started) / 1_000_000);
            FileScanResponse response = new FileScanResponse(file.getFileName().toString(), snapshot.sha256(), result.status(), status,
                    message, snapshot.sizeBytes(), result.source(), result.description(), file.toString(), snapshot.extension(),
                    snapshot.createdAt().toInstant(), snapshot.modifiedAt().toInstant(),
                    includeSignature ? snapshot.signature().status().name() : com.aiwatchdog.backend.fileshield.service.SignatureStatus.NOT_REQUESTED.name(),
                    includeSignature ? snapshot.signature().signerSubject() : null, signatureMessage);
            if (monitorEvents != null) {
                try { monitorEvents.recordFileInspection(response); }
                catch (RuntimeException failure) { log.warn("File scan audit failed: category={}", failure.getClass().getSimpleName()); }
            }
            return response;
        } catch (IOException | SecurityException e) {
            log.warn("File scan failed: category={}", e.getClass().getSimpleName());
            return new FileScanResponse(file.getFileName().toString(), null, ReputationStatus.UNKNOWN,
                    ScanStatus.FAILED, "The file could not be read consistently.", size, null, null,
                    file.toString(), null, null, null, "INSPECTION_ERROR", null, "File inspection failed or the file changed.");
        }
    }

    @Override
    public DirectoryScanResponse scanDirectory(Path requested) {
        Path dir = validatePath(requested, true);
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS))
            throw new FileShieldException(HttpStatus.BAD_REQUEST, "NOT_A_DIRECTORY", "The selected path is not a directory.");
        List<FileScanResponse> results = new ArrayList<>();
        int max = properties.getMaxFilesPerDirectoryScan();
        int[] discovered = {0};
        boolean[] limitReached = {false};
        try {
            Files.walkFileTree(dir, java.util.Set.of(), properties.getMaxDirectoryDepth() + 1,
                    new SimpleFileVisitor<>() {
                        @Override public FileVisitResult preVisitDirectory(Path path, BasicFileAttributes attrs) {
                            if (isQuarantinePath(path) || (!path.equals(dir) && (Files.isSymbolicLink(path) || !withinAllowedRoots(path)))) return FileVisitResult.SKIP_SUBTREE;
                            return FileVisitResult.CONTINUE;
                        }
                        @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                            if (attrs.isRegularFile() && !Files.isSymbolicLink(file)) {
                                discovered[0]++;
                                if (discovered[0] > max) { limitReached[0] = true; return FileVisitResult.TERMINATE; }
                                try { results.add(scanFile(file, false)); }
                                catch (FileShieldException ex) { results.add(new FileScanResponse(file.getFileName().toString(), null, ReputationStatus.UNKNOWN, ScanStatus.REJECTED, ex.getMessage(), 0, null, null)); }
                            }
                            return FileVisitResult.CONTINUE;
                        }
                        @Override public FileVisitResult visitFileFailed(Path file, IOException exc) {
                            discovered[0]++;
                            if (discovered[0] > max) { limitReached[0] = true; return FileVisitResult.TERMINATE; }
                            results.add(new FileScanResponse(file.getFileName().toString(), null, ReputationStatus.UNKNOWN, ScanStatus.FAILED, "File could not be accessed.", 0, null, null));
                            return FileVisitResult.CONTINUE;
                        }
                    });
        } catch (IOException e) {
            throw new FileShieldException(HttpStatus.FORBIDDEN, "DIRECTORY_UNREADABLE", "The selected directory could not be scanned.");
        }
        int scanned = (int) results.stream().filter(r -> r.sha256() != null).count();
        return new DirectoryScanResponse(dir.getFileName() == null ? dir.toString() : dir.getFileName().toString(),
                discovered[0], scanned,
                (int) results.stream().filter(r -> r.scanStatus() == ScanStatus.FAILED).count(),
                (int) results.stream().filter(r -> r.scanStatus() == ScanStatus.REJECTED).count(),
                count(results, ReputationStatus.KNOWN_MALICIOUS), count(results, ReputationStatus.KNOWN_CLEAN),
                count(results, ReputationStatus.SUSPICIOUS),
                count(results, ReputationStatus.UNKNOWN), count(results, ReputationStatus.LOOKUP_ERROR), limitReached[0], List.copyOf(results));
    }

    private int count(List<FileScanResponse> responses, ReputationStatus status) {
        return (int) responses.stream().filter(r -> r.reputationStatus() == status).count();
    }

    private Path validatePath(Path supplied, boolean directory) {
        if (!properties.isEnabled()) throw new FileShieldException(HttpStatus.SERVICE_UNAVAILABLE, "FILE_SHIELD_DISABLED", "File Shield is disabled.");
        if (supplied == null || supplied.toString().isBlank()) throw new FileShieldException(HttpStatus.BAD_REQUEST, "INVALID_PATH", "A valid path is required.");
        try {
            Path normalized = supplied.toAbsolutePath().normalize();
            if (hasSymbolicLinkComponent(normalized)) throw new FileShieldException(HttpStatus.FORBIDDEN, "SYMLINK_REJECTED", "Symbolic links are not scanned.");
            Path real = normalized.toRealPath();
            if (!withinAllowedRoots(real)) throw new FileShieldException(HttpStatus.FORBIDDEN, "PATH_NOT_ALLOWED", "The selected path is outside configured scan roots.");
            if (isQuarantinePath(real)) throw new FileShieldException(HttpStatus.FORBIDDEN, "QUARANTINE_PATH", "Quarantined files are not available for ordinary scans.");
            if (directory && !Files.isDirectory(real, LinkOption.NOFOLLOW_LINKS)) throw new FileShieldException(HttpStatus.BAD_REQUEST, "NOT_A_DIRECTORY", "The selected path is not a directory.");
            if (!directory && Files.isDirectory(real, LinkOption.NOFOLLOW_LINKS)) throw new FileShieldException(HttpStatus.BAD_REQUEST, "NOT_A_FILE", "A directory cannot be scanned as a single file.");
            return real;
        } catch (FileShieldException e) { throw e; }
        catch (java.nio.file.NoSuchFileException e) { throw new FileShieldException(HttpStatus.NOT_FOUND, "FILE_NOT_FOUND", "The selected path does not exist."); }
        catch (IOException | SecurityException e) { throw new FileShieldException(HttpStatus.FORBIDDEN, "PATH_UNAVAILABLE", "The selected path cannot be accessed."); }
    }

    private boolean hasSymbolicLinkComponent(Path path) {
        Path cursor = path.getRoot();
        for (Path component : path) {
            cursor = cursor == null ? component : cursor.resolve(component);
            if (Files.isSymbolicLink(cursor)) return true;
        }
        return false;
    }

    private boolean withinAllowedRoots(Path target) {
        for (Path root : properties.getAllowedRoots()) {
            try {
                Path realRoot = root.toAbsolutePath().normalize().toRealPath();
                if (target.toAbsolutePath().normalize().startsWith(realRoot)) return true;
            } catch (IOException | SecurityException ignored) { }
        }
        return false;
    }

    private boolean isQuarantinePath(Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        return properties.getAllowedRoots().stream().map(root -> root.toAbsolutePath().normalize().resolve(".aiwatchdog-quarantine"))
                .anyMatch(normalized::startsWith);
    }
}
