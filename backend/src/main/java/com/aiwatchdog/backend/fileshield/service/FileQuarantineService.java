package com.aiwatchdog.backend.fileshield.service;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import com.aiwatchdog.backend.fileshield.dto.QuarantineHistoryResponse;
import com.aiwatchdog.backend.fileshield.dto.QuarantineOperationResult;
import com.aiwatchdog.backend.fileshield.dto.QuarantineRequest;
import com.aiwatchdog.backend.fileshield.dto.RestoreQuarantinedFileRequest;
import com.aiwatchdog.backend.fileshield.exception.FileShieldException;
import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.aiwatchdog.backend.fileshield.reputation.HashReputation;
import com.aiwatchdog.backend.fileshield.reputation.HashReputationService;
import com.aiwatchdog.backend.logging.SecurityEvent;
import com.aiwatchdog.backend.logging.SecurityEventLogger;
import com.aiwatchdog.backend.logging.SecurityEventRepository;
import com.aiwatchdog.backend.policy.Decision;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Explicit, reversible, integrity-checked file quarantine. No operation is automatic. */
@Service
public class FileQuarantineService {
    private static final Logger log = LoggerFactory.getLogger(FileQuarantineService.class);
    private static final String QUARANTINE_FOLDER = ".aiwatchdog-quarantine";
    private final FileShieldProperties properties;
    private final FileInspectionService inspection;
    private final Sha256Scanner scanner;
    private final HashReputationService reputation;
    private final SecurityEventLogger audit;
    private final SecurityEventRepository events;
    private final WindowsPathSafety pathSafety;
    private final ObjectMapper mapper = new ObjectMapper();

    public FileQuarantineService(FileShieldProperties properties, FileInspectionService inspection, Sha256Scanner scanner,
                                 HashReputationService reputation, SecurityEventLogger audit,
                                 SecurityEventRepository events, WindowsPathSafety pathSafety) {
        this.properties = properties; this.inspection = inspection; this.scanner = scanner;
        this.reputation = reputation; this.audit = audit; this.events = events; this.pathSafety = pathSafety;
    }

    @PostConstruct
    public void recoverInterruptedOperations() {
        try {
            for (SecurityEvent event : events.findIncompleteFileOperations()) recover(event);
        } catch (RuntimeException failure) {
            log.warn("Quarantine recovery could not inspect prior operations: category={}", failure.getClass().getSimpleName());
        }
    }

    public QuarantineOperationResult quarantine(QuarantineRequest request) {
        requireConfirmation(request != null && request.confirmed());
        requireWindowsAndEnabled();
        if (request.path() == null || request.path().isBlank() || request.expectedSha256() == null
                || !request.expectedSha256().matches("(?i)[a-f0-9]{64}"))
            throw new FileShieldException(HttpStatus.BAD_REQUEST, "INVALID_QUARANTINE_REQUEST", "A file path and current SHA-256 are required.");
        Path source = approvedFile(parseRequestPath(request.path()));
        FileInspectionSnapshot current = inspectExpected(source, request.expectedSha256());
        HashReputation currentReputation = safeReputation(current.sha256());
        if (currentReputation.status() != ReputationStatus.KNOWN_MALICIOUS
                && currentReputation.status() != ReputationStatus.SUSPICIOUS) {
            String rejectedId = UUID.randomUUID().toString();
            writeAudit(rejectedId, new OperationAudit("QUARANTINE_REJECTED", source.getFileName().toString(), current.sha256(),
                    source.toString(), "", null, current.createdAt().toString(), current.modifiedAt().toString(),
                    current.signature().status().name(), "Quarantine refused because current reputation is " + currentReputation.status() + "."));
            throw new FileShieldException(HttpStatus.CONFLICT, "REPUTATION_NOT_QUARANTINABLE",
                    "Current reputation is not known malicious or suspicious. Unknown or unavailable reputation is never quarantined automatically.");
        }

        Path quarantineDir = quarantineDirectoryFor(source);
        ensureSecureDirectory(quarantineDir);
        Path target = null;
        for (int attempt = 0; attempt < 8; attempt++) {
            Path candidate = quarantineDir.resolve(UUID.randomUUID() + ".qdata");
            if (!Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) { target = candidate; break; }
        }
        if (target == null) throw new FileShieldException(HttpStatus.CONFLICT, "QUARANTINE_NAME_COLLISION", "A unique quarantine destination could not be reserved; no file was moved.");
        String operationId = UUID.randomUUID().toString();
        BasicFileAttributes attributes;
        try {
            attributes = readAttributes(source);
            recheckIdentity(source, current);
        } catch (IOException changed) {
            throw new FileShieldException(HttpStatus.CONFLICT, "FILE_IDENTITY_CHANGED", "File changed before quarantine; scan it again before proceeding.");
        }
        OperationAudit record = new OperationAudit("QUARANTINE_STARTED", source.getFileName().toString(), current.sha256(),
                source.toString(), target.toString(), null, attributes.creationTime().toString(),
                attributes.lastModifiedTime().toString(), current.signature().status().name(),
                "Quarantine operation was authorized and started.");
        writeAudit(operationId, record);

        try {
            requireSameFileStore(source, quarantineDir);
            pathSafety.rejectReparseComponents(source);
            pathSafety.rejectReparseComponents(quarantineDir);
            Files.move(source, target);
            secureFile(target);
            String movedHash = scanner.sha256(target, properties.getMaxFileSize());
            if (!current.sha256().equalsIgnoreCase(movedHash) || Files.exists(source, LinkOption.NOFOLLOW_LINKS)) {
                boolean rolledBack = rollbackMove(target, source);
                OperationAudit failed = record.with("QUARANTINE_FAILED", rolledBack
                        ? "Moved file failed identity verification and was restored to its original path."
                        : "Moved file failed identity verification; manual recovery is required.");
                writeAudit(operationId, failed);
                return result(operationId, failed, false);
            }
            OperationAudit complete = record.with("QUARANTINED", "File moved into the restricted quarantine directory and SHA-256 integrity was verified.");
            try { writeAudit(operationId, complete); }
            catch (RuntimeException auditFailure) {
                log.error("Quarantine completed but completion audit write failed: operationId={}", operationId);
                return result(operationId, record.with("QUARANTINE_STARTED",
                        "File is in quarantine and integrity was verified, but the completion audit could not be recorded; startup recovery will reconcile it."), false);
            }
            return result(operationId, complete, true);
        } catch (AtomicMoveNotSupportedException unsupported) {
            OperationAudit failed = record.with("QUARANTINE_FAILED", "The quarantine destination is on a different file system; the original file was not copied or deleted.");
            writeAudit(operationId, failed);
            return result(operationId, failed, false);
        } catch (IOException | SecurityException failure) {
            String state = Files.exists(target, LinkOption.NOFOLLOW_LINKS) && !Files.exists(source, LinkOption.NOFOLLOW_LINKS)
                    ? "RECOVERY_REQUIRED" : "QUARANTINE_FAILED";
            OperationAudit failed = record.with(state, "Quarantine operation failed safely: " + failureCategory(failure) + ".");
            writeAudit(operationId, failed);
            return result(operationId, failed, false);
        }
    }

    public QuarantineOperationResult restore(String operationId, RestoreQuarantinedFileRequest request) {
        requireConfirmation(request != null && request.confirmed());
        requireWindowsAndEnabled();
        try { UUID.fromString(operationId); }
        catch (IllegalArgumentException invalid) { throw new FileShieldException(HttpStatus.BAD_REQUEST, "INVALID_OPERATION_ID", "Quarantine operation ID is invalid."); }
        SecurityEvent event = events.findLatestFileOperation(operationId)
                .orElseThrow(() -> new FileShieldException(HttpStatus.NOT_FOUND, "QUARANTINE_NOT_FOUND", "Quarantine record was not found."));
        JsonNode data = details(event);
        String state = data.path("state").asText("");
        if (!Set.of("QUARANTINED", "RESTORE_FAILED", "RECOVERY_REQUIRED").contains(state))
            throw new FileShieldException(HttpStatus.CONFLICT, "NOT_RESTORABLE", "This quarantine record is not in a restorable state.");
        Path quarantined = Path.of(data.path("quarantinePath").asText());
        Path original = Path.of(data.path("originalPath").asText());
        Path destination = request.destinationPath() == null || request.destinationPath().isBlank()
                ? original : parseRequestPath(request.destinationPath()).toAbsolutePath().normalize();
        String expectedHash = data.path("sha256").asText("");
        if (!expectedHash.matches("(?i)[a-f0-9]{64}"))
            throw new FileShieldException(HttpStatus.CONFLICT, "INVALID_QUARANTINE_RECORD", "Quarantine record has no valid SHA-256.");
        try { approvedDestination(destination); }
        catch (FileShieldException rejected) {
            writeAudit(operationId, auditFrom(data, "RESTORE_FAILED", "Restore destination was rejected by approved-root or path-safety policy.", destination.toString()));
            throw rejected;
        }
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            writeAudit(operationId, auditFrom(data, "RESTORE_FAILED", "Restore was refused because the destination already exists; no file was overwritten.", destination.toString()));
            throw new FileShieldException(HttpStatus.CONFLICT, "RESTORE_DESTINATION_EXISTS", "Restore destination already exists. Choose another destination; no file was overwritten.");
        }
        FileInspectionSnapshot snapshot = inspectExpected(quarantined, expectedHash);
        if (request.reinspect()) {
            HashReputation current = safeReputation(snapshot.sha256());
            if (current.status() != ReputationStatus.KNOWN_CLEAN) {
                writeAudit(operationId, auditFrom(data, "RESTORE_FAILED", "Restore was refused because reinspection did not return a known-clean verdict (" + current.status() + ").", destination.toString()));
                throw new FileShieldException(HttpStatus.CONFLICT, "REINSPECTION_NOT_CLEAN", "Reinspection did not return a known-clean verdict; the file remains quarantined. You may explicitly disable reinspection to restore at your own risk.");
            }
        }
        Path parent = destination.getParent();
        String restoreId = operationId;
        OperationAudit started = auditFrom(data, "RESTORE_STARTED", "Authorized restore started.", destination.toString());
        writeAudit(restoreId, started);
        try {
            requireSameFileStore(quarantined, parent);
            recheckIdentity(quarantined, snapshot);
            pathSafety.rejectReparseComponents(quarantined);
            pathSafety.rejectReparseComponents(parent);
            Files.move(quarantined, destination);
            secureFile(destination);
            String restoredHash = scanner.sha256(destination, properties.getMaxFileSize());
            if (!expectedHash.equalsIgnoreCase(restoredHash)) {
                boolean rolledBack = rollbackMove(destination, quarantined);
                OperationAudit failed = started.with(rolledBack ? "RESTORE_FAILED" : "RECOVERY_REQUIRED",
                        "Restored file failed SHA-256 verification; " + (rolledBack ? "it remains quarantined." : "manual recovery is required."));
                writeAudit(restoreId, failed);
                return result(restoreId, failed, false);
            }
            String metadataNote = restoreTimestamps(destination, data);
            OperationAudit restored = started.with("RESTORED", "File restored and SHA-256 integrity verified." + metadataNote);
            try { writeAudit(restoreId, restored); }
            catch (RuntimeException auditFailure) {
                log.error("Restore completed but completion audit write failed: operationId={}", operationId);
                return result(restoreId, started.with("RESTORE_STARTED", "File was restored and verified, but audit completion could not be recorded; startup recovery will reconcile it."), false);
            }
            return result(restoreId, restored, true);
        } catch (AtomicMoveNotSupportedException unsupported) {
            OperationAudit failed = started.with("RESTORE_FAILED", "The restore destination is on a different file system; the quarantined file was left intact.");
            writeAudit(restoreId, failed);
            return result(restoreId, failed, false);
        } catch (IOException | SecurityException failure) {
            String finalState = Files.exists(quarantined, LinkOption.NOFOLLOW_LINKS) ? "RESTORE_FAILED" : "RECOVERY_REQUIRED";
            OperationAudit failed = started.with(finalState, "Restore failed safely: " + failureCategory(failure) + ".");
            writeAudit(restoreId, failed);
            return result(restoreId, failed, false);
        }
    }

    public QuarantineHistoryResponse history() {
        List<QuarantineOperationResult> active = new ArrayList<>();
        for (SecurityEvent event : events.findActiveQuarantines()) {
            QuarantineOperationResult item = operationResult(event);
            if (item != null && item.quarantinePath() != null && !item.quarantinePath().isBlank()) {
                try { if (Files.isRegularFile(Path.of(item.quarantinePath()), LinkOption.NOFOLLOW_LINKS)) active.add(item); }
                catch (java.nio.file.InvalidPathException ignored) { }
            }
        }
        List<QuarantineOperationResult> recent = events.findRecentFileOperations(100).stream()
                .map(this::operationResult).filter(java.util.Objects::nonNull).toList();
        return new QuarantineHistoryResponse(active, recent);
    }

    public String defaultDirectory() {
        return properties.getAllowedRoots().stream().findFirst().map(root -> root.toAbsolutePath().normalize().resolve(QUARANTINE_FOLDER).toString()).orElse("");
    }

    private void recover(SecurityEvent event) {
        JsonNode data = details(event);
        String state = data.path("state").asText("");
        String operationId = event.correlationId();
        if (operationId == null) return;
        Path original = path(data, "originalPath");
        Path quarantined = path(data, "quarantinePath");
        Path destination = path(data, "destinationPath");
        String hash = data.path("sha256").asText("");
        if (!hash.matches("(?i)[a-f0-9]{64}")) return;
        if ("QUARANTINE_STARTED".equals(state)) {
            boolean qValid = matchesHash(quarantined, hash);
            boolean sourceExists = Files.exists(original, LinkOption.NOFOLLOW_LINKS);
            if (qValid && !sourceExists) writeAudit(operationId, auditFrom(data, "QUARANTINED", "Startup recovery verified an interrupted quarantine move.", null));
            else if (sourceExists && !Files.exists(quarantined, LinkOption.NOFOLLOW_LINKS)) writeAudit(operationId, auditFrom(data, "QUARANTINE_FAILED", "Startup recovery confirmed the source file was not moved.", null));
            else writeAudit(operationId, auditFrom(data, "RECOVERY_REQUIRED", "Startup recovery found ambiguous file locations; no automatic move was attempted.", null));
        } else if ("RESTORE_STARTED".equals(state)) {
            boolean restored = matchesHash(destination, hash);
            boolean qExists = Files.exists(quarantined, LinkOption.NOFOLLOW_LINKS);
            if (restored && !qExists) writeAudit(operationId, auditFrom(data, "RESTORED", "Startup recovery verified an interrupted restore.", destination.toString()));
            else if (qExists && !Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) writeAudit(operationId, auditFrom(data, "RESTORE_FAILED", "Startup recovery confirmed the file remains quarantined.", destination.toString()));
            else writeAudit(operationId, auditFrom(data, "RECOVERY_REQUIRED", "Startup recovery found ambiguous file locations; no automatic move was attempted.", destination.toString()));
        }
    }

    private Path approvedFile(Path requested) {
        Path file = requested.toAbsolutePath().normalize();
        try {
            pathSafety.rejectReparseComponents(file);
            Path real = file.toRealPath();
            if (!Files.isRegularFile(real, LinkOption.NOFOLLOW_LINKS) || isInQuarantine(real)) throw new IOException();
            if (approvedRoot(real).isEmpty()) throw new IOException();
            return real;
        } catch (IOException | SecurityException failure) {
            throw new FileShieldException(HttpStatus.FORBIDDEN, "FILE_PATH_NOT_APPROVED", "File is inaccessible, redirected, or outside approved scan roots.");
        }
    }

    private void approvedDestination(Path destination) {
        Path target = destination.toAbsolutePath().normalize();
        Path parent = target.getParent();
        try {
            if (parent == null) throw new IOException();
            pathSafety.rejectReparseComponents(parent);
            Path realParent = parent.toRealPath();
            if (!Files.isDirectory(realParent, LinkOption.NOFOLLOW_LINKS) || approvedRoot(realParent).isEmpty()
                    || isInQuarantine(target) || Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IOException();
        } catch (IOException | SecurityException failure) {
            throw new FileShieldException(HttpStatus.FORBIDDEN, "RESTORE_PATH_NOT_APPROVED", "Restore destination must be a new file path inside an approved, accessible directory.");
        }
    }

    private FileInspectionSnapshot inspectExpected(Path file, String expectedHash) {
        try {
            pathSafety.rejectReparseComponents(file);
            FileInspectionSnapshot snapshot = inspection.inspect(file, true);
            if (!expectedHash.equalsIgnoreCase(snapshot.sha256()))
                throw new FileShieldException(HttpStatus.CONFLICT, "FILE_IDENTITY_CHANGED", "File contents changed since inspection; scan it again before proceeding.");
            return snapshot;
        } catch (FileShieldException failure) { throw failure; }
        catch (IOException | SecurityException failure) {
            throw new FileShieldException(HttpStatus.CONFLICT, "FILE_INSPECTION_FAILED", "File could not be rechecked; no filesystem operation was performed.");
        }
    }

    private HashReputation safeReputation(String hash) {
        try { return reputation.lookup(hash); }
        catch (RuntimeException failure) { return new HashReputation(ReputationStatus.LOOKUP_ERROR, "provider", "Reputation lookup failed."); }
    }

    private void recheckIdentity(Path path, FileInspectionSnapshot expected) throws IOException {
        BasicFileAttributes current = readAttributes(path);
        String key = current.fileKey() == null ? null : current.fileKey().toString();
        if (current.size() != expected.sizeBytes() || !current.lastModifiedTime().equals(expected.modifiedAt())
                || (expected.fileKey() != null && !expected.fileKey().equals(key))
                || !expected.sha256().equalsIgnoreCase(scanner.sha256(path, properties.getMaxFileSize())))
            throw new IOException("File identity changed before operation.");
    }

    private Path quarantineDirectoryFor(Path file) {
        Path root = approvedRoot(file).orElseThrow(() -> new FileShieldException(HttpStatus.FORBIDDEN, "PATH_NOT_ALLOWED", "No approved root contains this file."));
        return root.resolve(QUARANTINE_FOLDER);
    }

    private Optional<Path> approvedRoot(Path path) {
        return properties.getAllowedRoots().stream().map(root -> root.toAbsolutePath().normalize())
                .filter(root -> path.toAbsolutePath().normalize().startsWith(root))
                .max(java.util.Comparator.comparingInt(Path::getNameCount));
    }

    private boolean isInQuarantine(Path path) {
        return properties.getAllowedRoots().stream().map(root -> root.toAbsolutePath().normalize().resolve(QUARANTINE_FOLDER))
                .anyMatch(path.toAbsolutePath().normalize()::startsWith);
    }

    private void ensureSecureDirectory(Path directory) {
        try {
            pathSafety.rejectReparseComponents(directory.getParent());
            if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
                try { Files.createDirectory(directory); }
                catch (java.nio.file.FileAlreadyExistsException race) { }
            }
            pathSafety.rejectReparseComponents(directory);
            if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Not a directory.");
            secureDirectory(directory);
        } catch (IOException | SecurityException failure) {
            throw new FileShieldException(HttpStatus.INTERNAL_SERVER_ERROR, "QUARANTINE_STORAGE_UNAVAILABLE", "Restricted quarantine storage could not be created or secured.");
        }
    }

    private void secureDirectory(Path directory) throws IOException {
        AclFileAttributeView acl = Files.getFileAttributeView(directory, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl != null) {
            acl.setAcl(restrictiveAcl(directory, true));
            return;
        }
        PosixFileAttributeView posix = Files.getFileAttributeView(directory, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix == null) throw new IOException("No supported restrictive ACL mechanism.");
        Files.setPosixFilePermissions(directory, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
    }

    private void secureFile(Path file) throws IOException {
        PosixFileAttributeView posix = Files.getFileAttributeView(file, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) Files.setPosixFilePermissions(file, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        else {
            AclFileAttributeView acl = Files.getFileAttributeView(file, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (acl == null) throw new IOException("Quarantined file permissions cannot be verified.");
            acl.setAcl(restrictiveAcl(file, false));
        }
    }

    private List<AclEntry> restrictiveAcl(Path path, boolean inherit) throws IOException {
        UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
        UserPrincipal system;
        try { system = path.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName("NT AUTHORITY\\SYSTEM"); }
        catch (IOException missingLocalizedName) { system = path.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName("SYSTEM"); }
        EnumSet<AclEntryPermission> permissions = EnumSet.allOf(AclEntryPermission.class);
        AclEntry.Builder systemBuilder = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(system).setPermissions(permissions);
        AclEntry.Builder ownerBuilder = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner).setPermissions(permissions);
        if (inherit) {
            EnumSet<AclEntryFlag> inheritance = EnumSet.of(AclEntryFlag.DIRECTORY_INHERIT, AclEntryFlag.FILE_INHERIT);
            systemBuilder.setFlags(inheritance);
            ownerBuilder.setFlags(inheritance);
        }
        return List.of(systemBuilder.build(), ownerBuilder.build());
    }

    private void requireSameFileStore(Path file, Path directory) throws IOException {
        FileStore sourceStore = Files.getFileStore(file);
        FileStore targetStore = Files.getFileStore(directory);
        if (!sourceStore.equals(targetStore)) throw new AtomicMoveNotSupportedException(file.toString(), directory.toString(), "Cross-volume moves are not permitted.");
    }

    private boolean rollbackMove(Path moved, Path prior) {
        try {
            if (Files.exists(prior, LinkOption.NOFOLLOW_LINKS)) return false;
            Files.move(moved, prior);
            return true;
        } catch (IOException ignored) { return false; }
    }

    private String restoreTimestamps(Path target, JsonNode details) {
        try {
            FileTime created = FileTime.from(Instant.parse(details.path("createdAt").asText()));
            FileTime modified = FileTime.from(Instant.parse(details.path("modifiedAt").asText()));
            BasicFileAttributeView view = Files.getFileAttributeView(target, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            view.setTimes(modified, null, created);
            return " Original creation and modification times were restored.";
        } catch (Exception unsupported) { return " File integrity is verified; the file system did not restore its original timestamps."; }
    }

    private BasicFileAttributes readAttributes(Path path) throws IOException {
        return Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    }

    private boolean matchesHash(Path path, String hash) {
        try { return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && hash.equalsIgnoreCase(scanner.sha256(path, properties.getMaxFileSize())); }
        catch (IOException | SecurityException ignored) { return false; }
    }

    private void writeAudit(String operationId, OperationAudit data) {
        try {
            String json = mapper.writeValueAsString(data);
            audit.logOperation(new SecurityEvent(null, Instant.now(), null, null, null, null, null,
                    Decision.REVIEW.name(), "FILE_SHIELD_OPERATION", "FILE", data.sha256(), operationId, json));
        } catch (IOException failure) { throw new IllegalStateException("Could not serialize quarantine audit record.", failure); }
    }

    private OperationAudit auditFrom(JsonNode node, String state, String message, String destination) {
        return new OperationAudit(state, node.path("fileName").asText("unknown"), node.path("sha256").asText(""),
                node.path("originalPath").asText(""), node.path("quarantinePath").asText(""),
                destination == null ? node.path("destinationPath").asText(null) : destination,
                node.path("createdAt").asText(""), node.path("modifiedAt").asText(""),
                node.path("signatureStatus").asText("UNKNOWN"), message);
    }

    private JsonNode details(SecurityEvent event) {
        try { return mapper.readTree(event.detailsJson()); }
        catch (Exception invalid) { throw new FileShieldException(HttpStatus.CONFLICT, "INVALID_QUARANTINE_RECORD", "Quarantine history record cannot be read."); }
    }

    private Path path(JsonNode data, String field) {
        String value = data.path(field).asText("");
        return value.isBlank() ? Path.of(".").toAbsolutePath().resolve("missing") : Path.of(value);
    }

    private QuarantineOperationResult operationResult(SecurityEvent event) {
        try {
            JsonNode d = details(event);
            return new QuarantineOperationResult(event.correlationId(), d.path("state").asText("UNKNOWN"),
                    "QUARANTINED".equals(d.path("state").asText()) || "RESTORED".equals(d.path("state").asText()),
                    d.path("fileName").asText("unknown"), d.path("sha256").asText(""), d.path("originalPath").asText(""),
                    d.path("quarantinePath").asText(""), d.path("destinationPath").asText(null),
                    d.path("signatureStatus").asText("UNKNOWN"), event.timestamp(), d.path("message").asText(""));
        } catch (RuntimeException invalid) { return null; }
    }

    private QuarantineOperationResult result(String id, OperationAudit data, boolean success) {
        return new QuarantineOperationResult(id, data.state(), success, data.fileName(), data.sha256(), data.originalPath(),
                data.quarantinePath(), data.destinationPath(), data.signatureStatus(), Instant.now(), data.message());
    }

    private void requireConfirmation(boolean confirmed) {
        if (!confirmed) throw new FileShieldException(HttpStatus.FORBIDDEN, "USER_CONFIRMATION_REQUIRED", "Explicit user confirmation is required for this filesystem operation.");
    }

    private Path parseRequestPath(String value) {
        try { return Path.of(value); }
        catch (java.nio.file.InvalidPathException invalid) {
            throw new FileShieldException(HttpStatus.BAD_REQUEST, "INVALID_PATH", "The requested file path is invalid.");
        }
    }

    private void requireWindowsAndEnabled() {
        if (!System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win"))
            throw new FileShieldException(HttpStatus.SERVICE_UNAVAILABLE, "WINDOWS_ONLY", "Safe quarantine is supported only on Windows.");
        if (!properties.isEnabled()) throw new FileShieldException(HttpStatus.SERVICE_UNAVAILABLE, "FILE_SHIELD_DISABLED", "File Shield is disabled.");
    }

    private String failureCategory(Exception failure) { return failure.getClass().getSimpleName().toUpperCase(Locale.ROOT); }

    private record OperationAudit(String state, String fileName, String sha256, String originalPath,
                                  String quarantinePath, String destinationPath, String createdAt,
                                  String modifiedAt, String signatureStatus, String message) {
        private OperationAudit with(String newState, String newMessage) {
            return new OperationAudit(newState, fileName, sha256, originalPath, quarantinePath,
                    destinationPath, createdAt, modifiedAt, signatureStatus, newMessage);
        }
    }
}
