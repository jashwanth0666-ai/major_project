package com.aiwatchdog.backend.fileshield.service;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Locale;

/** Streams a bounded file hash and captures metadata/signature without executing file content. */
@Service
public class FileInspectionService {
    private final FileShieldProperties properties;
    private final Sha256Scanner scanner;
    private final AuthenticodeSignatureInspector signatures;

    public FileInspectionService(FileShieldProperties properties, Sha256Scanner scanner,
                                 AuthenticodeSignatureInspector signatures) {
        this.properties = properties;
        this.scanner = scanner;
        this.signatures = signatures;
    }

    public FileInspectionSnapshot inspect(Path path) throws IOException {
        return inspect(path, true);
    }

    public FileInspectionSnapshot inspect(Path path, boolean inspectSignature) throws IOException {
        if (path == null || Files.isSymbolicLink(path)
                || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Path is not a regular non-link file.");
        BasicFileAttributes before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (before.size() > properties.getMaxFileSize())
            throw new IOException("File size is outside the configured inspection limit.");
        String hash = scanner.sha256(path, properties.getMaxFileSize());
        if (hash == null || !hash.matches("[a-f0-9]{64}")) throw new IOException("SHA-256 inspection did not return a valid digest.");
        String name = path.getFileName() == null ? "" : path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String extension = dot < 0 ? "" : name.substring(dot + 1).toLowerCase(Locale.ROOT);
        SignatureInspection signature = inspectSignature ? signatures.inspect(path)
                : new SignatureInspection(SignatureStatus.NOT_REQUESTED, null, "Signature inspection was not requested.");
        BasicFileAttributes after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        String beforeKey = before.fileKey() == null ? null : before.fileKey().toString();
        String afterKey = after.fileKey() == null ? null : after.fileKey().toString();
        if (before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())
                || (beforeKey != null && !beforeKey.equals(afterKey)))
            throw new IOException("File identity changed during inspection.");
        return new FileInspectionSnapshot(hash, before.size(), extension, before.creationTime(),
                before.lastModifiedTime(), beforeKey, signature);
    }
}
