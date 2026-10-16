package com.aiwatchdog.backend.fileshield;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import com.aiwatchdog.backend.fileshield.dto.FileScanResponse;
import com.aiwatchdog.backend.fileshield.exception.FileShieldException;
import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.aiwatchdog.backend.fileshield.model.ScanStatus;
import com.aiwatchdog.backend.fileshield.reputation.HashReputation;
import com.aiwatchdog.backend.fileshield.reputation.HashReputationService;
import com.aiwatchdog.backend.fileshield.service.DefaultSha256Scanner;
import com.aiwatchdog.backend.fileshield.service.FileShieldServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class FileShieldServiceTest {
    @TempDir Path temp;

    @Test void scansFileAndReturnsUnknownWithoutCallingItSafe() throws Exception {
        Path file = Files.writeString(temp.resolve("sample.txt"), "abc");
        FileShieldServiceImpl service = service((hash) -> new HashReputation(ReputationStatus.UNKNOWN, "test", null));
        FileScanResponse response = service.scanFile(file);
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", response.sha256());
        assertEquals(ReputationStatus.UNKNOWN, response.reputationStatus());
        assertEquals(ScanStatus.COMPLETED, response.scanStatus());
        assertEquals("abc", Files.readString(file));
    }

    @Test void lookupFailureIsPartialAndUnapprovedPathRejected() throws Exception {
        Path file = Files.writeString(temp.resolve("sample.txt"), "abc");
        FileShieldServiceImpl service = service((hash) -> new HashReputation(ReputationStatus.LOOKUP_ERROR, "test", null));
        assertEquals(ScanStatus.PARTIAL, service.scanFile(file).scanStatus());
        Path outside = Files.createTempFile("outside", ".txt");
        try { assertEquals("PATH_NOT_ALLOWED", assertThrows(FileShieldException.class, () -> service.scanFile(outside)).code()); }
        finally { Files.deleteIfExists(outside); }
    }

    @Test void rejectsDirectoryAsSingleFileAndEnforcesSize() throws Exception {
        FileShieldProperties p = props(); p.setMaxFileSize(2);
        FileShieldServiceImpl service = new FileShieldServiceImpl(p, new DefaultSha256Scanner(), hash -> new HashReputation(ReputationStatus.UNKNOWN, "test", null));
        assertEquals("NOT_A_FILE", assertThrows(FileShieldException.class, () -> service.scanFile(temp)).code());
        Path file = Files.writeString(temp.resolve("large.txt"), "abc");
        assertEquals("FILE_TOO_LARGE", assertThrows(FileShieldException.class, () -> service.scanFile(file)).code());
    }

    @Test void scansDirectoryWithinConfiguredFileLimit() throws Exception {
        Files.writeString(temp.resolve("a.txt"), "a"); Files.createDirectories(temp.resolve("nested")); Files.writeString(temp.resolve("nested").resolve("b.txt"), "b");
        var result = service(hash -> new HashReputation(ReputationStatus.KNOWN_CLEAN, "test", null)).scanDirectory(temp);
        assertEquals(2, result.discovered()); assertEquals(2, result.scanned()); assertEquals(2, result.knownClean()); assertFalse(result.limitReached());
    }

    @Test void directoryScanStopsAtConfiguredFileLimitAndReportsIt() throws Exception {
        Files.writeString(temp.resolve("a.txt"), "a"); Files.writeString(temp.resolve("b.txt"), "b"); Files.writeString(temp.resolve("c.txt"), "c");
        FileShieldProperties p = props(); p.setMaxFilesPerDirectoryScan(2);
        var result = new FileShieldServiceImpl(p, new DefaultSha256Scanner(), hash -> new HashReputation(ReputationStatus.UNKNOWN, "test", null)).scanDirectory(temp);
        assertEquals(3, result.discovered()); assertEquals(2, result.scanned()); assertTrue(result.limitReached());
    }

    private FileShieldServiceImpl service(HashReputationService provider) {
        return new FileShieldServiceImpl(props(), new DefaultSha256Scanner(), provider);
    }
    private FileShieldProperties props() {
        FileShieldProperties p = new FileShieldProperties(); p.setAllowedRoots(java.util.List.of(temp)); return p;
    }
}
