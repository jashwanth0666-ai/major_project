package com.aiwatchdog.backend.fileshield;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import com.aiwatchdog.backend.fileshield.service.AuthenticodeSignatureInspector;
import com.aiwatchdog.backend.fileshield.service.DefaultSha256Scanner;
import com.aiwatchdog.backend.fileshield.service.FileInspectionService;
import com.aiwatchdog.backend.fileshield.service.SignatureStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FileInspectionServiceTest {
    @TempDir Path temp;

    @Test void capturesHashMetadataAndExplicitlyMarksSkippedSignature() throws Exception {
        Path file = Files.writeString(temp.resolve("sample.PS1"), "Write-Output 'safe fixture'");
        FileShieldProperties properties = new FileShieldProperties();
        var inspection = new FileInspectionService(properties, new DefaultSha256Scanner(), new AuthenticodeSignatureInspector());

        var result = inspection.inspect(file, false);

        assertEquals("ps1", result.extension());
        assertEquals(Files.size(file), result.sizeBytes());
        assertEquals(SignatureStatus.NOT_REQUESTED, result.signature().status());
        assertEquals(64, result.sha256().length());
    }

    @Test void inspectsEmptyFilesWithoutTreatingThemAsReadFailures() throws Exception {
        Path file = Files.createFile(temp.resolve("empty.bin"));
        FileShieldProperties properties = new FileShieldProperties();
        var inspection = new FileInspectionService(properties, new DefaultSha256Scanner(), new AuthenticodeSignatureInspector());

        var result = inspection.inspect(file, false);

        assertEquals(0, result.sizeBytes());
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result.sha256());
    }
}
