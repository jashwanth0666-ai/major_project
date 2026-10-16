package com.aiwatchdog.backend.fileshield;

import com.aiwatchdog.backend.fileshield.service.DefaultSha256Scanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class DefaultSha256ScannerTest {
    @TempDir Path temp;
    private final DefaultSha256Scanner scanner = new DefaultSha256Scanner();

    @Test void hashesKnownVector() throws Exception {
        Path file = temp.resolve("abc.txt"); Files.writeString(file, "abc");
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", scanner.sha256(file));
    }

    @Test void hashesEmptyAndLargeFiles() throws Exception {
        Path empty = temp.resolve("empty"); Files.createFile(empty);
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", scanner.sha256(empty));
        Path large = temp.resolve("large"); byte[] bytes = new byte[3 * 1024 * 1024]; Arrays.fill(bytes, (byte) 42); Files.write(large, bytes);
        assertEquals(java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes)), scanner.sha256(large));
    }

    @Test void missingFileFailsWithoutCreatingIt() {
        Path missing = temp.resolve("missing");
        assertThrows(java.io.IOException.class, () -> scanner.sha256(missing));
        assertFalse(Files.exists(missing));
    }
}
