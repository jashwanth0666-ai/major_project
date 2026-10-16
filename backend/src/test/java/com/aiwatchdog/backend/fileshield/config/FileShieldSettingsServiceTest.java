package com.aiwatchdog.backend.fileshield.config;

import com.aiwatchdog.backend.fileshield.watcher.FileShieldDirectoryWatcher;
import com.aiwatchdog.backend.fileshield.service.FileShieldService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class FileShieldSettingsServiceTest {
    @TempDir Path temp;

    @Test void updatePersistsAndAppliesSettingsAndRestartsWatcher() throws Exception {
        Path root = Files.createDirectory(temp.resolve("approved"));
        Path watch = Files.createDirectory(root.resolve("watch"));
        Path settingsFile = temp.resolve("user-settings.json");
        FileShieldProperties properties = new FileShieldProperties();
        FileShieldDirectoryWatcher watcher = mock(FileShieldDirectoryWatcher.class);
        FileShieldSettingsService service = new FileShieldSettingsService(properties, watcher,
                new ObjectMapper(), settingsFile);

        FileShieldSettingsResponse result = service.update(new FileShieldSettingsRequest(
                true, List.of(root.toString()), List.of(watch.toString()), temp.resolve("reputation.db").toString(),
                true, true, 3, 10_000, 120, 4));

        assertEquals(List.of(root.toRealPath()), properties.getAllowedRoots());
        assertTrue(properties.isEnabled());
        assertEquals(List.of(watch.toRealPath()), properties.getWatchDirectories());
        assertEquals(10_000, properties.getMaxFileSize());
        assertTrue(Files.isRegularFile(settingsFile));
        assertTrue(result.reputationDatabaseMessage().contains("unavailable"));
        verify(watcher).close();
        verify(watcher).start();
    }

    @Test void rejectsWatchFolderOutsideApprovedRootsBeforeChangingSettings() throws Exception {
        Path root = Files.createDirectory(temp.resolve("approved"));
        Path outside = Files.createDirectory(temp.resolve("outside"));
        FileShieldProperties properties = new FileShieldProperties();
        FileShieldDirectoryWatcher watcher = mock(FileShieldDirectoryWatcher.class);
        FileShieldSettingsService service = new FileShieldSettingsService(properties, watcher,
                new ObjectMapper(), temp.resolve("user-settings.json"));

        assertThrows(IllegalArgumentException.class, () -> service.update(new FileShieldSettingsRequest(
                true, List.of(root.toString()), List.of(outside.toString()), temp.resolve("reputation.db").toString(),
                true, true, 3, 10_000, 120, 4)));
        assertTrue(properties.getAllowedRoots().isEmpty());
        verifyNoInteractions(watcher);
    }

    @Test void reloadsSavedSettingsAfterServiceRestart() throws Exception {
        Path root = Files.createDirectory(temp.resolve("persisted-root"));
        Path settingsFile = temp.resolve("user-settings.json");
        FileShieldSettingsRequest request = new FileShieldSettingsRequest(true, List.of(root.toString()), List.of(),
                temp.resolve("reputation.db").toString(), false, false, 2, 1_048_576, 80, 2);
        FileShieldProperties firstProperties = new FileShieldProperties();
        FileShieldSettingsService first = new FileShieldSettingsService(firstProperties,
                mock(FileShieldDirectoryWatcher.class), new ObjectMapper(), settingsFile);
        first.update(request);

        FileShieldProperties afterRestart = new FileShieldProperties();
        FileShieldDirectoryWatcher newWatcher = mock(FileShieldDirectoryWatcher.class);
        FileShieldSettingsService reloaded = new FileShieldSettingsService(afterRestart, newWatcher,
                new ObjectMapper(), settingsFile);
        reloaded.loadPersistedSettings();

        assertEquals(List.of(root.toRealPath()), afterRestart.getAllowedRoots());
        assertEquals(80, afterRestart.getMaxFilesPerDirectoryScan());
        verify(newWatcher).start();
    }

    @Test void appliesWatcherEnableAndDisableWithoutRestartingSpring() throws Exception {
        Path root = Files.createDirectory(temp.resolve("runtime-watch"));
        FileShieldProperties properties = new FileShieldProperties();
        FileShieldDirectoryWatcher watcher = new FileShieldDirectoryWatcher(properties,
                mock(FileShieldService.class), event -> { });
        FileShieldSettingsService service = new FileShieldSettingsService(properties, watcher,
                new ObjectMapper(), temp.resolve("runtime-settings.json"));
        try {
            service.update(new FileShieldSettingsRequest(true, List.of(root.toString()), List.of(root.toString()),
                    temp.resolve("reputation.db").toString(), true, false, 0, 1_048_576, 10, 0));
            assertTrue(watcher.isRunning());
            service.update(new FileShieldSettingsRequest(false, List.of(root.toString()), List.of(),
                    temp.resolve("reputation.db").toString(), false, false, 0, 1_048_576, 10, 0));
            assertFalse(watcher.isRunning());
            assertFalse(properties.isEnabled());
        } finally {
            watcher.close();
        }
    }
}
