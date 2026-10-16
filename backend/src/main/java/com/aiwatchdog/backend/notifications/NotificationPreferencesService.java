package com.aiwatchdog.backend.notifications;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Persists local desktop notification preferences separately from scanner policy. */
@Service
public class NotificationPreferencesService {
    private final ObjectMapper mapper = new ObjectMapper();
    private final Path settingsFile = defaultSettingsPath();
    private NotificationPreferences current = NotificationPreferences.defaults();

    @PostConstruct
    synchronized void load() {
        if (!Files.isRegularFile(settingsFile)) return;
        try {
            NotificationPreferences saved = mapper.readValue(settingsFile.toFile(), NotificationPreferences.class);
            current = saved == null ? NotificationPreferences.defaults() : saved;
        } catch (IOException | RuntimeException ignored) {
            current = NotificationPreferences.defaults();
        }
    }

    public synchronized NotificationPreferences get() {
        return current;
    }

    public synchronized NotificationPreferences update(NotificationPreferences preferences) {
        if (preferences == null) throw new IllegalArgumentException("Notification preferences are required.");
        Path temporary = settingsFile.resolveSibling(settingsFile.getFileName() + ".tmp");
        try {
            Path parent = settingsFile.getParent();
            if (parent != null) Files.createDirectories(parent);
            mapper.writeValue(temporary.toFile(), preferences);
            try {
                Files.move(temporary, settingsFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException unsupportedAtomicMove) {
                Files.move(temporary, settingsFile, StandardCopyOption.REPLACE_EXISTING);
            }
            current = preferences;
            return current;
        } catch (IOException exception) {
            try { Files.deleteIfExists(temporary); } catch (IOException ignored) { }
            throw new IllegalStateException("Could not save notification preferences to the user configuration folder.");
        }
    }

    private static Path defaultSettingsPath() {
        String appData = System.getenv("APPDATA");
        Path base = appData == null || appData.isBlank()
                ? Path.of(System.getProperty("user.home"), ".aiwatchdog")
                : Path.of(appData, "AIWatchDog");
        return base.resolve("notification-preferences.json");
    }
}
