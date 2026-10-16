package com.aiwatchdog.backend.fileshield;

import com.aiwatchdog.backend.fileshield.dto.QuarantineRequest;
import com.aiwatchdog.backend.fileshield.exception.FileShieldException;
import com.aiwatchdog.backend.fileshield.service.FileQuarantineService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FileQuarantineServiceTest {
    @Test void refusesQuarantineWithoutExplicitConfirmationBeforeFilesystemAccess() {
        FileQuarantineService service = new FileQuarantineService(null, null, null, null, null, null, null);

        FileShieldException failure = assertThrows(FileShieldException.class,
                () -> service.quarantine(new QuarantineRequest("not-read", "a".repeat(64), false)));

        assertEquals("USER_CONFIRMATION_REQUIRED", failure.code());
    }
}
