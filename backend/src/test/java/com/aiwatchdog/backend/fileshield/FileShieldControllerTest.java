package com.aiwatchdog.backend.fileshield;

import com.aiwatchdog.backend.controller.GlobalExceptionHandler;
import com.aiwatchdog.backend.fileshield.controller.FileShieldController;
import com.aiwatchdog.backend.fileshield.dto.FileScanResponse;
import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.aiwatchdog.backend.fileshield.model.ScanStatus;
import com.aiwatchdog.backend.fileshield.service.FileShieldService;
import com.aiwatchdog.backend.fileshield.config.FileShieldSettingsService;
import com.aiwatchdog.backend.fileshield.config.FileShieldSettingsResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import java.util.List;

import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class FileShieldControllerTest {
    private MockMvc mvc;
    @Mock private FileShieldService service;
    @Mock private FileShieldSettingsService settings;

    @BeforeEach void setup() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean(); validator.afterPropertiesSet();
        mvc = MockMvcBuilders.standaloneSetup(new FileShieldController(service, settings))
                .setControllerAdvice(new GlobalExceptionHandler()).setValidator(validator).build();
    }

    @Test void validScanReturnsStructuredResponse() throws Exception {
        when(service.scanFile(java.nio.file.Path.of("C:/samples/a.txt"))).thenReturn(
                new FileScanResponse("a.txt", "a".repeat(64), ReputationStatus.UNKNOWN, ScanStatus.COMPLETED,
                        "Hash is not listed; this does not establish that the file is safe.", 3, "local", null));
        mvc.perform(post("/api/v1/file-shield/scan").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"path\":\"C:/samples/a.txt\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.sha256").value("a".repeat(64)))
                .andExpect(jsonPath("$.reputationStatus").value("UNKNOWN"));
    }

    @Test void blankAndMissingPathsAreRejected() throws Exception {
        mvc.perform(post("/api/v1/file-shield/scan").contentType(MediaType.APPLICATION_JSON).content("{\"path\":\" \"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/file-shield/scan").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test void settingsAreAvailableOnlyToLoopbackClients() throws Exception {
        when(settings.get()).thenReturn(new FileShieldSettingsResponse(true, List.of("C:/safe"), List.of(),
                "C:/data/reputation.db", false, true, 5, 1024, 100, 4,
                false, false, "Database unavailable."));
        mvc.perform(get("/api/v1/file-shield/settings").with(request -> { request.setRemoteAddr("127.0.0.1"); return request; }))
                .andExpect(status().isOk()).andExpect(jsonPath("$.allowedRoots[0]").value("C:/safe"))
                .andExpect(jsonPath("$.reputationDatabaseUsable").value(false));
        mvc.perform(get("/api/v1/file-shield/settings").with(request -> { request.setRemoteAddr("192.168.1.20"); return request; }))
                .andExpect(status().isForbidden());
        verify(settings).get();
    }

    @Test void settingsCanBeUpdatedFromLoopback() throws Exception {
        when(settings.update(org.mockito.ArgumentMatchers.any())).thenReturn(new FileShieldSettingsResponse(true,
                List.of("C:/safe"), List.of(), "C:/data/hashes.db", false, true, 5,
                104857600, 500, 5, false, false, "Database unavailable."));
        mvc.perform(put("/api/v1/file-shield/settings")
                        .with(request -> { request.setRemoteAddr("127.0.0.1"); return request; })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":true,\"allowedRoots\":[\"C:/safe\"],\"watchDirectories\":[],"
                                + "\"reputationDatabasePath\":\"C:/data/hashes.db\",\"monitoringEnabled\":false,"
                                + "\"recursiveMonitoring\":true,\"maxMonitoringDepth\":5,\"maxFileSizeBytes\":104857600,"
                                + "\"maxFilesPerDirectoryScan\":500,\"maxDirectoryDepth\":5}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.allowedRoots[0]").value("C:/safe"));
    }
}
