package com.aiwatchdog.backend.fileshield;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.aiwatchdog.backend.fileshield.reputation.ConfiguredThreatIntelProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfiguredThreatIntelProviderTest {
    @Test void isDisabledByDefaultAndReportsDisabledWithoutNetworkLookup() {
        ConfiguredThreatIntelProvider provider = new ConfiguredThreatIntelProvider(new FileShieldProperties());

        var result = provider.lookup("a".repeat(64));

        assertEquals(ReputationStatus.UNKNOWN, result.status());
        assertEquals("DISABLED", provider.health().state());
    }

    @Test void rejectsNonSha256InputAsUnavailableWithoutContactingProvider() {
        FileShieldProperties properties = new FileShieldProperties();
        properties.setThreatIntelEnabled(true);
        properties.setThreatIntelEndpoint("https://intel.example/v1/hash");
        ConfiguredThreatIntelProvider provider = new ConfiguredThreatIntelProvider(properties);

        var result = provider.lookup("not-a-sha256");

        assertEquals(ReputationStatus.LOOKUP_ERROR, result.status());
        assertEquals("CONFIGURED", provider.health().state());
    }
}
