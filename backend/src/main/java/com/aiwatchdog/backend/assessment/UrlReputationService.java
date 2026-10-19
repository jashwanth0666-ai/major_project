package com.aiwatchdog.backend.assessment;

public interface UrlReputationService {
    UrlReputationResult lookup(String host);

    /** Providers that support URL-level lookups can override this; hostname providers stay compatible. */
    default UrlReputationResult lookupUrl(String url, String host) { return lookup(host); }
}
