package com.aiwatchdog.service;

public class DemoModeService {
    private final BrowserMonitorService browserMonitor = new BrowserMonitorService();

    public String simulateSafeUrl() {
        return browserMonitor.safe();
    }

    public String simulateSuspiciousUrl() {
        return browserMonitor.suspicious();
    }

    public String simulatePhishingUrl() {
        return browserMonitor.phishing();
    }

    public String simulateRandomBrowserEvent() {
        return browserMonitor.simulateRandomEvent();
    }
}
