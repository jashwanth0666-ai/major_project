package com.aiwatchdog.service;

import java.util.List;
import java.util.Random;

public class BrowserMonitorService {
    private final List<String> demoUrls = List.of("https://www.google.com", "https://www.microsoft.com", "https://secure-account-verification.example.com/login", "http://192.168.1.20/login/verify", "http://paypal-login-security.example.com/verify");
    private final Random random = new Random();
    public String simulateRandomEvent() { return demoUrls.get(random.nextInt(demoUrls.size())); }
    public String safe() { return demoUrls.get(0); }
    public String suspicious() { return demoUrls.get(2); }
    public String phishing() { return demoUrls.get(3); }
}
