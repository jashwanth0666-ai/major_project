package com.aiwatchdog;

import com.aiwatchdog.service.ApiService;
import com.aiwatchdog.model.AnalyzeResponse;

public class ApiTest {
    public static void main(String[] args) {
        try {
            ApiService api = new ApiService();
            System.out.println("Testing Benign URL...");
            AnalyzeResponse res1 = api.analyzeUrl("https://www.google.com");
            System.out.println("Result: " + res1.prediction() + ", Score: " + res1.riskScore());
            
            System.out.println("Testing Suspicious URL...");
            AnalyzeResponse res2 = api.analyzeUrl("http://secure-login-paypal-update.com");
            System.out.println("Result: " + res2.prediction() + ", Score: " + res2.riskScore());
            
            System.out.println("Testing Invalid URL...");
            try {
                api.analyzeUrl("not-a-url");
            } catch (Exception e) {
                System.out.println("Caught exception for invalid URL: " + e.getMessage());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
