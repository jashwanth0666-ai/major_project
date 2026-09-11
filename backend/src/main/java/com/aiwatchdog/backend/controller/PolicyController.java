package com.aiwatchdog.backend.controller;

import com.aiwatchdog.backend.policy.PolicyEngine;
import com.aiwatchdog.backend.policy.PolicyRequest;
import com.aiwatchdog.backend.policy.PolicyResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/policy")
public class PolicyController {

    private final PolicyEngine policyEngine;

    public PolicyController(PolicyEngine policyEngine) {
        this.policyEngine = policyEngine;
    }

    @PostMapping("/evaluate")
    public ResponseEntity<PolicyResponse> evaluate(@Valid @RequestBody PolicyRequest request) {
        return ResponseEntity.ok(new PolicyResponse(
                request.url(),
                request.phishingProbability(),
                request.riskScore(),
                request.riskLevel(),
                request.prediction(),
                policyEngine.evaluate(request)));
    }
}