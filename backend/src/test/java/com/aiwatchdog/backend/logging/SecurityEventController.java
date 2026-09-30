package com.aiwatchdog.backend.logging;

import com.aiwatchdog.backend.policy.Decision;
import com.aiwatchdog.backend.policy.RiskLevel;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Locale;

@RestController
@RequestMapping("/api/security-events")
public class SecurityEventController {

    private final SecurityEventRepository repository;

    public SecurityEventController(SecurityEventRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public ResponseEntity<List<SecurityEvent>> getRecentEvents() {
        return ResponseEntity.ok(repository.findRecent(100));
    }

    @GetMapping("/risk/{riskLevel}")
    public ResponseEntity<List<SecurityEvent>> getByRiskLevel(@PathVariable String riskLevel) {
        RiskLevel level = RiskLevel.parse(riskLevel);
        return ResponseEntity.ok(repository.findByRiskLevel(level.name()));
    }

    @GetMapping("/decision/{decision}")
    public ResponseEntity<List<SecurityEvent>> getByDecision(@PathVariable String decision) {
        if (decision == null || decision.isBlank()) {
            throw new IllegalArgumentException("Decision must not be blank");
        }
        Decision dec;
        try {
            dec = Decision.valueOf(decision.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid decision: " + decision);
        }
        return ResponseEntity.ok(repository.findByDecision(dec.name()));
    }

    @GetMapping("/stats")
    public ResponseEntity<SecurityEventStats> getStats() {
        return ResponseEntity.ok(repository.getStats());
    }
}
