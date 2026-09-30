package com.aiwatchdog.backend.monitor;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/monitor-events")
public class MonitorEventController {
    private final MonitorEventAnalyzer analyzer;
    private final MonitorEventRepository repository;

    public MonitorEventController(MonitorEventAnalyzer analyzer, MonitorEventRepository repository) {
        this.analyzer = analyzer;
        this.repository = repository;
    }

    @PostMapping
    public ResponseEntity<MonitorEventResult> ingest(@Valid @RequestBody MonitorEventRequest request) {
        return ResponseEntity.ok(analyzer.analyze(request));
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> recent(@RequestParam(defaultValue = "100") int limit) {
        List<MonitorEventResult> events = repository.findRecent(limit);
        return ResponseEntity.ok(Map.of("events", events, "count", events.size()));
    }
}
