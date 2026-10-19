package com.aiwatchdog.backend.assessment;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import java.util.List;

@RestController
@RequestMapping("/api/v1/domain-whitelist")
public class DomainWhitelistController {
    private final ConfiguredLocalDomainRuleService rules;
    public DomainWhitelistController(ConfiguredLocalDomainRuleService rules) { this.rules = rules; }

    @GetMapping
    public List<String> list() { return rules.listAllowlist().stream().sorted().toList(); }

    @PostMapping
    public List<String> add(@RequestBody DomainRequest request) {
        try {
            if (request == null) throw new IllegalArgumentException("Enter a valid domain name, such as example.com.");
            rules.addAllowlistEntry(request.domain());
            return list();
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, invalid.getMessage());
        }
    }

    @DeleteMapping("/{domain}")
    public List<String> remove(@PathVariable String domain) {
        try {
            rules.removeAllowlistEntry(domain);
            return list();
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, invalid.getMessage());
        }
    }

    public record DomainRequest(String domain) { }
}
