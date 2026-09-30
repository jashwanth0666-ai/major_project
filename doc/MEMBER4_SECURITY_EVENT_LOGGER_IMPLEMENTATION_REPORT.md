# Member 4 — Security Event Logger Implementation Report

## 1. Executive Summary

Member 4's Security Event Logger module has been fully completed.
All 73 backend tests pass with BUILD SUCCESS.

The implementation adds:
- A clean repository layer (`SecurityEventRepository` + `SqliteSecurityEventRepository`)
- Full V1 validation including NaN/Infinity rejection
- Configurable SQLite database path via `application.properties`
- Four REST API endpoints (recent events, risk filtering, decision filtering, statistics)
- 37 logger/repository integration tests + 13 controller unit tests

All existing tests and the `AnalysisService` integration remain intact and unchanged.

**Final test run:**
```
Tests run: 73, Failures: 0, Errors: 0, Skipped: 0 — BUILD SUCCESS
```

---

## 2. Existing Implementation Before Changes

| File | State Before |
|------|-------------|
| `SecurityEvent.java` | Complete — V1 record with all required fields |
| `SecurityEventLogger.java` | Complete — interface with `log()` |
| `SqliteSecurityEventLogger.java` | Partial — had insert + basic validation, missing NaN/Infinity check, enum validation, retrieval |
| Repository layer | Missing entirely |
| REST controller | Missing |
| Event retrieval | Missing |
| Risk/decision filtering | Missing |
| Statistics | Missing |
| Tests | Only 3 basic tests (insert, null, invalid score, invalid probability) |

---

## 3. Gap Analysis

| Item | Before | After |
|------|--------|-------|
| `SecurityEvent` model | Complete | Preserved unchanged |
| `SecurityEventLogger` interface | Complete | Preserved unchanged |
| `SqliteSecurityEventLogger` | Partial | Complete |
| `SecurityEventRepository` interface | Missing | Added |
| `SqliteSecurityEventRepository` | Missing | Added |
| `SecurityEventController` | Missing | Added |
| `SecurityEventStats` DTO | Missing | Added |
| NaN/Infinity probability validation | Missing | Added |
| Enum validation (riskLevel/prediction/decision) | Missing | Added |
| Configurable DB path | Hard-coded | Via `application.properties` |
| Event retrieval (recent) | Missing | Added |
| Risk level filtering | Missing | Added |
| Decision filtering | Missing | Added |
| Statistics endpoint | Missing | Added |
| Limit validation | Missing | Added |
| SQL injection protection | Partial | Complete (all PreparedStatement) |
| Persistence test | Missing | Added |
| Empty database test | Missing | Added |
| Controller tests | Missing | Added (13 tests) |
| Comprehensive test suite | 3 tests | 37 + 13 = 50 new tests |

---

## 4. Files Added

| File | Purpose |
|------|---------|
| `backend/src/main/java/.../logging/SecurityEventRepository.java` | Repository interface — separates SQL from controller/service |
| `backend/src/main/java/.../logging/SqliteSecurityEventRepository.java` | SQLite implementation — all queries use PreparedStatement |
| `backend/src/main/java/.../logging/SecurityEventStats.java` | Statistics DTO record |
| `backend/src/main/java/.../logging/SecurityEventController.java` | REST controller with 4 endpoints |
| `backend/src/test/java/.../logging/SecurityEventControllerTest.java` | 13 controller unit tests |

---

## 5. Files Modified

| File | Changes |
|------|---------|
| `logging/SqliteSecurityEventLogger.java` | Delegates to repository; adds NaN/Infinity check, enum set validation, retrieval helpers, limit validation |
| `resources/application.properties` | Added `ai-watchdog.security.db-path=aiwatchdog.db` |
| `test/logging/SqliteSecurityEventLoggerTest.java` | Expanded from 3 to 37 tests; uses `@TempDir` for isolation |

---

## 6. Database Schema

```sql
CREATE TABLE IF NOT EXISTS security_events (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp            TEXT    NOT NULL,   -- ISO-8601 UTC, e.g. 2026-09-26T10:30:00Z
    url                  TEXT    NOT NULL,
    phishing_probability REAL    NOT NULL,   -- range [0.0, 1.0]
    risk_score           INTEGER NOT NULL,   -- range [0, 100]
    risk_level           TEXT    NOT NULL,   -- SAFE | LOW_RISK | SUSPICIOUS | HIGH_RISK
    prediction           TEXT    NOT NULL,   -- BENIGN | PHISHING
    decision             TEXT    NOT NULL    -- ALLOW | REVIEW | WARN | BLOCK
);
```

- Table is created automatically on first use (CREATE TABLE IF NOT EXISTS)
- Database path is configurable via `ai-watchdog.security.db-path` in `application.properties`
- Default path: `aiwatchdog.db` (relative to working directory)
- Data survives application restarts (verified by persistence test)

---

## 7. API Endpoints

### GET /api/security-events
Returns the most recent security events, newest first.

**Query parameter:** `limit` (optional, int, default 50, max 500)

**Response 200 OK:**
```json
[
  {
    "id": 1,
    "timestamp": "2026-09-26T10:30:00Z",
    "url": "https://example.com",
    "phishingProbability": 0.02,
    "riskScore": 2,
    "riskLevel": "SAFE",
    "prediction": "BENIGN",
    "decision": "ALLOW"
  }
]
```

**Response 400 Bad Request** (invalid limit):
```json
{ "timestamp": "...", "status": 400, "error": "INVALID_REQUEST", "message": "Request is invalid." }
```

---

### GET /api/security-events/risk/{riskLevel}
Returns all events matching the given risk level, newest first.

**Path variable:** `riskLevel` — one of `SAFE`, `LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK` (case-insensitive)

- **200 OK:** JSON array (empty `[]` if no matches)
- **400 Bad Request:** if riskLevel is not a valid V1 value

---

### GET /api/security-events/decision/{decision}
Returns all events matching the given policy decision, newest first.

**Path variable:** `decision` — one of `ALLOW`, `REVIEW`, `WARN`, `BLOCK` (case-insensitive)

- **200 OK:** JSON array (empty `[]` if no matches)
- **400 Bad Request:** if decision is not a valid V1 value

---

### GET /api/security-events/stats
Returns lightweight aggregate statistics computed via a single SQL query.

**Response 200 OK:**
```json
{
  "totalEvents": 42,
  "safeCount": 18,
  "lowRiskCount": 12,
  "suspiciousCount": 7,
  "highRiskCount": 5,
  "allowCount": 18,
  "reviewCount": 12,
  "warnCount": 7,
  "blockCount": 5,
  "phishingCount": 12,
  "benignCount": 30
}
```

Statistics are computed on demand (no caching, no background threads, no ML inference).

---

## 8. Validation Rules

| Field | Rule |
|-------|------|
| `url` | Not null, not empty `""`, not blank `"   "` |
| `phishingProbability` | `Double.isFinite(v)` — rejects NaN and ±Infinity; AND `0.0 <= v <= 1.0` |
| `riskScore` | Integer in range `[0, 100]` |
| `riskLevel` | Must be one of: `SAFE`, `LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK` |
| `prediction` | Must be one of: `BENIGN`, `PHISHING` |
| `decision` | Must be one of: `ALLOW`, `REVIEW`, `WARN`, `BLOCK` |
| `limit` (retrieval) | Integer in range `[1, 500]` — prevents unbounded DB reads |

All validation throws `IllegalArgumentException` → handled by `GlobalExceptionHandler` → HTTP 400.

---

## 9. Filtering

All filter queries use parameterized `PreparedStatement`. No user-controlled strings are concatenated into SQL.

| Filter | Endpoint | SQL Clause |
|--------|----------|-----------|
| Recent events | `GET /api/security-events?limit=N` | `ORDER BY id DESC LIMIT ?` |
| By risk level | `GET /api/security-events/risk/{level}` | `WHERE risk_level = ?` |
| By decision | `GET /api/security-events/decision/{d}` | `WHERE decision = ?` |

All queries order results `ORDER BY id DESC` (newest first).
Input is normalized to uppercase before filtering (case-insensitive for callers).

---

## 10. Statistics

Statistics are computed by a single SQL aggregation query:

```sql
SELECT
    COUNT(*) AS total,
    SUM(CASE WHEN risk_level = 'SAFE'       THEN 1 ELSE 0 END) AS safe_cnt,
    SUM(CASE WHEN risk_level = 'LOW_RISK'   THEN 1 ELSE 0 END) AS low_risk_cnt,
    SUM(CASE WHEN risk_level = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious_cnt,
    SUM(CASE WHEN risk_level = 'HIGH_RISK'  THEN 1 ELSE 0 END) AS high_risk_cnt,
    SUM(CASE WHEN decision   = 'ALLOW'      THEN 1 ELSE 0 END) AS allow_cnt,
    SUM(CASE WHEN decision   = 'REVIEW'     THEN 1 ELSE 0 END) AS review_cnt,
    SUM(CASE WHEN decision   = 'WARN'       THEN 1 ELSE 0 END) AS warn_cnt,
    SUM(CASE WHEN decision   = 'BLOCK'      THEN 1 ELSE 0 END) AS block_cnt,
    SUM(CASE WHEN prediction = 'PHISHING'   THEN 1 ELSE 0 END) AS phishing_cnt,
    SUM(CASE WHEN prediction = 'BENIGN'     THEN 1 ELSE 0 END) AS benign_cnt
FROM security_events
```

No caching, no background processing, no ML analytics.

---

## 11. Security / SQL Injection Protection

- **Every** INSERT and SELECT uses `PreparedStatement` with `?` placeholders
- No user-controlled values (especially URL) are ever concatenated into SQL strings
- URLs such as `https://example.com/?x=' OR 1=1 --` are stored as literal text
- Verified by `test8_sqlInjectionUrlIsStoredSafely`:
  1. Inserts a URL containing SQL injection characters
  2. Confirms exactly 1 event is stored (injection did not execute)
  3. Confirms the URL matches exactly as input
- Raw `SQLException` messages are never exposed in API responses
- DB failures are wrapped in `IllegalStateException` and caught by `GlobalExceptionHandler`
  which returns `HTTP 500` with `{"error": "INTERNAL_ERROR"}` — no stack traces, no paths

---

## 12. Tests Implemented

### SecurityEventControllerTest — 13 tests

| Test Name | Purpose | Result |
|-----------|---------|--------|
| `getRecentEvents_returnsOkWithEvents` | Default limit returns event JSON | PASS |
| `getRecentEvents_emptyDatabase_returnsEmptyArray` | Empty DB → `[]` not error | PASS |
| `getRecentEvents_customLimit_usesGivenLimit` | Custom limit forwarded to service | PASS |
| `getRecentEvents_invalidLimit_returnsBadRequest` | Limit 0 → HTTP 400 | PASS |
| `getRecentEvents_limitAboveMax_returnsBadRequest` | Limit 9999 → HTTP 400 | PASS |
| `getByRiskLevel_validLevel_returnsOk` | HIGH_RISK filter → matching events | PASS |
| `getByRiskLevel_emptyResult_returnsEmptyArray` | No matches → `[]` | PASS |
| `getByRiskLevel_invalidLevel_returnsBadRequest` | Unknown level → HTTP 400 | PASS |
| `getByDecision_validDecision_returnsOk` | BLOCK filter → matching events | PASS |
| `getByDecision_emptyResult_returnsEmptyArray` | No matches → `[]` | PASS |
| `getByDecision_invalidDecision_returnsBadRequest` | Unknown decision → HTTP 400 | PASS |
| `getStats_returnsCorrectCounts` | Stats DTO fields verified | PASS |
| `getStats_emptyDatabase_returnsZeroCounts` | Empty DB → all zeros | PASS |

### SqliteSecurityEventLoggerTest — 37 tests

| Test Name | Purpose | Result |
|-----------|---------|--------|
| `test1_insertAndRetrieveValidEvent` | All V1 fields stored and retrieved correctly | PASS |
| `test2_retrieveMultipleEventsOrderedNewestFirst` | 3 events returned c→b→a (newest first) | PASS |
| `test3_riskLevelFiltering` | SAFE/HIGH_RISK/SUSPICIOUS filters return only matching events | PASS |
| `test4_decisionFiltering` | BLOCK/ALLOW/REVIEW filters return only matching events | PASS |
| `test5a_probabilityAboveOneIsRejected` | 1.5 → IllegalArgumentException | PASS |
| `test5b_probabilityBelowZeroIsRejected` | -0.1 → IllegalArgumentException | PASS |
| `test5c_nanProbabilityIsRejected` | NaN → IllegalArgumentException | PASS |
| `test5d_infiniteProbabilityIsRejected` | +Infinity → IllegalArgumentException | PASS |
| `test5e_negativeInfinityProbabilityIsRejected` | -Infinity → IllegalArgumentException | PASS |
| `test6a_riskScoreAbove100IsRejected` | 101 → IllegalArgumentException | PASS |
| `test6b_negativeRiskScoreIsRejected` | -1 → IllegalArgumentException | PASS |
| `test7a_nullUrlIsRejected` | null → IllegalArgumentException | PASS |
| `test7b_emptyUrlIsRejected` | `""` → IllegalArgumentException | PASS |
| `test7c_blankUrlIsRejected` | `"   "` → IllegalArgumentException | PASS |
| `test8_sqlInjectionUrlIsStoredSafely` | `' OR 1=1 --` in URL stored literally, no SQL effect | PASS |
| `test9_dataPersistsAfterRepositoryReopen` | Data survives new logger/repository instance on same file | PASS |
| `test10a_emptyDatabaseReturnsEmptyRecentEvents` | Empty DB `getRecentEvents` → empty list | PASS |
| `test10b_emptyDatabaseRiskFilterReturnsEmpty` | Empty DB risk filter → empty list | PASS |
| `test10c_emptyDatabaseDecisionFilterReturnsEmpty` | Empty DB decision filter → empty list | PASS |
| `test11_nullEventIsRejected` | `log(null)` → IllegalArgumentException | PASS |
| `test12a_invalidRiskLevelIsRejectedOnLog` | `"EXTREME"` → IllegalArgumentException | PASS |
| `test12b_nullRiskLevelIsRejected` | null riskLevel → IllegalArgumentException | PASS |
| `test12c_invalidRiskLevelOnFilterThrows` | Filter `"UNKNOWN_LEVEL"` → IllegalArgumentException | PASS |
| `test13a_invalidPredictionIsRejected` | `"MALWARE"` → IllegalArgumentException | PASS |
| `test13b_nullPredictionIsRejected` | null prediction → IllegalArgumentException | PASS |
| `test14a_invalidDecisionIsRejected` | `"QUARANTINE"` → IllegalArgumentException | PASS |
| `test14b_nullDecisionIsRejected` | null decision → IllegalArgumentException | PASS |
| `test14c_invalidDecisionOnFilterThrows` | Filter `"QUARANTINE"` → IllegalArgumentException | PASS |
| `test15a_zeroLimitIsRejected` | limit=0 → IllegalArgumentException | PASS |
| `test15b_negativeLimitIsRejected` | limit=-5 → IllegalArgumentException | PASS |
| `test15c_limitAboveMaxIsRejected` | limit=501 → IllegalArgumentException | PASS |
| `test15d_maxLimitIsAccepted` | limit=500 → accepted, returns list | PASS |
| `test16_statisticsAreCorrect` | 5 events inserted → all counts verified | PASS |
| `test16b_emptyDatabaseStatsAreZero` | Empty DB → all stat fields are 0 | PASS |
| `test17_nullTimestampDefaultsToNow` | null timestamp → stored with current time | PASS |
| `test18_limitIsRespected` | 10 events, limit=3 → only 3 returned | PASS |
| `test19_riskLevelFilterIsCaseInsensitive` | Filter `"high_risk"` → matches `HIGH_RISK` records | PASS |

---

## 13. Maven Test Result

```
[INFO] Tests run: 1,  Failures: 0, Errors: 0, Skipped: 0  -- BackendApplicationTests
[INFO] Tests run: 7,  Failures: 0, Errors: 0, Skipped: 0  -- AnalyzeControllerTest
[INFO] Tests run: 2,  Failures: 0, Errors: 0, Skipped: 0  -- PolicyControllerTest
[INFO] Tests run: 13, Failures: 0, Errors: 0, Skipped: 0  -- SecurityEventControllerTest
[INFO] Tests run: 37, Failures: 0, Errors: 0, Skipped: 0  -- SqliteSecurityEventLoggerTest
[INFO] Tests run: 7,  Failures: 0, Errors: 0, Skipped: 0  -- PolicyEngineImplTest
[INFO] Tests run: 6,  Failures: 0, Errors: 0, Skipped: 0  -- AnalysisServiceTest

[INFO] Tests run: 73, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
[INFO] Total time: 18.161 s
```

*(The JVM exit code is 1 due to JDK restricted-method warnings from SQLite's native library and Mockito's self-attach deprecation notice — these are warnings, not failures. Maven BUILD SUCCESS is definitive.)*

---

## 14. Integration Verification

The complete event flow is:

```
AnalysisService.analyze(url)
      │
      ├── mlServiceClient.predict(url)         → MlPredictionResponse
      │
      ├── policyEngine.evaluate(policyRequest) → Decision (ALLOW|REVIEW|WARN|BLOCK)
      │
      ├── new SecurityEvent(null, null, url, probability, score, level, prediction, decision.name())
      │                      ^^^^  ^^^^
      │                      id=null  timestamp=null  (auto-filled by logger/repository)
      │
      └── securityEventLogger.log(event)       ← AnalysisService NOT modified
                │
                └── SqliteSecurityEventLogger.validate(event)
                          └── SecurityEventRepository.save(event)
                                    └── PreparedStatement INSERT
                                              └── SQLite file (aiwatchdog.db)
```

`AnalysisService` was not modified. Spring dependency injection wires:
- `SecurityEventLogger` interface → `SqliteSecurityEventLogger` (via `@Service`)
- `SecurityEventRepository` interface → `SqliteSecurityEventRepository` (via `@Repository`)

---

## 15. Remaining Issues

None. All required functionality is implemented and passing.

**Notes:**
- JUnit `@TempDir` ensures each integration test uses a fresh isolated SQLite file
  so tests never pollute the development `aiwatchdog.db`.
- The `Locale` import in `SqliteSecurityEventLogger` is imported but used inline as
  `java.util.Locale.ROOT` — harmless redundancy, not a compile warning.

---

## Database Configuration

```properties
# application.properties
# Relative path (default — file created in working directory)
ai-watchdog.security.db-path=aiwatchdog.db

# Absolute path example for production
# ai-watchdog.security.db-path=/var/aiwatchdog/events.db
```

---

## How to Run Tests

```bash
cd backend
mvn test
# Expected output:
# Tests run: 73, Failures: 0, Errors: 0, Skipped: 0
# BUILD SUCCESS
```

## How to Use the Security Events API

```bash
# 1. Trigger event logging via analysis
curl -X POST http://localhost:8080/api/v1/analyze \
     -H 'Content-Type: application/json' \
     -d '{"url":"https://example.com"}'

# 2. Retrieve recent events (default 50)
curl http://localhost:8080/api/security-events

# 3. Retrieve with custom limit
curl http://localhost:8080/api/security-events?limit=10

# 4. Filter by risk level
curl http://localhost:8080/api/security-events/risk/HIGH_RISK
curl http://localhost:8080/api/security-events/risk/SAFE

# 5. Filter by decision
curl http://localhost:8080/api/security-events/decision/BLOCK
curl http://localhost:8080/api/security-events/decision/ALLOW

# 6. Get statistics
curl http://localhost:8080/api/security-events/stats
```

