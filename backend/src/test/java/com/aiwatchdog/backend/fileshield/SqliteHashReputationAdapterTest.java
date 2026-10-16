package com.aiwatchdog.backend.fileshield;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.aiwatchdog.backend.fileshield.reputation.SqliteHashReputationAdapter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.DriverManager;

import static org.junit.jupiter.api.Assertions.*;

class SqliteHashReputationAdapterTest {
    @TempDir Path temp;
    private static final String HASH = "a".repeat(64);

    @Test void missingHashIsUnknownAndMissingDatabaseIsLookupError() throws Exception {
        Path db = temp.resolve("reputation.db"); createDb(db);
        var adapter = new SqliteHashReputationAdapter(props(db));
        assertEquals(ReputationStatus.UNKNOWN, adapter.lookup("b".repeat(64)).status());
        assertEquals(ReputationStatus.LOOKUP_ERROR, new SqliteHashReputationAdapter(props(temp.resolve("absent.db"))).lookup(HASH).status());
    }

    @Test void returnsValidatedRecordAndRejectsMalformedHash() throws Exception {
        Path db = temp.resolve("reputation.db"); createDb(db);
        try (var c = DriverManager.getConnection("jdbc:sqlite:" + db); var s = c.prepareStatement("INSERT INTO hash_reputation VALUES (?, ?, ?, ?, ?)") ) {
            s.setString(1, HASH); s.setString(2, "KNOWN_MALICIOUS"); s.setString(3, "test-fixture"); s.setString(4, "synthetic fixture"); s.setString(5, "2026-01-01T00:00:00Z"); s.executeUpdate();
        }
        assertEquals(ReputationStatus.KNOWN_MALICIOUS, new SqliteHashReputationAdapter(props(db)).lookup(HASH).status());
        assertThrows(IllegalArgumentException.class, () -> new SqliteHashReputationAdapter(props(db)).lookup("x' OR 1=1"));
    }

    private void createDb(Path db) throws Exception {
        try (var c = DriverManager.getConnection("jdbc:sqlite:" + db); var s = c.createStatement()) {
            s.execute("CREATE TABLE hash_reputation (sha256 TEXT PRIMARY KEY, reputation TEXT NOT NULL, source TEXT NOT NULL, description TEXT, updated_at TEXT NOT NULL)");
        }
    }
    private FileShieldProperties props(Path db) { FileShieldProperties p = new FileShieldProperties(); p.setReputationDatabasePath(db); return p; }
}
