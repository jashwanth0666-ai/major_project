package com.aiwatchdog.backend.monitor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Repository
public class SqliteMonitorEventRepository implements MonitorEventRepository {
    private final String dbUrl;

    public SqliteMonitorEventRepository(
            @Value("${ai-watchdog.security.db-path:aiwatchdog.db}") String dbPath) {
        dbUrl = "jdbc:sqlite:" + dbPath;
        try (Connection connection = connect(); Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS monitor_events (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp TEXT NOT NULL,
                      event_type TEXT NOT NULL,
                      action TEXT NOT NULL,
                      resource_name TEXT NOT NULL,
                      process_id INTEGER,
                      size_bytes INTEGER,
                      risk_score INTEGER NOT NULL,
                      risk_level TEXT NOT NULL,
                      decision TEXT NOT NULL,
                      reasons TEXT NOT NULL
                    )
                    """);
        } catch (SQLException exception) {
            throw new IllegalStateException("Failed to initialize monitor event storage", exception);
        }
    }

    @Override
    public MonitorEventResult save(MonitorEventResult event) {
        String sql = "INSERT INTO monitor_events(timestamp,event_type,action,resource_name,process_id,"
                + "size_bytes,risk_score,risk_level,decision,reasons) VALUES(?,?,?,?,?,?,?,?,?,?)";
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            statement.setString(1, event.timestamp().toString());
            statement.setString(2, event.eventType());
            statement.setString(3, event.action());
            statement.setString(4, event.resourceName());
            if (event.processId() == null) statement.setNull(5, java.sql.Types.BIGINT);
            else statement.setLong(5, event.processId());
            if (event.sizeBytes() == null) statement.setNull(6, java.sql.Types.BIGINT);
            else statement.setLong(6, event.sizeBytes());
            statement.setInt(7, event.riskScore());
            statement.setString(8, event.riskLevel());
            statement.setString(9, event.decision());
            statement.setString(10, String.join("\n", event.reasons()));
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                long id = keys.next() ? keys.getLong(1) : -1L;
                return new MonitorEventResult(id, event.timestamp(), event.eventType(), event.action(),
                        event.resourceName(), event.processId(), event.sizeBytes(), event.riskScore(),
                        event.riskLevel(), event.decision(), event.reasons());
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("Failed to persist monitor event", exception);
        }
    }

    @Override
    public List<MonitorEventResult> findRecent(int limit) {
        String sql = "SELECT * FROM monitor_events ORDER BY id DESC LIMIT ?";
        try (Connection connection = connect(); PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, Math.max(1, Math.min(limit, 500)));
            try (ResultSet rs = statement.executeQuery()) {
                List<MonitorEventResult> events = new ArrayList<>();
                while (rs.next()) {
                    events.add(new MonitorEventResult(rs.getLong("id"), Instant.parse(rs.getString("timestamp")),
                            rs.getString("event_type"), rs.getString("action"), rs.getString("resource_name"),
                            nullableLong(rs, "process_id"), nullableLong(rs, "size_bytes"),
                            rs.getInt("risk_score"), rs.getString("risk_level"), rs.getString("decision"),
                            List.of(rs.getString("reasons").split("\\n"))));
                }
                return events;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("Failed to retrieve monitor events", exception);
        }
    }

    private Connection connect() throws SQLException { return DriverManager.getConnection(dbUrl); }

    private Long nullableLong(ResultSet result, String column) throws SQLException {
        long value = result.getLong(column);
        return result.wasNull() ? null : value;
    }
}
