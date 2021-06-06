-- Sophos Endpoint Health Status Check EDR Query

SELECT
  (SELECT
    CASE
      WHEN data = 1 THEN 'GOOD ✅'
      WHEN data = 3 THEN 'BAD ❌ - Isolated'
    END Satus
  FROM
    registry
  WHERE key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\" AND name = 'admin') AS IsolateStatus,

  (SELECT
    CASE
      WHEN data = 1 THEN 'GOOD ✅'
      WHEN data = 2 THEN 'SUSPICIOUS ⚠️️'
      WHEN data = 3 THEN 'BAD ❌'
    END Satus
  FROM
    registry
  WHERE key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\" AND name = 'service') AS ServiceStatus,

  (SELECT
    CASE
      WHEN data = 1 THEN 'GOOD ✅'
      WHEN data = 2 THEN 'SUSPICIOUS ⚠️' || CHAR(10) || CAST((SELECT (json_extract(raw,'$.threatName') || ' --detected-- ' || json_extract(raw,'$.location')) AS "Threat Details" FROM sophos_events_summary WHERE id IN (SELECT regex_match(line,'(\{.*?\})',0) AS "EventID" FROM grep WHERE pattern LIKE 'Processing event id:' AND path = "C:\ProgramData\Sophos\Health\Logs\Health.log" ORDER BY regex_match(line,'(.*Z)',0) DESC LIMIT 2) AND type NOT LIKE '%web%') AS TEXT)
      WHEN data = 3 THEN 'BAD ❌' || CHAR(10) || CAST((SELECT (json_extract(raw,'$.threatName') || ' --detected-- ' || json_extract(raw,'$.location')) AS "Threat Details" FROM sophos_events_summary WHERE id IN (SELECT regex_match(line,'(\{.*?\})',0) AS "EventID" FROM grep WHERE pattern LIKE 'Processin event id:' AND path = "C:\ProgramData\Sophos\Health\Logs\Health.log" ORDER BY regex_match(line,'(.*Z)',0) DESC LIMIT 2) AND type NOT LIKE '%web%') AS TEXT)
    END Satus
  FROM
    registry
  WHERE key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\" AND name = 'threat') AS ThreatStatus,

  (SELECT
    CASE
      WHEN (SELECT
              CAST(group_concat(name, CHAR(10)) AS TEXT) AS "bad services"
            FROM
              registry
            WHERE
              key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\"
            AND name LIKE 'service.%' AND data IN (1,2)) IS NULL
      THEN 'NONE ✅'
      ELSE (SELECT
              CAST(group_concat(name, CHAR(10)) AS TEXT) AS "bad services"
            FROM
              registry
            WHERE
              key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\"
            AND name LIKE 'service.%' AND data IN (1,2))
    END Status) AS BadServices,

  (SELECT
    CASE
      WHEN data = 1 THEN 'GOOD ✅'
      WHEN data = 2 THEN 'SUSPICIOUS ⚠️'
      WHEN data = 3 THEN 'BAD ❌'
    END Satus
  FROM
    registry
  WHERE key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\" AND name = 'health') AS OverallHealthStatus
