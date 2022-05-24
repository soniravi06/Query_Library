--Sophos Endpoint Health Status Check EDR Query

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
      WHEN data = 2 THEN 'SUSPICIOUS ⚠️'
      WHEN data = 3 THEN 'BAD ❌'
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
