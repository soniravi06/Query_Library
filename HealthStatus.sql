WITH
servicestatus as (select data as "service" FROM registry where key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' and name = 'service'),
threatstatus as (select data as "threat" FROM registry where key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' and name = 'threat'),
badservices as (select CAST(group_concat(name, CHAR(10)) AS TEXT) as "bad services" FROM registry where key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' and name like 'service.%' and data = '1')
select * from servicestatus JOIN threatstatus join badservices where service = 1 OR threat = 1;


--Details to be included
Endpoint Name,
Online
Real-Time Scan
Last Update
Devie Encryption
Health servicestatus -
Agent Installed
Service Status - select data as "service" FROM registry where key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' and name = 'service'
Threat Status - select data as "threat" FROM registry where key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' and name = 'threat'
Isolated by Admin
Isolated awaiting action/not Isolated
Agent Summary




SELECT
   CASE
      WHEN data = 1 THEN 'GOOD ✅'
      WHEN data = 3 THEN 'BAD ❌ - Isolated'
   END Satus
FROM
   registry
WHERE key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' AND name = 'admin'

SELECT
   CASE
      WHEN data = 1 THEN 'GOOD ✅'
      WHEN data = 2 THEN 'SUSPICIOUS'
      WHEN data = 3 THEN 'BAD ❌'
   END Satus
FROM
   registry
WHERE key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' AND name = 'health'

SELECT
   CASE
      WHEN data = 1 THEN 'GOOD ✅'
      WHEN data = 2 THEN 'SUSPICIOUS'
      WHEN data = 3 THEN 'BAD ❌'
   END Satus
FROM
   registry
WHERE key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' AND name = 'service'

SELECT
   CASE
      WHEN data = 1 THEN 'GOOD ✅'
      WHEN data = 2 THEN 'SUSPICIOUS'
      WHEN data = 3 THEN 'BAD ❌'
   END Satus
FROM
   registry
WHERE key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' AND name = 'threat'



WITH
servicestatus as (select data as "service" FROM registry where key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' and name = 'service'),
threatstatus as (select data as "threat" FROM registry where key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' and name = 'threat'),
badservices as (select CAST(group_concat(name, CHAR(10)) AS TEXT) as "bad services" FROM registry where key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' and name like 'service.%' and data = '1')

WITH EndpointHealthStatus (IsolateStatus,ServiceStatus,ThreatStatus,BadServices,OverallHealthStatus)
AS (VALUES
  )


SELECT
  IsolateStatus AS (SELECT
     CASE
        WHEN data = 1 THEN 'GOOD ✅'
        WHEN data = 3 THEN 'BAD ❌ - Isolated'
     END Satus
  FROM
     registry
  WHERE key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' AND name = 'admin'),

  ServiceStatus AS (SELECT
     CASE
        WHEN data = 1 THEN 'GOOD ✅'
        WHEN data = 2 THEN 'SUSPICIOUS'
        WHEN data = 3 THEN 'BAD ❌'
     END Satus
  FROM
     registry
  WHERE key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' AND name = 'service'),

  ThreatStatus AS (SELECT
     CASE
        WHEN data = 1 THEN 'GOOD ✅'
        WHEN data = 2 THEN 'SUSPICIOUS'
        WHEN data = 3 THEN 'BAD ❌'
     END Satus
  FROM
     registry
  WHERE key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' AND name = 'threat'),

  BadServices AS (SELECT
    CAST(group_concat(name, CHAR(10)) AS TEXT) AS "bad services"
  FROM
    registry
  WHERE
    key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\'
  AND name LIKE 'service.%' AND data IN (1,2)),

  OverallHealthStatus AS (SELECT
     CASE
        WHEN data = 1 THEN 'GOOD ✅'
        WHEN data = 2 THEN 'SUSPICIOUS'
        WHEN data = 3 THEN 'BAD ❌'
     END Satus
  FROM
     registry
  WHERE key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\' AND name = 'health')

  FROM
    registry
  WHERE
    key = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status\'









SELECT
  regex_match(line,'(\{.*?\})',0) AS "EventID"
FROM
  grep
WHERE
  pattern LIKE 'Processing event id:'
    AND path = 'C:\ProgramData\Sophos\Health\Logs\Health.log'
ORDER BY regex_match(line,'(.*Z)',0) DESC
LIMIT 1




SELECT (json_extract(raw,'$.threatName') || ' --detected-- ' || json_extract(raw,'$.location')) AS 'Threat Details' FROM sophos_events_summary WHERE id IN (SELECT
  regex_match(line,'(\{.*?\})',0) AS "EventID"
FROM
  grep
WHERE
  pattern LIKE 'Processing event id:'
    AND path = 'C:\ProgramData\Sophos\Health\Logs\Health.log'
ORDER BY regex_match(line,'(.*Z)',0) DESC
LIMIT 2) AND type NOT LIKE '%web%'
