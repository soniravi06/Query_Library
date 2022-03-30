SELECT 
'machinetime',
timestamp as 'LocalTime',
datetime(CAST(unix_time AS unsigned_bigint),'unixepoch') as 'UTC Time'
from time

Union all

SELECT
   name,
   datetime(CAST(data AS unsigned_bigint),'unixepoch','localtime') AS Time,
   datetime(CAST(data AS unsigned_bigint),'unixepoch') AS Time2
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\LastUpdateTime'


Union all

SELECT
   name,
   datetime(CAST(data AS unsigned_bigint),'unixepoch','localtime') AS Time,
   datetime(CAST(data AS unsigned_bigint),'unixepoch') AS Time2
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\LastSyncedTime'

UNION ALL

SELECT
   name,
   datetime(CAST(data AS unsigned_bigint),'unixepoch','localtime') AS Time,
   datetime(CAST(data AS unsigned_bigint),'unixepoch') AS Time2
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\LastInstallStartedTime'

UNION ALL

SELECT
   name,
   datetime(CAST(data AS unsigned_bigint),'unixepoch','localtime') AS Time,
   datetime(CAST(data AS unsigned_bigint),'unixepoch') AS Time2
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\UpdateStartedTime'
