WITH
  total_data_sent_external (Day,total_data_sent_external_bytes,total_data_sent_external_MB) AS (
  SELECT
    strftime('%d',datetime(time,'unixepoch')) AS Day,
    (SUM(dataSent)) AS total_data_sent_external_bytes,
    (SUM(datasent)/(1024*1024)) || ' MB' AS total_data_sent_external_MB
FROM
    sophos_network_journal
WHERE
        destination NOT LIKE '192.168.%.%'
    AND destination NOT GLOB '172.1[6-9].*.*'
    AND destination NOT GLOB '172.2[0-9].*'
    AND destination NOT GLOB '172.3[0-1].*'
    AND destination NOT LIKE '10.%'
    AND destination NOT LIKE '127.%'
    AND time > $$start_time$$
    AND time < $$end_time$$
GROUP BY Day
),

total_data_sent (Day,total_data_sent_bytes,total_data_sent_MB,total_data_sent_GB) AS(
SELECT
    strftime('%d',datetime(time,'unixepoch')) AS Day,
    (SUM(dataSent)) AS total_data_sent_bytes,
    (SUM(dataSent)/(1024*1024) )|| ' MB' AS total_data_sent_MB,
    (SUM(dataSent)/(1024*1024*1024) )|| ' GB' AS total_data_sent_GB
FROM
    sophos_network_journal
WHERE
        time > $$start_time$$
    AND time < $$end_time$$
GROUP BY Day
)

SELECT
    tbl1.Day,
    total_data_sent_bytes,
    total_data_sent_MB,
    total_data_sent_GB,
    total_data_sent_external_bytes,
    total_data_sent_external_MB
FROM
    total_data_sent tbl1 JOIN total_data_sent_external tbl2 ON tbl1.Day = tbl2.Day
