SELECT

   strftime('%d',datetime(time,'unixepoch')) AS Day,

   (SUM(dataSent)) AS total_data_sent_bytes,

   (SUM(dataSent)/(1024*1024) )|| ' MB' AS total_data_sent_MB,

   (SUM(dataSent)/(1024*1024*1024) )|| ' GB' AS total_data_sent_GB,

   CAST((

       SELECT

       (SUM(dataSent)/(1024*1024)) || ' MB'

       FROM sophos_network_journal

       WHERE destination NOT LIKE '192.168.%'

       OR destination NOT GLOB '172.1[6-9].*'

       OR destination NOT GLOB '172.2[0-9].*'

       OR destination NOT GLOB '172.3[0-1].*'

       OR destination NOT LIKE '10.%'

       OR destination NOT LIKE '127.%'

       AND time > STRFTIME('%d', 'now', '-30 days')) AS text) total_data_sent_external_ips

FROM sophos_network_journal

WHERE

    time > STRFTIME('%d', 'now', '-30 days')

GROUP BY Day