SELECT
   (SELECT hostname FROM system_info) AS 'Machine Name',
   (SELECT name FROM os_version) AS 'OS Details',
   CAST((SELECT GROUP_CONCAT(DISTINCT CHAR(10)||address) FROM interface_addresses WHERE address like '%.%.%.%' AND address <> '127.0.0.1')AS TEXT) AS 'Machine IPs',
   datetime(sophos_events_details.time,'unixepoch','localtime') AS 'Date_Time',
   familyId,
   replace (json_extract(raw,'$.location'), rtrim(json_extract(raw,'$.location'), replace(json_extract(raw,'$.location'),"\", '')),'') AS 'File Name',
   replace (json_extract(raw,'$.location'), rtrim(json_extract(raw,'$.location'), replace(json_extract(raw,'$.location'),'.', '')),'') AS 'File Extension',
   json_extract(raw,'$.location') AS 'File Location',
   regex_match(json_extract(raw,'$.resourceId'),'(?:\.?(?:.*?\.)*)\.([^.]+\.[^.]+)$',1) AS 'Action Taken',
   ('MD5: '||hash.md5||CHAR(10)||'SHA1: '||hash.sha1||CHAR(10)||'SHA256: '||hash.sha256) AS 'Hash',
   json_extract(raw,'$.path') AS 'URL',
   json_extract(raw,'$.threatName') AS 'Threat Name'
FROM sophos_events_details
LEFT JOIN hash ON hash.path = json_extract(raw,'$.location')
WHERE familyId IN
(SELECT familyId FROM sophos_events_summary WHERE json_extract(raw,'$.resourceId') like '%.threat%')
ORDER BY sophos_events_details.time DESC,familyId
