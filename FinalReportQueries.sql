----------------------- Antivirus Report -----------------------
SELECT
    system_info.hostname AS 'Machine Name',
    (os_version.name || '---Version---' || os_version.version) AS 'OS Details',
    (SELECT address FROM interface_addresses WHERE friendly_name = 'Ethernet' AND mask like '255.%') AS 'IP',
    (SELECT datetime(mtime,'unixepoch','localtime') from registry where path like
    '%HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus%'
    ) AS 'SAU Last Update',
    (programs.name || '---Version---' || programs.version) AS 'Sophos Components'
FROM
    system_info JOIN os_version JOIN programs
    WHERE publisher = 'Sophos Limited'




----------------------- App Control Report -----------------------
SELECT
    system_info.hostname AS 'Machine Name',
    (os_version.name || '-->' || 'Version' || '-->' || os_version.version) AS 'OS Details',
    (SELECT address FROM interface_addresses WHERE friendly_name = 'Ethernet' AND mask like '255.%') AS 'IP',
    (SELECT (json_extract(raw,'$.threatName')) FROM sophos_events_summary WHERE type = 'control') AS 'Blocked Application Name',
    (SELECT rtrim(REPLACE(ltrim(json_extract(raw, '$.paths'),'["\\\\?\\'),'\\',"\"),'"]') FROM sophos_events_summary WHERE type = 'control') AS 'Application Path',
    (SELECT json_extract(raw, '$.customMessageType') FROM sophos_events_summary WHERE type = 'control') AS 'Policy Type'
FROM
system_info,os_version




----------------------- Peripheral Control Report -----------------------
SELECT
   (SELECT hostname FROM system_info) AS 'Machine Name',
   (SELECT name FROM os_version) AS 'OS Details',
   CAST((SELECT GROUP_CONCAT(DISTINCT CHAR(10)||address) FROM interface_addresses
   WHERE address like '%.%.%.%' AND address <> '127.0.0.1')AS TEXT) AS 'Machine IPs',
   datetime(sophos_events_details.time,'unixepoch','localtime') AS 'Date_Time',
   json_extract(raw, '$.customMessageType') AS 'Policy Type',
   json_extract(raw, '$.path') AS 'Device Details',
   regex_match(json_extract(raw,'$.resourceId'),'(?:\.?(?:.*?\.)*)\.([^.]+\.[^.]+)$',1) AS 'Action Taken'
FROM sophos_events_details
WHERE familyId IN
(SELECT familyId FROM sophos_events_summary WHERE json_extract(raw,'$.resourceId') like '%control%')




----------------------- Threat Detection Report -----------------------
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
ORDER BY familyId
