Antivirus Report:-

Machine Name | IP | Last Comunication | OS | last Update | Antivirus Version | Sophos Components Version


SELECT
    system_info.hostname AS 'Machine Name',
    os_version.name AS 'OS',
    os_version.version AS 'OS Version',
    (SELECT result FROM curl WHERE url = 'http:'||'/'||'/'||'ipv4bot.whatismyipaddress.com') AS 'IP',
    (SELECT installed_on FROM patches order by installed_on desc limit 1) AS 'Last Update',
    (SELECT name, version FROM programs WHERE publisher ='Sophos Limited') AS
    'Sophos Components Version'
FROM
    system_info JOIN os_version




    SELECT
        system_info.hostname AS 'Machine Name',
        (os_version.name || '---Version---' || os_version.version) AS 'OS Details',
        (SELECT result FROM curl WHERE url = 'http:'||'/'||'/'||'ipv4bot.whatismyipaddress.com') AS 'IP',
        (SELECT installed_on FROM patches order by installed_on desc limit 1) AS 'Windows Last Update',
        (programs.name || '---Version---' || programs.version) AS 'Sophos Components'
    FROM
        system_info JOIN os_version JOIN programs
        WHERE publisher = 'Sophos Limited'

---------1st Final Query Below-------------------------

        SELECT
            system_info.hostname AS 'Machine Name',
            (os_version.name || '---Version---' || os_version.version) AS 'OS Details',
            (SELECT address FROM interface_addresses WHERE friendly_name = 'Ethernet' AND mask like '255.%') AS 'IP',
            (SELECT datetime(mtime,'unixepoch','localtime') from registry where path like '%HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus%'
            ) AS 'SAU Last Update',
            (programs.name || '---Version---' || programs.version) AS 'Sophos Components'
        FROM
            system_info JOIN os_version JOIN programs
            WHERE publisher = 'Sophos Limited'

-----------EOF 1st Final Query------------------------



SELECT
    system_info.hostname AS 'Machine Name',
    (os_version.name || '-->' || 'Version' || '-->' || os_version.version) AS 'OS Details',
    (SELECT address FROM interface_addresses WHERE friendly_name = 'Ethernet' AND mask like '255.%') AS 'IP',
    /*(SELECT
    CAST(replace(datetime(sophos_events_summary.time,'unixepoch','localtime'),'','Time') AS TEXT) AS 'DateTime',
    type,
    REPLACE(ltrim(json_extract(raw, '$.paths'),'["\\\\?\\'),'\\',"\") AS 'Path',
    json_extract(raw, '$.customMessageType') AS 'Custom Message',
    json_extract(raw, '$.threatName' ) AS 'Application Name'
    FROM
    sophos_events_summary
    WHERE type = 'control')*/
    (SELECT (json_extract(raw,'$.threatName')) FROM sophos_events_summary WHERE type = 'control') AS 'Application Name',
    (SELECT REPLACE(ltrim(json_extract(raw, '$.paths'),'["\\\\?\\'),'\\',"\") FROM sophos_events_summary WHERE type = 'control') AS 'Application Path',
    (SELECT json_extract(raw, '$.customMessageType') FROM sophos_events_summary WHERE type = 'control') AS 'Policy Type'
FROM
system_info,os_version;

---------------------2nd Final Query---------------

SELECT
    system_info.hostname AS 'Machine Name',
    (os_version.name || '-->' || 'Version' || '-->' || os_version.version) AS 'OS Details',
    (SELECT address FROM interface_addresses WHERE friendly_name = 'Ethernet' AND mask like '255.%') AS 'IP',
    (SELECT (json_extract(raw,'$.threatName')) FROM sophos_events_summary WHERE type = 'control') AS 'Application Name',
    (SELECT rtrim(REPLACE(ltrim(json_extract(raw, '$.paths'),'["\\\\?\\'),'\\',"\"),'"]') FROM sophos_events_summary WHERE type = 'control') AS 'Application Path',
    (SELECT json_extract(raw, '$.customMessageType') FROM sophos_events_summary WHERE type = 'control') AS 'Policy Type'
FROM
    system_info,os_version;


---------------------EOF 2nd Query----------------------------


SELECT
    system_info.hostname AS 'Machine Name',
    (os_version.name || '-->' || 'Version' || '-->' || os_version.version) AS 'OS Details',

CAST(replace(datetime(sophos_events_summary.time,'unixepoch','localtime'),'','Time') AS TEXT) dateTime

CAST(rtrim(REPLACE(ltrim(json_extract(raw, '$.paths'),'["\\\\?\\'),'\\',"\"),) AS TEXT) AS InnerPath


  SELECT
    pathname,
    sha256,
    sha1,
    ((SELECT rtrim(REPLACE(ltrim(json_extract(raw, '$.paths'),'["\\\\?\\'),'\\',"\"),) FROM sophos_events_summary WHERE type = 'control') AS Path1)
  FROM sophos_file_properties WHERE pathname = Path1


  SELECT *
FROM
(
SELECT CAST(rtrim(REPLACE(ltrim(json_extract(raw, '$.paths'),'["\\\\?\\'),'\\',"\"),'"]') AS TEXT) InnerPath FROM sophos_events_summary WHERE type = 'control'
) AS InnerTable, sophos_file_properties
WHERE Innerpath = pathname





SELECT
    system_info.hostname AS 'Machine Name',
    (os_version.name || '---Version---' || os_version.version) AS 'OS Details',
    (SELECT address FROM interface_addresses WHERE friendly_name = 'Ethernet' AND mask like '255.%') AS 'IP',
    (SELECT datetime(mtime,'unixepoch','localtime') from registry where path like '%HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus%'
    ) AS 'SAU Last Update',
    (programs.name || '---Version---' || programs.version) AS 'Sophos Components'
FROM
    system_info JOIN os_version JOIN programs
    WHERE publisher = 'Sophos Limited'


-----------------------------4th Query----------------------------------

SELECT
    system_info.hostname AS 'Machine Name',
    (os_version.name || '---Version---' || os_version.version) AS 'OS Details',
    (SELECT DISTINCT source FROM sophos_network_journal WHERE destinationPort = 53 limit 1 AS 'IP',
    --sophos_events_summary.json_extract(raw,$.location) FileName
    --sophos_events_summary.json_extract(raw,$.path) File_Location
    --hash.FilePath (MD5,SHA1,SHA256)
    --sophos_network_journal.source AS Source_IP
    --sophos_network_journal.destination AS Destination_IP
    --ActionTaken
    --sophos_file_properties.File Extension
    --sophos_file_properties.size
    --sophos_events_summary.json_extract(raw,$.threatName) Threat Type/DetectionPolicy
FROM
  system_info,os_version,sophos_events_summary



  SELECT
   familyId,
   timeStamp,
   severity,
   type,
   raw
FROM sophos_events_summary
WHERE json_extract(raw,'$.customMessageType') = 'malware'

SELECT *
FROM sophos_events_details
WHERE familyId =
(SELECT familyID FROM sophos_events_summary WHERE json_extract(raw,'$.customMessageType') = 'malware')



SELECT
   familyId,
   datetime(time, 'unixepoch', 'localtime') AS 'Time',
   json_extract(raw,'$.resourceId') AS 'Action Taken',
   json_extract(raw,'$.location') AS 'File Location',
   json_extract(raw,'$.threatName') AS 'Threat Name',
   raw
FROM sophos_events_details
WHERE familyId IN
(SELECT familyID FROM sophos_events_summary WHERE familyId = '{38EB0050-1C75-439F-B828-0013FAF18E25}')/*WHERE json_extract(raw,'$.customMessageType') = 'malware'*/
--GROUP BY familyId

SELECT
   familyId,
   datetime(time,'unixepoch','localtime'),
   json_extract(raw,'$.resourceId') AS 'Action Taken',
   json_extract(raw,'$.location') AS 'File Location',
   json_extract(raw,'$.threatName') AS 'Threat Name',
   raw
FROM sophos_events_details
WHERE familyId IN
(SELECT familyID FROM sophos_events_summary /*WHERE json_extract(raw,'$.customMessageType') = 'malware'*/)
--GROUP BY familyId
order by time desc

select datetime(time,'unixepoch','localtime'),* from sophos_events_summary where datetime(time,'unixepoch','localtime') = '2021-04-27 07:24:44'






SELECT
   familyId,
   datetime(time,'unixepoch','localtime'),
   json_extract(raw,'$.resourceId') AS 'Action Taken',
   json_extract(raw,'$.location') AS 'File Location',
   replace (json_extract(raw,'$.location'), rtrim(json_extract(raw,'$.location'), replace(json_extract(raw,'$.location'),"\", '')),'') AS 'File Name',
   json_extract(raw,'$.path') AS 'URL',
   json_extract(raw,'$.threatName') AS 'Threat Name',
   raw
FROM sophos_events_details
WHERE familyId IN
(SELECT familyID FROM sophos_events_summary /*WHERE json_extract(raw,'$.customMessageType') = 'malware'*/)
AND json_extract(raw,'$.resourceId') like '%threat%'
--GROUP BY familyId



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




Peripheral Control Report

SELECT
   (SELECT hostname FROM system_info) AS 'Machine Name',
   (SELECT name FROM os_version) AS 'OS Details',
   CAST((SELECT GROUP_CONCAT(DISTINCT CHAR(10)||address) FROM interface_addresses WHERE address like '%.%.%.%' AND address <> '127.0.0.1')AS TEXT) AS 'Machine IPs',
   datetime(sophos_events_details.time,'unixepoch','localtime') AS 'Date_Time',
   familyId,
   *
   --replace (json_extract(raw,'$.location'), rtrim(json_extract(raw,'$.location'), replace(json_extract(raw,'$.location'),"\", '')),'') AS 'File Name',
   --replace (json_extract(raw,'$.location'), rtrim(json_extract(raw,'$.location'), replace(json_extract(raw,'$.location'),'.', '')),'') AS 'File Extension',
   --json_extract(raw,'$.location') AS 'File Location',
   --regex_match(json_extract(raw,'$.resourceId'),'(?:\.?(?:.*?\.)*)\.([^.]+\.[^.]+)$',1) AS 'Action Taken',
   --('MD5: '||hash.md5||CHAR(10)||'SHA1: '||hash.sha1||CHAR(10)||'SHA256: '||hash.sha256) AS 'Hash',
   --json_extract(raw,'$.path') AS 'URL',
   --json_extract(raw,'$.threatName') AS 'Threat Name'
FROM sophos_events_details
WHERE familyId IN
(SELECT familyId FROM sophos_events_summary WHERE json_extract(raw,'$.resourceId') like '%control%')




--DECLARE VARIABLE IN CENTRAL--
--VARIABLE: $$YYYY-MM-DD$$  STRING

WITH log_file AS (SELECT REPLACE(line,CHAR(9),',') AS line FROM grep WHERE pattern IN ("url") AND path = 'C:\ProgramData\Sophos\Web Intelligence\Logs\$$YYYY-MM-DD$$.log'),
log_table AS (SELECT
   SPLIT(line, ',', 0) Time, LTRIM(SPLIT(line, ',', 1),('action'||'=')) Action, LTRIM(SPLIT(line, ',', 2),'why=') Why,LTRIM(SPLIT(line, ',', 4),'threat=') Threat,
   LTRIM(SPLIT(line, ',', 5),'fileclass=') FileClass,
   CASE
    CAST (LTRIM(SPLIT(line, ',', 6),'category=') AS INT)
     WHEN 0 THEN 'Uncategorized'
     WHEN 1 THEN 'Adult/Sexually Explicit'
     WHEN 2 THEN 'Advertisements & Pop-Ups'
     WHEN 3 THEN 'Alcohol & Tobacco'
     WHEN 4 THEN 'Arts'
     WHEN 5 THEN 'Blogs & Forums'
     WHEN 6 THEN 'Business'
     WHEN 7 THEN 'Chat'
     WHEN 8 THEN 'Computing & Internet'
     WHEN 9 THEN 'Criminal Activity'
     WHEN 10 THEN 'Downloads'
     WHEN 11 THEN 'Education'
     WHEN 12 THEN 'Entertainment'
     WHEN 13 THEN 'Fashion & Beauty'
     WHEN 14 THEN 'Finance & Investment'
     WHEN 15 THEN 'Food & Dining'
     WHEN 16 THEN 'Gambling'
     WHEN 17 THEN 'Games'
     WHEN 18 THEN 'Government'
     WHEN 19 THEN 'Hacking'
     WHEN 20 THEN 'Health & Medicine'
     WHEN 21 THEN 'Hobbies & Recreation'
     WHEN 22 THEN 'Hosting Sites'
     WHEN 23 THEN 'Illegal Drugs'
     WHEN 24 THEN 'Infrastructure'
     WHEN 25 THEN 'Intimate Apparel & Swimwear'
     WHEN 26 THEN 'Intolerance & Hate'
     WHEN 27 THEN 'Job Search & Career Development'
     WHEN 28 THEN 'Kids Sites'
     WHEN 29 THEN 'Motor Vehicles'
     WHEN 30 THEN 'News'
     WHEN 31 THEN 'Peer-to-Peer'
     WHEN 32 THEN 'Personals and Dating'
     WHEN 33 THEN 'Philantropic & Professional Orgs.'
     WHEN 34 THEN 'Phishing & Fraud'
     WHEN 35 THEN 'Photo Searches'
     WHEN 36 THEN 'Polotics'
     WHEN 37 THEN 'Proxies & Translators'
     WHEN 38 THEN 'Real Estate'
     WHEN 39 THEN 'Reference'
     WHEN 40 THEN 'Religion'
     WHEN 41 THEN 'Ringtones/Mobile Phone Downloads'
     WHEN 42 THEN 'Search Engines'
     WHEN 43 THEN 'Sex Education'
     WHEN 44 THEN 'Shopping'
     WHEN 45 THEN 'Society & Culture'
     WHEN 46 THEN 'Spam URLs'
     WHEN 47 THEN 'Sports'
     WHEN 48 THEN 'Spyware'
     WHEN 49 THEN 'Streaming Media'
     WHEN 50 THEN 'Tasteless & Offensive'
     WHEN 51 THEN 'Travel'
     WHEN 52 THEN 'Violence'
     WHEN 53 THEN 'Weapons'
     WHEN 54 THEN 'Web-based E-mail'
     WHEN 55 THEN 'Custom'
     WHEN 56 THEN 'Anonymizing Proxies'
    ELSE 'Others'
   END Category,
   LTRIM((REPLACE(SPLIT(line, ',', 7),'hxxp','http')),'url=') URL
FROM log_File
)
SELECT * FROM log_Table
