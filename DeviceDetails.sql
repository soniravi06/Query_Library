
-- Cards orient the results in five columns
--    ATRIBUTE - The thing being checked
--    VALUE - The result of the evaluation
--    CONTEXT - Some useful information related to the Attribute
--    CONTEXT_DATA - The inoformation for the context information being shown
--    NOTES - Some additional relevant information on the Attribute/Value


-- COLLECT A LIST OF SUSPECT PUA AND SUSPECT MAL software seen running on the device in the last 7 days
WITH List_of_suspects AS ( SELECT *
FROM Sophos_File_Properties
WHERE sophos_File_properties.pathname IN (SELECT DISTINCT pathname FROM sophos_process_journal spj WHERE spj.time > strftime('%s','now','-7 days') GROUP BY sha256 )
AND $$Show Suspect Executables ( 1 = TRUE)$$
ORDER BY puascore DESC, mlscore DESC LIMIT 5
),
-- COLLECT A LIST OF new exeutablesdeployed in the 7 days with a limit of 10
New_executables AS ( SELECT 'NEW USER INSTALLED EXECUTABLE (last 7 days)' ATTRIBUTE, sfj.pathname VALUE, 'CREATING PROCESS NAME' CONTEXT, spj.processName CONTEXT_DATA,
   'CREATED BY: ' || u.username || ' CREATED ON: ' || datetime(sfj.creationTime,'unixepoch') || ' CREATING PROCESS SPID: ' || sfj.sophosPID NOTES
FROM sophos_file_journal sfj
   JOIN sophos_process_journal spj ON spj.sophosPID = sfj.sophosPID
   JOIN users u ON u.uuid = spj.sid
WHERE sfj.subject = 'FileBinaryChanges' AND sfj.time > strftime('%s','now','-7 days') AND sfj.eventType IN (0,1,3)
   AND u.username <> 'SYSTEM'
   AND sfj.pathname LIKE '%.exe'
   AND $$Show New Installs ( 1 = TRUE )$$
ORDER by sfj.creationTime DESC
LIMIT 10
)


-- BLANK LINE BETWEEN EACH DEVICE
SELECT CAST(' ' AS TEXT) ATTRIBUTE, CAST(' ' AS TEXT) VALUE, CAST(' ' AS TEXT) CONTEXT, CAST(' ' AS TEXT) CONTEXT_DATA, CAST(' ' AS TEXT) NOTES WHERE $$Add section headers and dividers ( 1 = TRUE)$$
UNION ALL
SELECT CAST('=========================' AS TEXT) ATTRIBUTE, CAST('=========================' AS TEXT) VALUE, CAST('=========================' AS TEXT) CONTEXT, CAST('=========================' AS TEXT) CONTEXT_DATA, CAST('=========================' AS TEXT) NOTES WHERE $$Add section headers and dividers ( 1 = TRUE)$$


UNION ALL
SELECT CAST('DEVICE INFO ' AS TEXT) ATTRIBUTE, CAST(' ' AS TEXT) VALUE, CAST(' ' AS TEXT) CONTEXT, CAST(' ' AS TEXT) CONTEXT_DATA, CAST(' ' AS TEXT) NOTES WHERE $$Add section headers and dividers ( 1 = TRUE)$$ AND $$Show Device Info ( 1 = TRUE)$$
UNION ALL
-- Operating System information
SELECT 'OPERATING SYSTEM' ATTRIBUTE, name VALUE, 'VERSION' CONTEXT, version CONTEXT_DATA,  'INSTALLED ON: ' || substr(install_date,1,4) || ' ' || substr(install_date,5,2) || ' ' || substr(install_date,7,2) || ' ' || substr(install_date,9,2) || ':' || substr(install_date,11,2) NOTES
FROM os_version
WHERE $$Show Device Info ( 1 = TRUE)$$


UNION ALL


-- Current IP/MAC and DHCP Server for the device
SELECT 'IP-ADDRESS' ATTRIBUTE, CAST(ia.address AS TEXT) VALUE, 'MAC ADDRESS' CONTEXT, id.mac CONTEXT_DATA, 'DHCP SERVER: ' || id.dhcp_server NOTES
FROM interface_addresses ia JOIN interface_details id ON id.interface = ia.interface
WHERE ia.address NOT IN ('::1','127.0.0.1') AND id.enabled <> 0
   AND $$Show Device Info ( 1 = TRUE)$$


-- UNION ALL


-- ISOLATED/HEALTH STATUS
-- SOME SQL CODE


UNION ALL


-- DISK INFO
-- TO DO - Add bitlocker enabled info for each drive
SELECT 'HARD DISK' ATTRIBUTE, device_id VALUE, 'SIZE ' CONTEXT, printf("%.2f", CAST(size AS FLOAT)/1024.0/1024.0/1024.0) || '(GB)' CONTEXT_DATA, printf("%.2f", (CAST (free_space AS FLOAT)/CAST(size AS FLOAT) ) * 100.0  ) || '% Free' NOTES
FROM logical_drives
WHERE size > 0
   AND $$Show Device Info ( 1 = TRUE)$$


UNION ALL


-- CPU AND MEMORY INFO
SELECT 'CPU/MEMORY ' ATTRIBUTE, si.cpu_brand VALUE, 'MEMORY' CONTEXT,  printf("%.2f", CAST(si.physical_memory AS FLOAT)/1024.0/1024.0/1024.0) || '(GB)' CONTEXT_DATA, 'CPU CORES: ' || ci.number_of_cores || ' VENDOR: ' || si.hardware_vendor || ' MODEL: ' || hardware_model NOTES
FROM system_info si JOIN cpu_info ci ON 1
WHERE $$Show Device Info ( 1 = TRUE)$$


UNION ALL


-- UP TIME
SELECT 'UP TIME' ATTRIBUTE, days || ' days, ' || hours || ' hours ' || minutes || ' minutes' VALUE, 'BOOT MODE' CONTEXT,
   (
     SELECT CASE JSON_EXTRACT(data, '$.EventData.BootMode') WHEN '0' THEN 'Normal_Boot' WHEN '1' THEN 'Safe-Mode' ELSE 'Unknown Mode: ' || JSON_EXTRACT(data, '$.EventData.BootMode') END AS 'Boot Mode'
     FROM sophos_windows_events WHERE (eventid = 12 AND task = 1) AND time > STRFTIME('%s','NOW','-90 DAYS') ORDER by 1 DESC LIMIT 1
   ) CONTEXT_VALUE, '' NOTES
FROM uptime
WHERE $$Show Device Info ( 1 = TRUE)$$


UNION ALL


-- CURRENT USERS with active processes
SELECT 'PROCESS COUNT BY USER' ATTRIBUTE, u.username VALUE, 'ACTIVE PROCESS COUNT' CONTEXT, count(p.uid) CONTEXT_DATA, 'USER TYPE: ' || u.type || ' UID: ' || u.uid || ' GID: ' || u.gid NOTES
FROM users u JOIN processes p ON p.uid = u.uid
WHERE $$Show Device Info ( 1 = TRUE)$$
GROUP BY p.uid


UNION ALL


-- SCHEDULED TASKS SETUP IN LAST 7 DAYS
SELECT 'NEW SCHEDULED TASKS (last 7 days)' ATTRIBUTE, spj.cmdline VALUE, 'CREATED BY USER' CONTEXT, u.username CONTEXT_DATA, 'DATE_TIME: ' || datetime(time, 'unixepoch') || ' SOPHOS PID: ' || spj.sophospid NOTES
FROM sophos_process_journal spj
   JOIN users u ON u.uuid = spj.sid
WHERE spj.time > strftime('%s','now', '-7 days') AND spj.eventtype = 0
   AND spj.processname = 'schtasks.exe'
   AND spj.cmdline LIKE '%create%'
   AND $$Show Device Info ( 1 = TRUE)$$


UNION ALL


SELECT CAST('Dangerous Policy ' AS TEXT) ATTRIBUTE, CAST(' ' AS TEXT) VALUE, CAST(' ' AS TEXT) CONTEXT, CAST(' ' AS TEXT) CONTEXT_DATA, CAST(' ' AS TEXT) NOTES WHERE $$Add section headers and dividers ( 1 = TRUE)$$
UNION ALL
-- RDP STATUS
SELECT DISTINCT 'CHECK IF RDP IS LISTENING' ATTRIBUTE, 'Listening for connection' VALUE, '' CONTEXT, '' CONTEXT_DATA, '' NOTES
FROM listening_ports lp
WHERE lp.port = 3389


UNION ALL


SELECT CAST('Suspect executables ( LIMIT 5 PUA and 5 MAL )' AS TEXT) ATTRIBUTE, CAST(' ' AS TEXT) VALUE, CAST(' ' AS TEXT) CONTEXT, CAST(' ' AS TEXT) CONTEXT_DATA, CAST(' ' AS TEXT) NOTES WHERE $$Add section headers and dividers ( 1 = TRUE)$$ AND $$Show Suspect Executables ( 1 = TRUE)$$
UNION ALL
-- SUSPECT PUA
-- TO DO: Add indicator if that process is currently running
SELECT 'SUSPECT PUA' ATTRIBUTE, pathname VALUE, 'PUA SCORE' CONTEXT, puascore CONTEXT_DATA, 'SHA256: ' || sha256 NOTES
FROM List_of_suspects los
WHERE puascore > 30
   AND $$Show Suspect Executables ( 1 = TRUE)$$


UNION ALL


-- SUSPECT MAL
-- TO DO: Add indicator if that process is currently running
SELECT 'SUSPECT MAL' ATTRIBUTE, pathname VALUE, 'MAL SCORE' CONTEXT, mlscore CONTEXT_DATA, 'SHA256: ' || sha256 NOTES
FROM List_of_suspects los
WHERE mlscore > 30
   AND $$Show Suspect Executables ( 1 = TRUE)$$


UNION ALL


SELECT CAST('NEW executables ( LIMIT 10 )' AS TEXT) ATTRIBUTE, CAST(' ' AS TEXT) VALUE, CAST(' ' AS TEXT) CONTEXT, CAST(' ' AS TEXT) CONTEXT_DATA, CAST(' ' AS TEXT) NOTES WHERE $$Add section headers and dividers ( 1 = TRUE)$$ AND $$Show New Installs ( 1 = TRUE )$$
UNION ALL
-- NEW Executables installed by the USERS in last 7 days
-- WARNING: PROCESSES CREATED BY THE USER 'SYSTEM' ARE EXCLUDED
SELECT * FROM New_Executables WHERE $$Show New Installs ( 1 = TRUE )$$


UNION ALL


SELECT CAST('Live off the land tool usage ' AS TEXT) ATTRIBUTE, CAST(' ' AS TEXT) VALUE, CAST(' ' AS TEXT) CONTEXT, CAST(' ' AS TEXT) CONTEXT_DATA, CAST(' ' AS TEXT) NOTES WHERE $$Add section headers and dividers ( 1 = TRUE)$$ AND $$Show Live off the land tool info ( 1 = TRUE )$$
UNION ALL
-- COMMON LOL TOOL USAGE
SELECT 'LIVE OFF LAND TOOL USE (Last 7 days)' ATTRIBUTE, spj.processname VALUE, 'RUN BY USER' CONTEXT, u.username CONTEXT_DATA,  'COMMAND LINE: ' || spj.cmdline || ' SOPHOS PID: ' || spj.sophosPID NOTES
FROM sophos_process_journal spj
   JOIN users u ON u.uuid = spj.sid
WHERE spj.eventtype = 0 AND spj.time > strftime('%s','now','-7 days')
   AND spj.processname IN ('arp.exe', 'hostname.exe', 'ntdutil.exe', 'schtasks.exe', 'at.exe', 'ipconfig.exe', 'pathping.exe', 'systeminfo.exe', 'bitsadmin.exe', 'nbtstat.exe', 'ping.exe', 'tasklist.exe',
   'certutil.exe', 'net.exe', 'powershell.exe', 'tracert.exe', 'cmd.exe', 'net1.exe', 'qprocess.exe', 'ver.exe', 'dsget.exe', 'netdom.exe', 'query.exe', 'vssadmin.exe', 'dsquery.exe', 'netsh.exe', 'qwinsta.exe', 'wevtutil.exe',
   'find.exe', 'netstat.exe', 'reg.exe', 'whoami.exe', 'findstr.exe', 'nltest.exe', 'rundll32.exe', 'wmic.exe', 'fsutil.exe', 'nslookup.exe', 'sc.exe', 'wusa.exe'
   )
   AND u.username NOT IN('SYSTEM', 'LOCAL SERVICE', '')
   AND $$Show Live off the land tool info ( 1 = TRUE )$$


UNION ALL


-- PLAY BOOK STEP.  For any COMMON LOL processes determine if they created any executable files
SELECT 'FILE CREATE OR MODIFY BY LOL PROCESS' ATTRIBUTE, spj.processname VALUE, 'CREATED EXECUTABLE' CONTEXT, spa.object CONTEXT_DATA, 'RUN BY USER' || u.username || 'COMMAND LINE: ' || spj.cmdline || ' SOPHOS PID: ' || spj.sophosPID NOTES
FROM sophos_process_journal spj
   JOIN users u ON u.uuid = spj.sid
   JOIN sophos_process_activity spa ON spa.SophosPID = spj.SophosPID AND spa.subject IN ('FileBinaryChanges','FileDataChanges','FileOtherChanges') AND spa.action IN ('Created','Renamed','Modified')
WHERE spj.eventtype = 0 AND spj.time > strftime('%s','now','-7 days')
   AND (spj.processname IN ('powershell.exe', 'cmd.exe', 'netsh.exe', 'rundll32.exe') OR spj.processname LIKE 'python%.exe')
   AND u.username NOT IN('SYSTEM', 'LOCAL SERVICE', '')
   AND $$Show Live off the land tool info ( 1 = TRUE )$$


UNION ALL


SELECT CAST('Encoded Commands ' AS TEXT) ATTRIBUTE, CAST(' ' AS TEXT) VALUE, CAST(' ' AS TEXT) CONTEXT, CAST(' ' AS TEXT) CONTEXT_DATA, CAST(' ' AS TEXT) NOTES WHERE $$Add section headers and dividers ( 1 = TRUE)$$
UNION ALL
-- ENCODED CMDLINES(last 7 days)
SELECT 'ENCOUDED COMMAND LINES (Last 7 days)' ATTRIBUTE, spj.cmdline VALUE, 'PROCESS NAME' CONTEXT, spj.processname CONTEXT_VALUE, 'SOPHOS PID: ' || spj.sophospid || ' USER: ' || u.username NOTES
FROM sophos_process_journal spj JOIN
   users u ON u.uuid = spj.sid
WHERE spj.eventtype = 0 AND spj.time > strftime('%s','now','-7 days')
   AND spj.cmdline LIKE 'encode'
   AND u.username NOT IN ('SYSTEM', 'LOCAL SERVICE', '')
