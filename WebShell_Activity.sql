SELECT
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS datetime,
   spj.path AS path,
   spj.cmd_line AS cmd_line,
   spj.sophos_pid AS sophos_PID,
   CAST (spj.process_name AS TEXT) process_name,
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time,
   CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time,
   CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) username,
   spj.sid AS sid,
   spj.sha256 AS sha256,
   spj.file_size AS file_size,
   CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = spj.path) AS text) First_Created_On_Disk,
   CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Modified,
   spj.parent_sophos_pid AS sophos_parent_PID,
   CAST ( (Select spj2.path from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_path,
   CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophospid = spj.parent_sophos_pid) AS text) parent_process,
   CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophospid = spj.parent_sophos_pid) AS text) parent_cmd_line,
   'Low' As Potential_FP_chance,
   'Possible WebShell Activity' As Details,
   'Process Journal/File/Users' AS Data_Source,
   'T1505.003 - WebShell Detection/Commandline' AS Query
FROM sophos_process_journal spj
WHERE (parent_process = 'w3wp.exe' OR parent_process = 'httpd.exe' OR parent_process LIKE 'tomcat%.exe' OR parent_process = 'nginx.exe' OR parent_process = 'beasvc.exe' OR parent_process = 'coldfusion.exe' OR parent_process = 'visualsvnserver.exe' OR parent_process = 'java.exe')
AND (process_name = 'cmd.exe' OR process_name = 'powershell.exe' OR process_name = 'powershell_ise.exe')
AND spj.time > $$start_time$$
AND spj.time < $$end_time$$
