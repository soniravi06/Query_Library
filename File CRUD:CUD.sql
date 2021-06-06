-- Files created, modfied or deleted in last N hours from date

-- VARIABLE $$Start search on date$$        DATE
-- VARIABLE $$Number of Hours to Search$$   STRING
-- VARIABLE $$filename$$                    STRING
-- VARIABLE $$path$$                        File Path
-- VARIABLE $$process name$$                STRING
-- VARIABLE $$sophos PID$$                  SophosPID

WITH Activity_List AS ( SELECT
   REPLACE(DATETIME(MIN(time), 'unixepoch'),' ','T') Date_Time,
   CASE WHEN spa.sophosPID LIKE '4:%' THEN 'SYSTEM' ELSE (SELECT processname FROM sophos_process_Journal spj WHERE spj.sophosPID = spa.SophosPID) END Process_Name,
   CAST(GROUP_CONCAT(DISTINCT action ) AS TEXT) Action,
   object,
   replace(object, rtrim(object, replace(object, "\", '')), '') File_Name,
   CASE WHEN (SELECT path FROM file f WHERE f.path = spa.object) > '' THEN 'Still on disk' ELSE 'Not Found' END On_Disk,
   CASE WHEN INSTR(object,'.') THEN LOWER(replace(object, rtrim(object, replace(object, '.', '')), '')) ELSE '' END ext,
   MAX(filesize) File_Size,
   sophosPID
FROM sophos_process_activity spa
WHERE subject IN ('FileBinaryChanges','FileOtherChanges', 'FileDataChanges')
   AND CASE WHEN '$$sophos PID$$' = '%' THEN 1 ELSE sophosPID ='$$sophos PID$$' END
   AND Process_Name LIKE '$$process name$$'
   AND object LIKE '$$path$$'
   AND File_Name LIKE '$$filename$$'
   AND action IN ('Created','Modified','Deleted')
   AND time > $$Start search on date$$
   AND time < $$Start search on date$$ + strftime('%s','now','-$$Number of Hours to Search$$ hours')
GROUP BY SophosPID, object, ext, On_Disk
ORDER BY time DESC
)
SELECT
   Date_Time,
   Process_Name,
   Action,
   CAST(File_Name AS TEXT) File_Name,
   On_Disk,
   ext,
   File_Size,
   Object FilePath,
   SophosPID
FROM Activity_List
