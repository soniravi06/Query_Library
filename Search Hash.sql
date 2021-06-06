-- Files created or modfied in last N hours

-- VARIABLE $$File Extension$$              STRING
-- VARIABLE $$Number of Hours to Search$$    STRING
-- VARIABLE $$Process Name$$                STRING
-- VARIABLE $$SophosPID$$                   STRING

WITH Activity_List AS ( SELECT
   REPLACE(DATETIME(MIN(time), 'unixepoch'),' ','T') Date_Time,
   CASE WHEN spa.sophosPID LIKE '4:%' THEN 'SYSTEM' ELSE (SELECT processname FROM sophos_process_Journal spj WHERE spj.sophosPID = spa.SophosPID) END Process_Name,
   CAST(GROUP_CONCAT(DISTINCT action ) AS TEXT) Action,
   object,
   CASE WHEN (SELECT path FROM file f WHERE f.path = spa.object) > '' THEN 1 ELSE 0 END On_Disk,
   LOWER(replace(object, rtrim(object, replace(object, '.', '')), '')) ext,
   MAX(filesize) File_Size,
   sophosPID
FROM sophos_process_activity spa
WHERE subject IN ('FileOtherChanges', 'FileDataChanges') --, 'FileBinaryChanges')
   AND ext LIKE LOWER('$$File Extension$$')
   AND CASE WHEN '$$SophosPID$$' = '%' THEN 1 ELSE sophosPID ='$$SophosPID$$' END
   AND Process_Name LIKE '%$$Process Name$$%'
   AND action IN ('Created','Modified') AND time > strftime('%s','now','-$$Number of Hours to Search$$ hours')
GROUP BY SophosPID, object, ext, On_Disk
ORDER BY time DESC
)

SELECT
   Date_Time,
   Process_Name,
   Action,
   Object,

   -- CHECK IF THE FILE IS ON DISK OR NOT If it is on the disk then dump the contents as ASCII OR HEX Depending on FILE TYPE

/*   CASE
      -- DO NOT Try and dump files that do not exist
      WHEN NOT CAST(On_Disk AS BOOLEAN) THEN '--FILE NOT FOUND--'

      -- DO NOT TRY AND dump LARGE FILES
      WHEN File_Size > 102400 THEN '--FILE SIZE > 100KB--'

      -- ASCII DUMP first 1KB for NON-Binary Files
      WHEN File_Size < 102401 AND ext IN ('txt','rtf','ps1','log','pid','csv') THEN '--FIRST 1KB OF TEXT--'||CHAR(10)||
         (SELECT SUBSTR(GROUP_CONCAT(line,CHAR(10)),0,1024) FROM grep g
          WHERE g.pattern IN (char(10),char(32),char(13),'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','0',':',';','<','>','.','?','|','/','\',
                             'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','~','!','@','#','$','%','^','&','*','(',')','-','_','+','=')
               AND g.path = object
         )
      -- HEX DUMP FOR BINARY FILES
      ELSE
         (SELECT '--HEX DUMP NOT SUPPORTED--'
         )
      END Content,
*/
   On_Disk,
   ext,
   File_Size,
   SophosPID
FROM Activity_List
