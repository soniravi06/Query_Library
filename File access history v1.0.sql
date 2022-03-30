-- LIST ALL FILE CHANGES IN A LOCATION FOR A TIME PERIOD

-- VARIABLE  $$Path Name$$                   STRING
-- VARIABLE  $$Begin Search on date$$        DATE
-- VARIABLE  $$Hours to Search$$             STRING
-- VARIABLE  $$With Matching SHA256 value$$  STRING
-- VARIABLE  $$Target Path Name$$            STRING

SELECT
   datetime(sfj.time,'unixepoch') Date_Time,
   users.username AS username,
   (SELECT spj.pathname FROM sophos_process_Journal spj WHERE spj.sophosPID = sfj.sophosPID ) Process_Pathname,
   sfj.subject,
   CASE sfj.eventType
      WHEN 0 THEN 'created'
      WHEN 1 THEN 'renamed'
      WHEN 2 THEN 'deleted'
      WHEN 3 THEN 'modified'
      WHEN 4 THEN 'hardLinkCreated'
      WHEN 5 THEN 'timestampsModified'
      WHEN 6 THEN 'permissionsModified'
      WHEN 7 THEN 'ownershipModified'
      WHEN 8 THEN 'accessed'
      WHEN 9 THEN 'binaryFileMapped'
      ELSE 'UNKNOWN: ' || CAST (sfj.eventType AS TEXT)
   END EventType,
   sfj.pathname File_Pathname,

   -- DUMP FILE CONTENTS
   CAST((SELECT CAST(group_concat(g.line, Char(10)) AS TEXT) Filedata FROM grep g WHERE g.pattern = " " AND g.path = sfj.pathname) AS TEXT) File_Contents,

   sfj.targetpathname Target_Pathname,
   sfj.filesize,
   sfj.sha256,
   CAST(CASE sfj.sha256 <> "" WHEN 1 THEN (SELECT CAST(sfp.pathname AS TEXT) from sophos_file_properties sfp WHERE sfp.sha256 = sfj.sha256) ELSE 'Unknown' END AS TEXT) FilePath,
   sfj.pesha256,
   CAST(CASE sfj.pesha256 <> "" WHEN 1 THEN (SELECT CAST(sfp.pathname AS TEXT) from sophos_file_properties sfp WHERE sfp.sha256 = sfj.pesha256) ELSE 'Unknown' END AS TEXT) FilePath
FROM sophos_file_journal sfj
LEFT JOIN sophos_process_journal AS spj ON spj.sophosPID = sfj.sophosPID
LEFT JOIN users ON users.uuid = spj.sid
WHERE sfj.pathname LIKE '$$Path Name$$%' AND
   sfj.time > $$Begin Search on date$$ and sfj.time < $$Begin Search on date$$ + $$Hours to Search$$ * 3600  AND
   sfj.subject IN ('FileBinaryChanges', 'FileDataChanges', 'FileOtherChanges') AND
   (sfj.sha256 LIKE '$$With Matching SHA256 value$$' OR sfj.pesha256 LIKE '$$With Matching SHA256 value$$') AND
   sfj.targetpathname LIKE '$$Target Path Name$$'
LIMIT 5
