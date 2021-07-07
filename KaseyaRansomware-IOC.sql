/* EDR Query to check for matching REvil-Kaseya-IOC's */

--VARIABLE    $$StartTime$$   DATE
--VARIABLE    $$EndTime$$     DATE

WITH IOC_LIST (IOC_Type, Indicator, note) AS (
 WITH IOC_FILE(Line, str) AS (
  SELECT 'ip,127.0.0.1,TEST DATA', (SELECT result from curl where url = 'https://raw.githubusercontent.com/sophoslabs/IoCs/master/Ransomware-REvil-Kaseya.csv') ||char(10)
  UNION ALL
  SELECT substr(str, 0, instr(str, char(10) )), substr(str, instr(str, char(10) )+1) FROM IOC_FILE WHERE str!=''
 )
SELECT
 replace(Line, ltrim(Line, replace(Line, ',', '')), '') 'Indicator Type',
 replace(replace(substr(Line, instr(Line, ',')+1), ltrim(substr(Line, instr(Line, ',')+1), replace(substr(Line, instr(Line, ',')+1), ',', '')), ''),'*','%')  Indicator,
 replace(Line, rtrim(Line, replace(Line, ',', '')), '') 'Note'
FROM IOC_FILE WHERE Line != '' AND Line != 'Indicator type,Data,Note' AND Line NOT LIKE 'Description%' AND Line NOT LIKE '%TEST DATA%' AND Line NOT LIKE '%indicator_type%'
)


SELECT DISTINCT
 CAST( datetime(spa.time,'unixepoch') AS TEXT) DATE_TIME,
 'MATCH FOUND' Detection,
 ioc.IOC_Type,
 ioc.Indicator,
 ioc.note,
 spa.subject,
 spa.SophosPID,
 CAST ( (select replace(spa.pathname, rtrim(spa.pathname, replace(spa.pathname, "\", '')), '')) AS TEXT) process_name,
 spa.action,
 spa.object,
 spa.url AS 'url/hash/pathname'
FROM IOC_LIST ioc
 JOIN sophos_process_activity spa ON spa.object LIKE ioc.Indicator AND spa.time BETWEEN $$StartTime$$ AND $$EndTime$$
WHERE ioc.IOC_Type = 'domain' AND spa.subject IN ('Dns','Http','Url','Network')

UNION ALL

SELECT DISTINCT
 CAST( datetime(spj.time,'unixepoch') AS TEXT) DATE_TIME,
 'MATCH FOUND' Detection,
 ioc.IOC_Type,
 ioc.Indicator,
 ioc.note,
 'sophos_process_journal',
 spj.SophosPID,
 CAST ( (select replace(spj.pathname, rtrim(spj.pathname, replace(spj.pathname, "\", '')), '')) AS TEXT) process_name,
 spj.eventtype,
 'process execution',
 spj.sha256
FROM IOC_LIST ioc
 JOIN sophos_process_journal spj ON spj.sha256 LIKE ioc.Indicator AND spj.time BETWEEN $$StartTime$$ AND $$EndTime$$
WHERE ioc.IOC_Type = 'sha256'

UNION ALL

SELECT DISTINCT
 CAST( datetime(spa.time,'unixepoch') AS TEXT) DATE_TIME,
 'MATCH FOUND' Detection,
 ioc.IOC_Type,
 ioc.Indicator,
 ioc.note,
 spa.subject,
 spa.SophosPID,
 CAST ( (select replace(spa.pathname, rtrim(spa.pathname, replace(spa.pathname, "\", '')), '')) AS TEXT) process_name,
 spa.action,
 spa.object,
 spa.pathname
FROM IOC_LIST ioc
 JOIN sophos_process_activity spa ON LOWER(spa.pathname) LIKE LOWER(ioc.Indicator) OR LOWER(spa.object) LIKE LOWER(ioc.Indicator) AND spa.time BETWEEN $$StartTime$$ AND $$EndTime$$
WHERE IOC_Type = 'file_path_name' AND spa.subject IN ('FileBinaryChanges','FileBinaryReads','FileDataChanges','FileDataReads','FileOtherChanges','FileOtherReads','Image','Process')

UNION ALL

SELECT DISTINCT
 CAST( datetime(file.btime,'unixepoch') AS TEXT) DATE_TIME,
 'MATCH FOUND' Detection,
 ioc.IOC_Type,
 ioc.Indicator,
 ioc.note,
 'File_system',
 '' ,
 file.filename,
 'on disk',
 file.path,
 ''
FROM IOC_LIST ioc
 LEFT JOIN file ON LOWER(ioc.IOC_Type) IN('pathname', 'file_path', 'file_path_name', 'filename') AND file.path LIKE ioc.indicator
WHERE DATE_TIME <> ''
