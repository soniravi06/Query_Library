-- SHOW ALL Agressive Classification records on the device (LABS)
SELECT
      datetime(IOC.time,'unixepoch') DateTime,
      verbosity Risk,
      (STRFTIME('%s','now')-ioc.time)/60 Minutes_Ago,
      IOC.threat_source,
      CAST(REPLACE( GROUP_CONCAT(DISTINCT
         JSON_EXTRACT((SELECT value FROM JSON_EACH(IOC.mitre_ttps)),'$.tactic')
         ||' '||
         JSON_EXTRACT((SELECT value FROM JSON_EACH(IOC.mitre_ttps)),'$.technique')
         ||CHAR(10)
         ),',','')
      AS TEXT) TTP_LIST,
      REPLACE(IOC.path, RTRIM(IOC.path, REPLACE(IOC.PATH, '\', '')), '') IOC_identified_Process_Name,
      spj.process_name SPID_processname,
      spj.cmdline SPID_CmdLine,
      IOC.sophos_pid,
      spj.parent_sophos_pid Parent_spid,
      IOC.path IOC_Path,
      IOC.mitre_ttps,
      IOC.events, *
   FROM Sophos_runtime_IOC_Journal IOC LEFT JOIN sophos_process_journal SPJ ON spj.sophosPID = IOC.sophos_pid
   WHERE IOC.time > $$Start Search ON Date$$ AND IOC.time < $$Start Search ON Date$$ + $$End Search N hours latter$$ * 3600
   GROUP BY IOC.sophos_pid
   ORDER BY ioc.time DESC
From the Data lake:

-- Search detections by Tactic and Technique
-- VARIABLE $$Tactic$$    STRING
-- VARIABLE $$Technique$$ STRING
-- VARIABLE $$category$$  STRING
-- VARIABLE $$type$$      STRING
-- VARIABLE $$device$$    DEVICE NAME
WITH Flat_Detections AS (
   SELECT
      meta_hostname,
      ingestion_timestamp,
      ioc_severity,
      CAST(JSON_EXTRACT(ioc_detection_mitre_attack, '$['||CAST(X.count AS VARCHAR)||'].tactic.name') AS VARCHAR) Tactic_Name,
      CAST(JSON_EXTRACT(ioc_detection_mitre_attack, '$['||CAST(X.count AS VARCHAR)||'].tactic.techniques['||CAST(Y.count AS VARCHAR)||'].name') AS VARCHAR) Technique_Name,
      username,
      CASE WHEN query_name = 'sophos_runtime_iocs_windows' THEN process_name ELSE name END p_name,
      CASE WHEN query_name = 'sophos_runtime_iocs_windows' THEN process_path ELSE path END p_path,
      CASE WHEN query_name = 'sophos_runtime_iocs_windows' THEN process_cmd_line ELSE cmdline END p_cmdline,
      ioc_event_path,
      sophos_pid,
      CASE WHEN query_name = 'sophos_runtime_iocs_windows' THEN process_parent_name ELSE parent_name END p_parent_name,
      CASE WHEN query_name = 'sophos_runtime_iocs_windows' THEN process_parent_path ELSE parent_path END p_parent_path,
      CASE WHEN query_name = 'sophos_runtime_iocs_windows' THEN process_parent_sophos_pid ELSE parent_sophos_pid END p_parent_sophos_pid,
      CAST(JSON_EXTRACT(ioc_detection_mitre_attack, '$['||CAST(X.count AS VARCHAR)||'].tactic.id') AS VARCHAR) Tactic_ID,
      CAST(JSON_EXTRACT(ioc_detection_mitre_attack, '$['||CAST(X.count AS VARCHAR)||'].tactic.techniques['||CAST(Y.count AS VARCHAR)||'].id') AS VARCHAR) Technique_ID,
      ioc_detection_mitre_attack,
      ioc_detection_description,
      ioc_detection_references,
      query_name,
      ioc_worker_id,
      ioc_detection_id,
      record_identifier,
      ioc_detection_category Category,
      ioc_detection_type Detection_Type
   FROM xdr_ti_data,
      UNNEST(SEQUENCE(0,JSON_ARRAY_LENGTH(ioc_detection_mitre_attack))) X(count),
      UNNEST(SEQUENCE(0,JSON_ARRAY_LENGTH(JSON_EXTRACT(ioc_detection_mitre_attack, '$['||CAST(X.count AS VARCHAR)||'].tactic.techniques')))) Y(count)
   WHERE LOWER(ioc_detection_category) LIKE LOWER('%$$category$$%')
      AND LOWER(ioc_detection_type) LIKE LOWER('%$$type$$%')
      AND LOWER(meta_hostname) LIKE LOWER('%$$device$$%')
   )
SELECT meta_hostname, ingestion_timestamp,ioc_severity, Tactic_Name, Technique_Name, username, p_name name, p_path path, p_cmdline cmdline, ioc_event_path, sophos_pid, p_parent_name parent_name, p_parent_path parent_path,
   p_parent_sophos_pid parent_sophos_pid, Tactic_ID, Technique_ID, ioc_detection_mitre_attack, ioc_detection_description, ioc_detection_references, query_name, ioc_worker_id, ioc_detection_id, record_identifier, Category,
   Detection_Type
FROM Flat_Detections
WHERE ( LOWER(Tactic_ID) LIKE LOWER('%$$Tactic$$%') OR LOWER(Tactic_Name) LIKE LOWER('%$$Tactic$$%') ) AND
      ( LOWER(Technique_ID) LIKE LOWER('%$$Technique$$%') OR LOWER(Technique_Name) LIKE LOWER('%$$Technique$$%') ) AND
      Tactic_ID > '' --AND Technique_ID > ''
ORDER BY ioc_severity DESC, record_identifier
