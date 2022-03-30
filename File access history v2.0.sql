-- LIST FILE ACTIVITY
-- VARIABLE $$start_time$$ DATE
-- VARIABLE $$end_time$$   DATE
-- VARIABLE $$file_path$$  FILE PATH
-- VARIABLE $$hash$$       SHA-256

SELECT
   STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(file_journal.time,'unixepoch')) AS date_time,
   users.username AS Username,
   process_journal.processName AS process_name,
   CASE file_journal.eventType
     WHEN 0 THEN 'Created'
     WHEN 1 THEN 'Renamed'
     WHEN 2 THEN 'Deleted'
     WHEN 3 THEN 'Modified'
     WHEN 4 THEN 'HardLink Created'
     WHEN 5 THEN 'Timestamps Modified'
     WHEN 6 THEN 'Permissions Modified'
     WHEN 7 THEN 'Ownership Modified'
     WHEN 8 THEN 'Accessed'
     WHEN 9 THEN 'Binary File Mapped'
   END AS event_type,
    file_journal.subject AS Subject,
    REPLACE(file_journal.pathname, RTRIM(file_journal.pathname, REPLACE(file_journal.pathname, CHAR(92), '')), '') AS file_name,
    process_journal.pathname AS process_path,
    file_journal.pathname AS file_path,
    file_journal.sophosPID AS sophos_pid,
    process_journal.sha256 AS sha256,
    process_properties.mlScore AS ml_score,
    process_properties.puaScore AS pua_score,
    process_properties.localRep AS local_rep,
    process_properties.globalRep AS global_rep
FROM sophos_file_journal AS file_journal
LEFT JOIN sophos_process_journal AS process_journal
    ON process_journal.sophosPID = file_journal.sophosPID
    AND process_journal.time = REPLACE(file_journal.sophosPID, RTRIM(file_journal.sophosPID, REPLACE(file_journal.sophosPID  , ':', '')), '') / 10000000 - 11644473600
LEFT JOIN users ON users.uuid = process_journal.sid
LEFT JOIN sophos_process_properties AS process_properties
    USING (sophosPID)
WHERE
    file_journal.pathname LIKE '$$file_path$$'
    AND process_journal.sha256 LIKE '$$hash$$'
    AND file_journal.time > $$start_time$$
    AND file_journal.time < $$end_time$$
ORDER BY file_journal.time DESC
LIMIT 10
