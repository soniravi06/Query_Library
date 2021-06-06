-------------------- Authentication attempts --------------------
/* Lists all authentication attempts (requires Windows event audit logging) */

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(time,'unixepoch')) dateTime,
    CAST(json_extract(data, '$.authenticationPackageName') AS TEXT) authPackageName,
    CAST(json_extract(data, '$.targetDomainName') AS TEXT) domain,
    CAST(json_extract(data, '$.targetUserName') AS TEXT) username,
    CAST(json_extract(data, '$.ipAddress') AS TEXT) remoteAddress,
    CAST(CASE json_extract(data, '$.logonType')
        WHEN 2 THEN 'Interactive'
        WHEN 3 THEN 'Network'
        WHEN 4 THEN 'Batch'
        WHEN 5 THEN 'Service'
        WHEN 7 THEN 'Unlock'
        WHEN 8 THEN 'NetworkCleartext'
        WHEN 9 THEN 'NewCredentials'
        WHEN 10 THEN 'RemoteInteractive'
        WHEN 11 THEN 'CachedInteractive'
        WHEN 12 THEN 'Cached Remote Interactive'
        ELSE 'UNKNOWN TYPE: ' || json_extract(data,'$.EventData.LogonType')
    END AS TEXT) logonType,
    CAST(CASE eventType
        WHEN 4624 THEN 'Authenticated'
        ELSE CASE json_extract(data, '$.subStatus')
            WHEN '0xc000005e' THEN 'There are currently no logon servers available to service the logon request'
            WHEN '0xc0000064' THEN 'Incorrect User - User logon with misspelled or bad user account'
            WHEN '0xc000006a' THEN 'Incorrect Password - User logon with misspelled or bad password'
            WHEN '0xc000006d' THEN 'Incorrect User or Auth - This is either due to a bad username or authentication information'
            WHEN '0xc000006f' THEN 'User logon outside authorized hours'
            WHEN '0xc0000070' THEN 'User logon from unauthorized workstation'
            WHEN '0xc0000072' THEN 'Disabled - User logon to account disabled by administrator'
            WHEN '0xc000015b' THEN 'The user has not been granted the requested logon type (aka logon right) at this machine'
            WHEN '0xc0000192' THEN 'An attempt was made to logon, but the Netlogon service was not started'
            WHEN '0xc0000193' THEN 'Expired - User logon with expired account'
            WHEN '0xc0000413' THEN 'Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine'
            ELSE 'UNKNOWN: ' || json_extract(data, '$.subStatus')
        END
    END AS TEXT) result
FROM sophos_winsec_journal
    WHERE eventType IN (4624, 4625)
    AND IFNULL(json_extract(data, '$.ipAddress'), '') LIKE '$$ipAddress$$'
    AND IFNULL(json_extract(data, '$.targetUserName'), '') LIKE '$$userName$$'
    AND time >= $$startTime$$
    AND time <= $$endTime$$

------------------------------------------------------------------------------------------------------------------------

/**************************************************************************\
| This query looks for PS activity to discver culter and keyboard layout   |
\**************************************************************************/

-- VARIABLE $$Begin search on$$  DATE
-- VARIABLE $$Hours to search$$  STRING

-- Provide a map to the MITRE INFO
WITH mitre_techniques(id, subid, tactic, technique, subtechnique) AS (
    VALUES
        -- DISCOVERY
        ('T1082', '',    'discovery', 'System Information Discovery', '')
),

-- Provide Detection rules based on CMD_LINE evaluations EVERYTHING HAS TO BE lowercase
-- ALL RULES are for ANY Process's CMD_LINE
mitre_methods(noise_level, id, subid, process, indicator) AS (
    VALUES
      -- T1000-1099
        (0,'T1082', '',    '%', '%get-culture%'),
        (0,'T1082', '',    '%', '%get-winuserlanguagelist%')
),

mitre_methods_ID AS ( SELECT ROW_NUMBER() OVER( ORDER BY id, subid, process, indicator) Rule_Id, id, noise_level, subid, process, indicator FROM mitre_methods ),

-- Identify which rules to run based on admin variable selections
ttp(mitre_id, mitre_subid, tactic, technique, subtechnique, process, hunt_rule, mitre_link, Rule_ID, noise_level) AS (
    SELECT
        mitre_techniques.id AS mitre_id,
        mitre_techniques.subid AS mitre_subid,
        mitre_techniques.tactic AS tactic,
        mitre_techniques.technique AS technique,
        mitre_techniques.subtechnique AS subtechnique,
        mitre_methods_ID.process AS process,
        mitre_methods_ID.indicator AS hunt_rule,
        CASE mitre_techniques.subid
            WHEN '' THEN 'https://attack.mitre.org/techniques/' || mitre_techniques.id
            ELSE 'https://attack.mitre.org/techniques/' || mitre_techniques.id || '/' || mitre_techniques.subid
        END AS mitre_link,
        mitre_methods_ID.Rule_ID Rule_ID,
        noise_level
    FROM mitre_methods_ID
    LEFT JOIN mitre_techniques ON
        mitre_methods_ID.id = mitre_techniques.id
        AND mitre_methods_ID.subid = mitre_techniques.subid
),

-- Perform the evaluations
detections AS (
    SELECT
        REPLACE(DATETIME(spj.time,'unixepoch'),' ','T') date_time,
        ttp.mitre_id,
        ttp.mitre_subid,
        ttp.tactic,
        ttp.technique,
        ttp.subtechnique,
        ttp.process process_filter,
        ttp.hunt_rule,
        ttp.mitre_link,
        (SELECT username FROM users WHERE users.uuid = spj.sid) AS username,
        spj.processname AS process_name,
        spj.cmdline AS cmd_line,
        spj.sophosPID AS sophos_pid,
        spj.pathname AS path_name,
        (SELECT spj2.processname FROM sophos_process_journal spj2 WHERE spj2.sophospid = spj.parentSophosPID AND spj2.eventtype = 0) parent_name,
        ttp.Rule_ID,
        ttp.noise_level
    FROM sophos_process_journal spj
    JOIN ttp ON spj.processname LIKE ttp.process AND spj.cmdline LIKE ttp.hunt_rule
    WHERE
        spj.eventType = 0
        AND spj.time > $$Begin search on$$ and spj.time < $$Begin search on$$ + $$Hours to search$$ * 3600
),

-- GROUP results so we can show counted number of events
ordered_results AS ( SELECT
    tactic AS MITRE_Tactic,
    technique AS MITRE_Technique,
    COUNT(tactic) AS Instances,
    process_name AS Process_Name,
    cmd_line AS Cmd_Line,
    MIN(sophos_pid) AS Sample_SophosPID,  -- NOTE THIS IS CRUDE
    REPLACE(GROUP_CONCAT(DISTINCT sophos_pid),',',CHAR(10)) AS FULL_sophos_pid_list,
    REPLACE(GROUP_CONCAT(DISTINCT username),',',CHAR(10)) AS user_list,
    subtechnique AS subtechnique,
    mitre_id AS MITRE_id,
    mitre_subid AS MITRE_subid,
    mitre_link AS MITRE_link,
    process_filter AS process_filter,
    hunt_rule AS hunt_rule,
    MIN(date_time) AS first_seen,
    MAX(date_time) AS last_seen,
    REPLACE(GROUP_CONCAT(DISTINCT path_name),',',CHAR(10)) AS path_name_list,
    REPLACE(GROUP_CONCAT(DISTINCT parent_name),',',CHAR(10)) AS parent_name_list,
    noise_level AS noise_level
FROM detections
GROUP BY
    detections.mitre_id,
    detections.mitre_subid,
    detections.tactic,
    detections.technique,
    detections.process_name,
    detections.cmd_line,
    detections.process_filter,
    detections.hunt_rule,
    detections.subtechnique,
    detections.mitre_link,
    detections.noise_level
ORDER BY instances DESC, detections.tactic, detections.technique, detections.mitre_id, detections.mitre_subid, detections.process_name
)
SELECT
    MITRE_Tactic,
    CAST(MITRE_Technique AS TEXT) MITRE_Technique,
    Instances,
    CAST(Process_Name AS TEXT) Process_Name,
    Cmd_Line,
    Sample_SophosPID,
    FULL_sophos_pid_list,
    user_list,
    CAST(subtechnique AS TEXT) MITRE_subtechnique,
    CAST(MITRE_id||REPLACE(PRINTF('.%03d',MITRE_subid),'.000','') AS TEXT) 'MITRE_id.subid',
    CAST(MITRE_link AS TEXT) MITRE_link,
    process_filter,
    hunt_rule,
    first_seen,
    last_seen,
    path_name_list,
    parent_name_list,
    noise_level
FROM ordered_results


---------------------------------------------------------------------------------------------

-- Extended Process Tree for a SophosPID

-- VARIABLE $$SophosPID$$ sophosPID

-- NOTE THE PROCESS OR ANCESTORS MAY STILL BE RUNNING SO HANDLE ENDTIME CORRECTLY by changing endtime for running processes to now + 10 min
WITH RECURSIVE
-- GET A LIST OF ALL ANCESTORS OF A SOPHOS PID
Ancestors(SophosPID, Level, parent, processname, pathname, cmdline, sha256, sid, start, end) AS (
   -- Define the SEED Row as the information on the SophosPID provided
   SELECT sophosPID, 0, ParentSophosPID, processname, pathname, cmdline, sha256, sid, time,
     CASE WHEN (SELECT endtime FROM sophos_process_Journal WHERE sophos_process_journal.SophosPID = '$$SophosPID$$' AND CAST(endtime AS INT) > 0) > 0
        THEN (SELECT endtime FROM sophos_process_Journal WHERE sophos_process_journal.SophosPID = '$$SophosPID$$' AND CAST(endtime AS INT) > 0)
        ELSE strftime('%s','now','+10 minutes') END
    FROM sophos_process_Journal WHERE sophos_process_journal.SophosPID = '$$SophosPID$$' AND CAST(endtime AS INT) = 0

   UNION ALL

   -- Recursvly identify all decendents
   SELECT spj.SophosPID, Level - 1, spj.ParentSophosPID, spj.processname, spj.pathname, spj.cmdline, spj.sha256, spj.sid, spj.time,
      CASE WHEN (SELECT spj2.endtime FROM sophos_process_Journal spj2 WHERE spj2.SophosPID = spj.SophosPID AND CAST(endtime AS INT) > 0) > 0
        THEN (SELECT spj2.endtime FROM sophos_process_Journal spj2 WHERE spj2.SophosPID = spj.SophosPID AND CAST(endtime AS INT) > 0)
        ELSE strftime('%s','now','+10 minutes') END
   FROM Ancestors JOIN Sophos_Process_Journal spj ON spj.SophosPID = Ancestors.parent AND CAST(spj.endtime AS INT) = 0
   -- Perform a Depth First Search ASC would perform a Breadth First Search
   ORDER BY 2 DESC
   ),
-- Add Row Numbers to the Ancestor List so we order the tree corretly
-- EXCLUDE the line for the specified SophosPID so that when we show the tree we do not have a duplicate row
Orderd_Ancestors AS (SELECT SophosPID, Level, parent, processname, pathname, cmdline, sha256, sid, start, end, -1 * ROW_Number() OVER () Row FROM Ancestors WHERE SophosPID NOT IN ('$$SophosPID$$') ),

-- GET A LIST OF ALL DECENDENTS OF A SOPHOS PID
-- NOTE THE PROCESS OR CHILDREN MAY STILL BE RUNNING SO HANDLE ENDTIME CORRECTLY by changing endtime for running processes to now + 10 min
Children(SophosPID, Level, parent, processname, pathname, cmdline, sha256, sid, start, end) AS (
   -- Define the SEED Row as the information on the SophosPID provided
   SELECT sophosPID, 0, ParentSophosPID, processname, pathname, cmdline, sha256, sid, time,
     CASE WHEN (SELECT endtime FROM sophos_process_Journal WHERE sophos_process_journal.SophosPID = '$$SophosPID$$' AND CAST(endtime AS INT) > 0) > 0
        THEN (SELECT endtime FROM sophos_process_Journal WHERE sophos_process_journal.SophosPID = '$$SophosPID$$' AND CAST(endtime AS INT) > 0)
        ELSE strftime('%s','now','+10 minutes') END
    FROM sophos_process_Journal WHERE sophos_process_journal.SophosPID = '$$SophosPID$$' AND CAST(endtime AS INT) = 0

   UNION ALL

   -- Recursvly identify all decendents
   SELECT spj.SophosPID, Level +1, spj.ParentSophosPID, spj.processname, spj.pathname, spj.cmdline, spj.sha256, spj.sid, spj.time,
      CASE WHEN (SELECT spj2.endtime FROM sophos_process_Journal spj2 WHERE spj2.SophosPID = spj.SophosPID AND CAST(endtime AS INT) > 0) > 0
        THEN (SELECT spj2.endtime FROM sophos_process_Journal spj2 WHERE spj2.SophosPID = spj.SophosPID AND CAST(endtime AS INT) > 0)
        ELSE strftime('%s','now','+10 minutes') END
   FROM Children JOIN Sophos_Process_Journal spj ON spj.ParentSophosPID = Children.SophosPID AND CAST(spj.endtime AS INT) = 0 AND spj.time > Children.start -5 and spj.time < Children.end +3600
   -- Perform a Depth First Search ASC would perform a Breadth First Search
   ORDER BY 2 DESC
   ),

   -- Add Row Numbers to the Decendent List so we order the tree corretly
   Orderd_Descendants AS (SELECT SophosPID, Level, parent, processname, pathname, cmdline, sha256, sid, start, end, ROW_Number() OVER () Row FROM Children),

   -- Now collect the activity for all descendents and the selected sophosPID using a UNION to list the decendent then the file activity it had
   File_Activity AS (

     -- FOR ANCESTORS WE WILL ONLY SHOW THE PROCESS TREE INFO (No activity will be collected)
     SELECT
      REPLACE(DATETIME(A.start,'unixepoch'), ' ','T') Date_Time,
      CASE A.SophosPID
		   WHEN '$$SophosPID$$' THEN A.ProcessName
		   ELSE substr('< < < < < < < < < < < < < < < < < < < < ', 1, A.Level * -2)  || A.processName
	   END Process_Tree,
	   '-----------' Subject,
      '-----------' Action,
      '-----------' Object,
      CAST(A.cmdline AS TEXT) Cmd_Line,
      A.SophosPID SophosPID,
      A.pathname Process_Pathname,
      A.sha256 Process_SHA256,
      A.SID Process_SID,
      A.Level Level,
      A.Row Row,
      0 Sub_Row,
      a.start time
   FROM Orderd_Ancestors A

   UNION ALL

   -- SHOW THE PROCESS TREE INFO FOR DESCENDENTS
   SELECT
      REPLACE(DATETIME(D.start,'unixepoch'), ' ','T') Date_Time,
      CASE D.SophosPID
		   WHEN '$$SophosPID$$' THEN D.ProcessName
		   ELSE substr('> > > > > > > > > > > > > > > > > > > > > > ', 1, D.Level * 2) || D.processName
	   END Process_Tree,
	   '-----------' Subject,
      '-----------' Action,
      '-----------' Object,
      CAST(D.cmdline AS TEXT) Cmd_Line,
      D.SophosPID SophosPID,
      D.pathname Process_Pathname,
      D.sha256 Process_SHA256,
      D.SID Process_SID,
      D.Level Level,
      D.Row Row,
      0 Sub_Row,
      D.start time
   FROM Orderd_Descendants D

   UNION ALL

   -- ADD THE PROCESS ACTIVITY FOR EACH DESCENDENT
   SELECT
      REPLACE(DATETIME(MIN(spa.time),'unixepoch'),' ','T') Date_Time,
      CASE D.SophosPID
		   WHEN '$$SophosPID$$' THEN '( '||D.processname||' ) ACTIVITY'
		   ELSE substr('~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~', 1, D.Level * 2) || '( '||D.processname||' ) ACTIVITY'
	   END Process_Tree,
      spa.subject Subject,
      CAST(GROUP_CONCAT(DISTINCT spa.action)||' ('||COUNT(spa.action)||')' AS TEXT) Action,
      spa.object,
      CAST(D.cmdline AS TEXT) Cmd_Line,
      D.SophosPID SophosPID,
      D.pathname Process_Pathname,
      D.sha256 Process_SHA256,
      D.SID Process_SID,
      '' Level,
      D.Row Row,
      1 Sub_Row,
      spa.time time
   -- NOTE The details for each process does not include 'FileDataReads', 'FileOtherReads', 'FileBinaryReads', 'Image', 'Thread'
   FROM Orderd_Descendants D LEFT JOIN Sophos_Process_Activity spa ON spa.subject IN ('FileDataReads', 'FileOtherReads', 'FileBinaryReads', 'Image', 'Thread','DirectoryChanges','Dns','FileBinaryChanges','FileDataChanges','FileOtherChanges','Http','Ip','Network','Url','Registry','Process')
      AND spa.SophosPID = D.SophosPID
      AND spa.time > D.start-1
      AND spa.time < D.end+1
   WHERE spa.subject > ''
   GROUP BY spa.subject, spa.action, spa.object, spa.SophosPID, D.processname, D.SophosPID, D.pathname, D.sha256, D.SID
   )

-- Now that we have all activity for each descendent, we need to provide the pretty list showing the Process Tree and File activity for each process in the tree
SELECT Date_Time, Process_Tree, Subject, Action, Object, Cmd_Line, SophosPID, Process_Pathname, Process_SHA256, Process_SID, row, sub_row, time,ROW_NUMBER() OVER( ORDER BY Row, Sub_Row, Time) SORT_ORDER_FOR_EXCEL
FROM File_Activity
ORDER By SORT_ORDER_FOR_EXCEL
