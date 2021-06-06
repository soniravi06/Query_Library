/*
To catch unauthorized software installation:
Query software installed in the past XX days that are not in a pre-defined allow list (e.g. from a text file)

To catch portable apps downloaded from Internet:
Query executables that were run in the past XX days, that can be traced back to a web download

To catch self-compile apps:
Query executables that were run in the past XX days, that have missing/dubious/untrusted/non-approved code signing info
*/

/* --------------------- ROUGH WORK -------------------------- */

Name
Version
Publisher = Vendor
Install_location = Install Source (Optional)
install_date = InstallDate (Optional)


/* ------------------------ Query Design -------------------------- */

-- Programs Not IN CSV TABLES

WITH
    Remote_CSV_file(Line, str) AS (
        SELECT '', (SELECT result from curl where url = '$$URL$$') ||char(10)
        UNION ALL
        SELECT substr(str, 0, instr(str, char(10) )), substr(str, instr(str, char(10) )+1) FROM Remote_CSV_file WHERE str!=''
    ),
    -- Create Table for Remote_CSV_file
    Remote_Loaded_Table (Col1, Col2, Col3, Col4, Col5, Col6) AS (
        SELECT SPLIT(Line,',',0) Col1, SPLIT(Line,',',1) Col2, SPLIT(Line,',',2) Col3, SPLIT(Line,',',3) Col4, SPLIT(Line,',',4) Col2, SPLIT(Line,',',5) Col6
        FROM Remote_CSV_file WHERE Line != ''
        LIMIT 5
    ),

    -- LOAD CSV from LOCAL SYSTEM
    Local_CSV_file AS (
        SELECT line FROM grep WHERE pattern = ',' AND path = '$$File Path$$'
    ),
    -- Create Table for Local_CSV_file
    Local_Loaded_Table AS (
        SELECT SPLIT(Line,',',0) Col1, SPLIT(Line,',',1) Col2, SPLIT(Line,',',2) Col3, SPLIT(Line,',',3) Col4, SPLIT(Line,',',4) Col2, SPLIT(Line,',',5) Col6
        FROM Local_CSV_file WHERE Line != ''
        --LIMIT 5
    )

SELECT
  *
FROM
  programs p, Local_Loaded_Table llt
WHERE name NOT LIKE llt.COL0 AND P.Version NOT LIKE llt.COL1

----------WORKING VERSION ------------------
WITH
    Remote_CSV_file(Line, str) AS (
        SELECT '', (SELECT result from curl where url = '$$URL$$') ||char(10)
        UNION ALL
        SELECT substr(str, 0, instr(str, char(10) )), substr(str, instr(str, char(10) )+1) FROM Remote_CSV_file WHERE str!=''
    ),
    -- Create Table for Remote_CSV_file
    Remote_Loaded_Table (Col1, Col2, Col3, Col4, Col5, Col6) AS (
        SELECT SPLIT(Line,',',0) Col1, SPLIT(Line,',',1) Col2, SPLIT(Line,',',2) Col3, SPLIT(Line,',',3) Col4, SPLIT(Line,',',4) Col2, SPLIT(Line,',',5) Col6
        FROM Remote_CSV_file WHERE Line != ''
        --LIMIT 5
    ),

    -- LOAD CSV from LOCAL SYSTEM
    Local_CSV_file AS (
        SELECT line FROM grep WHERE pattern = ',' AND path = '$$File Path$$'
    ),
    -- Create Table for Local_CSV_file
    Local_Loaded_Table AS (
        SELECT SPLIT(Line,',',0) Col1, SPLIT(Line,',',1) Col2, SPLIT(Line,',',2) Col3, SPLIT(Line,',',3) Col4, SPLIT(Line,',',4) Col2, SPLIT(Line,',',5) Col6
        FROM Local_CSV_file WHERE Line != ''
        --LIMIT 5
    )

   --SELECT Col1 FROM Local_Loaded_Table;
   --SELECT * FROM Remote_Loaded_Table

SELECT DISTINCT
   p.name,
   p.version,
   p.install_location,
   p.install_source,
   p.language,
   p.publisher,
   p.uninstall_string,
   p.install_date,
   p.identifying_number
FROM
  programs p
--WHERE p.name NOT IN (SELECT COL1 FROM Local_Loaded_table)  AND p.Version NOT IN (SELECT COL2 FROM Local_Loaded_Table)
WHERE p.name NOT IN (SELECT COL1 FROM Remote_Loaded_table)  AND p.Version NOT IN (SELECT COL2 FROM Remote_Loaded_Table)




------------------------------ Final UnAuth App List Query ----------------------------------

WITH
    Remote_CSV_file(Line, str) AS (
        SELECT '', (SELECT result from curl where url = '$$URL$$') ||char(10)
        UNION ALL
        SELECT substr(str, 0, instr(str, char(10) )), substr(str, instr(str, char(10) )+1) FROM Remote_CSV_file WHERE str!=''
    ),
    -- Create Table for Remote_CSV_file
    Remote_Loaded_Table (Col1, Col2, Col3, Col4, Col5, Col6) AS (
        SELECT SPLIT(Line,',',0) Col1, SPLIT(Line,',',1) Col2, SPLIT(Line,',',2) Col3, SPLIT(Line,',',3) Col4, SPLIT(Line,',',4) Col2, SPLIT(Line,',',5) Col6
        FROM Remote_CSV_file WHERE Line != ''
    )
SELECT DISTINCT
   name,
   version,
   install_location,
   install_source,
   language,
   publisher,
   uninstall_string,
   install_date,
   identifying_number
FROM
  programs
WHERE name NOT IN (SELECT Col1 FROM Remote_Loaded_table)  AND Version NOT IN (SELECT Col2 FROM Remote_Loaded_Table)


-------------------------------Untrusted sigin code signature----------------------------------
SELECT
  process.pid,
  process.path,
  authenticode.result
FROM
  processes as process LEFT JOIN authenticode ON process.path = authenticode.path
WHERE result IN ('missing','invalid','untrusted');



SELECT
    --strftime('%Y-%m-%dT%H:%M:%SZ', datetime(spj.time,'unixepoch')) processExecutionTime,
    datetime(spj.time,'unixepoch','localtime') processExecutionTime,
    spj.processName,
    spj.pathName processPath,
    spj.sophosPID,
    spj.cmdLine,
    spj.sha256,
    sfp.globalRep,
    sfp.localRep,
    sfp.mlScore,
    ac.result
FROM sophos_process_journal spj
LEFT JOIN sophos_file_properties sfp
    ON sfp.sha256 = (CASE
        WHEN spj.sha256 IS NULL OR spj.sha256 = ''
            THEN '0000000000000000000000000000000000000000000000000000000000000000'
        ELSE
            spj.sha256
        END
    )
LEFT JOIN authenticode ac
    ON spj.pathname = ac.path
WHERE ac.result IN ('missing','invalid','untrusted')
AND spj.time >= CAST(STRFTIME('%s','NOW','-3 HOURS') AS INT)


--------------------------------------------------------------------------------


SELECT 
    datetime(spj.time,'unixepoch','localtime') processExecutionTime,
    spj.processName,
    spj.pathName processPath,
    spj.sophosPID,
    spj.cmdLine,
    spj.sha256,
    ac.result
FROM sophos_process_journal spj
LEFT JOIN authenticode ac
    ON spj.pathname = ac.path
WHERE ac.result IN ('missing','invalid','untrusted')
AND spj.time >= STRFTIME('%H','NOW','2 HOURS')
