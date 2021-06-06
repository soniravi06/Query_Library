-- LOAD CSV from GIT LOCATION
-- VARIABLE $$File Path$$  STRING
-- VARIABLE $$URL$$        URL
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
        LIMIT 5
    )

-- DUMP THE TWO TABLES
SELECT 'REMOTE CSV FILE' COL0, 'Loaded FROM' COL1, '$$URL$$' COL2, '---' COL3, '---' COL4, '---' COL5
UNION ALL
SELECT * FROM Remote_Loaded_Table
UNION ALL
SELECT 'LOCAL CSV FILE' COL0, 'Loaded FROM' COL1, '$$File Path$$' COL2, '---' COL3, '---' COL4, '---' COL5
UNION ALL
SELECT * FROM Local_Loaded_Table
