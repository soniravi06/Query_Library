SELECT
   CAST (Line as Text)
FROM
   grep
WHERE
   pattern in ("url")
AND path = '$$FilePath$$'||'$$Date$$.log'

-------------------------------------------------------------------------------------------

WITH syslog_file AS (SELECT REPLACE(line,CHAR(9),',') AS line FROM grep WHERE pattern IN ("url") AND path = 'C:\ProgramData\Sophos\Web Intelligence\Logs\2021-04-26.log'),
syslog_table AS (SELECT
   SPLIT(line, ',', 0) col_0, SPLIT(line, ',', 1) col_1, SPLIT(line, ',', 2) col_2, SPLIT(line, ',', 3) col_3, SPLIT(line, ',', 4) col_4, SPLIT(line, ',', 5) col_5, SPLIT(line, ',', 6) col_6
FROM syslog_File
)
SELECT * FROM Syslog_Table WHERE col_3 LIKE UPPER('%$$Log Type$$%')


-------------------------------------------------------------------------------------------

WITH syslog_file AS (SELECT line FROM grep WHERE pattern = ' ' AND path = 'C:\Users\kacke\Desktop\Current Desktop\pan.log'),
syslog_table AS (SELECT
   SPLIT(line, ',', 0) col_0, SPLIT(line, ',', 1) col_1, SPLIT(line, ',', 2) col_2, SPLIT(line, ',', 3) col_3, SPLIT(line, ',', 4) col_4, SPLIT(line, ',', 5) col_5, SPLIT(line, ',', 6) col_6,
   SPLIT(line, ',', 7) col_7, SPLIT(line, ',', 8) col_8, SPLIT(line, ',', 9) col_9, SPLIT(line, ',', 10) col_10, SPLIT(line, ',', 11) col_11, SPLIT(line, ',', 12) col_12,
   SPLIT(line, ',', 13) col_13, SPLIT(line, ',', 14) col_14, SPLIT(line, ',', 15) col_15, SPLIT(line, ',', 16) col_16, SPLIT(line, ',', 17) col_17, SPLIT(line, ',', 18) col_18,
   SPLIT(line, ',', 19) col_19, SPLIT(line, ',', 21) col_20, SPLIT(line, ',', 22) col_21, SPLIT(line, ',', 23) col_22, SPLIT(line, ',', 24) col_24, SPLIT(line, ',', 25) col_25,
   SPLIT(line, ',', 26) col_26, SPLIT(line, ',', 27) col_27,SPLIT(line, ',', 28) col_28, SPLIT(line, ',', 29) col_29, SPLIT(line, ',', 30) col_30, SPLIT(line, ',', 31) col_31,
   SPLIT(line, ',', 32) col_32, SPLIT(line, ',', 33) col_33,SPLIT(line, ',', 34) col_34, SPLIT(line, ',', 35) col_35, SPLIT(line, ',', 36) col_36, SPLIT(line, ',', 37) col_37,
   SPLIT(line, ',', 38) col_38, SPLIT(line, ',', 39) col_39,SPLIT(line, ',', 40) col_40, SPLIT(line, ',', 41) col_41
FROM syslog_File
)
SELECT * FROM Syslog_Table WHERE col_3 LIKE UPPER('%$$Log Type$$%')



CASE CAST (SUM(snj.dataSent) / 1024 AS INT)
      WHEN 0 THEN 'â”‚'
      ELSE printf('%.' || CAST ( SUM(snj.dataSent)/1024 AS TEXT) ||'c', 'â–ˆ')
   END dataSentSize,
   CASE CAST ( SUM(snj.dataRecv)/1024 AS INT)
      WHEN 0 THEN 'â”‚'
      ELSE printf('%.' || CAST ( SUM(snj.dataRecv)/1024 AS TEXT) ||'c', 'â–ˆ')




WITH syslog_file AS (SELECT line FROM grep WHERE pattern IN ("url") AND path = 'C:\ProgramData\Sophos\Web Intelligence\Logs\2021-04-26.log')

SELECT
   substr(line,0,instr(line,'Z')+1),
   substr(line,instr(line,'Z')+1,(instr(line,'block')))
FROM syslog_file


REPLACE((SELECT line FROM grep WHERE pattern IN ("url") AND path = 'C:\ProgramData\Sophos\Web Intelligence\Logs\2021-04-26.log'),'',',')






WITH syslog_file AS (SELECT REPLACE(line,CHAR(9),',') AS line FROM grep WHERE pattern IN ("url") AND path = 'C:\ProgramData\Sophos\Web Intelligence\Logs\2021-04-26.log'),
syslog_table AS (SELECT
   SPLIT(line, ',', 0) col_0, SPLIT(line, ',', 1) col_1, SPLIT(line, ',', 2) col_2, SPLIT(line, ',', 3) col_3, SPLIT(line, ',', 4) col_4,
   SPLIT(line, ',', 5) col_5, SPLIT(line, ',', 6) col_6, SPLIT(line, ',', 7) col_7
FROM syslog_File
)
SELECT * FROM Syslog_Table







------------------Retouched one-----------------
WITH syslog_file AS (SELECT REPLACE(line,CHAR(9),',') AS line FROM grep WHERE pattern IN ("url") AND path = 'C:\ProgramData\Sophos\Web Intelligence\Logs\2021-04-26.log'),
syslog_table AS (SELECT
   SPLIT(line, ',', 0) Time, LTRIM(SPLIT(line, ',', 1),'action=') Action, LTRIM(SPLIT(line, ',', 2),'why=') Why, /*LTRIM(SPLIT(line, ',', 3),'policy-reason') PolicyReason,*/ LTRIM(SPLIT(line, ',', 4),'threat=') Threat,
   LTRIM(SPLIT(line, ',', 5),'fileclass=') FileClass, LTRIM(SPLIT(line, ',', 6),'category=') Category, LTRIM((REPLACE(SPLIT(line, ',', 7),'hxxp','http')),'url=') URL
FROM syslog_File
)
SELECT * FROM Syslog_Table



------------------------------------------------------------
--VARIABLE: $$YYYY-MM-DD$$  STRING
WITH log_file AS (SELECT REPLACE(line,CHAR(9),',') AS line FROM grep WHERE pattern IN ("url") AND path = 'C:\ProgramData\Sophos\Web Intelligence\Logs\$$YYYY-MM-DD$$.log'),
log_table AS (SELECT
   SPLIT(line, ',', 0) Time, LTRIM(SPLIT(line, ',', 1),('action'||'=')) Action, LTRIM(SPLIT(line, ',', 2),'why=') Why,LTRIM(SPLIT(line, ',', 4),'threat=') Threat,
   LTRIM(SPLIT(line, ',', 5),'fileclass=') FileClass,
   CASE
    CAST (LTRIM(SPLIT(line, ',', 6),'category=') AS INT)
     WHEN 0 THEN 'Uncategorized'
     WHEN 1 THEN 'Adult/Sexually Explicit'
     WHEN 2 THEN 'Advertisements & Pop-Ups'
     WHEN 3 THEN 'Alcohol & Tobacco'
     WHEN 4 THEN 'Arts'
     WHEN 5 THEN 'Blogs & Forums'
     WHEN 6 THEN 'Business'
     WHEN 7 THEN 'Chat'
     WHEN 8 THEN 'Computing & Internet'
     WHEN 9 THEN 'Criminal Activity'
     WHEN 10 THEN 'Downloads'
     WHEN 11 THEN 'Education'
     WHEN 12 THEN 'Entertainment'
     WHEN 13 THEN 'Fashion & Beauty'
     WHEN 14 THEN 'Finance & Investment'
     WHEN 15 THEN 'Food & Dining'
     WHEN 16 THEN 'Gambling'
     WHEN 17 THEN 'Games'
     WHEN 18 THEN 'Government'
     WHEN 19 THEN 'Hacking'
     WHEN 20 THEN 'Health & Medicine'
     WHEN 21 THEN 'Hobbies & Recreation'
     WHEN 22 THEN 'Hosting Sites'
     WHEN 23 THEN 'Illegal Drugs'
     WHEN 24 THEN 'Infrastructure'
     WHEN 25 THEN 'Intimate Apparel & Swimwear'
     WHEN 26 THEN 'Intolerance & Hate'
     WHEN 27 THEN 'Job Search & Career Development'
     WHEN 28 THEN 'Kids Sites'
     WHEN 29 THEN 'Motor Vehicles'
     WHEN 30 THEN 'News'
     WHEN 31 THEN 'Peer-to-Peer'
     WHEN 32 THEN 'Personals and Dating'
     WHEN 33 THEN 'Philantropic & Professional Orgs.'
     WHEN 34 THEN 'Phishing & Fraud'
     WHEN 35 THEN 'Photo Searches'
     WHEN 36 THEN 'Polotics'
     WHEN 37 THEN 'Proxies & Translators'
     WHEN 38 THEN 'Real Estate'
     WHEN 39 THEN 'Reference'
     WHEN 40 THEN 'Religion'
     WHEN 41 THEN 'Ringtones/Mobile Phone Downloads'
     WHEN 42 THEN 'Search Engines'
     WHEN 43 THEN 'Sex Education'
     WHEN 44 THEN 'Shopping'
     WHEN 45 THEN 'Society & Culture'
     WHEN 46 THEN 'Spam URLs'
     WHEN 47 THEN 'Sports'
     WHEN 48 THEN 'Spyware'
     WHEN 49 THEN 'Streaming Media'
     WHEN 50 THEN 'Tasteless & Offensive'
     WHEN 51 THEN 'Travel'
     WHEN 52 THEN 'Violence'
     WHEN 53 THEN 'Weapons'
     WHEN 54 THEN 'Web-based E-mail'
     WHEN 55 THEN 'Custom'
     WHEN 56 THEN 'Anonymizing Proxies'
    ELSE 'Others'
   END Category,
   LTRIM((REPLACE(SPLIT(line, ',', 7),'hxxp','http')),'url=') URL
FROM log_File
)
SELECT * FROM log_Table
--GROUP BY Category,URL
