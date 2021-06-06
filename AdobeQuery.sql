SELECT
  CASE
    WHEN (SELECT 1 FROM os_version WHERE name LIKE '%MAC%') = 1 THEN (SELECT
   CASE WHEN (
(SELECT 1 FROM apps WHERE name LIKE '%Acrobat Reader DC%' AND bundle_version <= '21.001.20149') = 1 OR
(SELECT 1 FROM apps WHERE name LIKE '%Acrobat DC%' AND bundle_version <= '21.001.20149') = 1
)
THEN 'SYSTEM REQUIRES ATTENTION: Adobe Acrobat vulnerable to CVE-2021-28550'
      ELSE 'Adobe Acrobat already patched or not installed on this system'
   END Status)
   ELSE
   (SELECT
   CASE WHEN (
(SELECT 1 FROM programs WHERE name LIKE '%Acrobat Reader DC%' AND version <= '21.001.20150') = 1 OR
(SELECT 1 FROM programs WHERE name LIKE '%Acrobat DC%' AND version <= '21.001.20150') = 1 OR
(SELECT 1 FROM programs WHERE name LIKE '%Acrobat 2020%' AND version <= '2020.001.30020') = 1 OR
(SELECT 1 FROM programs WHERE name LIKE '%Acrobat Reader 2020%' AND version <= '2020.001.30020') = 1 OR
(SELECT 1 FROM programs WHERE name LIKE '%Acrobat 2017%' AND version <= '2017.011.30194') = 1 OR
(SELECT 1 FROM programs WHERE name LIKE '%Acrobat Reader 2017%' AND version <= '2017.011.30194') = 1
)
THEN 'SYSTEM REQUIRES ATTENTION: Adobe Acrobat vulnerable to CVE-2021-28550'
      ELSE 'Adobe Acrobat already patched or not installed on this system'
   END Status)
   END Status
