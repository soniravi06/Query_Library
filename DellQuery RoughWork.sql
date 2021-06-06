Dell’s documentation is split into two lists of devices that need updating:

Table A: Supported Dell platforms. There are 381 model names here, including Dell brands such as Inspiron, Latitude, OptiPlex, Precision, Vostro. XPS and even some Dell Dock devices.
Table B: End of Service Life Dell platforms. A further 195 model names are listed, including seven Alienware computers.



Dell has included instructions for manually removing the buggy kernel driver, which it says will be found in one of two places:

    C:\Users\%USERNAME%\AppData\Local\Temp\dbutil_2_3.sys
    C:\Windows\Temp\dbutil_2_3.sys
If you are nervous about removing system files by hand, the company has published a download page with an automatic driver remover with the remarkable name of Dell-Security-Advisory-Update-DSA-2021-088_7PR57_WIN_1.0.0_A00.EXE.


SELECT *
FROM sophos_file_journal
WHERE pathname LIKE 'C:\Users\%%\AppData\Local\Temp\dbutil_2_3.sys'
OR pathname LIKE 'C:\Windows\Temp\dbutil_2_3.sys'

SELECT
datetime(btime,'unixepoch') AS created_time,
filename,
directory,
size AS fileSize,
datetime(atime, 'unixepoch') AS access_time,
datetime(mtime, 'unixepoch') AS modified_time
FROM file
WHERE
path LIKE 'C:\Users\%\AppData\Local\Temp\dbutil_2_3.sys' OR path LIKE 'C:\Windows\Temp\dbutil_2_3.sys'


SELECT
    datetime(btime,'unixepoch') AS created_time,
    filename,
    directory,
    size AS fileSize,
    datetime(atime, 'unixepoch') AS access_time,
    datetime(mtime, 'unixepoch') AS modified_time
FROM
    file
WHERE
    path LIKE 'C:\Users\%\AppData\Local\Temp\dbutil_2_3.sys' OR
    path LIKE 'C:\Windows\Temp\dbutil_2_3.sys'

SELECT
    datetime(f.btime,'unixepoch') AS created_time,
    f.filename,
    f.directory,
    f.size AS fileSize,
    datetime(f.atime, 'unixepoch') AS access_time,
    datetime(f.mtime, 'unixepoch') AS modified_time,
    (SELECT h.sha256 FROM hash h WHERE h.path = f.path) sha256
FROM
    file f
WHERE
    f.path LIKE 'C:\Users\%\AppData\Local\Temp\dbutil_2_3.sys' OR
    f.path LIKE 'C:\Windows\Temp\dbutil_2_3.sys'

    -- Check if the dbutil_2_3.sys file is present or not
SELECT
   CASE WHEN (SELECT 1 FROM file WHERE path LIKE 'C:\Users\%\AppData\Local\Temp\dbutil_2_3.sys' OR path LIKE 'C:\Windows\Temp\dbutil_2_3.sys') = 1
      THEN 'SYSTEM IS VULNERABLE: dbutil_2.3.sys located in directory '|| (SELECT directory FROM file WHERE path LIKE 'C:\Users\%\AppData\Local\Temp\dbutil_2_3.sys' OR path LIKE 'C:\Windows\Temp\dbutil_2_3.sys')
      ELSE 'file-not-found dbutil_2_3.sys -- This device is not vulnerable'
   END Status
