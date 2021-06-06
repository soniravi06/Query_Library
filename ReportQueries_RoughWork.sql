Antivirus Report:-

Machine Name | IP | Last Comunication | OS | last Update | Antivirus Version | Sophos Components Version


hostname - system_info ---Machine Name

name - os_version ----OS

version - os_version ----OS version

IP (SELECT result FROM curl WHERE url = 'http:'||'/'||'/'||'ipv4bot.whatismyipaddress.com')

last update (SELECT installed_on FROM patches order by installed_on desc limit 1)
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus

Antivirus Version | Sophos Component version
(SELECT name, version FROM programs WHERE publisher ='Sophos Limited')





(SELECT name, version FROM programs WHERE publisher ='Sophos Limited') AS
'Sophos Components Version'


----------------------------------------------------------------------------


{"app":"SAV","counterName":"control","customMessageType":"applicationControl","familyId":"{35F5BF19-CB2E-459F-B6F1-F7A39C78433C}","id":"{6438BA47-D96E-4DDC-84E6-5D1E92682DD1}","location":"\\\\?\\C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","paths":["\\\\?\\C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"],"resourceId":"events.sav.appcontrol.blocked","sequence":"50057","severity":1,"showNotification":true,"threatName":"Google Chrome","threatType":2,"timeStamp":"2021-04-21T10:26:23Z","total":1,"updateSummary":true}





SELECT
   CAST(replace(datetime(sophos_events_summary.time,'unixepoch','localtime'),'','Time') AS TEXT) AS 'DateTime',
   type,
   --json_extract(raw, '$.path', '$.customMessageType' ,'$.threatName' ) AS Path
   REPLACE(ltrim(json_extract(raw, '$.paths'),'["\\\\?\\'),'\\','\') AS 'Path',
   json_extract(raw, '$.customMessageType') AS 'Custom Message',
   json_extract(raw, '$.threatName' ) AS 'Application Name'
FROM
sophos_events_summary JOIN sophos_file_properties
WHERE type = 'control'
AND sophos.pathname = 'REPLACE(ltrim(json_extract(raw, '$.paths'),'["\\\\?\\'),'\\','\')'

SELECT pathname, sha256, sha1 FROM sophos_file_properties WHERE pathname = 'C:\Program Files\Google\Chrome\Application\chrome.exe'



------------Threat RoughWork------------------

{"app":"SAV","counterName":"malware_protection","customMessageType":"malware","familyId":"{38EB0050-1C75-439F-B828-0013FAF18E25}","id":"{F33B780A-3575-4B3E-BAE2-864456D20630}","location":"C:\\Users\\Ravi Soni\\Downloads\\eicar.com","paths":["\\\\?\\C:\\Users\\Ravi Soni\\Downloads\\eicar.com"],"resourceId":"events.sav.threat.created","sequence":"50071","severity":2,"showNotification":true,"threatName":"EICAR-AV-Test","threatType":0,"timeStamp":"2021-04-27T01:54:44Z","total":1,"updateSummary":true}


{"app":"SAV","counterName":"web_security","familyId":"{D72B5959-CCD9-4544-BC07-8F237DFCDEC6}","id":"{B5395F14-C5FA-4B73-A769-CF51E798DD82}","path":"https://secure.eicar.org/eicar.com","reboot":0,"resourceId":"events.sav.threat.webscan.blocked","sequence":"50072","severity":1,"showNotification":true,"threatName":"EICAR-AV-Test","timeStamp":"2021-04-27T01:54:44Z","total":1,"updateSummary":true,"userName":"RS-Win10Pro\\Ravi Soni","userSid":"S-1-5-21-1776263005-1615604970-2322643533-500"}

resourceId
location
threatName



{"app":"SAV","counterName":"control","customMessageType":"deviceControl","familyId":"{AB0D5CEB-702A-4DED-BA45-B8BDBBD369AE}","id":"{8FF6B3A4-C6CF-43AD-A551-89D83BBD740F}","path":"USB\\VID_0CF3&PID_0036\\6&410639D&0&6","reboot":0,"resourceId":"events.sav.devicecontrol.blocked","sequence":"50008","severity":1,"showNotification":true,"timeStamp":"2021-05-13T16:59:40Z","updateSummary":true}




{"app":"SAV","counterName":"control","customMessageType":"deviceControl","familyId":"{EF1D2D24-7796-4EFC-A65C-AFCDBC01C34F}","id":"{DF718F54-11FE-4A7E-8674-7806447EA934}","path":"USBSTOR\\DISK&VEN_SANDISK&PROD_CRUZER_BLADE&REV_1.27\\4C530001320810113590&0","reboot":0,"resourceId":"events.sav.devicecontrol.blocked","sequence":"50009","severity":1,"showNotification":true,"timeStamp":"2021-05-13T17:04:50Z","total":1,"updateSummary":true}
