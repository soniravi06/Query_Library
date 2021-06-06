/*---Check for failed login events for a user-----*/
-- VARIABLE   $$starttime$$   DATE
-- VARIABLE   $$endtime$$     DATE

SELECT
  datetime(time,'unixepoch','localtime') AS 'Time',
  source,
  eventid,
  task_message,
  CASE json_extract(data,'$.EventData.FailureReason')
  WHEN '%%2307' THEN 'Account locked out'
  WHEN '%%2305'THEN 'The specified user account has expired'
  WHEN '%%2309' THEN 'The specified account password has expired'
  WHEN '%%2310' THEN 'Account currently disabled'
  WHEN '%%2311' THEN 'Account logon time restriction violation'
  WHEN '%%2312' THEN 'User not allowed to logon at this computer.'
  WHEN '%%2313' THEN 'Unknown user name or bad password'
  ELSE json_extract(data,'$.EventData.FailureReason')
  END 'FailureReason',
  json_extract(data,'$.EventData.LogonType') AS 'LogonType',
  json_extract(data,'$.EventData.Status')AS 'Status',
  json_extract(data,'$.EventData.SubStatus') AS 'Substatus',
  json_extract(data,'$.EventData.TargetUserName') AS 'User',
  json_extract(data,'$.EventData.IpAddress') AS 'IpAddress'
FROM
  sophos_windows_events
WHERE
  eventid='4625'  AND
  source = 'Security' AND
  time BETWEEN $$starttime$$ AND $$endtime$$
ORDER BY
  IpAddress DESC



/*---Check for Account lockout ----*/
-- VARIABLE   $$starttime$$   DATE
-- VARIABLE   $$endtime$$     DATE

SELECT
  datetime(time,'unixepoch','localtime') AS'Time',
  source,
  eventid,
  task_message,
  json_extract(data,'$.EventData.SubjectUserName') AS 'Made the change',
  json_extract(data,'$.EventData.TargetUserName') AS 'Locked Account',
FROM
  sophos_windows_events
WHERE
  eventid='4740'  AND
  source = 'Security' AND
  time BETWEEN $$starttime$$ AND $$endtime$$
