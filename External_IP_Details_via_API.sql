-- RDP activity with External IP GeoIP-Details
-- VARIABLE   shodan_access_key   STRING
-- Note: Require shodan API access key (jDKK9VyBSo58ENagTAACDrpNBysxeGpD)

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime,
    eventid AS EventID,
    CASE WHEN eventid = 1149 THEN eventid || ' - User authentication succeeded' END AS Description,
    JSON_EXTRACT(data, '$.UserData.Param1') AS Username,
    JSON_EXTRACT(data, '$.UserData.Param2') AS Domain,
    JSON_EXTRACT(data, '$.UserData.Param3') AS Source_IP,
    CASE
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') LIKE '192.168.%' THEN 'Internal_IP'
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') GLOB '172.1[6-9].*' THEN 'Internal_IP'
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') GLOB '172.2[0-9].*' THEN 'Internal_IP'
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') GLOB '172.3[0-1].*' THEN 'Internal_IP'
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') LIKE '10.%' THEN 'Internal_IP'
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') LIKE '127.%' THEN 'Internal_IP'
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') LIKE '%::%' THEN 'unknown'
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') LIKE '' THEN 'unknown'
    ELSE 'External_IP' END AS External,
    (SELECT
      'Hostnames: '   ||json_extract(curl.result,'$.hostnames')         ||CHAR(10)||
      'Domains: '     ||json_extract(curl.result,'$.domains')           ||CHAR(10)||
      'Country: '     ||json_extract(curl.result,'$.country_name')      ||CHAR(10)||
      'City: '        ||json_extract(curl.result,'$.city')              ||CHAR(10)||
      'Organization: '||json_extract(curl.result,'$.org')               ||CHAR(10)||
      'ISP: '         ||json_extract(curl.result,'$.isp')               ||CHAR(10)||
      'Ports: '       ||json_extract(curl.result,'$.ports')
    FROM
      curl
    WHERE
      url = 'https://api.shodan.io/shodan/host/'||JSON_EXTRACT(data, '$.UserData.Param3')||'?key=$$shodan_access_key$$') AS External_IP_Details,
    'TS Remote Connection EVTX' AS Data_Source,
    'Logins.01.4' AS Query
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
AND eventid = 1149
