-----Define variables in Central-------
-----startTime -> Date--------
-----endTime   -> Date--------
-----userName  -> String------


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
    AND IFNULL(json_extract(data, '$.targetUserName'), '') LIKE '$$userName$$'
    AND time >= $$startTime$$
    AND time <= $$endTime$$
