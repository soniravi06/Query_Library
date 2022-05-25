-- Device Card Query for Datalake
-- VARIABLE   device_name   STRING    NOTE: Specify full Device Name in variable.
-- NOTE: This is a Single Device Card Query, Running this query for all or multiple devices will return complete/appropriate result. DO NOT USE WILDCARD in VARIABLE

WITH latest_result AS (
    SELECT
        meta_hostname AS ep_name,
        MAX(ingestion_timestamp) AS max_time
    FROM xdr_data
    WHERE query_name = 'disk_encryption_windows'
    GROUP BY meta_hostname
),

encryption_details AS (

SELECT
    xdr_data.meta_hostname AS ep_name,
    xdr_data.drive_letter,
    xdr_data.protection_status,
    xdr_data.unix_time AS latest_result,
    xdr_data.encryption_method,
    xdr_data.drive_device_id,
    xdr_data.persistent_volume_id,
    xdr_data.conversion_status,
    xdr_data.version,
    xdr_data.percentage_encrypted,
    xdr_data.lock_status
FROM xdr_data
INNER JOIN latest_result ON
    xdr_data.meta_hostname = latest_result.ep_name
    AND xdr_data.ingestion_timestamp = latest_result.max_time
WHERE
    xdr_data.query_name = 'disk_encryption_windows'
    AND xdr_data.meta_hostname LIKE '$$device_name$$'
),

PENDING_UPDATES AS (

  SELECT
      meta_hostname AS ep_name,
      title,
      support_url,
      msrc_severity,
      installed,
      mandatory,
      size,
      hotfix_id
  FROM xdr_data
  WHERE query_name = 'pending_windows_updates_patch'
  AND meta_hostname LIKE '$$device_name$$'
  LIMIT 5
),

LISTENING_PORTS AS (

  SELECT
    meta_hostname AS ep_name,
    name,
    address,
    port,
    pid,
    path
FROM xdr_data
WHERE query_name = 'listening_ports'
AND port < 1000 OR port = 3389
AND meta_hostname LIKE '$$device_name$$'
LIMIT 5

),

INTERFACE_DETAILS AS (

  SELECT DISTINCT
    meta_hostname AS ep_name,
   -- meta_ip_address,
   -- query_name,
    address,
   -- broadcast,
   -- ibytes,
    interface,
    mac
    /*mask,
    mtu,
    obytes,
    meta_boot_time,
    meta_eid,
    meta_endpoint_type,
    meta_ip_mask,
    meta_mac_address,
    meta_os_name,
    meta_os_platform,
    meta_os_version,
    meta_public_ip,
    meta_query_pack_version,
    meta_username,
    calendar_time,
    counter,
    epoch,
    host_identifier,
    numerics,
    osquery_action,
    unix_time,
    customer_id,
    endpoint_id,
    upload_size*/
FROM xdr_data
WHERE query_name = 'network_interfaces'
AND meta_hostname LIKE '$$device_name$$'
AND mask LIKE '255.%.%.%' AND address <> '127.0.0.1'
LIMIT 5

),

LIST_OF_PUA AS (

  WITH full_list AS (
    SELECT
        linux_processes.meta_hostname AS ep_name,
        linux_processes.time AS date_time,
        NULL AS parent_process_name,
        linux_processes.name AS process_name,
        (
            SELECT DISTINCT linux_users.username
            FROM
                xdr_data AS linux_users
            WHERE
                query_name = 'user_accounts'
                AND linux_users.meta_hostname = linux_processes.meta_hostname
                AND linux_users.uid = linux_processes.uid
        ) AS user_name,
        linux_processes.cmdline AS cmd_line,
        linux_processes.pids || ':' || CAST(linux_processes.time AS VARCHAR) AS sophos_pid,
        NULL AS parent_sophos_pid,
        linux_processes.sha256 AS sha256,
        linux_processes.sha1 AS sha1,
        linux_processes.path AS path,
        NULL AS ml_score,
        NULL AS pua_score,
        NULL AS global_rep,
        NULL AS local_rep,
        linux_processes.gid AS gid,
        linux_processes.uid AS uid,
        linux_processes.euid AS euid,
        linux_processes.egid AS egid,
        NULL AS parent_path
    FROM
        xdr_data AS linux_processes
    WHERE
        linux_processes.query_name = 'running_processes_linux_events'
        AND LOWER(linux_processes.meta_hostname) LIKE LOWER('$$device_name$$')

    UNION ALL

    SELECT
        windows_processes.meta_hostname AS ep_name,
        windows_processes.time AS date_time,
        windows_processes.parent_name AS parent_process_name,
        windows_processes.name AS process_name,
        windows_processes.username AS user_name,
        windows_processes.cmdline AS cmd_line,
        windows_processes.sophos_pid AS sophos_pid,
        windows_processes.parent_sophos_pid AS parent_sophos_pid,
        windows_processes.sha256 AS sha256,
        NULL AS sha1,
        windows_processes.path AS path,
        windows_processes.ml_score AS ml_score,
        windows_processes.pua_score AS pua_score,
        windows_processes.global_rep AS global_rep,
        windows_processes.local_rep AS local_rep,
        NULL AS gid,
        NULL AS uid,
        NULL AS euid,
        NULL AS egid,
        windows_processes.parent_path AS parent_path
    FROM
        xdr_data AS windows_processes
    WHERE
        windows_processes.query_name = 'running_processes_windows_sophos'
        AND LOWER(windows_processes.meta_hostname) LIKE LOWER('$$device_name$$')
)

SELECT
    ep_name,
    COUNT(DISTINCT sophos_pid) AS instances,
    process_name,
    path,
    cmd_line,
    DATE_FORMAT(FROM_UNIXTIME(MIN(date_time)), '%Y-%m-%dT%H:%i:%SZ') AS first_seen,
    DATE_FORMAT(FROM_UNIXTIME(MAX(date_time)), '%Y-%m-%dT%H:%i:%SZ') AS last_seen,
    user_name,
    parent_process_name,
    parent_path,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT sophos_pid), CHR(10)) AS sophos_pid_list,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT parent_sophos_pid), CHR(10)) AS parent_sophos_pid_list,
    sha256,
    sha1,
    ml_score,
    pua_score,
    global_rep,
    local_rep,
    gid,
    uid,
    euid,
    egid
FROM
    full_list
WHERE ep_name LIKE '$$device_name$$'
GROUP BY
    ep_name,
    user_name,
    parent_process_name,
    process_name,
    cmd_line,
    sha256,
    sha1,
    path,
    ml_score,
    pua_score,
    global_rep,
    local_rep,
    gid,
    uid,
    euid,
    egid,
    parent_path
ORDER BY pua_score DESC
LIMIT 5

),

LIST_OF_MAL AS (

  WITH full_list AS (
    SELECT
        linux_processes.meta_hostname AS ep_name,
        linux_processes.time AS date_time,
        NULL AS parent_process_name,
        linux_processes.name AS process_name,
        (
            SELECT DISTINCT linux_users.username
            FROM
                xdr_data AS linux_users
            WHERE
                query_name = 'user_accounts'
                AND linux_users.meta_hostname = linux_processes.meta_hostname
                AND linux_users.uid = linux_processes.uid
        ) AS user_name,
        linux_processes.cmdline AS cmd_line,
        linux_processes.pids || ':' || CAST(linux_processes.time AS VARCHAR) AS sophos_pid,
        NULL AS parent_sophos_pid,
        linux_processes.sha256 AS sha256,
        linux_processes.sha1 AS sha1,
        linux_processes.path AS path,
        NULL AS ml_score,
        NULL AS pua_score,
        NULL AS global_rep,
        NULL AS local_rep,
        linux_processes.gid AS gid,
        linux_processes.uid AS uid,
        linux_processes.euid AS euid,
        linux_processes.egid AS egid,
        NULL AS parent_path
    FROM
        xdr_data AS linux_processes
    WHERE
        linux_processes.query_name = 'running_processes_linux_events'
        AND LOWER(linux_processes.meta_hostname) LIKE LOWER('$$device_name$$')

    UNION ALL

    SELECT
        windows_processes.meta_hostname AS ep_name,
        windows_processes.time AS date_time,
        windows_processes.parent_name AS parent_process_name,
        windows_processes.name AS process_name,
        windows_processes.username AS user_name,
        windows_processes.cmdline AS cmd_line,
        windows_processes.sophos_pid AS sophos_pid,
        windows_processes.parent_sophos_pid AS parent_sophos_pid,
        windows_processes.sha256 AS sha256,
        NULL AS sha1,
        windows_processes.path AS path,
        windows_processes.ml_score AS ml_score,
        windows_processes.pua_score AS pua_score,
        windows_processes.global_rep AS global_rep,
        windows_processes.local_rep AS local_rep,
        NULL AS gid,
        NULL AS uid,
        NULL AS euid,
        NULL AS egid,
        windows_processes.parent_path AS parent_path
    FROM
        xdr_data AS windows_processes
    WHERE
        windows_processes.query_name = 'running_processes_windows_sophos'
        AND LOWER(windows_processes.meta_hostname) LIKE LOWER('$$device_name$$')
)

SELECT
    ep_name,
    COUNT(DISTINCT sophos_pid) AS instances,
    process_name,
    path,
    cmd_line,
    DATE_FORMAT(FROM_UNIXTIME(MIN(date_time)), '%Y-%m-%dT%H:%i:%SZ') AS first_seen,
    DATE_FORMAT(FROM_UNIXTIME(MAX(date_time)), '%Y-%m-%dT%H:%i:%SZ') AS last_seen,
    user_name,
    parent_process_name,
    parent_path,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT sophos_pid), CHR(10)) AS sophos_pid_list,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT parent_sophos_pid), CHR(10)) AS parent_sophos_pid_list,
    sha256,
    sha1,
    ml_score,
    pua_score,
    global_rep,
    local_rep,
    gid,
    uid,
    euid,
    egid
FROM
    full_list
WHERE ep_name LIKE '$$device_name$$'
GROUP BY
    ep_name,
    user_name,
    parent_process_name,
    process_name,
    cmd_line,
    sha256,
    sha1,
    path,
    ml_score,
    pua_score,
    global_rep,
    local_rep,
    gid,
    uid,
    euid,
    egid,
    parent_path
ORDER BY ml_score DESC
LIMIT 5

),

LIST_OF_ADMINS AS (

  SELECT DISTINCT
      meta_hostname AS ep_name,
      uid,
      --gid,
      username,
      description,
      directory,
      shell,
      type,
      uuid
  FROM xdr_data
  WHERE query_name = 'user_accounts'
  AND uid = 500
  AND meta_hostname LIKE '$$device_name$$'

)

-- BLANK LINE BETWEEN EACH DEVICE
SELECT CAST(' ' AS VARCHAR) ATTRIBUTE, CAST(' ' AS VARCHAR) VALUE, CAST(' ' AS VARCHAR) CONTEXT, CAST(' ' AS VARCHAR) CONTEXT_DATA, CAST(' ' AS VARCHAR) NOTES

UNION ALL

SELECT CAST('=========================' AS VARCHAR) ATTRIBUTE, CAST('=========================' AS VARCHAR) VALUE, CAST('=========================' AS VARCHAR) CONTEXT, CAST('=========================' AS VARCHAR) CONTEXT_DATA, CAST('=========================' AS VARCHAR) NOTES

UNION ALL

SELECT CAST('DEVICE INFO' AS VARCHAR) ATTRIBUTE, CAST(' ' AS VARCHAR) VALUE, CAST(' ' AS VARCHAR) CONTEXT, CAST(' ' AS VARCHAR) CONTEXT_DATA, CAST(' ' AS VARCHAR) NOTES

UNION ALL

--LIST_OF_ADMINS
SELECT CAST('Device Name: '||ep_name AS VARCHAR) ATTRIBUTE, 'LIST_OF_ADMINS' VALUE, CAST('User Name: ' || username AS VARCHAR) CONTEXT, CAST('Type: '|| type AS VARCHAR) CONTEXT_DATA, CAST(' ' AS VARCHAR) NOTES FROM LIST_OF_ADMINS WHERE ep_name LIKE '$$device_name$$'

UNION ALL

--ENCRYPTION DETAILS
SELECT CAST('Device Name: '||ep_name AS VARCHAR) ATTRIBUTE, 'ENCRYPTION_DETAILS' VALUE, CAST('Drive Letter: ' || drive_letter AS VARCHAR) CONTEXT, CAST('Protection_Status: '|| protection_status AS VARCHAR) CONTEXT_DATA, CAST(' ' AS VARCHAR) NOTES FROM encryption_details WHERE ep_name LIKE '$$device_name$$'

UNION ALL

--PENDING WINDOWS UPDATES (LIMIT 5)
SELECT CAST('Device Name: '||ep_name AS VARCHAR) ATTRIBUTE, 'PENDING_WINDOWS_UPDATES' VALUE, CAST('Title: ' || title AS VARCHAR) CONTEXT, CAST('HOTFIX_ID: '|| hotfix_id AS VARCHAR) CONTEXT_DATA, CAST(' ' AS VARCHAR) NOTES FROM PENDING_UPDATES WHERE ep_name LIKE '$$device_name$$'

UNION ALL

--LISTENING_PORTS (LIMIT 5) (1-1000,3389)
SELECT CAST('Device Name: '||ep_name AS VARCHAR) ATTRIBUTE, 'LISTENING_PORTS' VALUE, CAST('Process Name: '|| name AS VARCHAR) CONTEXT, 'LISTENING_PORTS: '||CAST(port AS VARCHAR) CONTEXT_DATA, CAST(' ' AS VARCHAR) NOTES FROM LISTENING_PORTS WHERE ep_name LIKE '$$device_name$$'

UNION ALL

--INTERFACE_DETAILS (LIMIT 5) (IPv4 ONLY)
SELECT CAST('Device Name: '||ep_name AS VARCHAR) ATTRIBUTE, 'INTERFACE_DETAILS' VALUE, 'IP_ADDR: '|| address CONTEXT, 'INTERFACE_NAME: '||interface||chr(10)||'MAC_ADDR: '|| mac CONTEXT_DATA, CAST(' ' AS VARCHAR) NOTES FROM INTERFACE_DETAILS WHERE ep_name LIKE '$$device_name$$'

UNION ALL

--SUSPECT PUA (LIMIT 5)
SELECT CAST('Device Name: '||ep_name AS VARCHAR) ATTRIBUTE, 'SUSPECT_PUA' VALUE, 'PROCESS_NAME: '|| process_name ||chr(10)||'INSTANCES: '||CAST(instances AS VARCHAR) CONTEXT, 'PUA_SCORE: '||CAST(pua_score AS VARCHAR)||chr(10)||'LAST_SEEN: '|| last_seen CONTEXT_DATA, 'USER_NAME: '||user_name NOTES FROM LIST_OF_PUA WHERE ep_name LIKE '$$device_name$$' AND pua_score > 30

UNION ALL

--SUSPECT MAL (LIMIT 5)
SELECT CAST('Device Name: '||ep_name AS VARCHAR) ATTRIBUTE, 'SUSPECT_MAL' VALUE, 'PROCESS_NAME: '|| process_name ||chr(10)||'INSTANCES: '||CAST(instances AS VARCHAR) CONTEXT, 'ML_SCORE: '||CAST(ml_score AS VARCHAR)||chr(10)||'LAST_SEEN: '|| last_seen CONTEXT_DATA, 'USER_NAME: '||user_name NOTES FROM LIST_OF_MAL WHERE ep_name LIKE '$$device_name$$' AND ml_score > 30
