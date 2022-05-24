WITH suspicious_pipes(pipe_name,pattern) AS (

    VALUES

    ('lsadump', 'credential_dump_tools'),

    ('cachedump', 'credential_dump_tools'),

    ('wceservicepipe', 'credential_dump_tools'),

    ('PSHost', 'Powershell_Execution'),

    ('psexec', 'PsExec_pipes'),

    ('paexec', 'PsExec_pipes'),

    ('remcom','PsExec_pipes'),

    ('csexec', 'PsExec_pipes'),

    ('mojo.5688.8052.183894939787088877', 'CobaltStrike_pattern'),

    ('mojo.5688.8052.35780273329370473', 'CobaltStrike_pattern'),

    ('mypipe-f', 'CobaltStrike_pattern'),

    ('mypipe-h', 'CobaltStrike_pattern'),

    ('ntsvcs_', 'CobaltStrike_pattern'),

    ('scerpc_', 'CobaltStrike_pattern'),

    ('status_', 'CobaltStrike_pattern'),

    ('MSSE-','CobaltStrike_pattern'),

    ('msagent_', 'CobaltStrike_pattern'),

    ('postex_', 'CobaltStrike_pattern'),

    ('spoolss_', 'CobaltStrike_pattern'),

    ('win_svc', 'CobaltStrike_pattern')

)



SELECT

    p.name As pipe_name,

    sp.pattern As pipe_pattern,

    p.pid,

    proc.name As process_name,

    proc.path As process_path,

    proc.cmdline As cmdline,

    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(proc.start_time,'unixepoch')) As process_start_time,

    proc.parent As process_parent_pid,

    CAST ( (Select proc2.path from processes proc2 where proc2.pid = proc.parent) AS text) parent_path,

    CAST ( (Select proc2.name from processes proc2 where proc2.pid = proc.parent) AS text) parent_process,

    p.instances As pipe_instances,

    p.max_instances As pipe_max_instances,

    p.flags As pipe_flags,

    'Pipes/Processes' AS Data_Source,

    'Suspicious Pipes.01.0' AS Query

FROM pipes p

JOIN suspicious_pipes sp ON p.name LIKE sp.pipe_name||'%'

LEFT JOIN processes proc ON proc.pid = p.pid

-------------------------------------
--VARIABLE  $$URL$$  STRING
--URL = https://gist.githubusercontent.com/svch0stz/c3288929c0e83eacdd558190b047df6e/raw/3cf50a09f9e2af7de7fe90d9aa73df76ca2a5fd1/Cobalt%2520Strike%2520Named%2520Pipe%2520Regex.csv

WITH
    Remote_CSV_file(Line, str) AS (
        SELECT '', (SELECT result from curl where url = '$$URL$$') ||char(10)
        UNION ALL
        SELECT substr(str, 0, instr(str, char(10) )), substr(str, instr(str, char(10) )+1) FROM Remote_CSV_file WHERE str!=''
    ),
    -- Create Table for Remote_CSV_file
    Remote_Loaded_Table (pipe_name, pattern) AS (
        SELECT SPLIT(Line,',',0) pipe_name, SPLIT(Line,',',1) pattern
        FROM Remote_CSV_file WHERE Line != ''

    )

    SELECT
    p.name As pipe_name,
    sp.pattern As pipe_pattern,
    p.pid,
    proc.name As process_name,
    proc.path As process_path,
    proc.cmdline As cmdline,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(proc.start_time,'unixepoch')) As process_start_time,
    proc.parent As process_parent_pid,
    CAST ( (Select proc2.path from processes proc2 where proc2.pid = proc.parent) AS text) parent_path,
    CAST ( (Select proc2.name from processes proc2 where proc2.pid = proc.parent) AS text) parent_process,
    p.instances As pipe_instances,
    p.max_instances As pipe_max_instances,
    p.flags As pipe_flags,
    'Pipes/Processes' AS Data_Source,
    'Suspicious Pipes.02.0' AS Query
FROM pipes p
JOIN Remote_Loaded_Table sp ON p.name LIKE regex_match(p.name,sp.pipe_name,0)||'%'
LEFT JOIN processes proc ON proc.pid = p.pid
