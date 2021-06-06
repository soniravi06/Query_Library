SELECT
	json_extract(curl.result,'$.continent_name')continent,
	json_extract(curl.result,'$.country_name')country,
	json_extract(curl.result,'$.region_name')region,
	json_extract(curl.result,'$.city')city,
	json_extract(curl.result,'$.ip')IP_Address,
	json_extract(curl.result,'$.type')IP_Type
FROM
	curl
WHERE url = 'http:' || '/' || '/' || 'api.ipstack.com/' ||
	(SELECT result FROM curl WHERE url = 'http:'||'/'||'/'||'ipv4bot.whatismyipaddress.com')||
	'?access_key=adef373589e4c12ac2553a53319896ae';

-------------------------***************-----------------------------


SELECT datetime(sophos_dns_journal.time, 'unixepoch', 'localtime'),
sophos_dns_journal.sophosPID,
sophos_process_journal.cmdline,
sophos_dns_journal.name
FROM sophos_dns_journal
JOIN sophos_process_journal
WHERE sophos_dns_journal.name LIKE '%sophos.com'
AND sophos_process_journal.sophosPID = sophos_dns_journal.sophosPID

-------------------------***************-----------------------------

SELECT
		datetime(time, 'unixepoch', 'localtime'),
		name
FROM
		sophos_dns_journal
WHERE
	name like '%sophos%'
	AND
	time > strftime('%s','Now','-2 hours');



---------------------------------------------------------------------
SELECT
   strftime('%Y-%m-%dT%H:%M:%SZ', datetime(snj.time,'unixepoch')) dateTime,
   snj.source,
   snj.sourcePort,
   snj.destination,
   snj.destinationPort
FROM sophos_network_journal snj
WHERE
	 snj.sourcePort = '53'
	 limit 5
