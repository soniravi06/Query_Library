WITH HOST_IOC AS (
   WITH IOC_LIST (IOC_Type, Indicator) AS ( 
      VALUES
             ('filepath','C:\inetpub\wwwroot\aspnet_client\%.aspx'),
             ('filepath','C:\inetpub\wwwroot\aspnet_client\system_web\%.aspx'),
             ('filepath','%PROGRAMFILES%\Microsoft\Exchange             Server\V15\FrontEnd\HttpProxy\owa\auth\%.aspx'),
             ('filepath','C:\Exchange\FrontEnd\HttpProxy\owa\auth\%.aspx'),
             ('hash','b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0'),
             ('hash','097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e'),
             ('hash','2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1'),
             ('hash','65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5'),
             ('hash','511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1'),
             ('hash','4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea'),
             ('hash','811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d'),
             ('hash','1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944')
   )

/* CHECK filepath */

SELECT DISTINCT
  datetime(time,'unixepoch') Date_time,
   CASE sfj.pathname NOT NULL
      WHEN 1 THEN 'FILE PRESENT' || '>>>> ' || sfj.pathname
      ELSE 'INDICATOR NOT PRESENT'
   END Result,
   IOC_type,
   Indicator
FROM IOC_LIST ioc
   JOIN sophos_file_journal sfj ON sfj.pathname LIKE ioc.indicator
WHERE ioc.ioc_type = 'filepath'

UNION ALL

/* CHECK hash */

SELECT DISTINCT
   datetime(time,'unixepoch') Date_time,
   CASE sfhj.sha256 NOT NULL
      WHEN 1 THEN 'HASH PRESENT' || '>>>> ' || sfhj.sha256
      ELSE 'INDICATOR NOT PRESENT'
   END Result,
   IOC_type,
   Indicator
FROM IOC_LIST ioc
   JOIN sophos_file_hash_journal sfhj ON sfhj.sha256 LIKE ioc.indicator
WHERE ioc.ioc_type = 'hash')
SELECT * FROM HOST_IOC
ORDER BY Result;
