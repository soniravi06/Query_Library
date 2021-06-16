/* EDR Query to check Temper Protection Status */

SELECT
   CASE
      WHEN data LIKE '0' THEN 'Disabled ❌'
      WHEN data LIKE '1' THEN 'Enabled ✅'
   END Tamper_Protection_Status
FROM
   registry
WHERE
   key='HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config'
AND name='SEDEnabled'
