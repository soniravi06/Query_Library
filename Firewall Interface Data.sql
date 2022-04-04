-- Firewall Interface Usages (Datalake)
-- VARIABLE $$start_time$$  DATA
-- VARIABLE $$end_time$$    DATA

SELECT
   in_interface,
   out_interface,
   SUM(COALESCE(bytes_sent, 0))/1000000 AS Total_bytes_sent,
   SUM(COALESCE(bytes_received, 0))/1000000 AS Total_bytes_received,
   (SUM(COALESCE(bytes_sent, 0)) + SUM(COALESCE(bytes_received, 0)))/1000000 AS Total_Bytes
FROM
   xgfw_data
WHERE timestamp BETWEEN FROM_UNIXTIME($$start_time$$) AND FROM_UNIXTIME($$end_time$$)
GROUP BY
   in_interface,
   out_interface
ORDER BY
   Total_Bytes DESC
