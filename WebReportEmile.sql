--Date is a string to represent the date of the file 2021-04-26

WITH epp_file AS (SELECT line FROM grep WHERE pattern = 'url' AND path = 'C:\ProgramData\Sophos\Web Intelligence\Logs\$$Date$$.log'),
epp_table AS ( SELECT
  split(line,Char(9),0) as "time (utc)",
  regex_match(line,'.*action=(.*?)[\t]',1) as "action",
  regex_match(line,'.*why=(.*?)[\t]',1) as "why",
  regex_match(line,'.*policy-reason=(.*?)[\t]',1) as "policy-reason",
  regex_match(line,'.*threat=(.*?)[\t]',1) as "threat",
  regex_match(line,'.*risk=(.*?)[\t]',1) as "risk",
  regex_match(line,'.*fileclass=(.*?)[\t]',1) as "fileclass",
  regex_match(line,'.*category=(.*?)[\t]',1) as "category_id_decimal",
  case regex_match(line,'.*category=(.*?)[\t]',1)
    when "0" then "Uncategorized"
    when "1" then "Adult/Sexually Explicit"
    when "2" then "Advertisements & Pop-Ups"
    when "3" then "Alcohol & Tobacco"
    when "4" then "Arts"
    when "5" then "Blogs & Forums"
    when "6" then "Business"
    when "7" then "Chat"
    when "8" then "Computing & Internet"
    when "9" then "Criminal Activity"
    when "10" then "Downloads"
    when "11" then "Education"
    when "12" then "Entertainment"
    when "13" then "Fashion & Beauty"
    when "14" then "Finance & Investment"
    when "15" then "Food & Dining"
    when "16" then "Gambling"
    when "17" then "Games"
    when "18" then "Government"
    when "19" then "Hacking"
    when "20" then "Health & Medicine"
    when "21" then "Hobbies & Recreation"
    when "22" then "Hosting Sites"
    when "23" then "Illegal Drugs"
    when "24" then "Infrastructure"
    when "25" then "Intimate Apparel & Swimwear"
    when "26" then "Intolerance & Hate"
    when "27" then "Job Search & Career Development"
    when "28" then "Kids Sites"
    when "29" then "Motor Vehicles"
    when "30" then "News"
    when "31" then "Peer-to-Peer"
    when "32" then "Personals and Dating"
    when "33" then "Philanthropic & Professional Orgs."
    when "34" then "Phishing & Fraud"
    when "35" then "Photo Searches"
    when "36" then "Politics"
    when "37" then "Proxies & Translators"
    when "38" then "Real Estate"
    when "39" then "Reference"
    when "40" then "Religion"
    when "41" then "Ringtones/Mobile Phone Downloads"
    when "42" then "Search Engines"
    when "43" then "Sex Education"
    when "44" then "Shopping"
    when "45" then "Society & Culture"
    when "46" then "Spam URLs"
    when "47" then "Sports"
    when "48" then "Spyware"
    when "49" then "Streaming Media"
    when "50" then "Tasteless & Offensive"
    when "51" then "Travel"
    when "52" then "Violence"
    when "53" then "Weapons"
    when "54" then "Web-based E-mail"
    when "55" then "Custom"
    when "56" then "Anonymizing Proxies"
    ELSE '-'
   END as category_text,
  regex_match(line,'.*url=(.*?)$',1) as "url"
FROM epp_file
)
select * from epp_table
