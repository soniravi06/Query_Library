
Computer Name
Bitlocker (drive letter, protection status, encryption method)
Hardware_vendor
OS (name, version)
CPU model
Memory (percent_free_memory, free_space_memory, memory_size)
Disk (percent_free_disk, free_space_disk, disk_size)
MAC address
Open port
Login user
Application
Certificate
Windows Update
Networks (DNS server, DHCP server, description)


Hi Vu,

Thank you for reaching out to querydesk!

Combining all the mentioned information in a single query would not be feasible option here since we do not put everything into data lake, some are only specific to 'only on device' (Endpoint Queries) and various other limitation.

However, we have many canned queries for both data lake and Endpoint

I have segregated the data available in respective database platform along with their respective canned query to find the information from.

We do not put all the info into the data lake. Some are only on the device (Live Discover)




Available in Datalake:
Computer Name
Bitlocker (drive letter, protection status, encryption method)
Application - Windows Programs (Data Lake)
Windows Update - Windows Updates(Data Lake)

Available in Endpoint: (run on online devices)
OS (name, version), CPU model, Hardware_vendor - Hardware and operating system details
Open port - Processes with an open network connection, Processes listening on ports
Login user - Authentication attempts
Certificate - Certificates
MAC address. Networks (DNS server, DHCP server, description) - Network interface details

Disk information -

Memory (percent_free_memory, free_space_memory, memory_size)
Disk (percent_free_disk, free_space_disk, disk_size) - Disk information

---------------------------------------------------------------------------------------------
