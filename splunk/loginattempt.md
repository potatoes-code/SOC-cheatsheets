splunk
Failed Login Attempt Detection
Detect multiple failed login attempts from the same IP address or user. Windows Event Code 4625 indicates failed logon.
--> spl
search index=winlogs EventCode=4625
| stats count by src_ip, user
| where count > 5
| table _time, src_ip, user, count









