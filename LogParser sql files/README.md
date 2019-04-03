# Usage:

## Symantec_system_log.sql
LogParser.exe file:Symantec_system_log.sql?destinationDirectory=**<directory_path>**+sourceFile=**<syslog.log>** -stats:OFF -i:TSV -headerRow:off -nSkipLines:1 -nFields:9 -filemode:0
## Symantec_control_log.sql
LogParser.exe file:Symantec_control_log.sql?destinationDirectory=**<directory_path>**+sourceFile=**<syslog.log>** -stats:OFF -i:TSV -headerRow:off -nSkipLines:1 -nFields:28 -filemode:0
