$IISLogs = (Get-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.directory).Value
$IISLogs = $IISLogs -replace '%SystemDrive%',$env:systemdrive

Get-ChildItem -Path $IISLogs -Include *.log -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).addDays(-60)} | Foreach-Object {Remove-Item $_.FullName}