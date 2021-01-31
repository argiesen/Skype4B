### Get-CsRegistration
This script will query the RTCLOCAL SQL Express instance on registrar servers and pull a list of all registered endpoints including SIP address and user agent. This is useful in determining what users are registered, how many times, where, and what type of endpoint and software version.

The script presents a menu of available pools to query and offers a selection of outputs via parameters.

Default output is GridView

* PSView - Outputs to PowerShell
* CsvExport - Exports output to a CSV
* CsvPath - Sets CSV path, defaults to .\EndpointRegistrations.csv


### Get-CsClsLogSize
Determines size of Centralized Logging Service log files on all servers in the topology by inspecting C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\Tracing on each server.


### Get-WindowsFabricLogSize
Determines size of Windows Fabric Service log files on all registrars in the topology by inspecting C:\ProgramData\Windows Fabric\Fabric\log\Traces and C:\ProgramData\Windows Fabric\Log\Traces on each server.


### Invoke-CsUpgradeCheck
Invoke-CsUpgradeCheck checks for Skype for Business Server 2015 in-place upgrade prerequisites.

It validates the following items:
1. 32GB of free drive space for databases.
2. PowerShell version is 6.2.9200.0 or greater.
3. SQL Express 2012 SP1.
4. Operating System is Server 2008 R2/2012/2012 R2.
5. OS specific IIS hot fixes:
	* KB2533623 (Windows Server 2008 R2)
	* KB2858668 (Windows Server 2012)
	* KB2982006 (Windows Server 2012 R2)
6. LRS Admin Portal.

You may run this script directly from GitHub with the commands below:
```
$CsUpgradeCheck = Invoke-WebRequest https://raw.githubusercontent.com/argiesen/CsScripts/master/Invoke-CsUpgradeCheck.ps1
Invoke-Expression $($CsUpgradeCheck.Content)
```


### Invoke-CsAdPrepCheck
Invoke-CsAdPrepCheck checks for prerequisites to perform Active Directory preparation via Deployment Wizard on a Domain Controller.

It validates the following items:
1. Operating System is Server 2008 R2/2012/2012 R2/2016
2. PowerShell 3.0 or greater
3. Active Directory RSAT
4. .NET Framework 4.5

You may run this script directly from GitHub with the commands below:
```
$CsAdPrepCheck = Invoke-WebRequest https://raw.githubusercontent.com/argiesen/CsScripts/master/Invoke-CsAdPrepCheck.ps1
Invoke-Expression $($CsAdPrepCheck.Content)
```
