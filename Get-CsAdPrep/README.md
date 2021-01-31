# Get-CsAdPrep

Get-CsAdPrep checks for prerequisites to perform Active Directory preperation via Deployment Wizard.

It validates the following items:
1. Operating System is Server 2008 R2/2012/2012 R2/2016
2. PowerShell 3.0 or greater
3. Active Directory RSAT
4. .NET Framework 4.5

You may run this script directly from GitHub with the commands below:
```
$GetCsAdPrep = Invoke-WebRequest https://raw.githubusercontent.com/argiesen/Get-CsAdPrep/master/Get-CsAdPrep.ps1
Invoke-Expression $($GetCsAdPrep.Content)
```
