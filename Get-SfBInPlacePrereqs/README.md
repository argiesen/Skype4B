# Get-SfBInPlacePrereqs

Get-SfBInPlacePrereqs checks for Skype for Business Server 2015 in-place upgrade prerequisites.

It validates the following items:
1. 32GB of free drive space for databases.
2. PowerShell version is 6.2.9200.0 or greater.
3. SQL Express 2012 SP1.
4. Operating System is Server 2008 R2/2012/2012 R2.
5. OS specific IIS hotfixes:
	* KB2533623 (Windows Server 2008 R2)
	* KB2858668 (Windows Server 2012)
	* KB2982006 (Windows Server 2012 R2)
6. LRS Admin Portal.

You may run this script directly from GitHub with the commands below:
```
$GetSfBInPlacePrereqs = Invoke-WebRequest https://raw.githubusercontent.com/argiesen/Get-SfBInPlacePrereqs/master/Get-SfBInPlacePrereqs.ps1
Invoke-Expression $($GetSfBInPlacePrereqs.Content)
```
