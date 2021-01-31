#Validate OS
if((Get-WMIObject -Class Win32_OperatingSystem).Caption -match "Server (2008 R2|2012|2012 R2|2016)"){
	Write-Host "Operating System" -ForegroundColor Green
}else{
	Write-Host "Operating System" -ForegroundColor Red
}

#Validate PS version is 3.0 or greater
if ($PSVersionTable.PSVersion -ge "3.0"){
	Write-Host "PowerShell 3.0" -ForegroundColor Green
}else{
	Write-Host "PowerShell 3.0" -ForegroundColor Red
}

#Validate AD PS module is available
if (Get-Module -Name ActiveDirectory -ListAvailable){
	Write-Host "Active Directory RSAT" -ForegroundColor Green
}else{
	Write-Host "Active Directory RSAT" -ForegroundColor Red
}

#Import ServerManager module
if (!(Get-Module ServerManager)){
	Import-Module ServerManager
}

#Validate .NET Framework 4.5 is installed
if ((Get-WindowsFeature -Name NET-Framework-45-Core).InstallState -eq "Installed"){
	Write-Host ".NET Framework 4.5" -ForegroundColor Green
}else{
	Write-Host ".NET Framework 4.5" -ForegroundColor Red
}
