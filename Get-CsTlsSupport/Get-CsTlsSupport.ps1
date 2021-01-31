#https://msdn.microsoft.com/en-us/library/hh925568%28v=vs.110%29.aspx
$VersionHashNDP = @{
	378389="4.5"
	378675="4.5.1"
	378758="4.5.1"
	379893="4.5.2"
	393295="4.6"
	393297="4.6"
	394254="4.6.1"
	394271="4.6.1"
	394747="4.6.2"
	394748="4.6.2"
	394802="4.6.2"
	394806="4.6.2"
	460798="4.7"
	460805="4.7"
	461308="4.7.1"
	461310="4.7.1"
	461808="4.7.2"
	461814="4.7.2"
}

#Download Pat Richard's CS version XML
try {
	[xml]$VersionXmlCs = (New-Object System.Net.WebClient).DownloadString("https://www.ucunleashed.com/downloads/2641/version.xml")
}catch{
	$VersionXmlCs = $false
}

$csServers = @()
try {
	$csPool = Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
	$csServers = $csPool | Select-Object -ExpandProperty Computers | Select-Object @{l='ServerName';e={$_}},CS,NET,SQL,SQLNativeClient,ODBCDriver,SQLMgmtObjects,SQLClrTypes,Messages
}catch{
	$csServers = Get-CsTopology -LocalStore | Select-Object -ExpandProperty Machines | Where-Object Fqdn -match ([System.Net.Dns]::GetHostByName((hostname)).HostName) | `
		Select-Object @{l='ServerName';e={$_.Fqdn}},CS,NET,SQL,SQLNativeClient,ODBCDriver,SQLMgmtObjects,SQLClrTypes,Messages
	$local = $true
}

foreach ($Server in $csServers){
	$Messages = @()
	
	if ($local){
		#Skype for Business Server CU6HF2 (6.0.9319.516)
		$csVersion = (Get-CimInstance Win32_Product | Where-Object Name -match "Skype for Business Server" | `
		Where-Object Name -notmatch "(Debugging Tools|Resource Kit)" | Select-Object Name,Version | Sort-Object Version -Descending)[0].Version
		
		#.NET 4.7
		$ndpRelease = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release").Release
		
		#SQL 2014
		#$Instances = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server").InstalledInstances[0]
		#$InstanceName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server").InstalledInstances[0]
		#$InstanceName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL").$Instance
		#$SQLVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceName\Setup").Version
		$SQLVersion = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.ParentDisplayName -eq "Microsoft SQL Server 2014 (64-bit)" -and $_.ReleaseType -eq "ServicePack"}).DisplayVersion
		
		#SQL Native Client
		$SQL12NativeClientVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SQLNCLI11").InstalledVersion
		
		#ODBC Driver 11 for SQL Server
		$SQLODBCDriverVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft ODBC Driver 11 for SQL Server\CurrentVersion").Version
		
		#Shared Management Objects for SQL Server 2014 SP2
		$SQLMgmtObjectsVersion = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -match "SQL Server 2014 Management Objects"}).DisplayVersion
		
		#SQLSysClrTypes for SQL server 2014 SP2
		$SQLClrTypesVersion = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -match "System CLR Types for SQL Server 2014"}).DisplayVersion
	}else{
		#Skype for Business Server CU6HF2 (6.0.9319.516)
		$csVersion = (Get-CimInstance Win32_Product -ComputerName $Server.ServerName | Where-Object Name -match "Skype for Business Server" | `
		Where-Object Name -notmatch "(Debugging Tools|Resource Kit)" | Select-Object Name,Version | Sort-Object Version -Descending)[0].Version
		
		#.NET 4.7
		$ndpRelease = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release").Release}
		
		#SQL 2014
		#$InstanceName = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server").InstalledInstances[0]}
		#$SQLVersion = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceName\Setup").Version}
		$SQLVersion = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.ParentDisplayName -eq "Microsoft SQL Server 2014 (64-bit)" -and $_.ReleaseType -eq "ServicePack"}).DisplayVersion}
		
		#SQL Native Client
		$SQL12NativeClientVersion = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SQLNCLI11").InstalledVersion}
		
		#ODBC Driver 11 for SQL Server
		$SQLODBCDriverVersion = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft ODBC Driver 11 for SQL Server\CurrentVersion").Version}
		
		#Shared Management Objects for SQL Server 2014 SP2
		$SQLMgmtObjectsVersion = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -match "SQL Server 2014 Management Objects"}).DisplayVersion}
		
		#SQLSysClrTypes for SQL server 2014 SP2
		$SQLClrTypesVersion = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -match "System CLR Types for SQL Server 2014"}).DisplayVersion}
	}
	
	#Skype for Business Server CU6HF2 (6.0.9319.516)
	if ($VersionXmlCs){
		$csVersionOut = "$csVersion ($(($VersionXmlCs.catalog.UpdateVersion | Where-Object Id -eq $csVersion).UpdateName))"
	}else{
		$csVersionOut = "$csVersion"
	}
	if ($csVersion -ge 6.0.9319.516){
		$Server.CS = $true
	}else{
		$Server.CS = $false
	}

	#.NET 4.7
	$ndpVersion = $VersionHashNDP.Item($ndpRelease)
	if ($ndpRelease -ge 460805 -or $ndpRelease -ge 460798){
		$Server.NET = $true
	}else{
		$Server.NET = $false
	}
	
	#https://support.microsoft.com/en-us/help/3135244/tls-1-2-support-for-microsoft-sql-server
	#https://www.microsoft.com/en-us/download/details.aspx?id=53168
	#SQL 2014
	#SQL 2014 SP2: 12.0.5000.0
	#SQL 2014 SP1 CU5: 12.0.4439.1
	#SQL 2014 CU12: 12.0.2564.0
	if ($SQLVersion -ge 12.0.5000.0){
		$Server.SQL = $true
		$Messages += "SQL 2014 SP2+ detected."
	}elseif ($SQLVersion -ge 12.0.4439.1){
		$Server.SQL = $true
		$Messages += "SQL 2014 SP1 CU5+ detected."
	}elseif ($SQLVersion -ge 12.0.2564.0){
		$Server.SQL = $true
		$Messages += "SQL 2014 CU12+ detected."
	}else{
		$Server.SQL = $false
		$Messages += "SQL 2014 SP2/SP1 CU5/CU12+ required."
	}

	#SQL Native Client
	#https://www.microsoft.com/en-us/download/details.aspx?id=50402
	#11.0.7001.0
	if ($SQL12NativeClientVersion -ge 11.0.7001.0){
		$Server.SQLNativeClient = $true
	}else{
		$Server.SQLNativeClient = $false
		$Messages += "SQL Native Client version 11.0.7001.0+ required. $SQL12NativeClientVersion detected. Download available: https://www.microsoft.com/en-us/download/details.aspx?id=50402"
	}

	#ODBC Driver 11 for SQL Server
	#https://www.microsoft.com/en-us/download/confirmation.aspx?id=36434
	#12.0.5543.11
	if ($SQLODBCDriverVersion -ge 12.0.5543.11){
		$Server.ODBCDriver = $true
	}else{
		$Server.ODBCDriver = $false
		$Messages += "ODBC Driver 11 for SQL Server 12.0.5543.11+ required. $SQLODBCDriverVersion detected. Download available: https://www.microsoft.com/en-us/download/confirmation.aspx?id=36434"
	}

	#Shared Management Objects for SQL Server 2014 SP2
	#12.0.2000.8
	if ($SQLMgmtObjectsVersion -ge 12.0.2000.8){
		$Server.SQLMgmtObjects = $true
	}else{
		$Server.SQLMgmtObjects = $false
		$Messages += "Shared Management Objects for SQL Server 2014 SP2 version 12.0.2000.8+ required. $SQLMgmtObjectsVersion detected. Download available: "
	}

	#SQLSysClrTypes for SQL server 2014 SP2
	#12.0.2000.8
	if ($SQLClrTypesVersion -ge 12.0.2000.8){
		$Server.SQLClrTypes = $true
	}else{
		$Server.SQLClrTypes = $false
		$Messages += "SQLSysClrTypes for SQL server 2014 SP2 version 12.0.2000.8+ required. $SQLClrTypesVersion detected. Download available: "
	}
	
	$Server.Messages = ($Messages | Out-String).Trim()
}

#$csServers | Format-Table -AutoSize
$csServers | Format-List
#$csServers | Export-Csv SfBPrereqs.csv -NoTypeInformation