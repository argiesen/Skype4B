$csServers = @()
try {
	$csPool = Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
	$csServers = $csPool | Select-Object -ExpandProperty Computers | Select-Object @{l='ServerName';e={$_}},FreeSpace,PSVersion,SQLVersion,SQLSP,OSVersion,OSHotfix,LRSAdmin,Messages
}catch{
	$csServers = Get-CsTopology -LocalStore | Select-Object -ExpandProperty Machines | Where-Object Fqdn -match ([System.Net.Dns]::GetHostByName((hostname)).HostName) | Select-Object @{l='ServerName';e={$_.Fqdn}},FreeSpace,PSVersion,SQLVersion,SQLSP,OSVersion,OSHotfix,LRSAdmin,Messages
	$local = $true
}

foreach ($Server in $csServers){
	$Messages = @()
	
	if ($local){
		$drives = Get-CimInstance Win32_Volume -Filter 'DriveType = 3' | Where-Object DriveLetter -ne $null | Select-Object @{l='FreeSpaceGB';e={$_.FreeSpace/1GB}}
		$psVersion = $PSVersionTable.BuildVersion
		$Server.SQLVersion = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.ParentDisplayName -eq "Microsoft SQL Server 2012 (64-bit)" -and $_.ReleaseType -eq "ServicePack"}).DisplayVersion
		$osVersion = (Get-CimInstance Win32_OperatingSystem).Caption
		$lrsApplication = Get-WebApplication lrs -ErrorAction SilentlyContinue
		
		#Windows Server 2008 R2 - KB2533623
		#Windows Server 2012 - KB2858668
		#Windows Server 2012 R2 - KB2982006
		if ($osVersion -match "Server 2012 R2"){
			$hotfix = Get-Hotfix KB2982006 -ErrorAction SilentlyContinue
			$hotfixId = "KB2982006"
		}elseif ($osVersion -match "Server 2012"){
			$hotfix = Get-Hotfix KB2858668 -ErrorAction SilentlyContinue
			$hotfixId = "KB2858668"
		}elseif ($osVersion -match "Server 2008 R2"){
			$hotfix = Get-Hotfix KB2533623 -ErrorAction SilentlyContinue
			$hotfixId = "KB2533623"
		}
	}else{
		#$drives = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {Get-CimInstance Win32_Volume -Filter 'DriveType = 3' | Where-Object DriveLetter -ne $null | Select-Object @{l='FreeSpaceGB';e={$_.FreeSpace/1GB}}}
		$drives = Get-CimInstance Win32_Volume -ComputerName $Server.ServerName -Filter 'DriveType = 3' | Where-Object DriveLetter -ne $null | Select-Object @{l='FreeSpaceGB';e={$_.FreeSpace/1GB}}
		$psVersion = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {$PSVersionTable.BuildVersion}
		$Server.SQLVersion = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.ParentDisplayName -eq "Microsoft SQL Server 2012 (64-bit)" -and $_.ReleaseType -eq "ServicePack"}).DisplayVersion}
		#$osVersion = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {(Get-CimInstance -Class Win32_OperatingSystem).Caption}
		$osVersion = (Get-CimInstance Win32_OperatingSystem -ComputerName $Server.ServerName).Caption
		$lrsApplication = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {Get-WebApplication lrs -ErrorAction SilentlyContinue}
		
		#Windows Server 2008 R2 - KB2533623
		#Windows Server 2012 - KB2858668
		#Windows Server 2012 R2 - KB2982006
		if ($osVersion -match "Server 2012 R2"){
			#$hotfix = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {Get-Hotfix KB2982006 -ErrorAction SilentlyContinue}
			$hotfix = Get-Hotfix KB2982006 -ComputerName $Server.ServerName -ErrorAction SilentlyContinue
			$hotfixId = "KB2982006"
		}elseif ($osVersion -match "Server 2012"){
			#$hotfix = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {Get-Hotfix KB2858668 -ErrorAction SilentlyContinue}
			$hotfix = Get-Hotfix KB2858668 -ComputerName $Server.ServerName -ErrorAction SilentlyContinue
			$hotfixId = "KB2858668"
		}elseif ($osVersion -match "Server 2008 R2"){
			#$hotfix = Invoke-Command -ComputerName $Server.ServerName -ScriptBlock {Get-Hotfix KB2533623 -ErrorAction SilentlyContinue}
			$hotfix = Get-Hotfix KB2533623 -ComputerName $Server.ServerName -ErrorAction SilentlyContinue
			$hotfixId = "KB2533623"
		}
	}
	
	#Check 32GB free space
	if ($drives.FreeSpaceGB -gt 32){
		$Server.FreeSpace = $true
	}else{
		$Server.FreeSpace = $false
		$Messages += "There must have 32GB of free space available."
	}
	
	#Check PowerShell build version
	if ($psVersion -lt 6.2.9200.0){
		$Server.PSVersion = $false
		$Messages += "PowerShell version 6.2.9200.0 or greater is required."
	}else{
		$Server.PSVersion = $true
	}
	
	#Check SQL Server 2012 SP1
	if ($Server.SQLVersion -ge 11.1.3000.0){
		$Server.SQLSP = $true
	}else{
		$Server.SQLSP = $false
		$Messages += "SQL Server 2012 SP1 or greater is required."
	}
	
	#Check for OS
	if($osVersion -match "Server 2012 R2"){
		$Server.OSVersion = $true
	}elseif($osVersion -match "Server (2008 R2|2012)"){
		$Server.OSVersion = $true
		$Messages += "Windows Server 2012 R2 is the recommended operating system."
	}else{
		$Server.OSVersion = $false
		$Messages += "Windows Server 2008 R2/2012/2012 R2 are the required operating systems."
	}
	
	#Check for OS KB
	if ($hotfix){
		$Server.OSHotfix = $true
	}else{
		$Server.OSHotfix = $false
		$Messages += "Hotfix $hotfixId required."
	}
	
	#Check for LRS Admin tool
	if ($lrsApplication){
		$Server.LRSAdmin = $false
		$Messages += "LRS Admin Portal must be uninstalled."
	}else{
		$Server.LRSAdmin = $true
	}
	
	$Server.Messages = ($Messages | Out-String).Trim()
}


#$csServers | Format-Table -AutoSize
$csServers | Format-List
$csServers | Export-Csv SfBPrereqs.csv -NoTypeInformation
