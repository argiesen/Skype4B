# Title: Get-CsDeviceUpdates
# Version: 3.1
# Author: Andy Giesen
# Date: 1/26/13

# Credits: Pat Richard of www.ehloworld.com for ModuleStatus and FileDownload functions

# Change Log
# 6/11/17
# PSAnalyzer updates
# Fixed incorrect variable for device update cleanup
# Replace Pat Richard's FileDownload function with Start-Download function
# Download 7zip exe and dll from GitHub
# Replaced 7zip 9.20 with 16.04
# Replaced Invoke-Expression for Uncompress and Expand
# 
# 3/5/16
# Added option to import to all pools
# Added Get-Help information
# Improved update clean up methodology
# Misc code optimizations
#
# 6/10/15
# Added parameters for non-interactive execution. Useful for scheduled tasks or copy/paste code snippet interaction.
# 
# 5/8/15
# Further streamlined user experience
#
# 2/3/15
# Streamlined user experience so the user does not need to wait for prompts
# Added device update store clean up
# 
# 12/18/14
# Added multi-select menu
# 
# 10/31/13
# Added third party update processing from 3PIP folder
# Added choice to download LPE updates from Microsoft or not
# 
# To-Dos
# Add automatic download for VVX phones

<#
    .SYNOPSIS
      This script automatically downloads, extracts, imports, approves, and cleans up device updates for LPE devices. Automatic import, approval and clean up is supported for 3PIP devices.

	  Executing this script without any parameters will result in an interactive experience. However parameters are provided for non-interactive execution.
	.PARAMETER Pool
	  Define a single pool to which updates will be imported and approved.
    .PARAMETER HP
	  Processes updates for HP LPE devices.
	.PARAMETER Aastra
	  Processes updates for Aastra LPE devices.
	.PARAMETER Polycom
	  Processes updates for Polycom Aries LPE devices.
	.PARAMETER Tanjay
	  Processes updates for Polycom Tanjay (CX700) LPE devices.
	.PARAMETER 3PIP
	  Processes updates for 3PIP phones placed in the 3PIP folder.
	.PARAMETER Download
	  Automatically downloads the latest selected LPE firmware directly from Microsoft.
	.PARAMETER Import
	  Automatically import updates to selected pool.
	.PARAMETER ImportToAllPools
	  Automatically import updates to all pools.
	.PARAMETER Approve
	  Automatically approve ALL pending firmware updates on selected pools. Note: This does not discriminate from already existing pending updates.
	.PARAMETER Cleanup
	  Searches the pool file share for firmware files that do not match the currently approved, pending, or restore firmware versions.
	.EXAMPLE
      Get-CsDeviceUpdates.ps1 -Pool cspool1.domain.com -Polycom -Download -Import -Approve -Cleanup
	  This command will download the Polycom LPE updates from Microsoft, import them to pool cspool1, approve the updates, and clean up old firmware files on the file share.
	.EXAMPLE
	  Get-CsDeviceUpdates.ps1 -Polycom -3PIP -ImportToAllPools -Approve -Cleanup
	  This command will import pre-staged Polycom LPE and any 3PIP update files from the 3PIP folder to all pools, approve the updates, and clean up old firmware files on the file share.
#>

[CmdLetBinding(DefaultParameterSetName="None")]
param(
	[Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='ImportOne')]
	[string]$Pool="",
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[switch]$HP,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[switch]$Aastra,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[switch]$Polycom,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[switch]$Tanjay,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[switch]$3PIP,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[switch]$Download,
	[Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='ImportOne')]
	[switch]$Import,
	[Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='ImportAll')]
	[switch]$ImportToAllPools,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='ImportOne')]
	[Parameter(ParameterSetName='ImportAll')]
	[switch]$Approve,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='ImportOne')]
	[Parameter(ParameterSetName='ImportAll')]
	[switch]$Cleanup
)

function Get-ModuleStatus { 
	param	(
		[parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Mandatory=$true, HelpMessage="No module name specified!")] 
		[string]$name
	)
	if(!(Get-Module -name "$name")) { 
		if(Get-Module -ListAvailable | Where-Object {$_.name -eq "$name"}) { 
			Import-Module -Name "$name" 
			# module was imported
			return $true
		}else{
			# module was not available
			return $false
		}
	}else{
		# module was already imported
		# Write-Host "$name module already imported"
		return $true
	}
} # end function Get-ModuleStatus

function Get-InternetConnectivity {
	param (
		[string]$Site = "http://www.google.com"
	)
	
	if (Get-NetConnectionProfile -IPv4Connectivity Internet -ErrorAction SilentlyContinue){
		try {
			$out = Invoke-WebRequest -Uri $Site -Method Head
		}catch{
			return $false
		}
		
		if ($out.StatusCode -eq 200){
			return $true
		}else{
			return $false
		}
	}else{
		return $false
	}
}

function Start-Download {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[string]$JobName,
		[string]$Source,
		[string]$Destination,
		[string]$FileName,
		$WebSession,
		[switch]$Web,
		[switch]$SuppressProgress
	)
	
	if (!($FileName)){
		$FileName = $Source.Substring($Source.LastIndexOf("/") + 1)
	}
	if (Test-Path $Destination\$FileName){
		return
	}
	if (!(Get-InternetConnectivity)){
		Write-Log "Download failed: $FileName" -Level "Error" -OutTo $LogOutTo
		Write-Log "Unable to request file" -Level "Error" -OutTo $LogOutTo
		return
	}
	if (!(Test-Path $Destination)){
		New-Item $Destination -Type Directory | Out-Null
	}
	
	if ($SuppressProgress){
		$ProgressPreference='SilentlyContinue'
	}
	
	if ($Web){
		$outFile = $Destination + "\" + $FileName
	
		try {
			if ($WebSession){
				Invoke-WebRequest -Uri $Source -OutFile $outFile -WebSession $WebSession
			}else{
				Invoke-WebRequest -Uri $Source -OutFile $outFile
			}
		}catch{
			Write-Log "Download failed: $FileName" -Level "Error" -OutTo $LogOutTo
			Write-Log $error[0] -Level "Error" -OutTo $LogOutTo
		}
	}else{
		if ($JobName){
			if (Get-BitsTransfer $JobName -ErrorAction SilentlyContinue){
				Get-BitsTransfer $JobName | Add-BitsFile -Source $Source -Destination $Destination | Out-Null
			}else{
				Start-BitsTransfer -Source $Source -Destination $Destination -DisplayName $JobName -Asynchronous | Out-Null
			}
		}else{
			Start-BitsTransfer -Source $Source -Destination $Destination
		}
	}
	
	$ProgressPreference='Continue'
}


if ((Get-Module BitsTransfer).installed -eq $true){
	[bool] $WasInstalled = $true
}else{
	[bool] $WasInstalled = $false
}
#[bool] $HasInternetAccess = ([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet)
#$HasInternetAccess = Get-InternetConnectivity

Start-Download -Source "https://github.com/argiesen/Get-CsDeviceUpdate/raw/master/7zip/7za.dll" -Destination ".\7zip" -SuppressProgress
Start-Download -Source "https://github.com/argiesen/Get-CsDeviceUpdate/raw/master/7zip/7za.exe" -Destination ".\7zip" -SuppressProgress

if ((Test-Path .\7zip\7za.dll) -and (Test-Path .\7zip\7za.exe)){
	#Continue
}else{
	Write-Error "7za.exe and 7za.dll must exist in .\7zip"
	return
}

$DeviceUpdate = @{}
$DeviceUpdate[0] = @{"Brand" = "HP";"Folder" = ".\HP";"URL" = "http://download.microsoft.com/download/8/8/C/88CDF8C2-30D2-4189-8124-2E57D0078EE5/UCUpdates.exe";"Uncompress" = '.\7zip\7z.exe x -oHP -y .\HP\UCUpdates.exe UCUpdates.cab | out-null';"Expand" = 'expand .\HP\UCUpdates.cab -f:updateInfo.xml .\HP | out-null';"CabWithVersion" = "";"Process" = $false}
$DeviceUpdate[1] = @{"Brand" = "Aastra";"Folder" = ".\Aastra";"URL" = "http://download.microsoft.com/download/C/A/E/CAEB181B-7A20-49C6-BDDE-D676EA8F02A1/UCUpdates.exe";"Uncompress" = '.\7zip\7z.exe x -oAastra -y .\Aastra\UCUpdates.exe UCUpdates.cab | out-null';"Expand" = 'expand .\Aastra\UCUpdates.cab -f:updateInfo.xml .\Aastra | out-null';"CabWithVersion" = "";"Process" = $false}
$DeviceUpdate[2] = @{"Brand" = "Polycom";"Folder" = ".\Polycom";"URL" = "http://download.microsoft.com/download/2/8/D/28DA8A01-C9EC-4F3E-A55A-FC5F46DBF0A1/UCUpdates.exe";"Uncompress" = '.\7zip\7z.exe x -oPolycom -y .\Polycom\UCUpdates.exe UCUpdates.cab | out-null';"Expand" = 'expand .\Polycom\UCUpdates.cab -f:updateInfo.xml .\Polycom | out-null';"CabWithVersion" = "";"Process" = $false}
$DeviceUpdate[3] = @{"Brand" = "Tanjay";"Folder" = ".\Tanjay";"URL" = "http://download.microsoft.com/download/F/8/8/F88C7D24-FCCB-41E4-A0A0-FCA813C3FDD9/UCUpdates.exe";"Uncompress" = '.\7zip\7z.exe x -oTanjay -y .\Tanjay\UCUpdates.exe UCUpdates.cab | out-null';"Expand" = 'expand .\Tanjay\UCUpdates.cab -f:updateInfo.xml .\Tanjay | out-null';"CabWithVersion" = "";"Process" = $false}
$LPEUpdates = $false
$OptionSelected = $false
$Interactive = $true

#3rd party IP phone variables
$3PIPPath = ".\3PIP"
$3PIPFilter = "*.cab"
$3PIPFiles = @(Get-ChildItem -Recurse -Path $3PIPPath -Filter $3PIPFilter | Resolve-Path -Relative)
$3PIPProcess = $false

#Process CLI parameters
if ($Pool -ne ""){$WebServers = Get-CsService -WebServer -PoolFqdn $Pool;$Interactive = $false}
if ($HP.isPresent){$DeviceUpdate[0].Process = $true}
if ($Aastra.isPresent){$DeviceUpdate[1].Process = $true}
if ($Polycom.isPresent){$DeviceUpdate[2].Process = $true}
if ($Tanjay.isPresent){$DeviceUpdate[3].Process = $true}
if ($3PIP.isPresent){$3PIPProcess = $true}
if ($Download.isPresent){$DownloadUpdates = 0;$Interactive = $false}
if ($Import.isPresent){$ImportUpdates = 0;$Interactive = $false}
if ($ImportToAllPools.isPresent){$ImportUpdates = 0;$WebServers = Get-CsService -WebServer;$Interactive = $false}
if ($Approve.isPresent){$ApproveUpdates = 0;$Interactive = $false}
if ($Cleanup.isPresent){$CleanupUpdates = 0;$Interactive = $false}

#Load Lync module
Get-ModuleStatus Lync | Out-Null

#Interactive menu
if ($Interactive){
	do{
		do{
			#Update selection
			Write-Host
			Write-Host "[" -NoNewLine;if($DeviceUpdate[0].Process -eq $true){Write-Host "X" -NoNewLine}else{Write-Host " " -NoNewLine};"] 1. HP"
			Write-Host "[" -NoNewLine;if($DeviceUpdate[1].Process -eq $true){Write-Host "X" -NoNewLine}else{Write-Host " " -NoNewLine};"] 2. Aastra"
			Write-Host "[" -NoNewLine;if($DeviceUpdate[2].Process -eq $true){Write-Host "X" -NoNewLine}else{Write-Host " " -NoNewLine};"] 3. Polycom"
			Write-Host "[" -NoNewLine;if($DeviceUpdate[3].Process -eq $true){Write-Host "X" -NoNewLine}else{Write-Host " " -NoNewLine};"] 4. Tanjay"
			if($3PIPFiles.Count -gt 0){Write-Host "[" -NoNewLine;if($3PIPProcess -eq $true){Write-Host "X" -NoNewLine}else{Write-Host " " -NoNewLine};"] 5. 3PIP"}
			Write-Host
			Write-Host "0. Continue"
			Write-Host "X. Exit"
			Write-Host
			Write-Host "Select which devices you would like to update firmware for: " -NoNewLine
			
			$selection = Read-Host
			
			Write-Host
			
			if($3PIPFiles.Count -gt 0){
				$valid = $selection -match '^[1-5|0|x|X]$'
			}else{
				$valid = $selection -match '^[1-4|0|x|X]$'
			}
			
			if (-not $valid){
				Write-Host "Invalid selection." -ForegroundColor Red
			}
		}until($valid)
		
		#Process selection to set device specific variables
		if ($selection -ne "X" -and $selection -ne "0"){
			$select = $selection - 1
		
			if ($DeviceUpdate[$select].Process -ne $true -and $select -ne 4){$DeviceUpdate[$select].Process = $true}
			elseif ($select -ne 4){$DeviceUpdate[$select].Process = $false}
			if ($select -eq 4 -and $3PIPProcess -ne $true){$3PIPProcess = $true}
			elseif ($select -eq 4){$3PIPProcess = $false}
		}
	}until($selection -match "0" -or $selection -match "[x|X]")
	
	if ($selection -match "[x|X]"){Write-Host "Exiting."; Write-Host; Return}
	
	#Check for selected options and set global variables to trigger further processing or quit
	for ($i=0; $i -lt $DeviceUpdate.Count; $i++){
		if ($DeviceUpdate[$i].Process -eq $true){$LPEUpdates = $true;$OptionSelected = $true}
	}
	if ($3PIPProcess){$OptionSelected = $true}
	
	if (!($OptionSelected)){
		Write-Host "No options selected. Quitting."; Write-Host; Return
	}
	
	#Download LPE updates prompt (Prompting for scenarios where update files are pre-staged)
	if ($LPEUpdates){
		$message = "Download LPE device updates from Microsoft?"
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Continues downloading LPE device updates from Microsoft."
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Quits."
		$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		$DownloadUpdates = $host.ui.PromptForChoice($title, $message, $options, 0)
		
		Write-Host
	}
	
	#Import updates prompt
	$message = "Import device updates?"
	$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Continues to pool selection for device update import."
	$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Quits."
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
	$ImportUpdates = $host.ui.PromptForChoice($title, $message, $options, 0)
	
	Write-Host
	
	#If importing prompt for web server, approval, and cleanup
	if ($ImportUpdates -eq 0){
		$WebServers = Get-CsService -WebServer
		
		#List available web servers
		if ($WebServers.Count -gt 1){
			Write-Host "PoolFqdn"
			Write-Host "--------"
			
			for ($i=0; $i -lt $WebServers.Count; $i++){
				$a = $i + 1
				$b = $a + 1
				Write-Host ($a, $WebServers[$i].PoolFqdn)
				if ($i -eq ($WebServers.Count - 1)){Write-Host ($b, "All pools")}
			}
			
			$range = '(1-' + ($WebServers.Count + 1) + ')'
			Write-Host
			$select = Read-Host "Select pool to import device updates to" $range
			$select = $select - 1
			
			if (($select -gt $WebServers.Count) -or ($select -lt 0)){
				Write-Host
				Write-Host "Invalid selection." -ForegroundColor Red
				Return
			}elseif ($select -ne $WebServers.Count){
				$WebServers = $WebServers[$select]
			}
		}
		
		Write-Host
		Write-Host "Importing to pool(s):" 
		foreach($WebServer in $WebServers){Write-Host $WebServer.PoolFqdn}
		Write-Host
		
		#Approve updates prompt
		$message = "Approve device updates after import (NOTE: Approves all pending updates)?"
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Approves all pending device updates on selected pool."
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Does not approve any device updates."
		$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		$ApproveUpdates = $host.ui.PromptForChoice($title, $message, $options, 0)
		
		Write-Host
		
		#Clean up update store prompt
		$message = "Clean up device update store?"
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Approves all pending device updates on selected pool."
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Does not approve any device updates."
		$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		$CleanupUpdates = $host.ui.PromptForChoice($title, $message, $options, 0)
		
		Write-Host
	}else{
		$ApproveUpdates = 1
		$CleanupUpdates = 1
	}
}

#Download updates
if ($DownloadUpdates -eq 0){
	#Download device updates from Microsoft
	for ($i=0; $i -lt $DeviceUpdate.Count; $i++){
		if ($DeviceUpdate[$i].Process -eq $true){
			if (Test-Path $DeviceUpdate[$i].Folder){
				Get-ChildItem $DeviceUpdate[$i].Folder -Recurse -Include *.cab | Foreach-Object {Remove-Item $_.FullName}
			}
			
			#$downloadCmd = "New-FileDownload " + $DeviceUpdate[$i].URL + " " + $DeviceUpdate[$i].Folder
			#Invoke-Expression $downloadCmd
			Start-Download -Source $DeviceUpdate[$i].URL -Destination $DeviceUpdate[$i].Folder
			#Invoke-Expression $DeviceUpdate[$i].Uncompress
			& .\7zip\7za.exe x -o"$($DeviceUpdate[$i].Brand)" -y $($DeviceUpdate[$i].Folder)\UCUpdates.exe UCUpdates.cab | Out-Null
			#Invoke-Expression $DeviceUpdate[$i].Expand
			& expand "$($DeviceUpdate[$i].Folder)\UCUpdates.cab" -f:updateInfo.xml $($DeviceUpdate[$i].Folder) | Out-Null
			
			$xmlPath = $DeviceUpdate[$i].Folder + "\updateInfo.xml"
			[xml]$xml = Get-Content $xmlPath
			Write-Host $DeviceUpdate[$i].Brand"version:" $xml.Updates.Updates.Update.version
			$DeviceUpdate[$i].CabWithVersion = "UCUpdates." + $xml.Updates.Updates.Update.version + ".cab"
			$cabPathWithoutVersion = $DeviceUpdate[$i].Folder + "\UCUpdates.cab"
			Rename-Item $cabPathWithoutVersion $DeviceUpdate[$i].CabWithVersion -force -ErrorAction SilentlyContinue
			
			Write-Host
		}
	}

	#Clean up extraneous files
	Write-Host "Cleaning up extraneous update files..." -NoNewline
	Get-ChildItem . -Recurse -Include UCUpdates.exe | Foreach-Object {Remove-Item $_.FullName}
	Get-ChildItem . -Recurse -Include UCUpdates.cab | Foreach-Object {Remove-Item $_.FullName}
	Get-ChildItem . -Recurse -Include updateInfo.xml | Foreach-Object {Remove-Item $_.FullName}
	Write-Host " COMPLETE" -ForegroundColor Green
}

Write-Host

#Import device updates to Lync pool
#
#Importing device updates
if ($ImportUpdates -eq 0){
	#Imports device updates to a selected pool
	for ($i=0; $i -lt $DeviceUpdate.Count; $i++){
		if (($DeviceUpdate[$i].Process -eq $true) -and (Get-ChildItem -Path $DeviceUpdate[$i].Folder -Filter "*.cab" -ErrorAction SilentlyContinue)){
			Write-Host "Importing" $DeviceUpdate[$i].Brand "LPE device updates..." -NoNewLine
			$updatePath = Get-ChildItem -Path $DeviceUpdate[$i].Folder -Filter "*.cab" | Resolve-Path -Relative
			
			foreach ($WebServer in $WebServers){
				Import-CsDeviceUpdate -Identity $WebServer.Identity -FileName $updatePath
			}
			Write-Host " COMPLETE" -ForegroundColor Green
		}
	}
	
	Write-Host
}

#Importing third-party device updates
if ($3PIPProcess){
	if($3PIPFiles.Count -gt 0){
		foreach ($3PIPFile in $3PIPFiles){
			Write-Host "Importing third-party device update:" $3PIPFile"..." -NoNewLine
			
			foreach ($WebServer in $WebServers){
				Import-CsDeviceUpdate -Identity $WebServer.Identity -FileName $3PIPFile
			}
			Write-Host " COMPLETE" -ForegroundColor Green
		}
	}else{
		Write-Host "No third-party device updates found."
	}
	
	Write-Host
}

#Approve updates
switch ($ApproveUpdates){
	0 {Write-Host "Approving device updates..." -NoNewline; foreach ($WebServer in $WebServers){Get-CsDeviceUpdateRule | Where-Object {$_.Identity -match $WebServer.PoolFqdn} | Approve-CsDeviceUpdateRule}; Write-Host " COMPLETE" -ForegroundColor Green}
	1 {Write-Host "No device updates approved." -NoNewline}
}

Write-Host

#Device update store clean up
if ($CleanupUpdates -eq 0){
	Write-Host "Performing clean up of device update store..." -NoNewLine

	#Cycle through selected pool(s) then cycle through device updates for removal
	foreach ($WebServer in $WebServers){
		$deviceUpdateRules = Get-CsDeviceUpdateRule | Where-Object {$_.Identity -match $WebServer.PoolFqdn}
		$poolFileStore = Get-CsService -FileStore | Where-Object {$_.DependentServiceList -match $WebServer.PoolFqdn}
		
		foreach ($deviceUpdateRule in $deviceUpdateRules){
			$path = $poolFileStore.UncPath+"\"+$WebServer.ServiceId+"\DeviceUpdateStore\"+$deviceUpdateRule.DeviceType+"\"+$deviceUpdateRule.Brand+"\"+$deviceUpdateRule.Model+"\"+$deviceUpdateRule.Revision+"\"+$deviceUpdateRule.Locale
			
			Get-ChildItem -Path $path -Exclude $deviceUpdateRule.ApprovedVersion,$deviceUpdateRule.RestoreVersion,$deviceUpdateRule.PendingVersion | Remove-Item -Recurse
		}
	}
	
	Write-Host " COMPLETE" -ForegroundColor Green
}