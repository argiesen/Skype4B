param (
	[switch]$ADOverviewOnly,
	[switch]$CSOverviewOnly,
	[switch]$ADOverview,
	[switch]$CSOverview
)

function Write-Log {
	param(
		[string]$Message,
		[ValidateSet("File", "Screen", "FileAndScreen")]
		[string]$OutTo = "FileAndScreen",
		[ValidateSet("Info", "Warn", "Error", "Verb", "Debug")]
		[string]$Level = "Info",
		[ValidateSet("Black", "DarkMagenta", "DarkRed", "DarkBlue", "DarkGreen", "DarkCyan", "DarkYellow", "Red", "Blue", "Green", "Cyan", "Magenta", "Yellow", "DarkGray", "Gray", "White")]
		[String]$ForegroundColor = "White",
		[ValidateRange(1,30)]
		[int]$Indent = 0,
		[switch]$Clobber,
		[switch]$NoNewLine
	)
	
	if (!($LogPath)){
		$LogPath = "$($env:ComputerName)-$(Get-Date -f yyyyMMdd).log"
	}
	
	$msg = "{0} : {1} : {2}{3}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level.ToUpper(), ("  " * $Indent), $Message
	if ($OutTo -match "File"){
		if (($Level -ne "Verb") -or ($VerbosePreference -eq "Continue")){
			if ($Clobber){
				$msg | Out-File $LogPath -Force
			}else{
				$msg | Out-File $LogPath -Append
			}
		}
	}
	
	$msg = "{0}{1}" -f ("  " * $Indent), $Message
	if ($OutTo -match "Screen"){
		switch ($Level){
			"Info" {
				if ($NoNewLine){
					Write-Host $msg -ForegroundColor $ForegroundColor -NoNewLine
				}else{
					Write-Host $msg -ForegroundColor $ForegroundColor
				}
			}
			"Warn" {Write-Warning $msg}
			"Error" {$host.ui.WriteErrorLine($msg)}
			"Verb" {Write-Verbose $msg}
			"Debug" {Write-Debug $msg}
		}
	}
}

$OutTo = "Screen"
$CollectPath = "$env:userprofile\Desktop\AssessmentCollection"

if ($ADOverviewOnly -or $ADOverview){
	if (!(Get-Module ActiveDirectory -ListAvailable)){
		Write-Log "Active Directory module not available" -OutTo $OutTo -Level Error
		break
	}
}
if ($CSOverviewOnly -or $CSOverview){
	if (!(Get-Module SkypeForBusiness -ListAvailable) -or !(Get-Module Lync -ListAvailable)){
		Write-Log "Lync/Skype4B module not available" -OutTo $OutTo -Level Error
		break
	}
}

if ($ADOverviewOnly -or $ADOverview){
	if(!(Test-Path $CollectPath)){
		Write-Log "Creating AssessmentCollection folder on Desktop" -OutTo $OutTo
		New-Item $CollectPath -ItemType directory | Out-Null
		Write-Log -OutTo $OutTo
	}
	
	Write-Log "Active Directory Overview" -OutTo $OutTo
	
	Write-Log "Gathering AD forest properties" -OutTo $OutTo
	Get-ADForest | Select-Object Name,RootDomain,ForestMode,DomainNamingMaster,SchemaMaster,@{name='Sites';expression={$_.Sites -join ','}},@{name='GlobalCatalogs';expression={$_.GlobalCatalogs -join ','}}, `
		@{name='UPNSuffixes';expression={$_.UPNSuffixes -join ','}} | `
		Out-File $CollectPath\ADInfo.txt

	Write-Log "Gathering AD domain properties" -OutTo $OutTo
	Get-ADDomain | Select-Object Name,Forest,NetBIOSName,ParentDomain,@{name='ChildDomains';expression={$_.ChildDomains -join ','}},DomainMode,PDCEmulator,RIDMaster,InfrastructureMaster, `
		@{name='ReadOnlyReplicaDirectoryServers';expression={$_.ReadOnlyReplicaDirectoryServers -join ','}} | `
		Out-File $CollectPath\ADInfo.txt -Append

	Write-Log "Gathering list of domain controllers in domain" -OutTo $OutTo
	Get-ADDomainController -Filter * | Select-Object HostName,Site,Enabled,IPv4Address,OperatingSystem,OperatingSystemVersion,@{name='OperationMasterRoles';expression={$_.OperationMasterRoles -join ','}} | `
		Out-File $CollectPath\ADInfo.txt -Append

	Write-Log "Gathering list of subnets" -OutTo $OutTo
	Get-ADReplicationSubnet -Filter * | Select-Object Name,Location,Site | Out-File $CollectPath\ADInfo.txt -Append

	Write-Log "Testing if RTC Service object exists in System container" -OutTo $OutTo
	$RTCDN = "AD:\CN=RTC Service,CN=Microsoft,CN=System," + (Get-ADDomain).DistinguishedName
	$RTCDN | Out-File $CollectPath\ADInfo.txt -Append
	Test-Path -Path $RTCDN | Out-File $CollectPath\ADInfo.txt -Append

	Write-Log "Testing if RTC Service object exists in Configuration container" -OutTo $OutTo
	$RTCDN = "AD:\CN=RTC Service,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName
	$RTCDN | Out-File $CollectPath\ADInfo.txt -Append
	Test-Path -Path $RTCDN | Out-File $CollectPath\ADInfo.txt -Append

	Write-Log "Gathering CA details and algorithms" -OutTo $OutTo
	certutil -TCAInfo | Out-File $CollectPath\CAInfo.txt
	certutil -TCAInfo | Where-Object {$_ -match "Machine Name: (.*)"} | Foreach-Object {
		certutil -config $matches[1] -getreg ca\csp\CNGHashAlgorithm
		certutil -config $matches[1] -getreg ca\csp\CNGPublicKeyAlgorithm
		certutil -config $matches[1] -getreg ca\CRLPublicationURLs
	} | Out-File $CollectPath\CAInfo.txt -Append

	Write-Log "Gathering users where SIP address and SMTP address do not match" -OutTo $OutTo
	Get-CsAdUser | Where-Object {($_.WindowsEmailAddress -and $_.SipAddress) -and ($_.WindowsEmailAddress -ne ($_.SipAddress -replace "sip:",""))} | Select-Object DisplayName,WindowsEmailAddress,SIPAddress

	Write-Log "Gathering list of phone numbers for format check; Must review on screen at the end of script, not saved to file" -OutTo $OutTo
	$PhoneNumbers = Get-ADUser -Filter * -Properties OfficePhone | Where-Object OfficePhone -ne $null
	
	Write-Log -OutTo $OutTo
	Write-Log -OutTo $OutTo
}


if ($CSOverviewOnly -or $CSOverview){
	if(!(Test-Path $CollectPath)){
		Write-Log "Creating AssessmentCollection folder on Desktop" -OutTo $OutTo
		New-Item $CollectPath -ItemType directory | Out-Null
		Write-Log -OutTo $OutTo
	}
	
	Write-Log "Lync\Skype4B Overview" -OutTo $OutTo

	Write-Log "Gathering user counts" -OutTo $OutTo
	"Total users (EV/RCC/Total): " + `
		(Get-CsUser | Where-Object {$_.EnterpriseVoiceEnabled -eq $true}).Count + "/" + `
		(Get-CsUser | Where-Object {$_.RemoteCallControlTelephonyEnabled -eq $true}).Count + "/" + `
		(Get-CsUser).Count | Out-File $CollectPath\CsOverview.txt
	foreach ($registrar in (Get-CsService -Registrar)){
		$registrar.PoolFqdn + " (EV/RCC/Total): " + `
			(Get-CsUser | Where-Object {$_.RegistrarPool -match $registrar.PoolFqdn -and $_.EnterpriseVoiceEnabled -eq $true}).Count + "/" + `
			(Get-CsUser | Where-Object {$_.RegistrarPool -match $registrar.PoolFqdn -and $_.RemoteCallControlTelephonyEnabled -eq $true}).Count + "/" + `
			(Get-CsUser | Where-Object {$_.RegistrarPool -match $registrar.PoolFqdn}).Count | `
			Out-File $CollectPath\CsOverview.txt -Append
	}

	Write-Log "Gathering media information" -OutTo $OutTo
	Get-CsService -ConferencingServer | Select-Object Identity,AudioPort*,VideoPort*,AppSharingPort*,SiteId | Out-File $CollectPath\CsMediaConfig.txt
	Get-CsService -ApplicationServer | Select-Object Identity,AudioPort*,VideoPort*,AppSharingPort*,SiteId | Out-File $CollectPath\CsMediaConfig.txt -Append
	Get-CsConferencingConfiguration | Select-Object Identity,Client* | Out-File $CollectPath\CsMediaConfig.txt -Append
	Get-CsMediaConfiguration | Out-File $CollectPath\CsMediaConfig.txt -Append
	Get-CsUCPhoneConfiguration | Out-File $CollectPath\CsMediaConfig.txt -Append

	Write-Log "Gathering device updates" -OutTo $OutTo
	Get-CsDeviceUpdateRule | Format-Table DeviceType,Brand,Model,*Version -AutoSize | Out-file $CollectPath\CsDeviceUpdates.txt

	Write-Log "Gathering conferencing policies" -OutTo $OutTo
	Get-CsConferencingPolicy | Export-Clixml $CollectPath\CsConferencingPolicy.xml

	Write-Log "Gathering PIN policies" -OutTo $OutTo
	Get-CsPinPolicy | Out-File $CollectPath\CsPINPolicy.txt

	Write-Log "Gathering client policies" -OutTo $OutTo
	Get-CsClientPolicy | Export-Clixml $CollectPath\CsClientPolicy.xml

	Write-Log "Gathering location policies" -OutTo $OutTo
	Get-CsLocationPolicy | Export-Clixml $CollectPath\CsLocationPolicy.xml

	Write-Log "Gathering mobility policies" -OutTo $OutTo
	Get-CsMobilityPolicy | Export-Clixml $CollectPath\CsMobilityPolicy.xml

	Write-Log "Gathering access edge configuration" -OutTo $OutTo
	Get-CsAccessEdgeConfiguration | Export-Clixml $CollectPath\CsAccessEdgeConfiguration.xml

	Write-Log "Gathering external access policies" -OutTo $OutTo
	Get-CsExternalAccessPolicy | Export-Clixml $CollectPath\CsExternalAccessPolicy.xml

	Write-Log "Gathering allowed SIP domains" -OutTo $OutTo
	Get-CsAllowedDomain | Select-Object Domain,ProxyFqdn,Comment | Export-Csv $CollectPath\CsAllowedDomains.csv -NoTypeInformation

	Write-Log "Gathering blocked SIP domains" -OutTo $OutTo
	Get-CsBlockedDomain | Select-Object Domain,ProxyFqdn,Comment | Export-Csv $CollectPath\CsBlockedDomains.csv -NoTypeInformation

	#Write-Log "Gathering database versions" -OutTo $OutTo
	# Test for server version
	# Test-CsDatabase

	Write-Log "Gathering network region information" -OutTo $OutTo
	Get-CsNetworkRegion | Select-Object NetworkRegionID,CentralSite,Description,@{name='BWAlternatePaths';expression={$_.BWAlternatePaths -join ','}} | Export-Csv $CollectPath\CsNetworkRegions.csv -NoTypeInformation
	Get-CsNetworkSite | Select-Object NetworkSiteID,NetworkRegionID,Description,BWPolicyProfileID,LocationPolicy,EnableLocationBasedRouting,VoiceRoutingPolicy | Export-Csv $CollectPath\CsNetworkSites.csv -NoTypeInformation
	Get-CsNetworkSubnet | Select-Object SubnetID,MaskBits,NetworkSiteID,Description | Export-Csv $CollectPath\CsNetworkSubnets.csv -NoTypeInformation
	Get-CsNetworkBandwidthPolicyProfile | Select-Object BWPolicyProfileID,Description,@{name='BWPolicy';expression={$_.BWPolicy -join ','}} | Export-Csv $CollectPath\CsNetworkBandwidthPolicies.csv -NoTypeInformation

	Write-Log "Gathering CLS information" -OutTo $OutTo
	Get-CsClsConfiguration | Out-File $CollectPath\CsOverview.txt -Append
	Show-CsClsLogging | Format-List | Out-File $CollectPath\CsOverview.txt -Append
	
	Write-Log -OutTo $OutTo
	Write-Log -OutTo $OutTo
}




if (!($ADOverviewOnly) -and !($CSOverviewOnly)){
	if(!(Test-Path $CollectPath)){
		Write-Log "Creating AssessmentCollection folder on Desktop" -OutTo $OutTo
		New-Item $CollectPath -ItemType directory | Out-Null
		Write-Log -OutTo $OutTo
	}
	
	Write-Log "$($env:ComputerName) Overview" -OutTo $OutTo

	###  Download Lync 2013 BPA
	#Start-BitsTransfer "http://download.microsoft.com/download/2/E/4/2E4CF74C-B323-4912-9ADD-C684E6346A6F/rtcbpa.msi" $CollectPath

	Write-Log "Gathering systeminfo output" -OutTo $OutTo
	systeminfo | Out-File $CollectPath\$env:computername.txt

	Write-Log "Gathering CPU information" -OutTo $OutTo
	Get-CimInstance Win32_Processor | Select-Object Name,SocketDesignation,NumberOfCores,NumberOfLogicalProcessors,CurrentClockSpeed,MaxClockSpeed | Out-File $CollectPath\$env:computername.txt -Append

	Write-Log "Gathering power plan" -OutTo $OutTo
	(Get-CimInstance Win32_PowerPlan -Namespace root\cimv2\power -Filter "IsActive='$true'").ElementName | Out-File $CollectPath\$env:computername.txt -Append

	Write-Log "Gathering firewall state" -OutTo $OutTo
	(netsh advfirewall show allprofiles) -match "Profile|State" | Out-File $CollectPath\$env:computername.txt -Append

	Write-Log "Gathering hard drive information" -OutTo $OutTo
	Get-CimInstance Win32_Volume -Filter 'DriveType = 3' | Where-Object {$_.DriveLetter -ne $null} | `
		Select-Object DriveLetter,Label,@{l='CapacityGB';e={"{0:N2}" -f ($_.Capacity/1GB)}},@{l='FreeSpaceGB';e={"{0:N2}" -f ($_.FreeSpace/1GB)}},@{l='FreeSpacePercent';e={"{0:N2}" -f (($_.FreeSpace/$_.Capacity)*100)}} | `
		Out-File $CollectPath\$env:computername.txt -Append

	Write-Log "Gathering current Lync/SfB versions" -OutTo $OutTo
	(Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" | Foreach-Object {Get-ItemProperty $_.pspath} | `
		Where-Object {($_.DisplayName -imatch "Microsoft Lync Server") -or ($_.DisplayName -imatch "Microsoft Office Web Apps Server 2013") -or ($_.DisplayName -imatch "Skype for Business Server")}) | `
		Format-Table DisplayName,DisplayVersion -AutoSize | Out-File $CollectPath\$env:computername.txt -Append

	Write-Log "Gathering Lync/SfB install path" -OutTo $OutTo
	(Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" | Foreach-Object {Get-ItemProperty $_.pspath} | `
		Where-Object {$_.DisplayName -imatch ", Core Components"}) | Format-List InstallLocation | Out-File $CollectPath\$env:computername.txt -Append

	Write-Log "Gathering QoS policies" -OutTo $OutTo
	if (Get-ChildItem "HKLM:\Software\Policies\Microsoft\Windows\QoS" -ErrorAction SilentlyContinue){
		Get-ChildItem "HKLM:\Software\Policies\Microsoft\Windows\QoS" -ErrorAction SilentlyContinue | Out-File $CollectPath\$env:computername.txt -Append
	}else{
		"No QoS policies" | Out-File $CollectPath\$env:computername.txt -Append
	}

	Write-Log "Gathering Certificates" -OutTo $OutTo
	Get-ChildItem Cert:\LocalMachine\My | select Subject,DnsNameList,Issuer,FriendlyName,NotBefore,NotAfter,EnhancedKeyUsageList, `
		@{l='SignatureAlgorithm';e={$_.SignatureAlgorithm.FriendlyName}},HasPrivateKey,@{l='PrivateKeySize';e={$_.PrivateKey.KeySize}}, `
		@{l='KeyExchangeAlgorithm';e={$_.PrivateKey.KeyExchangeAlgorithm}},Thumbprint | Out-File $CollectPath\$env:computername.txt -Append
	try {
		Get-CsCertificate | Format-List | Out-File $CollectPath\$env:computername.txt -Append
	}catch{
		#Continue
	}

	Write-Log "Gathering ipconfig" -OutTo $OutTo
	ipconfig /all | Out-File $CollectPath\$env:computername.txt -Append

	Write-Log "Gathering routes" -OutTo $OutTo
	route print | Out-File $CollectPath\$env:computername.txt -Append

	Write-Log "Gathering hosts file" -OutTo $OutTo
	Get-Content C:\Windows\system32\drivers\etc\hosts | Out-File $CollectPath\$env:computername.txt -Append

	Write-Log "Exporting event viewer Lync Server events" -OutTo $OutTo
	function GetMilliseconds ($date){
		$ts = New-TimeSpan -Start $date -End (Get-Date)
		[math]::Round($ts.TotalMilliseconds)
	}
	$startDate = GetMilliseconds((Get-Date).addDays(-2))
	$endDate = GetMilliseconds(Get-Date)
	wevtutil epl "Lync Server" $CollectPath\$env:computername.evtx /q:"*[System[TimeCreated[timediff(@SystemTime) >= $endDate] and TimeCreated[timediff(@SystemTime) <= $startDate]]]"
	
	Write-Log -OutTo $OutTo
	Write-Log -OutTo $OutTo
}

if ($PhoneNumbers){
	Write-Log "Review phone numbers for format" -OutTo $OutTo
	$PhoneNumbers | Format-Wide OfficePhone -AutoSize
	Remove-Variable PhoneNumbers
	
	Write-Log -OutTo $OutTo
}