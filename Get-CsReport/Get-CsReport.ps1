[cmdletbinding()]
param (
	[switch]$Timing
)

#https://sysadmins.lv/blog-en/test-whether-ca-server-is-online-and-which-interfaces-are-available.aspx
function Test-CAOnline {
	[CmdletBinding()]
	param(
		[Parameter(Position = 0)]
		[string]$Config,
		[switch]$ShowUI
	)
	
$signature = @"
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CertSrvIsServerOnline(
	string pwszServerName,
	ref bool pfServerOnline
);
"@
	
    Add-Type -MemberDefinition $signature -Namespace CryptoAPI -Name CertAdm
    $CertConfig = New-Object -ComObject CertificateAuthority.Config
    if ($Config -ne "" -and !$Config.Contains("\")) {
        Write-Error -Category InvalidArgument -ErrorId InvalidArgumentException -Message "Config string must be passed in 'CAHostName\CAName' form."
        break
    } elseif ($Config -eq "" -and !$ShowUI) {
        try {$Config = $CertConfig.GetConfig(0x3)}
        catch {
            Write-Error -Category ObjectNotFound -ErrorId ObjectNotFoundElement -Message "Certificate Services are not installed on local computer."
            break
        }
    } elseif ($Config -eq "" -and $ShowUI) {
        $Config = $CertConfig.GetConfig(0x1)
    }
	
    if ($Config) {
        [void]($Config -match "(.+)\\(.+)")
        $Server = $matches[1]
        $CAName = $matches[2]
        $ServerStatus = $false
        #$hresult = [CryptoAPI.CertAdm]::CertSrvIsServerOnline($Server,[ref]$ServerStatus)
        [CryptoAPI.CertAdm]::CertSrvIsServerOnline($Server,[ref]$ServerStatus) | Out-Null
        if ($ServerStatus) {
            $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
            $CertRequest = New-Object -ComObject CertificateAuthority.Request
            $CA = New-Object psobject -Property @{
                Name = $CAName;
                ICertAdmin = $true;
                ICertRequest = $true
            }
            try {$retn = $CertAdmin.GetCAProperty($Config,0x6,0,4,0)}
            catch {$CA.ICertAdmin = $false}
            try {$retn = $CertRequest.GetCAProperty($Config,0x6,0,4,0)}
            catch {$CA.ICertRequest = $false}
            $CA
        } else {
            Write-Error -Category ObjectNotFound -ErrorId ObjectNotFoundException -Message "Unable to find a Certification Authority server on '$Server'."
        }
    } else {
		return
	}
}

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
}

#Start total time
$StopWatch = [system.diagnostics.stopwatch]::startNew()

#Download Pat Richard's CS version XML
try {
	[xml]$VersionXmlCs = (New-Object System.Net.WebClient).DownloadString("https://www.ucunleashed.com/downloads/2641/version.xml")
}catch{
	$VersionXmlCs = $false
}


##############################################################################################################
##                                                                                                          ##
##                        Collect global info for AD, CA and Skype4B summaries                              ##
##                                                                                                          ##
##############################################################################################################

#Start all collect time
$CollectStopWatch = [system.diagnostics.stopwatch]::startNew()
#Start AD collect time
$StepStopWatch = [system.diagnostics.stopwatch]::startNew()

#Collect global info
#Collect AD forest properties
$adForest = Get-ADForest | Select-Object `
	Name,`
	RootDomain,`
	ForestMode,`
	Sites,`
	UPNSuffixes

#Collect AD domain properties
$adDomain = Get-ADDomain | Select-Object `
	Name,`
	Forest,`
	NetBIOSName,`
	DNSRoot,`
	ParentDomain,`
	@{name='ChildDomains';expression={$_.ChildDomains -join ','}},`
	DomainMode

#Collect Domain Controllers
try {
	$adDomainControllers = Get-ADDomainController -Filter * | Select-Object `
		Site,`
		@{name='HostName';expression={($_.HostName).ToLower()}},`
		@{name='IP Address';expression={$_.IPv4Address}},`
		@{name='OS';expression={$_.OperatingSystem -replace 'Windows ',''}},`
		@{name='OS Version';expression={$_.OperatingSystemVersion}},`
		@{name='Roles';expression={$_.OperationMasterRoles -join ', '}},`
		@{name='Global Catalog';expression={$_.IsGlobalCatalog}},`
		@{name='Read Only';expression={$_.IsReadOnly}}
}catch{
	Write-Warning "Unable to run Get-ADDomainController"
}

#Check CS and RTC groups for inheritance disabled
$adGroupAdmin = Get-ADGroup -Filter {adminCount -gt 0} -Properties adminCount -ResultSetSize $null | Where-Object Name -match "^CS|^RTC"

#Collect internal CAs
$adRoot = [ADSI]"LDAP://RootDSE"
$adDN = $adRoot.Get("rootDomainNamingContext")
$configRoot = [ADSI]"LDAP://CN=Configuration,$adDN"
$query = new-object System.DirectoryServices.DirectorySearcher($configRoot)
$query.filter = "(&(objectClass=PKIEnrollmentService)(CN=*))"
$query.SearchScope = "subtree"
$caResults = $query.findall()
$CAs = @()

#Process collected CAs for hosting server, common name, online status and access to WebServer template
foreach ($ca in $caResults){
	$output = $CA.GetDirectoryEntry()
	
	$caOut = "" | Select-Object CommonName,Server,WebServerTemplate,Online
	$caOut.Server = $output.dnsHostName | Out-String
	$caOut.CommonName = $output.cn | Out-String
	
	if (!((Test-CAOnline -Config "$($output.dnsHostName)\$($output.cn)" -ErrorAction SilentlyContinue).ICertRequest)){
		$caOut.Online = $false
		$CAs += $caOut
		continue
	}else{
		$caOut.Online = $true
	}
	
	if ($output.certificateTemplates -match "^WebServer$"){
		$caOut.WebServerTemplate = $true
	}else{
		$caOut.WebServerTemplate = $false
	}
	$CAs += $caOut
}

#Stop AD collect time
$StepStopWatch.Stop()
if ($Timing){
	Write-Output "AD collect: $($StepStopWatch.Elapsed.ToString('dd\.hh\:mm\:ss'))"
}

#Start CS collect time
$StepStopWatch = [system.diagnostics.stopwatch]::startNew()

#Collect sites
$csSites = Get-CsSite

#Collect users for global usage
$users = Get-CsUser -ResultSize Unlimited -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

#Collect users with address mismatch
$addressMismatchUsers = Get-CsAdUser | Where-Object {($_.WindowsEmailAddress -and $_.SipAddress) -and ($_.WindowsEmailAddress -ne ($_.SipAddress -replace "sip:",""))}

#Collect users who are disabled in AD but enabled in Skype
$disabledAdUsers = Get-CsAdUser -ResultSize Unlimited | `
	Where-Object {$_.UserAccountControl -match "AccountDisabled" -and $_.Enabled -eq $true} | `
	Select-Object Name,Enabled,SipAddress

#Collect admin users
$adminUsers = Get-AdUser -Filter {adminCount -gt 0} -Properties adminCount -ResultSetSize $null | `
	Foreach-Object {Get-CsUser $_.SamAccountName -ErrorAction SilentlyContinue}
	
#Collect analog devices
$analogDevices = Get-CsAnalogDevice | Where-Object Enabled -eq $true
	
#Collect common area phones
$commonAreaPhones = Get-CsCommonAreaPhone | Where-Object Enabled -eq $true

#Collect RGS workflows
$rgsWorkflows = Get-CsRgsWorkflow | Where-Object Active -eq $true

#Collect CS pools
$csPools = Get-CsPool | Where-Object Services -match "Registrar"

#Collect CS gateways
$csGateways = Get-CsService -PstnGateway

#Collect Management Replication
$csMgmtReplication = (Get-CsPool | Where-Object Services -match "Registrar|PersistentChatServer|MediationServer|Director|Edge|VideoInteropServer").Computers | `
	ForEach-Object {Get-CsManagementStoreReplicationStatus -ReplicaFqdn $_} | Where-Object UpToDate -eq $false

#Collect global CS info
$csSummary = "" | Select-Object CMS,SipDomain,MeetUrl,DialinUrl,AdminUrl
$csSummary.CMS = Get-CsService -CentralManagement | Select-Object SiteId,PoolFqdn,Version,Active
$csSummary.SipDomain = Get-CsSipDomain
$csSummary.MeetUrl = Get-CsSimpleUrlConfiguration | Select-Object -ExpandProperty SimpleUrl | Where-Object {$_.Component -eq "meet"}
$csSummary.DialinUrl = Get-CsSimpleUrlConfiguration | Select-Object -ExpandProperty SimpleUrl | Where-Object {$_.Component -eq "dialin"}
$csSummary.AdminUrl = Get-CsSimpleUrlConfiguration | Select-Object -ExpandProperty SimpleUrl | Where-Object {$_.Component -eq "cscp"}

#Collect sites info
$sites = Get-CsSite | Select-Object Identity,@{l='Name';e={$_.DisplayName}},Users,"Voice Users","RCC Users",Pools,Gateways
$pools = Get-CsPool | Where-Object Services -match "Registrar|PersistentChatServer|MediationServer|Director"

#Stop CS collect time
$StepStopWatch.Stop()
if ($Timing){
	Write-Output "CS collect: $($StepStopWatch.Elapsed.ToString('dd\.hh\:mm\:ss'))"
}

#Stop all collect time
$CollectStopWatch.Stop()
if ($Timing){
	Write-Output "Total collect: $($CollectStopWatch.Elapsed.ToString('dd\.hh\:mm\:ss'))"
}

#Create global user summary table and populate
$globalSummary = "" | Select-Object Sites,Users,"Address Mismatch","AD Disabled","Admin Users","Voice Users","RCC Users","Analog","Common Area",RGS,Pools,Gateways
$globalSummary.Sites = $csSites.Count
$globalSummary.Users = ($users | Where-Object {$_.Enabled -eq $true}).Count
$globalSummary."Address Mismatch" = $addressMismatchUsers.Count
$globalSummary."AD Disabled" = $disabledAdUsers.Count
$globalSummary."Admin Users" = $adminUsers.Count
$globalSummary."Voice Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true}).Count
$globalSummary."RCC Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true}).Count
$globalSummary."Analog" = $analogDevices.Count
$globalSummary."Common Area" = $commonAreaPhones.Count
$globalSummary.RGS = $rgsWorkflows.Count
$globalSummary.Pools = $csPools.Count
$globalSummary.Gateways = $csGateways.Count


##############################################################################################################
##                                                                                                          ##
##                 Process each site in topology for site summary, then server summary                      ##
##                                                                                                          ##
##############################################################################################################

foreach ($site in $sites){
	$sitePools = $pools | `
		Where-Object {$_.Site -eq $site.Identity} | `
		Select-Object @{l='Name';e={$_.Fqdn}},Services,Users,"Voice Users","RCC Users"
	$site.Users = 0
	$site."Voice Users" = 0
	$site."RCC Users" = 0
	$site.Pools = (Get-CsPool | Where-Object {$_.Services -match "Registrar" -and $_.Site -eq $site.Identity}).Count
	$site.Gateways = (Get-CsService -PstnGateway | Where-Object SiteId -eq $site.Identity).Count
	$siteServers = @()
	$siteFailItems = @()
	$siteWarnItems = @()
	$siteInfoItems = @()
	
	#If pools exist in site, process pools for servers
	if ($sitePools){
		#Process pools in site
		foreach ($pool in $sitePools){
			$pool.Users = ($users | Where-Object {$_.Enabled -eq $true -and $_.RegistrarPool -match $pool.Name}).Count
			$pool."Voice Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true -and $_.RegistrarPool -match $pool.Name}).Count
			$pool."RCC Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true -and $_.RegistrarPool -match $pool.Name}).Count
			
			$site.Users = $site.Users + $pool.Users
			$site."Voice Users" = $site."Voice Users" + $pool."Voice Users"
			$site."RCC Users" = $site."RCC Users" + $pool."RCC Users"
			
			$servers = (Get-CsPool $pool.Name).Computers | Select-Object `
				@{label='Site';expression={$site.Identity}},`
				Pool,`
				@{label='Server';expression={$_}},`
				AdminCount,`
				Role,`
				Version,`
				Hardware,`
				vmTools,`
				Sockets,`
				Cores,`
				Memory,`
				HDD,`
				PowerPlan,`
				Uptime,`
				OS,`
				DotNet,`
				Certs,`
				CACerts,`
				QoS,`
				DnsCheck,`
				LastUpdate,`
				Connectivity,`
				Permission
			
			#Process servers in pool
			foreach ($server in $servers){
				#Start server collect time
				$StepStopWatch = [system.diagnostics.stopwatch]::startNew()
				
				#Determine CS role
				if ($pool.Services -match "Registrar" -and $pool.Services -match "UserServer"){
					$server.Role = "Front End"
				}elseif ($pool.Services -match "Registrar"){
					$server.Role = "SBA/SBS"
				}elseif ($pool.Services -match "Director"){
					$server.Role = "Director"
				}elseif ($pool.Services -match "PersistentChatServer"){
					$server.Role = "pChat"
				}elseif ($pool.Services -match "MediationServer"){
					$server.Role = "Mediation"
				}
				
				#Check for adminCount gt 1
				$server.adminCount = (Get-ADComputer $(($server.Server).Split(".")[0]) -Properties adminCount -ErrorAction SilentlyContinue | `
				Select-Object adminCount).adminCount
				
				#Test connectivity for queries
				$server.Pool = $pool.Name
				$server.Connectivity = Test-Connection -ComputerName $server.Server -Count 1 -ErrorAction SilentlyContinue
				
				$error.Clear()
				Get-CimInstance Win32_ComputerSystem -ComputerName $server.Server -ErrorAction SilentlyContinue | Out-Null
				
				if ($error.Exception.Message -match "access denied"){
					Write-Verbose "$($server.Server) is not accessible due to permissions."
					$server.Permission = $false
				}elseif ($error.Exception.Message -match "WinRM cannot complete the operation"){
					Write-Verbose "$($server.Server) is not accessible due to WinRM."
					$server.Connectivity = $false
				}else{
					Write-Verbose "$($server.Server) is accessible."
					$server.Permission = $true
				}
				
				if ($server.Connectivity -and $server.Permission){
					#Get CS product version
					$server.Version = (Get-CimInstance Win32_Product -ComputerName $server.Server | Where-Object Name -match "(Lync Server|Skype for Business Server)" | `
					Where-Object Name -notmatch "(Debugging Tools|Resource Kit)" | Select-Object Name,Version | Sort-Object Version -Descending)[0].Version
					if ($VersionXmlCs){
						$server.Version = "$($server.Version)<br />($(($VersionXmlCs.catalog.UpdateVersion | Where-Object Id -eq $server.Version).UpdateName))"
					}else{
						$server.Version = "$($server.Version)"
					}
					
					#Get hardware info
					$computer = Get-CimInstance Win32_ComputerSystem -ComputerName $server.Server -ErrorAction SilentlyContinue
					if ($computer.Manufacturer -match "VMware"){
						$server.Hardware = "VMware"
					}elseif ($computer.Manufacturer -match "Microsoft"){
						$server.Hardware = "Microsoft"
					}else{
						$server.Hardware = "$($computer.Manufacturer) $($computer.Model)"
					}
					
					#If VMware get VMware Tools info
					if ($server.Hardware -eq "VMware"){
						$server.vmTools = Invoke-Command -ComputerName $server.Server -ScriptBlock {
							Set-Location (Get-Item "HKLM:\Software\VMware, Inc.\VMware Tools").GetValue("InstallPath")
							& .\VMwareToolboxCmd.exe upgrade status
						}
						if (!($server.vmTools)){
							$server.vmTools = "Not Installed"
						}elseif ($server.vmTools -match "up-to-date"){
							$server.vmTools = "Up-to-date"
						}else{
							$server.vmTools = "Update available"
						}
					}else{
						$server.vmTools = "N/A"
					}
					
					#Get CPU info
					$processors = Get-CimInstance Win32_Processor -ComputerName $server.Server | Select-Object Name,MaxClockSpeed,CurrentClockSpeed,NumberOfCores,NumberOfLogicalProcessors
					$server.Sockets = $processors.Count
					if (!($server.Sockets)){
						$server.Sockets = 1
					}
					$server.Cores = $processors[0].NumberOfCores * $server.Sockets
					
					#Get RAM info
					$server.Memory = (Get-CimInstance Win32_OperatingSystem -ComputerName $server.Server).TotalVisibleMemorySize/1MB
					
					#Get HDD info
					$server.HDD = Get-CimInstance Win32_Volume -Filter 'DriveType = 3' -ComputerName $server.Server | `
						Where-Object DriveLetter -ne $null | `
						Select-Object DriveLetter,Label,@{l='CapacityGB';e={$_.Capacity/1GB}},@{l='FreeSpaceGB';e={$_.FreeSpace/1GB}},@{l='FreeSpacePercent';e={($_.FreeSpace/$_.Capacity)*100}}
					
					#Get PowerPlan
					$server.PowerPlan = (Get-CimInstance Win32_PowerPlan -ComputerName $server.Server -Namespace root\cimv2\power -Filter "IsActive='$true'").ElementName
					
					#Get uptime
					$boot = Get-CimInstance Win32_OperatingSystem -ComputerName $server.Server | Select-Object LastBootUpTime,LocalDateTime
					[int]$server.Uptime = (New-TimeSpan -Start $boot.LastBootUpTime -End $boot.LocalDateTime).TotalHours
					
					#Get OS info
					$server.OS = (Get-CimInstance Win32_OperatingSystem -ComputerName $server.Server).Caption
					
					#Get certificate info
					$server.Certs = Invoke-Command -ComputerName $server.Server -ScriptBlock {
						$certsOutput = Get-CsCertificate -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | `
							Foreach-Object {
								$error.Clear()
								Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq $_.Thumbprint
								if ($error.Exception.Message -match "Assigned certificate not found or untrusted"){
									$notFoundOrUntrusted = $true
								}else{
									$notFoundOrUntrusted = $false
								}
							} | `
							Select-Object -Unique Subject,Issuer,NotAfter,@{l='SignatureAlgorithm';e={$_.SignatureAlgorithm.FriendlyName}},@{l='NotFoundOrUntrusted';e={$notFoundOrUntrusted}}
						
						return $certsOutput
					}
					
					#Get CA certificate info
					$server.CACerts = Invoke-Command -ComputerName $server.Server -ScriptBlock {
						$CACerts = "" | Select-Object MisplacedCertInRootStore,DuplicateRoot,RootCertCount,DuplicateFriendlyName,MisplacedRootInIntStore
						
						#https://blogs.technet.microsoft.com/uclobby/2015/06/19/checks-to-do-in-the-lyncskype4b-certificate-store/
						$CACerts.MisplacedCertInRootStore = Get-ChildItem cert:\LocalMachine\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject}
						$CACerts.DuplicateRoot = Get-ChildItem cert:\LocalMachine\root | Group-Object -Property Thumbprint | Where-Object {$_.Count -gt 1}
						$CACerts.RootCertCount = Get-ChildItem cert:\LocalMachine\root | Measure-Object
						$CACerts.DuplicateFriendlyName = Get-ChildItem cert:\LocalMachine\my | Group-Object -Property FriendlyName | Where-Object {$_.Count -gt 1}
						$CACerts.MisplacedRootInIntStore = Get-ChildItem Cert:\localmachine\CA | Where-Object {$_.Issuer -eq $_.Subject}
						return $CACerts
					}
					
					#Get QoS Policies
					$csPool = Get-CsPool | Where-Object Computers -match $server.Server
					$isConfServer = (Get-CsService -ConferencingServer) -match $csPool.Identity
					$isMedServer = (Get-CsService -MediationServer) -match $csPool.Identity
					
					$server.QoS = Invoke-Command -ComputerName $server.Server -ArgumentList $isConfServer,$isMedServer -ScriptBlock {
						param (
							$isConfServer = $args[0],
							$isMedServer = $args[1]
						)
					
						$QoSPolicies = "" | Select-Object Audio,Video,AppShare,Signaling
						
						$qosGroupPolicies = Get-ChildItem -Path HKLM:\Software\Policies\Microsoft\Windows\QoS | ForEach-Object {Get-ItemProperty $_.PSPath} | `
							Select-Object @{l="Name";e={($_.PSPath -split "\\")[7]}},Version,Protocol,"Application Name",`
							"Local Port","Local IP","Local IP Prefix Length","Remote Port","Remote IP","Remote IP Prefix Length","DSCP Value", `
							AppName,SrcPortLow,SrcPortHigh,DSCP
						
						if ($qosGroupPolicies){
							if ($isConfServer){
								$audioPolicy = $qosGroupPolicies | Where-Object {$_.DSCP -match 46 -or $_."DSCP Value" -match 46}
								$videoPolicy = $qosGroupPolicies | Where-Object {$_.DSCP -match 34 -or $_."DSCP Value" -match 34}
								#$appSharePolicy = $qosGroupPolicies | Where-Object {$_.DSCP -match 18 -or $_."DSCP Value" -match 18}
								
								#Check for audio QoS policies
								if ($audioPolicy | Where-Object Version -eq "1.0"){
									if (($audioPolicy | Where-Object "Local Port" -match $isConfServer.AudioPortStart) | Where-Object "Local Port" -match ($isConfServer.AudioPortStart + $isConfServer.AudioPortCount)){
										$QoSPolicies.Audio = $true
									}else{
										$QoSPolicies.Audio = $false
									}
								}elseif ($audioPolicy | Where-Object Version -eq "2.0"){
									if (($audioPolicy | Where-Object SrcPortLow -match $isConfServer.AudioPortStart) | Where-Object SrcPortHigh -match ($isConfServer.AudioPortStart + $isConfServer.AudioPortCount)){
										$QoSPolicies.Audio = $true
									}else{
										$QoSPolicies.Audio = $false
									}
								}
								
								#Check for video QoS policies
								if ($videoPolicy | Where-Object Version -eq "1.0"){
									if (($videoPolicy | Where-Object "Local Port" -match $isConfServer.VideoPortStart) | Where-Object "Local Port" -match ($isConfServer.VideoPortStart + $isConfServer.VideoPortCount)){
										$QoSPolicies.Video = $true
									}else{
										$QoSPolicies.Video = $false
									}
								}elseif ($videoPolicy | Where-Object Version -eq "2.0"){
									if (($videoPolicy | Where-Object SrcPortLow -match $isConfServer.VideoPortStart) | Where-Object SrcPortHigh -match ($isConfServer.VideoPortStart + $isConfServer.VideoPortCount)){
										$QoSPolicies.Video = $true
									}else{
										$QoSPolicies.Video = $false
									}
								}
								
								#Check for appshare QoS policies
							<# 	if ($appSharePolicy | Where-Object Version -eq "1.0"){
									if (($videoPolicy | Where-Object "Local Port" -match $isConfServer.AppSharingPortStart) | Where-Object "Local Port" -match ($isConfServer.AppSharingPortStart + $isConfServer.AppSharingPortCount)){
										$QoSPolicies.AppShare = $true
									}else{
										$QoSPolicies.AppShare = $false
									}
								}elseif ($appSharePolicy | Where-Object Version -eq "2.0"){
									if (($appSharePolicy | Where-Object SrcPortLow -match $isConfServer.AppSharingPortStart) | Where-Object SrcPortHigh -match ($isConfServer.AppSharingPortStart + $isConfServer.AppSharingPortCount)){
										$QoSPolicies.AppShare = $true
									}else{
										$QoSPolicies.AppShare = $false
									}
								} #>
							}elseif ($isMedServer){
								#Check for audio QoS policy for mediation
								if ($audioPolicy | Where-Object Version -eq "1.0"){
									if (($audioPolicy | Where-Object "Local Port" -match $isMedServer.AudioPortStart) | Where-Object "Local Port" -match ($isMedServer.AudioPortStart + $isMedServer.AudioPortCount)){
										$QoSPolicies.Audio = $true
									}else{
										$QoSPolicies.Audio = $false
									}
								}elseif ($audioPolicy | Where-Object Version -eq "2.0"){
									if (($audioPolicy | Where-Object SrcPortLow -match $isMedServer.AudioPortStart) | Where-Object SrcPortHigh -match ($isMedServer.AudioPortStart + $isMedServer.AudioPortCount)){
										$QoSPolicies.Audio = $true
									}else{
										$QoSPolicies.Audio = $false
									}
								}
							}
						}else{
							#No QoS Policies found
							$QoSPolicies.Audio = $false
							$QoSPolicies.Video = $false
							$QoSPolicies.AppShare = $false
							$QoSPolicies.Signaling = $false
						}
						
						return $QoSPolicies
					}
					
					#Get .NET Framework
					$server.DotNet = Invoke-Command -ComputerName $server.Server -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release").Release}
					$server.DotNet = $VersionHashNDP.Item($server.DotNet)
					
					#Get DNS check
					if (Resolve-DnsName $server.Server -DnsOnly -Type A -QuickTimeout){
						$server.DnsCheck = "Pass"
					}else{
						$server.DnsCheck = "Fail"
					}
					
					#Get last update install
					$server.LastUpdate = ((Get-HotFix -ComputerName $server.Server | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue)[0]).InstalledOn
				}
				
				#Stop server collect time
				$StepStopWatch.Stop()
				if ($Timing){
					Write-Output $server.server
					Write-Output "Server collect: $($StepStopWatch.Elapsed.ToString('dd\.hh\:mm\:ss'))"
				}
			}
			
			#Aggregate servers from each pool in site
			$siteServers += $servers
		}
		
		#Null variable for next loop
		$siteServersHtmlTable = $null
		
		foreach ($server in $siteServers){
			#Start server html time
			$StepStopWatch = [system.diagnostics.stopwatch]::startNew()
			
			#Perform tests and build servers HTML table rows
			$htmlTableRow = "<tr>"
			$htmlTableRow += "<td><b>$(($server.Pool).Split(".")[0])</b></td>"
			if ($server.adminCount -eq 1){
				$siteFailItems += "<li>One or more servers were detected with adminCount greater than 0.`
				See <a href='https://github.com/argiesen/Get-CsReport/wiki/Server-Tests#admincount-greater-than-0' target='_blank'>adminCount greater than 0</a>.</li>"
			}
			
			#If server is accessible build row with values
			if ($server.Connectivity -and $server.Permission){
				#Column server name
				$htmlTableRow += "<td>$(($server.Server).Split(".")[0])</td>"
				
				#Column server role
				$htmlTableRow += "<td>$($server.Role)</td>"
				
				#Column CS version
				$htmlTableRow += "<td>$($server.Version)</td>"
				
				#Column server hardware
				$htmlTableRow += "<td>$($server.Hardware)</td>"
				
				#Column VMware Tools status
				if ($server.vmTools -match "(Up-to-date|N/A)"){
					$htmlTableRow += "<td>$($server.vmTools)</td>"
				}elseif($server.vmTools -match "Not Installed"){
					$htmlTableRow += "<td class=""fail"">$($server.vmTools)</td>"
					$siteFailItems += "<li>One or more servers were detected as VMware VMs without VMware Tools installed.</li>"
				}else{
					$htmlTableRow += "<td class=""warn"">$($server.vmTools)</td>"
					$siteWarnItems += "<li>One or more servers were detected as VMware VMs with an update available for VMware Tools.</li>"
				}
				
				#Column server sockets and socket warning
				if ($server.Sockets -eq $server.Cores -and $server.Sockets -gt 1){
					$htmlTableRow += "<td class=""warn"">$($server.Sockets)</td>"
					$siteWarnItems += "<li>One or more servers CPU sockets is equal to cores. See `
						<a href='https://github.com/argiesen/Get-CsReport/wiki/Server-Tests#sockets-equal-to-corescores-less-than-4' `
						target='_blank'>Sockets equal to cores/Cores less than 4</a>.</li>"
				}else{
					$htmlTableRow += "<td>$($server.Sockets)</td>"
				}
				
				#Column server cores
				if ($server.Cores -lt 4 -and $server.Role -ne "SBA/SBS"){
					$htmlTableRow += "<td class=""warn"">$($server.Cores)</td>"
					$siteWarnItems += "<li>One or more servers total cores is less than 4. See `
						<a href='https://github.com/argiesen/Get-CsReport/wiki/Server-Tests#sockets-equal-to-corescores-less-than-4' `
						target='_blank'>Sockets equal to cores/Cores less than 4</a>.</li>"
				}else{
					$htmlTableRow += "<td>$($server.Cores)</td>"
				}
				
				#Column server memory and inadequate server memory warning
				if ($server.Memory -lt 16.00 -and $server.Role -ne "SBA/SBS"){
					$server.Memory = "$('{0:N2}GB' -f $server.Memory)"
					$htmlTableRow += "<td class=""warn"">$($server.Memory)</td>"
					$siteWarnItems += "<li>RAM is less than 16GB.</li>"
					
				}else{
					$server.Memory = "$('{0:N2}GB' -f $server.Memory)"
					$htmlTableRow += "<td>$($server.Memory)</td>"
				}
				
				#Column server drives and drive space warning
				if ($server.HDD.FreeSpaceGB -lt 32){
					$htmlTableRow += "<td class=""warn""><ul.hdd style='margin: 0;'>"
					foreach ($hdd in $server.HDD){
						$htmlTableRow += "<li>$($hdd.DriveLetter) $('{0:N2}GB' -f $hdd.FreeSpaceGB)/$('{0:N2}GB' -f $hdd.CapacityGB)</li>"
					}
				}else{
					$htmlTableRow += "<td><ul.hdd style='margin: 0;'>"
					foreach ($hdd in $server.HDD){
						$htmlTableRow += "<li>$($hdd.DriveLetter) $('{0:N2}GB' -f $hdd.FreeSpaceGB)/$('{0:N2}GB' -f $hdd.CapacityGB)</li>"
					}
				}
				$htmlTableRow += "</ul.hdd></td>"
				
				#Column server power plan
				if ($server.PowerPlan -eq "High Performance"){
					$htmlTableRow += "<td>$($server.PowerPlan)</td>"
				}else{
					$htmlTableRow += "<td class=""fail"">$($server.PowerPlan)</td>"
					$siteFailItems += "<li>One or more servers power plan is not set to high performance. See `
						<a href='https://support.microsoft.com/en-us/help/2207548/slow-performance-on-windows-server-when-using-the-balanced-power-plan' `
						target='_blank'>KB2207548</a>.</li>"
				}
				
				#Column server uptime
				if ($server.Uptime -gt 2160){
					$htmlTableRow += "<td class=""warn"">$($server.Uptime)</td>"
				}else{
					$htmlTableRow += "<td>$($server.Uptime)</td>"
				}
				
				#Column server OS and unsupported OS warning
				if ($server.OS -match "Server 2008 R2" -and $server.Role -eq "SBA/SBS" -and $server.Version -match "5.0"){
					$htmlTableRow += "<td class=""warn"">$($server.OS -replace 'Microsoft Windows ','')</td>"
					$siteWarnItems += "<li>One or more servers is running Server 2008 R2 which is End-of-Life. `
						Because this is a Lync Server 2013 SBA this is just a warning. See `
						<a href='https://technet.microsoft.com/en-us/library/dn951388.aspx?f=255&mspperror=-2147217396#Anchor_1' `
						target='_blank'>Operating systems for Skype for Business Server 2015</a>.</li>"
				}elseif ($server.OS -match "Server 2008 R2"){
					$htmlTableRow += "<td class=""fail"">$($server.OS -replace 'Microsoft Windows ','')</td>"
					$siteFailItems += "<li>One or more servers is running Server 2008 R2 which is End-of-Life. See `
						<a href='https://technet.microsoft.com/en-us/library/dn951388.aspx?f=255&mspperror=-2147217396#Anchor_1' `
						target='_blank'>Operating systems for Skype for Business Server 2015</a>.</li>"
				}elseif ($server.OS -notmatch "Server (2012|2012 R2|2016)"){
					$htmlTableRow += "<td class=""fail"">$($server.OS -replace 'Microsoft Windows ','')</td>"
					$siteFailItems += "<li>One or more servers is not running a supported OS. See `
						<a href='https://technet.microsoft.com/en-us/library/dn951388.aspx?f=255&mspperror=-2147217396#Anchor_1' `
						target='_blank'>Operating systems for Skype for Business Server 2015</a>.</li>"
				}else{
					$htmlTableRow += "<td>$($server.OS -replace 'Microsoft Windows ','')</td>"
				}
				
				#Column server .NET and .NET version warning
				if ($server.DotNet -notmatch "(4.6.2|4.5.2)"){
					$htmlTableRow += "<td class=""warn"">$($server.DotNet)</td>"
					$siteWarnItems += "<li>One or more servers .NET Framework is out-of-date. Version 4.5.2 or 4.6.2 is recommended. See `
						<a href='https://blogs.technet.microsoft.com/nexthop/2016/02/11/on-net-framework-4-6-2-and-skype-for-businesslync-server-compatibility/' `
						target='_blank'>.NET Framework 4.6.2 and Skype for Business/Lync Server Compatibility</a>.</li>"
				}else{
					$htmlTableRow += "<td>$($server.DotNet)</td>"
				}
				
				#Column server certificate status and certificate warnings
				$certStatus = "" | Select-Object Expiration,SignatureAlgorithm,NotFoundOrUntrusted
				if ($server.Certs.NotAfter -lt (Get-Date).AddDays(30)){
					$certStatus.Expiration = "Fail"
					$siteFailItems += "<li>One or more servers certificates is expiring inside 30 days.</li>"
				}elseif ($server.Certs.NotAfter -lt (Get-Date).AddDays(60)){
					$certStatus.Expiration = "Warn"
					$siteWarnItems += "<li>One or more servers certificates is expiring inside 60 days.</li>"
				}
				if ($server.Certs.SignatureAlgorithm -match "sha1RSA"){
					$certStatus.SignatureAlgorithm = "Warn"
					$siteWarnItems += "<li>One or more servers certificates signing algorithm is SHA1.</li>"
				}
				if ($server.Certs.NotFoundOrUntrusted -eq $true){
					$certStatus.NotFoundOrUntrusted = "Fail"
					$siteWarnItems += "<li>One or more servers certificates is missing or untrusted.</li>"
				}
				if ($certStatus -match "Fail"){
					$htmlTableRow += "<td class=""fail"">Fail</td>"
				}elseif ($certStatus -match "Warn"){
					$htmlTableRow += "<td class=""warn"">Warn</td>"
				}else{
					$htmlTableRow += "<td>Pass</td>"
				}
				
				#Root and intermediate certificate warnings
				if ($server.CACerts.MisplacedCertInRootStore){
					$siteFailItems += "<li>One or more servers have non-root certificates in the Trusted Root Certifiate Store. This will cause the Front-End service to fail to start. `
						See <a href='https://github.com/argiesen/Get-CsReport/wiki/Server-Tests#non-root-certificates-in-trusted-root-certificate-store' `
						target='_blank'>Non-root certificates in Trusted Root Certificate Store</a> for more information.</li>"
				}
				if ($server.CACerts.DuplicateRoot){
					$siteWarnItems += "<li>One or more servers have duplicate certificates in the Trusted Root Certificate Store. `
						See <a href='https://github.com/argiesen/Get-CsReport/wiki/Server-Tests#duplicates-in-trusted-root-certificate-store' `
						target='_blank'>Duplicates in Trusted Root Certificate Store</a> for more information.</li>"
				}
				if ($server.CACerts.RootCertCount.Count -gt 100){
					$siteWarnItems += "<li>One or more servers has more than 100 certificates in the Trusted Root Certificate Store. This can cause TLS failures. `
						See <a href='https://github.com/argiesen/Get-CsReport/wiki/Server-Tests#more-than-100-certificates-in-trusted-root-certificate-store' `
						target='_blank'>More than 100 certificates in Trusted Root Certificate Store</a> for more information.</li>"
				}
				if ($server.CACerts.DuplicateFriendlyName){
					$siteWarnItems += "<li>One or more servers have certificates with duplicate friendly names. `
						See <a href='https://github.com/argiesen/Get-CsReport/wiki/Server-Tests#duplicate-friendly-name' `
						target='_blank'>Duplicate Friendly Name</a> for more information.</li>"
				}
				
				#Column QoS check
				if ($server.QoS -match $false){
					$htmlTableRow += "<td class=""fail"">Fail</td>"
					$siteFailItems += "<li>One or more servers is missing or has misconfigured QoS policies."
				}else{
					$htmlTableRow += "<td>Pass</td>"
				}
				
				#Column DNS check and DNS check warning
				if ($server.DnsCheck -ne "Pass"){
					$htmlTableRow += "<td class=""fail"">$($server.DnsCheck)</td>"
					$siteFailItems += "<li>One or more servers is missing DNS A records."
				}else{
					$htmlTableRow += "<td>$($server.DnsCheck)</td>"
				}
				
				#Column last update install date
				if ($server.LastUpdate -lt (Get-Date).addDays(-90)){
					$server.LastUpdate = ($server.LastUpdate).ToString('MM/dd/yyyy')
					$htmlTableRow += "<td class=""warn"">$($server.LastUpdate)</td>"
					$siteWarnItems += "<li>One or more servers has not had Windows patches applied in the last 90 days."
				}else{
					$server.LastUpdate = ($server.LastUpdate).ToString('MM/dd/yyyy')
					$htmlTableRow += "<td>$($server.LastUpdate)</td>"
				}
			}else{
				#If server is unaccessible build row with blank values
				$htmlTableRow += "<td class=""fail"">$(($server.Server).Split(".")[0])</td>"
				if (!($server.Connectivity)){
					$siteFailItems += "<li>One or more servers are not accessible or offline.</li>"
				}elseif (!($server.Permission)){
					$siteFailItems += "<li>One or more servers could not be queried due to permissions. `
						Verify the user generating this report has local administrator rights on each server.</li>"
				}
				$htmlTableRow += "<td></td>" #$server.Role
				$htmlTableRow += "<td></td>" #$server.Version
				$htmlTableRow += "<td></td>" #$server.Hardware
				$htmlTableRow += "<td></td>" #$server.vmTools
				$htmlTableRow += "<td></td>" #$server.Sockets
				$htmlTableRow += "<td></td>" #$server.Cores
				$htmlTableRow += "<td></td>" #$server.Memory
				$htmlTableRow += "<td></td>" #$server.HDD
				$htmlTableRow += "<td></td>" #$server.PowerPlan
				$htmlTableRow += "<td></td>" #$server.Uptime
				$htmlTableRow += "<td></td>" #$server.OS
				$htmlTableRow += "<td></td>" #$server.DotNet
				$htmlTableRow += "<td></td>" #$server.Certs
				$htmlTableRow += "<td></td>" #$server.QoS
				$htmlTableRow += "<td></td>" #$server.DnsCheck
				$htmlTableRow += "<td></td>" #$server.LastUpdate
			}
			$htmlTableRow += "</tr>"
			
			$siteServersHtmlTable += $htmlTableRow
			
			#Stop server HTML time
			$StepStopWatch.Stop()
			if ($Timing){
				Write-Output $server.server
				Write-Output "Server HTML: $($StepStopWatch.Elapsed.ToString('dd\.hh\:mm\:ss'))"
			}
		}
		
		#Convert site header, site summary, and site server summary to HTML and combine with body
		$siteHtmlBody += "<h3>$($Site.Name)</h3>
			<p>$($site | Select-Object * -ExcludeProperty Identity,Name | ConvertTo-Html -As Table -Fragment)</p>
			<p>
			<table class=""csservers"">
			<tr>
			<th width=""100px"">Pool</th>
			<th width=""100px"">Server</th>
			<th width=""60px"">Role</th>
			<th width=""80px"">Version</th>
			<th width=""100px"">Hardware</th>
			<th width=""70px"">VMware Tools</th>
			<th width=""40px"">Sockets</th>
			<th width=""40px"">Cores</th>
			<th width=""40px"">Memory</th>
			<th width=""130px"">HDD</th>
			<th width=""95px"">Power Plan</th>
			<th width=""40px"">Uptime</th>
			<th width=""120px"">OS</th>
			<th width=""30px"">.NET</th>
			<th width=""30px"">Certs</th>
			<th width=""30px"">QoS</th>
			<th width=""30px"">DNS</th>
			<th width=""50px"">Last Update</th>
			</tr>
			$siteServersHtmlTable
			</table>
			</p>"
		
		#Create site message lists
		if ($siteFailItems){
			$siteHtmlFail = "<p>Failed Items</p>
				<ul>
				$($siteFailItems | Select-Object -Unique)
				</ul>"
		}else{
			$siteHtmlFail = $null
		}
		if ($siteWarnItems){
			$siteHtmlWarn = "<p>Warning Items</p>
				<ul>
				$($siteWarnItems | Select-Object -Unique)
				</ul>"
		}else{
			$siteHtmlWarn = $null
		}
		if ($siteInfoItems){
			$siteHtmlInfo = "<p>Info Items</p>
				<ul>
				$($siteInfoItems | Select-Object -Unique)
				</ul>"
		}else{
			$siteHtmlInfo = $null
		}
		
		#Combine site HTML body and lists
		$siteHtmlBody = "$siteHtmlBody
			$siteHtmlFail
			$siteHtmlWarn
			$siteHtmlInfo"
	}
}


##############################################################################################################
##                                                                                                          ##
##                                       Building Final HTML                                                ##
##                                                                                                          ##
##############################################################################################################

#Start HTML build time
$StepStopWatch = [system.diagnostics.stopwatch]::startNew()

#Header
$HtmlHead = "<html>
	<style>
		BODY{font-family: Calibri; font-size: 11pt; margin-top: 10px; margin-bottom: 60px;}
		H1{font-size: 22px;}
		H2{font-size: 19px; padding-top: 10px;}
		H3{font-size: 17px; padding-top: 8px;}
		TABLE{border: 1px solid black; border-collapse: collapse; font-size: 9pt; table-layout: fixed;}
		TABLE.csservers{table-layout: fixed;}
		TABLE.testresults{width: 850px;}
		TABLE.summary{text-align: center; width: auto;}
		TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
		TH.summary{width: 80px;}
		TH.test{width: 120px;}
		TH.description{width: 150px;}
		TH.outcome{width: 50px}
		TH.comments{width: 120px;}
		TH.details{width: 270px;}
		TH.reference{width: 60px;}
		TD{border: 1px solid black; padding: 5px; vertical-align: top; word-wrap:break-word;}
		td.pass{background: #7FFF00;}
		td.warn{background: #FFFF00;}
		td.fail{background: #FF0000; color: #ffffff;}
		td.info{background: #85D4FF;}
		tr:nth-child(even){background: #dae5f4;}
		tr:nth-child(odd){background: #b8d1f3;}
		ul.hdd{list-style: inside; padding-left: 0px; list-style-type:square;}
		ul{list-style: inside; padding-left: 10px; list-style-type:square; margin: -10px 0;}
		p2{font-size: 9pt;}
	</style>
	<body>"

#Active Directory
foreach ($suffix in $($adForest.UPNSuffixes)){
	$adSuffixes += "<li>$suffix</li>"
}

#Build AD site HTML list
foreach ($site in $($adForest.Sites)){
	$adSites += "<li>$site</li>"
}

#Convert global summary tables to HTML and combine with AD body
$adHtmlBody = "<h2>Environment Overview</h2>
	<p></p>
	<h3>Active Directory</h3>
	<p><b>Forest Name:</b> $($adForest.Name)<br />
	<b>Forest Mode:</b> $($adForest.ForestMode)<br />
	<b>Domain Name:</b> $($adDomain.DNSRoot) ($($adDomain.NetBIOSName))<br />
	<b>Domain Mode:</b> $($adDomain.DomainMode)<br />
	<b>UPN Suffixes:</b>
	<ul>
	$adSuffixes
	</ul>
	</p>
	<p><b>Sites:</b>
	<ul>
	$adSites
	</ul>
	</p>"
	
#Convert adminCount groups to HTML and combine with AD body
if ($adGroupAdmin){
	$adHtmlBody += "<p>Failed Items</p>
		<ul>"
	foreach ($adGroup in $adGroupAdmin){
		$adHtmlBody += "<li>$($adGroup.Name) has adminCount greater than 0. `
		See <a href='https://github.com/argiesen/Get-CsReport/wiki/User-Tests#admincount-greater-than-0' target='_blank'>adminCount greater than 0</a>.</li>"
	}
	$adHtmlBody += "</ul>"
}
	
#Convert Domain Controllers to HTML and combine with AD body
if ($adDomainControllers){
	$adHtmlBody += "<h3>Domain Controllers</h3>
		<p>$($adDomainControllers | ConvertTo-Html -As Table -Fragment)</p>"
}

#Certificate Authorities
if ($CAs){
	#Build CA HTML table rows
	foreach ($ca in $CAs){
		$htmlTableRow = "<tr>"
		$htmlTableRow += "<td>$($ca.CommonName)</td>"
		$htmlTableRow += "<td>$($ca.Server)</td>"
		if ($ca.Online){
			$htmlTableRow += "<td>$($ca.Online)</td>"
			if (!($ca.WebServerTemplate)){
				$caWarnItems += "<li>$($ca.Server): Web server template is unavailable.</li>"
			}
		}else{
			$htmlTableRow += "<td class=""fail"">$($ca.Online)</td>"
			$caWarnItems += "<li>$($ca.Server): CA server is unavailable (this is expected if this CA is designed as an offline root).</li>"
		}
		
		$caHtmlTable += $htmlTableRow
	}
	
	if ($caWarnItems){
		$caHtmlWarn = "<p>Warning Items</p>
			<ul>
			$caWarnItems
			</ul>"
	}
	
	#Build CA HTML
	$caHtmlBody = "<h3>Certificate Authorities</h3>
		<table>
		<tr>
		<th>Common Name</th>
		<th>Server</th>
		<th>Online</th>
		</tr>
		$caHtmlTable
		</table>
		$caHtmlWarn"
}

#Generate global CS HTML
#Generate CMS HTML
$cmsHtml = "<b>Active CMS:</b> $(($csSummary.CMS | Where-Object Active -eq $true).PoolFqdn)"
if ($csSummary.CMS | Where-Object Active -eq $false){
	$cmsHtml += "<br /><b>Backup CMS:</b> $(($csSummary.CMS | Where-Object Active -eq $false).PoolFqdn)"
}

#Generate SIP domains HTML
foreach ($sipDomain in $($csSummary.SipDomain)){
	if ($sipDomain.IsDefault){
		$sipDomainHtml += "<li>$($sipDomain.Name) (Default)</li>"
	}else{
		$sipDomainHtml += "<li>$($sipDomain.Name)</li>"
	}
}

#Generate meet URLs HTML
foreach ($meetUrl in $($csSummary.MeetUrl)){
	$meetUrlHtml += "<li>$($meetUrl.ActiveUrl) ($($meetUrl.Domain))</li>"
}

#Generate dialin URLs HTML
foreach ($dialinUrl in $($csSummary.DialinUrl)){
	$dialinUrlHtml += "<li>$($dialinUrl.ActiveUrl) ($($dialinUrl.Domain))</li>"
}

if ($csMgmtReplication){
	$cmsReplicaHtml = "<p><b>Failed CMS Replicas:</b>
		$($csMgmtReplication | ConvertTo-Html -As Table -Fragment)</p>"
}

#Generate CS topology info HTML
$csTopologyHtml = "<p>$cmsHtml
	<br /><b>SIP Domains:</b>
		<ul>
		$sipDomainHtml
		</ul></p>
	<p><b>Meet URLs:</b>
		<ul>
		$meetUrlHtml
		</ul></p>
	<p><b>Dailin URLs:</b>
		<ul>
		$dialinUrlHtml
		</ul></p>
	<p><b>Admin URL:</b> $($csSummary.AdminUrl.ActiveUrl)</p>
	$cmsReplicaHtml"

#Global Summary
$csSummaryHtml = "<p><b>Summary:</b>
	$($globalSummary | ConvertTo-Html -As Table -Fragment)</p>"

#Generate messages
if ($globalSummary."Address Mismatch" -gt 0){
	$globalWarnItems += "<li>Users exist whose SIP address and primary STMP addresses do not match. `
		This will cause Exchange integration issues for these users. `
		See <a href='https://github.com/argiesen/Get-CsReport/wiki/User-Tests#address-mismatch' target='_blank'>Address Mismatch</a>.</li>"
}
if ($globalSummary."AD Disabled" -gt 0){
	$globalWarnItems += "<li>Users exist that are disabled in AD but are enabled for Skype4B. `
		These users may still be able to login to Skype4B. `
		See <a href='https://github.com/argiesen/Get-CsReport/wiki/User-Tests/_edit#ad-disabled' target='_blank'>AD Disabled</a>.</li>"
}
if ($globalSummary."Admin Users" -gt 0){
	$globalInfoItems += "<li>Users exist with adminCount greater than 0. `
		Attempts to modify these users Skype4B configurations may fail with access denied. `
		See <a href='https://github.com/argiesen/Get-CsReport/wiki/User-Tests#admincount-greater-than-0' target='_blank'>adminCount greater than 0</a>.</li>"
}
if ($csMgmtReplication){
	$globalFailItems += "<li>One or more servers CMS replicas are not up to date. `
		See <a href='https://github.com/argiesen/Get-CsReport/wiki/Server-Tests#cms-replica-not-up-to-date' target='_blank'>CMS replica not up-to-date</a>.</li>"
}

#Generate message lists
if ($globalFailItems){
	$globalHtmlFail = "<p>Failed Items</p>
		<ul>
		$globalFailItems
		</ul>"
}
if ($globalWarnItems){
	$globalHtmlWarn = "<p>Warning Items</p>
		<ul>
		$globalWarnItems
		</ul>"
}
if ($globalInfoItems){
	$globalHtmlInfo = "<p>Info Items</p>
		<ul>
		$globalInfoItems
		</ul>"
}

#Combine csTopologyHtml and csSummaryHtml with message lists
$globalCsHtmlBody += "<br />
	<h2>Skype for Business Server</h2>
	$csTopologyHtml
	$csSummaryHtml
	$globalHtmlFail
	$globalHtmlWarn
	$globalHtmlInfo"

#Close Report
$HtmlTail = "</body>
	</html>"

#Stop HTML build time
$StepStopWatch.Stop()
if ($Timing){
	Write-Output "HTML build: $($StepStopWatch.Elapsed.ToString('dd\.hh\:mm\:ss'))"
}

#Stop total time
$StopWatch.Stop()
if ($Timing){
	Write-Output "Total: $($StopWatch.Elapsed.ToString('dd\.hh\:mm\:ss'))"
}

#Title generated at end of script for runtime information
$HtmlTitle = "<h1>Skype for Business Report</h1>
	<p2>Date: $(Get-Date)<br />
	Author: $(whoami)<br />
	Machine: $(hostname)<br />
	Elapsed: $($StopWatch.Elapsed.ToString('mm\:ss'))</p2>"

#Combine HTML sections
$htmlReport = $HtmlHead + $HtmlTitle + $adHtmlBody + $caHtmlBody + $globalCsHtmlBody + $siteHtmlBody + $HtmlTail

$htmlReport | Out-File "$env:UserProfile\Desktop\CsReport.html" -Encoding UTF8

Invoke-Expression "$env:UserProfile\Desktop\CsReport.html"
