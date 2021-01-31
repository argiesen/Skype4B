# Title: Install-CsServer
# Version: 1.5
# Author: Andy Giesen
# Date: 2018/3/20
# 
# 
#
#
#
#

<#
    .SYNOPSIS
      This script automates deployment of Skype for Business Server roles and adjunct components including Office Online Server and IIS Application Request Routing.
	  
	  It is intended to be run start to finish rather than a-la-carte. A scheduled task is created to facilitate unattended installation across reboots.
	  
	  Basic Troubleshooting
	  If an error is encountered, attempt to stop and restart the script using the desktop icons.
	  If the error persists after a restart of the script, run the script from PowerShell as .\Install-CsServer.ps1 -Resume, this may reveal more information about the cause.
	  If necessary, a task section may be skipped by using .\Install-CsServer.ps1 -RunTask "TaskName" -Resume
	  
	.DESCRIPTION
	  ***Prerequisites per ServerType***
	  FEStd, FEEnt, Dir, PChat, Med:
	  -SFB media mounted via hypervisor or MediaPath defined with to path of setup.exe or .iso/.img.
		*Mounting ISO within Windows is not supported as it is not persistant across reboots.
	  -SourcePath should be defined with path to Windows sources folder.
	  
	  Edge:
	  -SFB media mounted via hypervisor or MediaPath defined with to path of setup.exe or .iso/.img.
		*Mounting ISO within Windows is not supported as it is not persistant across reboots.
	  -SourcePath should be defined with path to Windows sources folder.
	  -CertOrg, CertCity, CertState, CertCountry, and CertOU must be specified for External certificate request.
	  -PrimaryDNSSuffix must be defined.
	  
	  OOS:
	  -OOS media mounted via hypervisor or MediaPath defined with to path of setup.exe or .iso/.img.
		*Mounting ISO within Windows is not supported as it is not persistant across reboots.
	  -Certificate created and imported with chain.
	  -FriendlyName may be defined with the friendly name.
	  -WACExternalUrl should be defined. Otherwise defaults to https://oos.addomain.com.
	  -WACPrimaryServer must be defined if this is not the first OOS server in the farm.
	  
	  IISARR:
	  -Certificate created and imported with chain.
	  -FriendlyName may be defined with the friendly name.
	  -WebServicesIntFQDN must be defined.
	  -WebServicesExtFQDN must be defined.
	  -PrimaryDNSSuffix must be defined.
	  -Domains must be defined with list of SIP domains.
	
	  =====================================================================================
	
	  ***Tasks***
	  PrereqCheck
	  Runs prerequisite checks and reports. Applicable to all ServerType.
	  
	  PrereqDownload
	  Downloads prerequisite software and files. Applicable to all ServerType.
	  
	  PrereqInstall
	  Installs prerequisite software, roles/features, and additional software (eg. Wireshark). Applicable to all ServerType.
	  
	  CSCoreInstall
	  Installs Skype for Business core components, Admin Tools, and SQL Express. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge
	  
	  CSADPrep
	  Active Directory preparation for Schema, Forest, and Domain. Adds current user to CS and RTC groups. Requires PrimaryServer switch and Domain Admins, Enterprise Admins, and Schema Admins membership. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med
	  
	  CSComponentInstall
	  Creates file share for Standard edition servers, exports topology file for Edge servers/imports topology file on Edge servers, installs local management store, runs bootstrapper to install Skype for Business components, and installs SQL databases if not already. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge
	  
	  CSCertificates
	  Performs online or offline certificate requests, assigns to services. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge
	  
	  CSUpdates
	  Installs Debugging Tools and Resource Kit. Applies Skype for Business Server updates and installs database updates. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge
	  
	  CSConfigure
	  On Edge servers, verifies IP addresses gainst the topology, renames the interfaces INTERNAL and EXTERNAL, creates static routes for RFC1918 address ranges, disables NetBIOS and dynamic DNS registration. Deploys KHIs to all roles. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge
	  
	  CSServices
	  Starts Skype for Business Server services. Enterprise Pools must be started manually. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge
	  
	  CSCustomize
	  Deploy monitoring reports, configure ports and QoS policies, misc. policies, dial plan, ABS normalization rules, disable IE ESC, add internal web services URLs to trusted sites. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge
	  
	  OWASInstall
	  Installs OOS software and patches. Applicable to ServerType: OOS
	  
	  OWASConfigure
	  Create OfficeWebAppsFarm. Requires certificate to already be imported and trusted. Applicable to ServerType: OOS
	  
	  ARRConfigure
	  Configures IIS ARR rules. Requires certificate to already be imported and trusted. Applicable to ServerType: IISARR
	  
	  Applications
	  Installs third party applications. Applicable to all ServerType.
	  
	  Logon
	  Customizes user profile with pinned taskbar items. Applicable to all ServerType.
	  
	  PostInstallTasks
	  **Currently under development**
	  Creates PostInstallTasks.txt on the desktop with commands for Microsoft DNS server record creation, DHCPUtil output, OAuth configuration, and OWA integration configuration.
	  
	.PARAMETER RunTask
	  Run a specific task:
	  PrereqCheck, PrereqDownload, PrereqInstall, CSCoreInstall, CSADPrep, CSComponentInstall, CSCertificates, CSUpdates, CSConfigure, CSServices, CSCustomize, OWASInstall, OWASConfigure, ARRConfigure, Applications, Logon, PostInstallTasks
    .PARAMETER ServerType
	  Server role:
	  FEStd, FEEnt, Dir, PChat, Med, Edge, OOS, IISARR
	.PARAMETER MediaPath
	  Skype for Business Server install media path. Can be path to setup.exe, .iso/.img, or local/remote base folder path. If image file, the image will be mounted and the path to setup.exe discovered automatically.
	.PARAMETER SourcePath
	  Path to Windows sources (Sources\WinSxS) for role and feature installation. Defaults to $env:SystemDrive\Windows\WinSxS. Does not automatically mount images or discover path at this time. If using Windows media, it must be mounted and path to WinSxS (sources\sxs) defined.
	.PARAMETER InstallDrive
	  Drive letter to install Skype for Business Server and others components.
	.PARAMETER PrimaryServer
	  Defines the deployment instance that will make global changes including:
	  Active Directory preparation
	  Request OAuth certificate
	  Install and update backend databases
	  Deploy monitoring reports
	  Configure media ports
	  Configure policies
	  Configure dial plans
	  Configure address book normalizations
	  Import device updates
	.PARAMETER PrepareAD
	  Indicates that Active Directory preparation tasks should be executed. Requires Schema Admins, Enterprise Admins, and Domain Admins.
	.PARAMETER PrepareFirstStd
	  Indicates that this is the first standard edition front end in the environment and to prepare the RTC SQL instance.
	.PARAMETER PrimaryDNSSuffix
	  Primary DNS suffix to be configured on Edge and reverse proxy servers.
	.PARAMETER FileShareServer
	  File share server to perform pre-deployment validation against. If null and the ServerType is FEStd then a file share will be configured locally.
	.PARAMETER FileSharePath
	  Local file share path if the file share is local. Default is C:\CsShare.
	.PARAMETER FileShareName
	  File share name to validate if remote, or create if local.
	.PARAMETER SQLServer
	  SQL server to perform pre-deployment validation against.
	.PARAMETER SQLInstance
	  SQL server instance to perform pre-deployment validation against. If null then default instance is assumed.
	.PARAMETER MonReportUser
	  Service account username for monitoring reports deployment.
	.PARAMETER MonReportPassword
	  Service account password for monitoring reports deployment.
	.PARAMETER WebServicesIntIP
	  **Currently under development** Internal web services IP address for post install tasks DNS creation commands.
	.PARAMETER WebServicesExtIP
	  **Currently under development** External web services IP address for post install tasks DNS creation commands.
	.PARAMETER WebServicesIntFQDN
	  Internal web services FQDN for IIS ARR configuration. Used as the destination.
	.PARAMETER WebServicesExtFQDN
	  External web services FQDN for IIS ARR configuration. Other URLs are dynamically generated.
	.PARAMETER Domains
	  Array for domains to create IIS ARR simple URL rules for. Example: "domain1.com","domain2.com"
	.PARAMETER CAName
	  Internal certificate authority name. Must be in ServerName\CAName format. If left null the CA name is automatically discovered from Active Directory. If none exists, offline certificate requests are generated.
	.PARAMETER CertCity
	  City for CSR generation.
	.PARAMETER CertState
	  State for CSR generation.
	.PARAMETER CertCountry
	  Country for CSR generation.
	.PARAMETER CertOrg
	  Organization for CSR generation.
	.PARAMETER CertOU
	  OU for CSR generation.
	.PARAMETER CertKeySize
	  Certificate key size. Only 2048 and 4096 are accepted.
	.PARAMETER OfflineRequest
	  Forces offline certificate requests.
	.PARAMETER PortAudioStart
	  Audio port range starting port. Default is 49152.
	.PARAMETER PortAudioEnd
	  Audio port range ending port. Port count is automatically determined. Default is 57500.
	.PARAMETER PortVideoStart
	  Video port range starting port. Default is 57501.
	.PARAMETER PortVideoEnd
	  Video port range ending port. Port count is automatically determined. Default is 65535.
	.PARAMETER PortAppShareStart
	  AppSharing port range starting port. Default is 40803.
	.PARAMETER PortAppShareEnd
	  Video port range ending port. Port count is automatically determined. Default is 49151.
	.PARAMETER PortFileTransferStart
	  File transfer port range starting port. Default is 40702.
	.PARAMETER PortFileTransferEnd
	  File transfer port range ending port. Port count is automatically determined. Default is 40802.
	.PARAMETER QoSAudioDSCP
	  DSCP value for audio. Default is 46 (EF).
	.PARAMETER QoSVideoDSCP
	  DSCP value for video. Default is 34 (AF41).
	.PARAMETER QoSAppShareDSCP
	  DSCP value for appsharing. Default is 18 (AF21).
	.PARAMETER QoSServer
	  Configures server side port ranges and QoS policies.
	.PARAMETER QoSClient
	  Configures client side port ranges.
	.PARAMETER Policies
	  Configures a variety of common policies. Useful for lab, demo, or greenfield deployments.
	  PIN Policy
	  Mobility Policy
	  Access Edge Configuration
	  Push Notifications
	  Public IM Provider
	  Conferencing Policy
	  Persistent Chat Policy (if PChat pool exists)
	  Archiving Policy (if Archiving database is defined)
	  Client Policy (Enabled SkypeUI and MOH)
	  External Access Policies
	.PARAMETER DialPlan
	  Configures US national dial plan. Useful for lab, demo, or greenfield deployments.
	.PARAMETER DeviceUpdates
	  Downloads, imports, and approves LPE device updates during pool deployment.
	.PARAMETER MonitoringReports
	  Deploys monitoring reports.
	.PARAMETER ABSNormNA
	  Configures ABS normalization rules for North America.
	.PARAMETER ABSNormIntl
	  Configures ABS normalization rules for international dial plans.
	.PARAMETER ACSyslog
	  Install AudioCodes Syslog Viewer.
	.PARAMETER Wireshark
	  Install Wireshark.
	.PARAMETER SQLMgmtStudio
	  Install SQL Management Studio 2016
	.PARAMETER KeepPowerPlan
	  Windows power plan will be set to High Performance for Front End, Mediation, and Edge server roles. This parameter will preserve the current power plan.
	.PARAMETER ShowServerManager
	  By default Server Manager will be disabled from starting on logon. This parameter will keep the Server Manager starting on logon.
	.PARAMETER SkipWindowsUpdates
	  Skips running Windows Updates post deployment.
	.PARAMETER PCI31
	  Set IISCrypto to use the PCI 3.1 template. PCI 3.1 disables TLS 1.0. Ensure that all connecting clients and servers support and are enabled for TLS 1.1 or higher.
	  
	  More information here: https://blogs.msdn.microsoft.com/kaushal/2011/10/02/support-for-ssltls-protocols-on-windows/
	.PARAMETER WACPrimaryServer
	  Indicates the primary OOS server that additional OOS servers should use to join an existing farm.
	.PARAMETER WACExternalUrl
	  OOS external URL formatted as https://oos.domain.com.
	.PARAMETER WACInternalUrl
	  OOS internal URL formatted as https://oos.domain.com. By default this will equal WACExternalURL.
	.PARAMETER FriendlyName
	  OOS or IIS ARR certificate friendly name. May be automatically discovered by matching WACExternalUrl or WebServicesExtFQDN against installed certificates.
	.PARAMETER PrereqsOnly
	  Executes prerequisite validations only.
	.PARAMETER DownloadsOnly
	  Only performs software downloads. Downloads software for all roles for staging in environments without internet access.
	.PARAMETER SoftwareDir
	  Directory for DownloadsOnly to download software. Default is C:\CsInstall\software.
	.PARAMETER PostInstallTasks
	  **Currently under development** Generates DHCP options, DNS creation commands, and other post install tasks.
	.PARAMETER OverridePrereqs
	  Override prerequisite failure that prevents installation. Use with caution, this may result in failures during or after deployment.
	.PARAMETER Clean
	  Clears temporary working directory of all previous logs, downloads, and configurations.
	.PARAMETER Manual
	  The script does not automatically resume after reboots. Useful for debugging.
	.PARAMETER Resume
	  Run to resume script from last completed task.
	.EXAMPLE
      Install-CsServer.ps1 -ServerType "FEStd" -PrimaryServer -PrepareAD -PrepareFirstStd -QoSServer -QoSClient -Policies -DialPlan -DeviceUpdates -ACSyslog -Wireshark -ABSNormNA -MonitoringReports -MonReportUser "contoso\csreports" -MonReportPassword "Password1"
	  
	  This command will prepare the first standard edition server, prepare AD, configure QoS, policies, dial plan, import and approve device updates, install Syslog Viewer, Wireshark, set the power plan to High Performance, and deploy monitoring reports.
	.EXAMPLE
	  Install-CsServer.ps1 -ServerType "FEStd" -PrimaryServer -QoSServer -QoSClient -DeviceUpdates -ACSyslog -Wireshark -Sources\Path D:\Sources\WinSxS
	  
	  This command will install a standard edition server into an existing topology with Windows media for role/feature installation, configure QoS, import and approve device updates, install Syslog Viewer, Wireshark, set the power plan to High Performance, and deploy monitoring reports.
	.EXAMPLE
      Install-CsServer.ps1 -ServerType "FEEnt" -PrimaryServer -PrepareAD -SQLServer sql1 -FileShareServer fs1 -FileShareName CsShare -QoSServer -QoSClient -Policies -DialPlan -DeviceUpdates -ACSyslog -Wireshark -ABSNormNA -MonitoringReports -MonReportUser "contoso\csreports" -MonReportPassword "Password1"
	  
	  This command will install a enterprise edition front end server as the "primary server" to prepare AD, configure QoS globally for clients and the pool, policies, dial plan, import and approve device updates, install Syslog Viewer, Wireshark, set the power plan to High Performance, and deploy monitoring reports.
	  
	  Install-CsServer.ps1 -ServerType "FEEnt" -QoSServer -Wireshark
	  
	  This command will install the additional enterprise front end servers in the pool.
	.EXAMPLE
      Install-CsServer.ps1 -ServerType "Edge" -QoSServer -MediaPath C:\install\en_skype_for_business_server_2015_x64_dvd_6622058.iso -PrimaryDNSSuffix "contoso.local" -CertOrg "Contoso" -CertOU "Engineering" -CertCity "Redmond" -CertState "Washington" -CertCountry "US" -OfflineRequest
	  
	  This command will deploy an Edge server specifying unmounted SFB installation media, the primary DNS suffix, and offline certificate requests.
	.EXAMPLE
      Install-CsServer.ps1 -ServerType "OOS" -WACUrl "https://oos.contoso.com" -MediaPath C:\install\en_office_online_server_may_2016_x64_dvd_8484396.iso
	  
	  This command will deploy an Office Online Server with a internal and external URL of oos.contoso.com and unmounted OOS installation media.
	.EXAMPLE
      Install-CsServer.ps1 -ServerType "IISARR" -WebServicesExtFQDN csweb-ext.contoso.com -WebServicesIntFQDN csweb-int.contoso.com -WacUrl https://oos.contoso.com -Domains "contoso.com" -PrimaryDNSSuffix "contoso.local" -CertOrg "Contoso" -CertOU "Engineering" -CertCity "Redmond" -CertState "Washington" -CertCountry "US"
	  
	  This command will deploy IIS ARR with simple URLs for the contoso.com and csweb-ext.contoso.com external web services URL and proxy them to the csweb-int.contoso.com internally.
	
#>

[cmdletbinding()]
param(
	[ValidateSet("PrereqCheck", "PrereqDownload", "PrereqInstall", "CSCoreInstall", "CSADPrep", "CSComponentInstall", "CSCertificates", "CSUpdates", "CSConfigure", "CSServices", "CSCustomize", "OWASInstall", "OWASConfigure", "ARRConfigure", "Applications", "WindowsUpdates", "Logon", "PostInstallTasks")]
	[string]$RunTask="PrereqCheck",
	[ValidateSet("FEStd", "FEEnt", "Dir", "PChat", "Med", "Edge", "OOS", "IISARR", "All")]
	[string]$ServerType,
	[string]$MediaPath,
	[string]$SourcePath = "$env:SystemDrive\Windows\WinSxS",
	[ValidatePattern("^[c-zC-Z]:")]
	[string]$InstallDrive,
	[switch]$PrimaryServer,
	[switch]$PrepareAD,
	[switch]$PrepareFirstStd,
	[string]$PrimaryDNSSuffix,
	[alias("FSServer")]
	[string]$FileShareServer,
	[alias("FSPath")]
	[string]$FileSharePath = "C:\CsShare",
	[alias("FSName")]
	[string]$FileShareName = "CsShare",
	[string]$SQLServer,
	[string]$SQLInstance,
	[string]$MonReportUser,
	[string]$MonReportPassword,
	[string]$WebServicesIntIP,
	[string]$WebServicesExtIP,
	[string]$WebServicesIntFQDN,
	[string]$WebServicesExtFQDN,
	[array]$Domains,
	[string]$CAName,
	[ValidateNotNull()]
	[string]$CertCity = "",
	[ValidateNotNull()]
	[string]$CertState = "",
	[ValidateNotNull()]
	[string]$CertCountry = "",
	[ValidateNotNull()]
	[string]$CertOrg = "",
	[ValidateNotNull()]
	[string]$CertOU = "",
	[ValidateSet("2048", "4096")]
	[int]$CertKeySize = 2048,
	[ValidateRange(1024,65535)]
	[int]$PortAudioStart = 49152,
	[ValidateRange(1024,65535)]
	[int]$PortAudioEnd = $PortAudioStart + 8348,
	[ValidateRange(1024,65535)]
	[int]$PortVideoStart = 57501,
	[ValidateRange(1024,65535)]
	[int]$PortVideoEnd = $PortVideoStart + 8034,
	[ValidateRange(1024,65535)]
	[int]$PortAppShareStart = 40803,
	[ValidateRange(1024,65535)]
	[int]$PortAppShareEnd = $PortAppShareStart + 8348,
	[ValidateRange(1024,65535)]
	[int]$PortFileTransferStart = 40702,
	[ValidateRange(1024,65535)]
	[int]$PortFileTransferEnd = $PortFileTransferStart + 100,
	[ValidateRange(0,56)]
	[int]$QoSAudioDSCP = 46,
	[ValidateRange(0,56)]
	[int]$QoSVideoDSCP = 34,
	[ValidateRange(0,56)]
	[int]$QoSAppShareDSCP = 18,
	#[ValidateRange(0,56)]
	#[int]$QoSSignalingDSCP = 24,
	[switch]$OfflineRequest,
	[switch]$QoSServer,
	[switch]$QoSClient,
	[switch]$Policies,
	[switch]$DialPlan,
	[switch]$DeviceUpdates,
	[switch]$MonitoringReports,
	[switch]$ABSNormNA,
	[switch]$ABSNormIntl,
	[switch]$ACSyslog,
	[switch]$Wireshark,
	[switch]$Firefox,
	[switch]$Chrome,
	[switch]$SQLMgmtStudio,
	[switch]$KeepPowerPlan,
	[switch]$ShowServerManager,
	[switch]$SkipWindowsUpdates,
	[switch]$PCI31,
	[string]$WACPrimaryServer,
	[alias("WACUrl")]
	[string]$WACExternalUrl,
	[string]$WACInternalUrl = $WACExternalUrl,
	[string]$FriendlyName,
	[switch]$PrereqsOnly,
	[switch]$DownloadsOnly,
	[string]$SoftwareDir,
	[switch]$PostInstallTasks,
	[switch]$OverridePrereqs,
	[switch]$Clean,
	[switch]$Manual,
	[switch]$Resume,
	[PSCredential]$Credential
)



#https://rcmtech.wordpress.com/2014/03/12/powershell-function-to-pin-and-unpin-from-windows-taskbar/
function Pin-Taskbar([string]$Item = "",[string]$Action = ""){
    if($Item -eq ""){
        Write-Error -Message "You need to specify an item" -ErrorAction Continue
    }
    if($Action -eq ""){
        Write-Error -Message "You need to specify an action: Pin or Unpin" -ErrorAction Continue
    }
    if((Get-Item -Path $Item -ErrorAction SilentlyContinue) -eq $null){
        Write-Error -Message "$Item not found" -ErrorAction Continue
    }
    $Shell = New-Object -ComObject "Shell.Application"
    $ItemParent = Split-Path -Path $Item -Parent
    $ItemLeaf = Split-Path -Path $Item -Leaf
    $Folder = $Shell.NameSpace($ItemParent)
    $ItemObject = $Folder.ParseName($ItemLeaf)
    $Verbs = $ItemObject.Verbs()
    switch($Action){
        "Pin"   {$Verb = $Verbs | Where-Object -Property Name -EQ "Pin to Tas&kbar"}
        "Unpin" {$Verb = $Verbs | Where-Object -Property Name -EQ "Unpin from Tas&kbar"}
        default {Write-Error -Message "Invalid action, should be Pin or Unpin" -ErrorAction Stop}
    }
    if($Verb -eq $null){
        Write-Error -Message "That action is not currently available on this item" -ErrorAction Continue
    } else {
        $Result = $Verb.DoIt()
    }
}

#http://www.ehloworld.com/2545
function New-TrustedIESite {
	<#
		.SYNOPSIS  
			Programmatically add a URI to a security zone in Internet Explorer.
		
		.DESCRIPTION  
			URIs can be added to the Trusted Sites, Local Intranet, Restricted Sites, or Internet zones in Internet Explorer. Full support for using either any protocol including http, https, ftp, etc.
		
		.NOTES  
			Version      	   		: 1.0 
			Wish list						: scope for machine (all users) or current user
													: remove entry
			Rights Required			: TBD
			Sched Task Req'd		: No
			Lync Version				: N/A
			Author(s)      			: Pat Richard, Lync MVP
			Email/Blog/Twitter	: pat@innervation.com  http://www.ehloworld.com  @patrichard
			Dedicated Post			: http://www.ehloworld.com/2545
			Disclaimer   				: You running this script means you won't blame me if this breaks your stuff. This script is
		    										provided AS IS without warranty of any kind. I disclaim all implied warranties including, 
														without limitation, any implied warranties of merchantability or of fitness for a particular
		    										purpose. The entire risk arising out of the use or performance of the sample scripts and 
		    										documentation remains with you. In no event shall I be liable for any damages whatsoever 
		    										(including, without limitation, damages for loss of business profits, business interruption,
		    										loss of business information, or other pecuniary loss) arising out of the use of or inability
		    										to use the script or documentation. 
			Acknowledgements 		: http://msdn.microsoft.com/en-us/library/system.uri(v=VS.90).aspx
		                      : http://blogs.technet.com/b/heyscriptingguy/archive/2005/02/14/how-can-i-add-a-web-site-to-the-trusted-sites-zone.aspx
			Assumptions					: 
			Limitations					: Not tested in an environment where a GPO locks down the security zones
			Known issues				: None yet, but I'm sure you'll find some!    		
		
		.LINK  
			http://www.ehloworld.com/2545
		
		.EXAMPLE
			.\New-TrustedIESite.ps1 -url https://www.contoso.com -zone 1 
		 
			Description
			-----------
			Adds https://www.contoso.com to the Trusted Intranet Sites in Internet Explorer
	#>
	#Requires -Version 2.0
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		# Defines the URL to be placed into a security zone. URL must contain protocol, such as http, https, ftp, etc.
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)] 
		[ValidateNotNullOrEmpty()]
		[string] $url,
	
		# This parameter defines what security zone the url specified via -url will be placed in. Options are 1 (Local Intranet), 2 (Trusted Sites), 3 (Internet), and 4 (Restricted Sites)
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)] 
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1,4)]
		[int] $zone = 1,
		
		# Specified whether the site should be added for all users. If not specified, it is configured for the current user only
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)] 
		[switch] $AllUsers
	)
	
	$error.clear()
	[object] $uri = [system.URI] $url
	[string] $scheme = ($uri).Scheme
	[string] $fqdn = ($uri).host
	[string] $resource = $fqdn.split(".",2)[0]
	[string] $domainname = $fqdn.split(".",2)[1]
	[string] $regkey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
	
	# domain
	if (Test-Path "$regkey\$domainname") { 
		Write-Warning "Domain $domainname already exists."
	} else { 
		# md "$regkey\$domainname" | Out-Null
		New-Item -Path "$regkey\$domainname" | Out-Null
		Write-Output "Domain name $domainname added"
	} 
	 
	# resource
	if (Test-Path "$regkey\$domainname\$resource") { 
		Write-Warning "Site $resource.$domainname already exists."
	} else { 
		New-Item -Path "$regkey\$domainname\$resource" | Out-Null
		Write-Output "Resource $resource added"
	} 
	
	# scheme
	if (Get-ItemProperty -Name $scheme -path "$regkey\$domainname\$resource" -ErrorAction SilentlyContinue) { 
		Write-Warning "Scheme $scheme already exists."
		Write-Warning "Setting for zone $zone"
		Set-ItemProperty "$regkey\$domainname\$resource" -Name $scheme -Value $zone | Out-Null
	} else { 
		New-ItemProperty "$regkey\$domainname\$resource" -Name $scheme -Value $zone -PropertyType "DWord" | Out-Null
		Write-Output "Scheme $scheme configured"
	}
}

function Install-Software {
	[CmdletBinding(SupportsShouldProcess = $true, SupportsPaging = $true)]
	param (
		[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true, HelpMessage = "No installation file specified")]
		[ValidateNotNullOrEmpty()]
		[string]$File,
		[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[array]$Switches,
		[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string]$Title,
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
		[string]$WaitForProcessName,
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
		[ValidatePattern("^HKLM:|^HKCU:|^\D:\\|^\\\\\w")]
		[string]$ConfirmPath,
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
		[string]$ConfirmName,
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
		[string]$ConfirmHotfix,
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
		[array]$IgnoreExitCodes,
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
		[switch]$DontWait,
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
		[ValidateSet("Continue", "Stop")]
		[string]$ErrorHandling = "Continue"
	)

	if ($Title){
		Write-Log "Installing $Title."
	}

	if ($ConfirmPath){
		if (Test-Path $ConfirmPath){
			Write-Log "Already installed." -Indent $Indent -OutTo $LogOutTo
			return
		}
	}elseif ($ConfirmName){
		$name64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -match $ConfirmName}
		$name32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -match $ConfirmName}
		if ($name64 -or $name32){
			Write-Log "Already installed." -Indent $Indent -OutTo $LogOutTo
			return
		}
	}elseif ($ConfirmHotfix){
		if (Get-Hotfix $ConfirmHotfix -ErrorAction SilentlyContinue){
			Write-Log "Already installed." -Indent $Indent -OutTo $LogOutTo
			return
		}
	}
	
	if ((Split-Path $File) -eq ""){
		if (Test-Path "$(Get-Location)\$File"){
			$File = "$(Get-Location)\$File"
		}elseif (Test-Path "C:\Windows\System32\$File"){
			$File = "C:\Windows\System32\$File"
		}else{
			Write-Log "Installation failed: Unable to resolve File." -Level "Error" -Indent $Indent -OutTo $LogOutTo
			if ($ErrorHandling -eq "Continue"){
				return
			}elseif ($ErrorHandling -eq "Stop"){
				exit
			}
		}
	}
	
	$error.clear()
	if (Test-Path $File){
		Write-Log "Install string: $File $Switches" -Indent $Indent -OutTo $LogOutTo
		
		Push-Location
		Set-Location (Split-Path $File)
		if ($Switches){
			if ($DontWait){
				$process = Start-Process -FilePath (Split-Path $File -Leaf) -Verb RunAs -ArgumentList $Switches -Passthru
			}else{
				$process = Start-Process -FilePath (Split-Path $File -Leaf) -Verb RunAs -ArgumentList $Switches -Wait -Passthru
			}
		}else{
			if ($DontWait){
				$process = Start-Process -FilePath (Split-Path $File -Leaf) -Verb RunAs -Passthru
			}else{
				$process = Start-Process -FilePath (Split-Path $File -Leaf) -Verb RunAs -Wait -Passthru
			}
		}
		Pop-Location
		if (!($DontWait)){
			if ($IgnoreExitCodes){
				foreach ($errcode in $IgnoreExitCodes){
					if ($process.ExitCode -eq $errcode){
						$ignoreExitCode = $true
					}
				}
			}
			if ($ignoreExitCode){
				Write-Log "Installation returned error code that was ignored: $($process.ExitCode)" -Level "Warn" -Indent $Indent -OutTo $LogOutTo
			}elseif ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010){
				Write-Log "Installation returned error code: $($process.ExitCode)" -Level "Error" -Indent $Indent -OutTo $LogOutTo
				if ($ErrorHandling -eq "Continue"){
					return
				}elseif ($ErrorHandling -eq "Stop"){
					exit
				}
			}
		}

		if ($WaitForProcessName){
			Start-Sleep -s 1
			Write-Log "Waiting for process `"$WaitForProcessName`" to finish running" -Indent $Indent -OutTo $LogOutTo
			Wait-Process -Name $WaitForProcessName -ErrorAction SilentlyContinue -ErrorVariable wait
			if ($wait){
				$error.clear()
			}
		}
	}else{
		Write-Log "$File does not exist." -Level "Error" -Indent $Indent -OutTo $LogOutTo
		if ($ErrorHandling -eq "Continue"){
			return
		}elseif ($ErrorHandling -eq "Stop"){
			exit
		}
	}
	
	if ($error){
		Write-Log "Installation failed: An error has occurred." -Level "Error" -Indent $Indent -OutTo $LogOutTo
		Write-Log $error.Exception -Level "Error" -Indent $Indent -OutTo $LogOutTo
		if ($ErrorHandling -eq "Continue"){
			return
		}elseif ($ErrorHandling -eq "Stop"){
			exit
		}
	}elseif ($ConfirmPath){
		if (Test-Path $ConfirmPath){
			Write-Log "Installation successful" -Indent $Indent -OutTo $LogOutTo
		}else{
			Write-Log "Installation failed: Could not verify path." -Level "Error" -Indent $Indent -OutTo $LogOutTo
			Write-Log $ConfirmPath -Level "Error" -Indent $Indent -OutTo $LogOutTo
			if ($ErrorHandling -eq "Continue"){
				return
			}elseif ($ErrorHandling -eq "Stop"){
				exit
			}
		}
	}elseif ($ConfirmName){
		$name64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -match $ConfirmName}
		$name32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -match $ConfirmName}
		if ($name64 -or $name32){
			Write-Log "Installation successful" -Indent $Indent -OutTo $LogOutTo
		}else{
			Write-Log "Installation failed: Could not verify name." -Level "Error" -Indent $Indent -OutTo $LogOutTo
			Write-Log $ConfirmName -Level "Error" -Indent $Indent -OutTo $LogOutTo
			if ($ErrorHandling -eq "Continue"){
				return
			}elseif ($ErrorHandling -eq "Stop"){
				exit
			}
		}
	}elseif ($ConfirmHotfix){
		if (Get-Hotfix $ConfirmHotfix -ErrorAction SilentlyContinue){
			Write-Log "Installation successful" -Indent $Indent -OutTo $LogOutTo
		}else{
			Write-Log "Installation failed: Could not verify hotfix." -Level "Error" -Indent $Indent -OutTo $LogOutTo
			Write-Log $ConfirmHotfix -Level "Error" -Indent $Indent -OutTo $LogOutTo
			if ($ErrorHandling -eq "Continue"){
				return
			}elseif ($ErrorHandling -eq "Stop"){
				exit
			}
		}
	}else{
		Write-Log "Installation successful" -Indent $Indent -OutTo $LogOutTo
	}
} # end function Install-Software

function Manage-ScheduledTask {
	param (
		[parameter(Mandatory = $true, HelpMessage = "No task name specified")]
		[ValidateNotNullOrEmpty()]
		[string]$TaskName,
		[ValidateSet("Add", "Remove")]
		[string]$Action,
		[string]$Execute,
		[string]$Argument,
		[ValidateSet("AtStartup", "AtLogon", "OnDemand", "Scheduled")]
		[string]$StartupType,
		[ValidateSet("Once", "Daily", "Weekly")]
		[string]$Recurrence,
		[string]$Time,
		[array]$DaysOfWeek,
		[string]$User,
		[string]$Password,
		[PSCredential]$Credential
	)
	
	if (Get-ScheduledTask $TaskName -ErrorAction SilentlyContinue){
		if ($Action -eq "Add"){
			return "$TaskName already exists."
		}
	}else{
		if ($Action -eq "Remove"){
			return "$TaskName does not exist"
		}
	}
	
	$error.Clear()
	if ($Action -eq "Add"){
		$Script:TaskAction = New-ScheduledTaskAction -Execute $Execute -Argument $Argument
		if ($StartupType -eq "OnDemand"){
			$schedTask = New-ScheduledTask -Action $Script:TaskAction
		}elseif ($StartupType -eq "AtStartup"){
			$Script:TaskTrigger = New-ScheduledTaskTrigger -AtStartup
			$schedTask = New-ScheduledTask -Action $Script:TaskAction -Trigger $Script:TaskTrigger
		}elseif ($StartupType -eq "AtLogon"){
			$Script:TaskTrigger = New-ScheduledTaskTrigger -AtLogon
			$schedTask = New-ScheduledTask -Action $Script:TaskAction -Trigger $Script:TaskTrigger
		}elseif ($StartupType -eq "Scheduled"){
			if ($Recurrence -eq "Once"){
				$Script:TaskTrigger = New-ScheduledTaskTrigger -At $Time -Once
			}elseif ($Recurrence -eq "Daily"){
				$Script:TaskTrigger = New-ScheduledTaskTrigger -At $Time -Daily
			}elseif ($Recurrence -eq "Weekly"){
				$Script:TaskTrigger = New-ScheduledTaskTrigger -At $Time -Weekly -DaysOfWeek $DaysOfWeek
			}
			$schedTask = New-ScheduledTask -Action $Script:TaskAction -Trigger $Script:TaskTrigger
		}
		
		if ($Credential){
			Register-ScheduledTask $TaskName -InputObject $schedTask -User $Credential.Username -Password $Credential.GetNetworkCredential().Password | Out-Null
		}elseif ($Password){
			Register-ScheduledTask $TaskName -InputObject $schedTask -User $User -Password $Password | Out-Null
		}else{
			Register-ScheduledTask $TaskName -InputObject $schedTask -User $User | Out-Null
		}
		
		if ($error){
			return "Failed to register $TaskName."
		}else{
			return "Successfully registered $TaskName."
		}
	}
	
	$error.Clear()
	if ($Action -eq "Remove"){
		Unregister-ScheduledTask $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
		
		if ($error){
			return "Failed to unregister $TaskName."
		}else{
			return "Successfully unregistered $TaskName."
		}
	}
}

function Toggle-ScheduledTask {
	param (
		[parameter(Mandatory = $true, HelpMessage = "No task name specified")]
		[ValidateNotNullOrEmpty()]
		[string]$TaskName,
		[ValidateSet("Enable", "Disable")]
		[string]$Action
	)
	
	if (!(Get-ScheduledTask $TaskName -ErrorAction SilentlyContinue)){
		return "$TaskName does not exist."
	}
	
	$error.Clear()
	if ($Action -eq "Enable"){
		Enable-ScheduledTask $TaskName -ErrorAction SilentlyContinue | Out-Null
		$msg = "Enabled $TaskName."
	}elseif ($Action -eq "Disable"){
		Disable-ScheduledTask $TaskName -ErrorAction SilentlyContinue | Out-Null
		$msg = "Disabled $TaskName."
	}elseif ((Get-ScheduledTask $TaskName).State -eq "Disabled"){
		Enable-ScheduledTask $TaskName -ErrorAction SilentlyContinue | Out-Null
		$msg = "Enabled $TaskName."
	}elseif ((Get-ScheduledTask $TaskName).State -ne "Disabled"){
		Disable-ScheduledTask $TaskName -ErrorAction SilentlyContinue | Out-Null
		$msg = "Disabled $TaskName."
	}
	
	if ($error){
		return $msg
	}else{
		return $msg
	}
}

function Install-CsSQLInstance {
	param (
		[ValidateSet("RTCLOCAL", "LYNCLOCAL", "RTC")]
		[string]$Instance,
		[ValidateNotNullOrEmpty()]
		[string]$SQLPath = "$env:ProgramFiles\Microsoft SQL Server",
		[ValidateNotNullOrEmpty()]
		[string]$SQLMediaDir,
		[ValidateNotNullOrEmpty()]
		[string]$SQLConfigPath,
		[switch]$OpenPorts
	)
	
	if (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -Name "$Instance" -ErrorAction SilentlyContinue){
		Write-Log "SQL Express 2014 ($Instance) already installed" -Indent $Indent -OutTo $LogOutTo
		return
	}
	
	#Configure SQL parameters
	$Config = "/ACTION=`"Install`"", `
			  "/QUIET=`"True`"", `
			  "/IACCEPTSQLSERVERLICENSETERMS=`"True`"", `
			  "/FEATURES=SQLENGINE,Tools", `
			  "/INSTALLSHAREDDIR=`"$SQLPath`"", `
			  "/INSTANCEDIR=`"$SQLPath`"", `
			  "/INSTANCENAME=`"$Instance`"", `
			  "/INSTANCEID=`"$Instance`"", `
			  "/SQLSYSADMINACCOUNTS=`"BUILTIN\ADMINISTRATORS`"", `
			  "/ADDCURRENTUSERASSQLADMIN=`"True`"", `
			  "/BROWSERSVCSTARTUPTYPE=`"Automatic`"", `
			  "/AGTSVCACCOUNT=`"NT AUTHORITY\NETWORK SERVICE`"", `
			  "/AGTSVCSTARTUPTYPE=`"Automatic`"", `
			  "/SQLSVCACCOUNT=`"NT AUTHORITY\NETWORK SERVICE`"", `
			  "/SQLSVCSTARTUPTYPE=`"Automatic`"", `
			  "/TCPENABLED=`"1`""
	
	$process = Start-Process -FilePath "$SQLMediaDir\SQLEXPR_x64_ENU\Setup.exe" -ArgumentList $Config -Wait -Passthru -Verb RunAs
	if ($process.ExitCode -ne 0 -and !(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -Name "$Instance" -ErrorAction SilentlyContinue)){
		Write-Log "SQLEXPR_x64_ENU.exe ($Instance) returned error code: $($process.ExitCode)" -Level "Error" -OutTo $LogOutTo
		if ($process.ExitMessage){
			Write-Log "SQLEXPR_x64_ENU.exe ($Instance) returned exit message: $($process.ExitMessage)" -Level "Error" -OutTo $LogOutTo
		}
		return
	}
	
	if ($OpenPorts){
		if (!(Get-NetFirewallRule -DisplayName "SQL Database Engine ($Instance)" -ErrorAction SilentlyContinue)){
			Write-Log "Creating firewall rule for SQL Database Engine ($Instance)." -Indent $Indent -OutTo $LogOutTo
			$path = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$Instance\Setup" | Select-Object -ExpandProperty SQLPath
			New-NetFirewallRule -DisplayName "SQL Database Engine ($Instance)" -Direction Inbound -Action Allow -Profile Any -Program $path\Binn\sqlservr.exe | Out-Null
		}
	}
}

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

#http://poshcode.org/1393
function Export-UserCredential {
	param (
		[ValidateNotNullOrEmpty()]
		[string]$Domain,
		[string]$CredPath,
		[string]$Username,
		[string]$Password,
		[PSCredential]$Credential,
		[switch]$ValidateOnly
	)
	Add-Type -AssemblyName System.DirectoryServices.AccountManagement
	
	if ($Credential){
		$Creds = $Credential
	}elseif ($Username -and $Password){
		$securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
		$Creds = New-Object -TypeName System.Management.Automation.PSCredential($Username,$securePassword)
	}else{
		$Creds = Get-Credential -Username "$env:userdomain\$env:username" -Message "Enter your credentials."
	}
	
	try {
		$domainjoined = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
	}catch{
		#continue
		Write-Log "Catching error in GetComputerDomain." -Level "Verb"
	}
	if ($domainjoined){
		$ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
	}else{
		$ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Machine
	}
	$PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $ContextType,$Domain
	
	$out = @{}
	try {
		#Found SimpleBind here: https://github.com/PowerShell/xActiveDirectory/issues/61
		#ContextOptions: https://msdn.microsoft.com/en-us/library/system.directoryservices.accountmanagement.contextoptions%28v=vs.110%29.aspx?f=255&MSPPError=-2147217396
		if ($domainjoined){
			$out.Status = $PrincipalContext.ValidateCredentials($Creds.Username,$Creds.GetNetworkCredential().Password,[DirectoryServices.AccountManagement.ContextOptions]::Negotiate -bor `
				[System.DirectoryServices.AccountManagement.ContextOptions]::SimpleBind)
		}else{
			$out.Status = $PrincipalContext.ValidateCredentials($Creds.Username,$Creds.GetNetworkCredential().Password)
		}
	}catch{
		$out.Status = $false
	}
	$out.Creds = $Creds
	
	if (!($ValidateOnly)){
		if ($out.Status){
			$fileName = $Creds.Username -replace ".*\\",""
			$fileName = $fileName+"_cred.xml"
			$Creds | Export-Clixml -Path $CredPath\$fileName
		}
	}
	return $out
}

#http://stackoverflow.com/questions/9368305/disable-ie-security-on-windows-server-via-powershell
function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer -Force -Confirm:$false
    return "IE Enhanced Security Configuration (ESC) has been disabled."
}

function Enable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1
    Stop-Process -Name Explorer -Force -Confirm:$false
    return "IE Enhanced Security Configuration (ESC) has been enabled."
}

function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000
    return "User Access Control (UAC) has been disabled."  
}

function Get-InternetConnectivity {
	param (
		[string]$Site = "http://www.google.com"
	)
	
	if (Get-NetConnectionProfile -IPv4Connectivity Internet -ErrorAction SilentlyContinue){
		try {
			$out = Invoke-WebRequest -Uri $Site -Method Head -UseBasicParsing
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

#Start function Start-Download
#https://www.briantist.com/errors/could-not-establish-trust-relationship-for-the-ssltls-secure-channel/
#https://www.powershellgallery.com/packages/f5-ltm/1.3.29/Content/Validation.cs
$definition = "using System.Collections.Generic;
	using System.Net;
	using System.Net.Security;
	using System.Security.Cryptography.X509Certificates;

	public static class SSLValidator
	{
		private static Stack<RemoteCertificateValidationCallback> funcs = new Stack<RemoteCertificateValidationCallback>();

		private static bool OnValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			return true;
		}

		public static void OverrideValidation()
		{
			funcs.Push(ServicePointManager.ServerCertificateValidationCallback);
			ServicePointManager.ServerCertificateValidationCallback = OnValidateCertificate;
		}

		public static void RestoreValidation()
		{
			if (funcs.Count > 0) {
				ServicePointManager.ServerCertificateValidationCallback = funcs.Pop();
			}
		}
	}"

try {
	Add-Type $definition
}catch{
	Write-Log "SSLValidator already exists." -Level "Verb"
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
		[switch]$SuppressProgress,
		[switch]$IgnoreSslValidation
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
		Write-Error "Unable to request file" -ErrorAction SilentlyContinue
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
		
		if ($IgnoreSslValidation){
			[SSLValidator]::OverrideValidation()
		}
		
		try {
			if ($WebSession){
				Invoke-WebRequest -Uri $Source -OutFile $outFile -WebSession $WebSession -TimeoutSec 30
			}else{
				Invoke-WebRequest -Uri $Source -OutFile $outFile -TimeoutSec 30
			}
		}catch{
			Write-Log "Download failed: $FileName" -Level "Error" -OutTo $LogOutTo
			Write-Log $error[0] -Level "Error" -OutTo $LogOutTo
		}
		
		if ($IgnoreSslValidation){
			[SSLValidator]::RestoreValidation()
		}
	}else{
		if ($JobName){
			if (Get-BitsTransfer $JobName -ErrorAction SilentlyContinue){
				Get-BitsTransfer $JobName | Add-BitsFile -Source $Source -Destination $Destination | Out-Null
			}else{
				Start-BitsTransfer -Source $Source -Destination $Destination -DisplayName $JobName -Asynchronous | Out-Null
			}
		}else{
			try {
				Start-BitsTransfer -Source $Source -Destination $Destination
			}catch{
				Write-Log "Download failed: $FileName" -Level "Error" -OutTo $LogOutTo
				Write-Log $error[0] -Level "Error" -OutTo $LogOutTo
			}
		}
	}
	
	$ProgressPreference='Continue'
}

function Save-Variables {
	$xml = Import-Clixml $Clixml
	Get-Variable $xml.Name | Export-Clixml $Clixml
}

function End-Task {
	param (
		[string]$NextTask,
		[switch]$Reboot,
		[switch]$Quiet,
		[switch]$NoSave
	)
	
	if ($Quiet){
		$logLevel = "Verb"
	}else{
		$logLevel = "Info"
	}
	
	$StopWatch.Stop()
	if ($TimingEnabled){
		$msg = "$Script:Task runtime: "+$StopWatch.Elapsed.ToString('dd\.hh\:mm\:ss')
	}
	
	if ($Reboot){
		$Script:ResumeTask = $NextTask
		Write-Log "Completed $Script:Task. Proceeding to $Script:ResumeTask after reboot." -OutTo $LogOutTo -Level $logLevel
	}elseif ($NextTask -eq "None"){
		if (!($DownloadsOnly)){
			$Script:ResumeTask = $NextTask
			Write-Log "Completed $Script:Task." -OutTo $LogOutTo -Level $logLevel
		}
	}else{
		$Script:ResumeTask = $NextTask
		Write-Log "Completed $Script:Task. Proceeding to $Script:ResumeTask." -OutTo $LogOutTo -Level $logLevel
		$Script:Task = $NextTask
	}
	if (!($NoSave)){
		Save-Variables
	}
	Write-Log -OutTo $LogOutTo -Level $logLevel

	if ($TimingEnabled){
		$msg | Write-Log -Level "Verb" -OutTo $LogOutTo
		if (!($PrereqsOnly) -and !($DownloadsOnly)){
			$msg | Out-File $StopWatchPath -Append
		}
	}
	
	if ($Reboot){
		if ($Manual){
			Write-Log "Completed $Script:Task. Manually continue by running script with Resume icon or -Resume." -OutTo $LogOutTo
			Write-Log -OutTo $LogOutTo
		}else{
			Toggle-ScheduledTask -TaskName "CSDeploymentReboot" -Action "Enable" | Write-Log -Level "Verb" -OutTo $LogOutTo
			Write-Log -Level "Verb" -OutTo $LogOutTo
		}
		Write-Log "Rebooting" -OutTo $LogOutTo
		Restart-Computer -Force
	}
}

function Complete-Script {
	param (
		[switch]$Reboot
	)
	
	#Run PS cmdlet help update
	Write-Log "Updating cmdlet help information."
	Write-Log
	Update-Help -ErrorAction SilentlyContinue
	
	#Create run once for customization at logon
	Write-Log "Creating RunOnce registry entry for Logon task."
	Write-Log
	if (!(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "Logon" -ErrorAction SilentlyContinue)){
		New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "Logon" -Value "powershell.exe -Command `"& $TempDir\Install-CsServer.ps1 Logon`"" | Out-Null
	}
	
	#Clean up residue
	Write-Log "Cleaning up shortcuts, scheduled tasks, and temp directory files."
	#Remove-Item "$env:Public\Desktop\Status.lnk" -ErrorAction SilentlyContinue
	Remove-Item "$env:Public\Desktop\Certificates.lnk" -ErrorAction SilentlyContinue
	Remove-Item "$env:Public\Desktop\Resume.lnk" -ErrorAction SilentlyContinue
	Remove-Item "$env:Public\Desktop\Stop.lnk" -ErrorAction SilentlyContinue
	Remove-Item "$env:Public\Desktop\Temp Directory.lnk" -ErrorAction SilentlyContinue
	Remove-Item "$ScriptsDir\Get-CsDeviceUpdates.v3.0.zip" -ErrorAction SilentlyContinue
	Get-ChildItem $TempDir -Exclude "Install-CsServer.ps1","$($env:ComputerName).xml","$($env:ComputerName).txt","$($env:ComputerName).log","topology.zip" -Recurse | `
		ForEach-Object {Remove-Item $_.FullName -Recurse -Force -Confirm:$false}
	Manage-ScheduledTask -TaskName "CSDeploymentReboot" -Action "Remove"
	Write-Log
	
	#Remove WU Spectre/Meltdown AV compatibility registry entry if added by script
	if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -ErrorAction SilentlyContinue)."WUAVCOMPATADDED" -eq 1){
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Force -ErrorAction SilentlyContinue | Out-Null
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "WUAVCOMPATADDED" -Force -ErrorAction SilentlyContinue | Out-Null
		Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Force -ErrorAction SilentlyContinue | Out-Null
	}
	
	#Archive temp folder to zip on desktop
	Write-Log "Archiving $TempDir"
	Add-Type -Assembly "system.io.compression.filesystem"
	$zipDestination = "$env:Public\Desktop\$($env:ComputerName).zip"
	if (!(Test-Path $zipDestination)){
		[io.compression.zipfile]::CreateFromDirectory($TempDir, $zipDestination)
	}
	Write-Log
	Write-Log
	
	$EndTime = Get-Date -f "MM/dd/yy HH:mm:ss"
	$startMsg = "Start time: "+$StartTime
	$endMsg = "End time: "+$EndTime
	$totalRuntime = "Total runtime: "+(New-TimeSpan -Start $StartTime -End $EndTime).ToString('dd\.hh\:mm\:ss')
	Write-Log $startMsg
	Write-Log $endMsg
	Write-Log $totalRuntime
	Write-Log
	
	if ($TimingEnabled){
		$startMsg | Out-File $StopWatchPath -Append
		$endMsg | Out-File $StopWatchPath -Append
		$totalRuntime | Out-File $StopWatchPath -Append
	}
	
	if ($Reboot){
		Write-Log "Rebooting"
		Restart-Computer -Force
	}
	Manage-ScheduledTask -TaskName "CSDeployment" -Action "Remove"
}

function Invoke-DiscoverMedia {
	param (
		[string]$MediaPath,
		[string]$ExecutablePath
	)
	
	#If media path not set, continue to search for mounted media
	if ($MediaPath){
		#Check if path is valid, if not exit
		Write-Log "Checking media path."
		if (Test-Path $MediaPath){
			#Check if path is ExecutablePath, .iso, or .img
			#If ExecutablePath set setup path variable and continue
			#If .iso continue to search for mounted media, else exit
			
			if ($ExecutablePath){
				$testPath = $MediaPath + "\" + $ExecutablePath
				if (Test-Path $testPath){
					Write-Log "Media found at $MediaPath"
					$Script:Path = $MediaPath
				}
			}elseif ($MediaPath -match ".iso|.img"){
				#Continue
				Write-Log "Media is an image." -Level "Verb"
			}else{
				Write-Log "Media path is not valid. Must be path to path or image." -Level "Error"
				exit
			}
		}else{
			Write-Log "Media path is not valid. Must be path to path or image." -Level "Error"
			exit
		}
		Write-Log
	}
	
	#If ExecutablePath not detected, mount if .iso/.img or continue to search for ExecutablePath on already mounted media
	if (!($Script:Path)){
		if ($MediaPath -match ".iso|.img"){
			Write-Log "Mounting image: $MediaPath."
			Write-Log
			Mount-DiskImage $MediaPath
			$Script:ImageMounted = $true
		}
		
		#Enumerate mounted media
		$mountedDrives = Get-WMIObject win32_logicaldisk | Where-Object DriveType -eq 5
		if (($mountedDrives).Count -eq 0){
			Write-Log "No path provided and no mounted media detected." -Level "Error"
			exit
		}
		
		#Search mounted media for setup.exe
		Write-Log "Searching mounted media for $ExecutablePath."
		foreach ($mountedDrive in $mountedDrives){
			$testPath = $mountedDrive.DeviceID + "\" + $ExecutablePath
			if (Test-Path $testPath){
				Write-Log "setup.exe found on mounted media: $($mountedDrive.DeviceID)"
				$Script:Path = $mountedDrive.DeviceID
				$setupFound = $true
			}
		}
		if (!($setupFound)){
			Write-Log "No path provided and $ExecutablePath was not found on mounted media." -Level "Error"
			exit
		}
		Write-Log
	}
}

#http://sharemypoint.in/2011/04/18/powershell-script-to-check-sql-server-connectivity-version-custering-status-user-permissions/
function Test-SQLConnection {
	param (
		[ValidateNotNullOrEmpty()]
		[string]$Server,
		[string]$Instance,
		[ValidateSet("sysadmin","dbcreator","diskadmin","processadmin","serveradmin","setupadmin","securityadmin","fake")]
		[ValidateNotNullOrEmpty()]
		[array]$ServerRolesToCheck = "sysadmin",
		[PSCredential]$Credential
	)
	
	if ($Credential){
		$currentUser = $Credential.Username
	}else{
		$currentUser = "$env:USERDOMAIN\$Env:USERNAME"
	}
	if ($Instance){
		$Server = $Server +"\"+$Instance
	}
	
	$output = @{}
	$objSQLConnection = New-Object System.Data.SqlClient.SqlConnection
	$objSQLCommand = New-Object System.Data.SqlClient.SqlCommand
	
	try {
		if ($Credential){
			$objSQLConnection.ConnectionString = "Server=$Server;uid=$($Credential.Username);pwd=$($Credential.GetNetworkCredential().Password);"
		}else{
			$objSQLConnection.ConnectionString = "Server=$Server;Integrated Security=SSPI;"
		}
		$objSQLConnection.Open() | Out-Null
		$output.Connectivity = $true
		
		$strCmdSvrDetails = "SELECT SERVERPROPERTY('productversion') as Version"
		$strCmdSvrDetails += ",SERVERPROPERTY('MachineName') as MachineName"
		$strCmdSvrDetails += ",SERVERPROPERTY('ComputerNamePhysicalNetBIOS') as NodeName"
		$strCmdSvrDetails += ",SERVERPROPERTY('Edition') as Edition"
		$strCmdSvrDetails += ",SERVERPROPERTY('IsClustered') as Clustering"
		$strCmdSvrDetails += ",SERVERPROPERTY('IsHADREnabled') as AlwaysOn"
		$objSQLCommand.CommandText = $strCmdSvrDetails
		$objSQLCommand.Connection = $objSQLConnection
		$objSQLDataReader = $objSQLCommand.ExecuteReader()
		if($objSQLDataReader.Read()){
			$output.Version = $objSQLDataReader.GetValue(0)
			$output.MachineName = $objSQLDataReader.GetValue(1)
			$output.NodeName = $objSQLDataReader.GetValue(2)
			$output.Edition = $objSQLDataReader.GetValue(3)
			if ($objSQLDataReader.GetValue(4) -eq 1){
				$output.Clustered = $true
			}else{
				$output.Clustered = $false
			}
			if ($objSQLDataReader.GetValue(5) -eq 1){
				$output.AlwaysOn = $true
			}else{
				$output.AlwaysOn = $false
			}
		}
		$objSQLDataReader.Close()
		
		foreach($serverRole in $ServerRolesToCheck) {
			$objSQLCommand.CommandText = "SELECT IS_SRVROLEMEMBER('$serverRole')"
			$objSQLCommand.Connection = $objSQLConnection
			$objSQLDataReader = $objSQLCommand.ExecuteReader()
			if ($objSQLDataReader.Read() -and $objSQLDataReader.GetValue(0) -eq 1){
				$output.$($serverRole) = $true
			}elseif($objSQLDataReader.GetValue(0) -eq 0) {
				$output.$($serverRole) = $false
			}else{
				$output.$($serverRole) = $false
			}
			$objSQLDataReader.Close()
		}
		
		$objSQLConnection.Close()
	}catch{
		$output.Connectivity = $false
		$output.Error =  $Error[0].ToString()
	}
	return $output
}

function Invoke-CsCertificateProcess {
	param (
		[switch]$Request,
		[switch]$Assign,
		[array]$Uses,
		[string]$DomainName,
		[ValidateSet("Default","Internal","External","OAuthTokenIssuer")]
		[string]$Name,
		[string]$CA,
		[string]$OU,
		[string]$Org,
		[string]$City,
		[string]$State,
		[string]$Country,
		[ValidateSet("2048", "4096")]
		[int]$KeySize = 2048,
		[string]$OutDir
	)
	
	if ($Request){
		Write-Log "Requesting $Name certificate." -OutTo $LogOutTo
		$friendlyName = "Skype for Business Server 2015 $Name certificate ($(Get-Date -f M/d/yyyy))"
		
		if (!($Country) -or !($State) -or !($City) -or !($Org) -or !($OU)){
			$certReq = "Request-CsCertificate -New -Type `$Uses -FriendlyName `$friendlyName -KeySize `$KeySize -PrivateKeyExportable `$True -AllSipDomain"
		}else{
			$certReq = "Request-CsCertificate -New -Type `$Uses -FriendlyName `$friendlyName -KeySize `$KeySize -PrivateKeyExportable `$True -AllSipDomain -Country `$Country -State `$State -City `$City -Organization `$Org -OU `$OU"
		}
		if ($DomainName){
			$certReq = $certReq + " -DomainName `$DomainName"
		}
		if ($CA){
			$certReq = $certReq + " -CA `$CA | Out-Null"
		}else{
			$certReq = $certReq + " -Output `$OutDir\`$Name.txt | Out-Null"
			#$offlineCert = $true
		}
		
		try {
			Invoke-Expression $certReq
		}catch{
			Write-Log "Errors requesting $Name certificate." -Level "Error" -OutTo $LogOutTo
			Write-Log $error[0].Exception.Message -Level "Error" -OutTo $LogOutTo
			exit
		}

		#Stop if offline certs issued
		if ($offlineCert){
			Write-Log "Certificate requests created at $OutDir." -OutTo $LogOutTo
			Write-Log -OutTo $LogOutTo
			Write-Log "Submit the CSRs for signing to the appropriate certificate authority, import the signed certificate and the certificate chain." -OutTo $LogOutTo
			Write-Log "Ensure that the friendly names contains the words Default, Internal, External, or OAuthTokenIssuer according to type." -OutTo $LogOutTo
			Write-Log "The script will wait until all certificates have been imported and trusted before proceeding." -OutTo $LogOutTo
			Write-Log "Note: If there are multiple Edge servers, only submit one external request for signing, and install that certificate on all Edge servers." -OutTo $LogOutTo
			Write-Log -OutTo $LogOutTo
		}
	}
	
	if ($Assign){
		$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -match $Name
		$pending = Request-CsCertificate -List | Where-Object CertificateUses -match $Name
		
		if ($cert){
			$assignCert = $true
		}elseif ($pending){
			$cert = Request-CsCertificate -Retrieve -RequestId $pending.RequestId | Out-Null
			if ($cert.Thumbprint){
				#Write-Log "Assigning $Name certificate from pending request $($pending.RequestId): $($cert.Thumbprint)" -OutTo $LogOutTo
				$assignCert = $true
			}
		}
		
		if ($assignCert){
			$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -match $Name
			Write-Log "Assigning $Name certificate:"
			Write-Log "Thumbprint: $($cert.Thumbprint)" -Indent $Indent -OutTo $LogOutTo
			Write-Log "Subject: $($cert.Subject)" -Indent $Indent -OutTo $LogOutTo
			Write-Log "SANs: $($cert.DnsNameList -join ', ')" -Indent $Indent -OutTo $LogOutTo
			Write-Log "Issuer: $($cert.Issuer)" -Indent $Indent -OutTo $LogOutTo
			Write-Log "Signature Algorithm: $($cert.SignatureAlgorithm.FriendlyName)" -Indent $Indent -OutTo $LogOutTo
			Write-Log "Expiration: $($cert.NotAfter)" -Indent $Indent -OutTo $LogOutTo
			try {
				if ($Uses -match "OAuthTokenIssuer"){
					Set-CsCertificate -Identity Global -Type $Uses -Thumbprint $cert.Thumbprint -Confirm:$false | Out-Null
				}else{
					Set-CsCertificate -Type $Uses -Thumbprint $cert.Thumbprint -Confirm:$false | Out-Null
				}
			}catch{
				Write-Log "Errors assigning $Name certificate." -Level "Error" -OutTo $LogOutTo
				Write-Log $error[0].Exception.Message -Level "Error" -OutTo $LogOutTo
				exit
			}
		}elseif ($pending){
			Write-Log "Certificate pending." -OutTo $LogOutTo
		}else{
			Write-Log "Unable to find certificate $Name." -OutTo $LogOutTo
		}
	}
}

function New-IISARRRule {
	#Original code by Kevin Bingham
	param (
		[string]$Url,
		[int]$HTTPPort,
		[int]$HTTPSPort,
		[string]$Destination = $Url
	)
	
	$hostname = $Url.Split(".",2)[0]
	$domain = $Url.Split(".",2)[1]
	$rulename = "ARR_"+$Url+"_loadbalance_SSL"
	
	if (!(Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$Url']" -Name ".")){
		Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms" -Name "." -Value @{name=$Url}
		Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$Url']/applicationRequestRouting/protocol" -Name "timeout" -Value "00:16:00"
		Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$Url']/applicationRequestRouting/protocol/cache" -Name "enabled" -Value "False"
		Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$Url']" -Name "." -Value @{address=$Destination}
		Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$Url']/server[@address='$Destination']/applicationRequestRouting" -Name "httpPort" -Value $HTTPPort
		Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "webFarms/webFarm[@name='$Url']/server[@address='$Destination']/applicationRequestRouting" -Name "httpsPort" -Value $HTTPSPort
	}

	if (!(Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/rewrite/globalRules/rule[@name='$rulename']" -Name ".")){
		Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/rewrite/globalRules" -Name "." -Value @{name=$rulename;patternSyntax='Wildcard';stopProcessing='True'}
		Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/rewrite/globalRules/rule[@name='$rulename']/match" -Name "url" -Value "*"
		Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/rewrite/globalRules/rule[@name='$rulename']/conditions" -Name "." -Value @{input='{HTTPS}';pattern='on'}
		Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/rewrite/globalRules/rule[@name='$rulename']/conditions" -Name "." -Value @{input='{HTTP_HOST}';pattern="$hostname.*"}
		Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/rewrite/globalRules/rule[@name='$rulename']/action" -Name "type" -Value "Rewrite"
		Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/rewrite/globalRules/rule[@name='$rulename']/action" -Name "url" -Value "https://$Url/{R:0}"
	}
}

function Test-RFC1918 {
	param (
		$IPAddress
	)
	
	[ref]$a = $null
	if (!([System.Net.IPAddress]::TryParse($IPAddress,$a))){
		return $false
	}
	
	$IPAddress = [IPAddress]$IPAddress
	$RFC1918 = $false
	
	if ($IPAddress.GetAddressBytes()[0] -eq 10){
		$RFC1918 = $true
	}elseif ($IPAddress.GetAddressBytes()[0] -eq 172){
		if (($IPAddress.GetAddressBytes()[1] -ge 16) -and ($IPAddress.GetAddressBytes()[1] -le 31)){
			$RFC1918 = $true
		}
	}elseif ($IPAddress.GetAddressBytes()[0] -eq 192){
		if ($IPAddress.GetAddressBytes()[1] -eq 168){
			$RFC1918 = $true
		}
	}
	
	return $RFC1918
}

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
        $hresult = [CryptoAPI.CertAdm]::CertSrvIsServerOnline($Server,[ref]$ServerStatus)
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
    } else {return}
}

#From DeployReports.ps1 script provided with SFB installation
function Get-SQLReportURL($namespace, $instanceName, $computer){  
	$classes = Get-WmiObject -Namespace $namespace -ComputerName $computer -List
	$class = $null
	foreach ($classTemp in $classes){
		if($classTemp.Name -eq "MSReportServer_Instance"){
			$class = $classTemp
			break
		}
	}
	
	if($class){
		$rsInstance = Get-WmiObject -Namespace $namespace -Query "select * from MSReportServer_Instance where InstanceName='$instanceName'" -ComputerName $computer
		
		if($rsInstance.ReportServerUrl){
			return $rsInstance.ReportServerUrl
		}elseif($rsInstance.GetReportServerUrls){
			$urls = $rsInstance.GetReportServerUrls()
			$httpUrl = $null
			$httpsUrl = $null
            
			for($index = 0; $index -lt $urls.ApplicationName.Count; $index++){
				if($urls.ApplicationName[$index] -eq "ReportServerWebService"){
					$url =  New-Object System.Uri($urls.URLs[$index])
					
					if($url -and $url.UriSchemeHttps){
						$httpsUrl = $urls.URLs[$index]
					}else{
						$httpUrl = $urls.URLs[$index]
					}
				}
			}
			
			if($httpsUrl){
				return $httpsUrl
			}else{
				return $httpUrl
			}
		}
	}else{ 
		$subNamespaces = Get-WmiObject -Namespace $namespace -ComputerName $computer -Class __NAMESPACE
		foreach($subNamespace in $subNamespaces){
			$reportingUrl = Get-SQLReportURL ($namespace + "\" + $subNamespace.Name) $instanceName $computer
			
			if($reportingUrl){
				return $reportingUrl
			}
		}
	}
}

#Windows Updates functions
function Invoke-WindowsUpdates(){
	if (!($UpdateSession)){
		$UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
		$UpdateSession.ClientApplicationID = 'Packer Windows Update Installer'
		$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
		$SearchResult = New-Object -ComObject 'Microsoft.Update.UpdateColl'
	}

	#Checking WU for available updates
	Write-Log "Checking for Windows Updates..."
	Write-Log
	$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
	$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
	
	if ($SearchResult.Updates.Count -ne 0){
		#List raw update output for debugging
		#$SearchResult.Updates | Select-Object -Property Title, Description, SupportUrl, UninstallationNotes, RebootRequired, EulaAccepted | Format-List
		
		$resultcode = @{0="Not Started"; 1="In Progress"; 2="Succeeded"; 3="Succeeded With Errors"; 4="Failed"; 5="Aborted"}
	
		#Checking available updates for applicable updates
		Write-Log "Evaluating $($SearchResult.Updates.Count) available updates:"
		$UpdatesToDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl'
		foreach ($Update in $SearchResult.Updates) {
			if (($Update -ne $null) -and (!$Update.IsDownloaded)){
				if ($Update.InstallationBehavior.CanRequestUserInput){
					Write-Log "> Skipping: $($Update.Title) because it requires user input"
				}else{
					if (!($Update.EulaAccepted)){
						Write-Log "> Note: $($Update.Title) has a license agreement that must be accepted. Accepting the license."
						$Update.AcceptEula()
					}
					Write-Log "Adding: $($Update.Title)"
					$UpdatesToDownload.Add($Update) | Out-Null
				}
			}
		}
		Write-Log
		
		#Checking if updates are already downloaded, if not download
		if ($UpdatesToDownload.Count -ne 0){
			Write-Log "Downloading $($UpdatesToDownload.Count) updates..."
			$Downloader = $UpdateSession.CreateUpdateDownloader()
			$Downloader.Updates = $UpdatesToDownload
			$Downloader.Download() | Out-Null
		}else{
			Write-Log "No updates to download"
		}
		Write-Log
		
		#Determine which downloaded updates to install
		if (($SearchResult.Updates | Where-Object {$_.IsDownloaded -eq $true}).Count -ne 0){
			$UpdatesToInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl'
			Write-Log "The following updates are downloaded and ready to be installed:"
			foreach ($Update in $SearchResult.Updates){
				if (($Update.IsDownloaded)){
					Write-Log "> $($Update.Title)"
					$UpdatesToInstall.Add($Update) | Out-Null
				}
			}
			Write-Log
			
			if (($UpdatesToInstall | Select-Object -ExpandProperty InstallationBehavior) | Where-Object {$_.RebootBehavior -gt 0}){
				Write-Log "These updates may require a reboot"
				Write-Log
			}
		}
		
		#Install downloaded updates
		if ($UpdatesToInstall.Count -ne 0){
			Write-Log "Installing updates..."
			Write-Log
			
			$Installer = $UpdateSession.CreateUpdateInstaller()
			$Installer.Updates = $UpdatesToInstall
			$InstallationResult = $Installer.Install()
			
			#Display results
			Write-Log "Listing of updates installed and individual installation results:"
			for($i=0; $i -lt $UpdatesToInstall.Count; $i++){
				Write-Log "$($resultcode[$InstallationResult.GetUpdateResult($i).ResultCode]): $($UpdatesToInstall.Item($i).Title)"
			}
			Write-Log
			
			Write-Log "Installation Result: $($resultcode[$InstallationResult.ResultCode])"
			Write-Log "Reboot Required: $($InstallationResult.RebootRequired)"
			Write-Log
			
			#Reboot if needed, otherwise check for additional updates
			if ($InstallationResult.RebootRequired){
				Toggle-ScheduledTask -TaskName "CSDeploymentReboot" -Action "Enable" | Write-Log -Level "Verb" -OutTo $LogOutTo
				Write-Log "Rebooting"
				Write-Log
				Restart-Computer -Force
				exit
			}else{
				Write-Log "No restart required"
				Write-Log
				Invoke-WindowsUpdates
			}
		}else{
			#If no updates available, drop from function
			Write-Log "There are no applicable updates. Windows Updates complete"
			Write-Log
			return
		}
	}else{
		Write-Log "There are no applicable updates. Windows Updates complete"
		Write-Log
		return
	}
}

function New-Shortcut {
	param (
		[string]$Path,
		[string]$TargetPath,
		[string]$Arguments,
		[switch]$Overwrite
	)
	
	if ((Test-Path $Path) -and !$Overwrite){
		return
	}
	
	$wScriptShell = New-Object -ComObject WScript.Shell
	$shortcut = $wScriptShell.CreateShortcut($Path)
	$shortcut.TargetPath = $TargetPath
	if ($Arguments){
		$shortcut.Arguments = $Arguments
	}
	$shortcut.Save()
}





#Setting variables
$Script:Task = $RunTask
$TempDir = "C:\CsInstall"
$UserTempDir = [environment]::GetEnvironmentVariable("temp","user")
if (!($SoftwareDir)){
	$SoftwareDir = "$TempDir\software"
}
$ScriptsDir = "C:\CsScripts"
$Clixml = $TempDir+"\$($env:ComputerName.ToLower()).xml"
$LogPath = $TempDir+"\$($env:ComputerName.ToLower()).log"
$StopWatchPath = $TempDir+"\$($env:ComputerName.ToLower()).txt"
$Script:Path = $null
$SetupPath = $null
$IntSrvTypes = "FEStd|FEEnt|Dir|Med|PChat|OOS|All"
$IntCsSrvTypes = "FEStd|FEEnt|Dir|Med|PChat|All"
$ExtSrvTypes = "Edge|IISARR|All"
$ExtCsSrvTypes = "Edge|All"
$CsSrvTypes = "FEStd|FEEnt|Dir|Med|PChat|Edge|All"
$LogOutTo = "FileAndScreen"
$Script:ResumeTask = $null
$Script:ImageMounted = $false
$Indent = 1
$CAFullName = $null
if ($PrereqsOnly){
	$Script:Task = "PrereqCheck"
	$LogOutTo = "Screen"
	$TempDir = (Get-Location).Path
}
if ($DownloadsOnly){
	$Script:Task = "PrereqDownload"
	$ServerType = "All"
	$LogOutTo = "Screen"
	#$TempDir = $SoftwareDir
	$ScriptsDir = $SoftwareDir+"\CsScripts"
	if (!(Test-Path $SoftwareDir)){
		Write-Log "Creating download directory: $SoftwareDir" -Level "Verb" -OutTo $LogOutTo
		New-Item $SoftwareDir -Type Directory | Out-Null
	}
	if (!(Test-Path $ScriptsDir)){
		Write-Log "Creating script directory: $ScriptsDir" -Level "Verb" -OutTo $LogOutTo
		New-Item $ScriptsDir -Type Directory | Out-Null
	}
	$KB2982006Required = $true
	$KB2919355Required = $true
	$KB2919442Required = $true
	$NDPUpgradeStatus = $false
}
if ($PostInstallTasks){
	$Script:Task = "PostInstallTasks"
	$ServerType = "All"
	$LogOutTo = "Screen"
}

#$HasInternetAccess = ([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet)
$HasInternetAccess = Get-InternetConnectivity

#Debugging variables
$TimingEnabled = $true
$StartTime = Get-Date -f "MM/dd/yy HH:mm:ss"

#Download URLs
#SQL Files
#$SQLExp14Url = "https://download.microsoft.com/download/E/A/E/EAE6F7FC-767A-4038-A954-49B8B05D04EB/Express%2064BIT/SQLEXPR_x64_ENU.exe"
#$SQLExp14SP1Url = "https://download.microsoft.com/download/1/5/6/156992E6-F7C7-4E55-833D-249BD2348138/ENU/x64/SQLEXPR_x64_ENU.exe"
$SQLExp14SP2Url = "https://download.microsoft.com/download/2/A/5/2A5260C3-4143-47D8-9823-E91BB0121F94/SQLEXPR_x64_ENU.exe"
#https://msdn.microsoft.com/en-us/library/mt238290.aspx
$SQLSMSUrl = "https://download.microsoft.com/download/9/3/3/933EA6DD-58C5-4B78-8BEC-2DF389C72BE0/SSMS-Setup-ENU.exe"

#Skype4B Files
#Skype4B Debugging Tools
#14.0.24123.0
#$DebugVC2015U3Url = "https://download.microsoft.com/download/0/6/4/064F84EA-D1DB-4EAA-9A5C-CC2F0FF6A638/vc_redist.x64.exe"
$CS15DebugSrcUrl = "https://download.microsoft.com/download/A/6/0/A603FC51-2C03-48B2-A072-587FA1D3DFAF/SkypeForBusinessDebugTools.msi"
#Skype4B Current Updates
$CS15UpdatesSrcUrl = "https://download.microsoft.com/download/F/B/C/FBC09794-2DB9-415E-BBC7-7202E8DF7072/SkypeServerUpdateInstaller.exe"
#Skype4B Resource Kit
$CS15ResKitURL = "https://download.microsoft.com/download/4/6/9/469BFE52-9F8B-4398-8998-D3460619D2B2/OCSReskit.msi"
#Key Health Indicators
$CSKHIUrl = "https://download.microsoft.com/download/9/F/8/9F809EC8-F3B3-45B5-8B96-68D8D99BEA45/KHI_Resources.zip"

#Silverlight
#$SilverlightUrl = "http://silverlight.dlservice.microsoft.com/download/8/E/7/8E7D9B4B-2088-4AED-8356-20E65BE3EC91/40728.00/Silverlight_x64.exe"
$SilverlightUrl = "https://download.microsoft.com/download/F/D/0/FD0B0093-DE8A-4C4E-BDC4-F0C56D72018C/50907.00/Silverlight_x64.exe"

#.NET Framework Patch
#KB3186497
$NDPUrl = "https://download.microsoft.com/download/D/D/3/DD35CC25-6E9C-484B-A746-C5BE0C923290/NDP47-KB3186497-x86-x64-AllOS-ENU.exe"

#Office Online Server
#14.0.23026.0
#$OOSVC2015Url = "https://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x64.exe"
$IdentityExtensionsUrl = "https://download.microsoft.com/download/0/1/D/01D06854-CA0C-46F1-ADBA-EBF86010DCC6/MicrosoftIdentityExtensions-64.msi"
$OOSLanguagePackUrl = "https://download.microsoft.com/download/6/D/7/6D75C9CB-FFEE-48B0-9AA6-D03C74E3939E/wacserverlanguagepack.exe"
$OOSPatchUrl = "https://download.microsoft.com/download/8/B/A/8BAC033E-44E8-4FF5-B590-574D4DE4454C/wacserver2016-kb4011023-fullfile-x64-glb.exe"

#KB2982006 (IIS Hotfix)
$KB2982006Url = "http://download.windowsupdate.com/d/msdownload/update/software/htfx/2014/09/windows8.1-kb2982006-x64_d96bea78d5746c48cb712c8ef936c29b5077367f.msu"
$KB2919355Url = "https://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/Windows8.1-KB2919355-x64.msu"
$KB2919442Url = "https://download.microsoft.com/download/D/6/0/D60ED3E0-93A5-4505-8F6A-8D0A5DA16C8A/Windows8.1-KB2919442-x64.msu"

#URL Rewrite for IIS 10.0 on Server 2016
$UrlRewriteUrl = "https://download.microsoft.com/download/C/9/E/C9E8180D-4E51-40A6-A9BF-776990D8BCA9/rewrite_amd64.msi"

#IIS ARR
$IISARRUrl = "https://download.microsoft.com/download/A/D/C/ADC4BAF8-A094-47B5-A6F6-CE4C5ED18BF8/ARRv3_setup_amd64_en-us.exe"

#VC++ 2015 - 14.0.24215.1 (OOS and Debugging Tools)
#https://www.visualstudio.com/vs/older-downloads/
#$VC2015Url = "https://download.microsoft.com/download/6/A/A/6AA4EDFF-645B-48C5-81CC-ED5963AEAD48/vc_redist.x64.exe"
$VC2015Url = "https://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x64.exe"

#Utilities
#7zip
$7zipExeUrl = "https://raw.githubusercontent.com/argiesen/CsScripts/master/7zip/1805_x64/7za.exe"
$7zipDllUrl = "https://raw.githubusercontent.com/argiesen/CsScripts/master/7zip/1805_x64/7za.dll"

#DigiCert Utility
$DigiCertUtilUrl = "https://www.digicert.com/StaticFiles/DigiCertUtil.zip"

#Disable SSL and weak ciphers registry entry
$IISCryptoUrl = "https://www.nartac.com/Downloads/IISCrypto/IISCryptoCli.exe"

#Third party applications
#Wireshark
$WiresharkUrl = "https://1.na.dl.wireshark.org/win64/all-versions/Wireshark-win64-2.6.0.exe"
$WinPcapUrl = "https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe"

#AudioCodes Syslog
$ACSyslogUrl = "http://redirect.audiocodes.com/install/syslogViewer/syslogViewer-setup.exe"

#Mozilla Firefox
#https://download-installer.cdn.mozilla.net/pub/firefox/releases/
$FirefoxUrl = "https://download-installer.cdn.mozilla.net/pub/firefox/releases/60.0esr/win64/en-US/Firefox%20Setup%2060.0esr.exe"

#Google Chrome
#https://enterprise.google.com/chrome/chrome-browser/thankyou.html?platform=win64msi
$ChromeUrl = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B22D8AD5B-C79D-525B-B197-2E860B2D020D%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_1%26brand%3DGCEA/dl/chrome/install/googlechromestandaloneenterprise64.msi"

#Scripts
$CsClsLogSizeUrl = "https://raw.githubusercontent.com/argiesen/CsScripts/master/Get-CsClsLogSize.ps1"
$CsDeviceUpdatesUrl = "https://github.com/argiesen/CsScripts/raw/master/Packages/Get-CsDeviceUpdates.v3.0.zip"
$CsEndpointRegistrationsUrl = "https://raw.githubusercontent.com/argiesen/CsScripts/master/Get-CsEndpointRegistrations.ps1"
$WindowsFabricLogSizeUrl = "https://raw.githubusercontent.com/argiesen/CsScripts/master/Get-WindowsFabricLogSize.ps1"
$CleanWACIISLogsUrl = "https://raw.githubusercontent.com/argiesen/CsScripts/master/Clean-IISLogs.ps1"
#$CsMeetingWarmupUrl = ""
$CsSyncDefaultTMXUrl = "https://raw.githubusercontent.com/argiesen/CsScripts/master/Sync-CsClsDefaultTmx.ps1"

#Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" | Get-ItemProperty | Sort-Object DisplayName | Format-Table DisplayName,PSChildName
#Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Get-ItemProperty | Sort-Object DisplayName | Format-Table DisplayName,PSChildName
#Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Skype for Business Server*"}
#GUIDs
$VC2013Name = "Microsoft Visual C++ 2013 x64 Minimum Runtime -"
$VC2013GUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{A749D8E6-B613-3BE3-8F5F-045C84EBA29B}"
#$VC2013Wireshark224GUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{ABB19BB4-838D-3082-BDA4-87C6604181A2}"
$OOSVC2015GUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{0D3E9E15-DE7A-300B-96F1-B4AF12B96488}"
$VC2015GUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{0D3E9E15-DE7A-300B-96F1-B4AF12B96488}"
$VC2015Name = "Microsoft Visual C\+\+ 2015 x64 Minimum Runtime - 14\.0\.24[1,2]\d{2}"
#VC2015U3 = 14.0.24123
$DebugVC2015U3GUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{FDBE9DB4-7A91-3A28-B27E-705EF7CFAE57}"
$MSIDEXGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{F99F24BF-0B90-463E-9658-3FD2EFC3C991}"
$OOSGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{90160000-1151-0000-1000-0000000FF1CE}"
$OOSLangPackGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{90160000-1157-0409-1000-0000000FF1CE}"
$SFBOcsCoreGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{DE39F60A-D57F-48F5-A2BD-8BA3FE794E1F}"
$SFBAdminToolsGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{9D5751C8-F6AC-4A33-9704-B1D2EB1769B6}"
$SFBDebugToolsGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{28AD6D73-F01E-404F-B5B0-92437B7D3BE6}"
$SFBResKitGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{AB30E3C1-9100-418D-9848-9A2891DCEAC5}"
$Silverlightx64GUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00}"
$Silverlightx64Name = "Microsoft Silverlight"
$UCMA5CoreRuntimeGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{C3FF05AC-3EF0-45A8-A7F2-9FD3C0F6DE39}"
$SQLMgmtObjectsGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{1F9EB3B6-AED7-4AA7-B8F1-8E314B74B2A5}"
$SQLClrTypesGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{8C06D6DB-A391-4686-B050-99CC522A7843}"
$SQL14ClrTypesName = "Microsoft System CLR Types for SQL Server 2014"
$SQL12NativeClientName = "Microsoft SQL Server 2012 Native Client"
$SQL12NativeClientGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{49D665A2-4C2A-476E-9AB8-FCC425F526FC}"
$SQL16SSMSNativeClientGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{1385D3DB-8E80-427B-91D2-B7535862B8E4}"
$WiresharkGUID = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark"
$ACSyslogGUID = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Syslog Viewer_is1"
$FirefoxName = "Mozilla Firefox"
$ChromeGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{BE40B3E0-129E-313C-B663-94C192C5143F}"
$ChromeName = "Google Chrome"
#KB4011023
$OOSPatchGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{90160000-1151-0000-1000-0000000FF1CE}_Office16.WacServer_{9DC3F506-577F-4C83-9A5D-095860A2928E}"
$IISARRGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{279B4CB0-A213-4F94-B224-19D6F5C59942}"
$SQLSMSPath = "C:\Program Files (x86)\Microsoft SQL Server\130\Tools\Binn\ManagementStudio\Ssms.exe"
$UrlRewriteGUID = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{08F0318A-D113-4CF0-993E-50F191D397AD}"

#File Hashes
$pthreadVC64SHA1Hash = "6668EBE373CE58C33017697C477557653427E626"
$npf32SHA1Hash = "8206E2D8374F5E7BF626E47D56D2431EDC939652"
$Packet32SHA1Hash ="80A2E420B99FFE294A523C6C6D87ED09DFC8D82B"
$Packet64SHA1Hash ="6CCDE3A8C76879E49B34E4ABB3B8DFAF7A9D77B5"
$wpcap32SHA1Hash = "B68E64401D91C75CAFA810086A35CD0838C61A4B"
$wpcap64SHA1Hash = "E5F449766722C5C25FA02B065D22A854B6A32A5B"

#Schema versions
#https://eightwone.com/references/ad-schema-versions/
#https://blogs.technet.microsoft.com/poshchap/2014/03/07/one-liner-active-directory-schema-version/
$SchemaHashAD = @{
	13="Windows 2000 Server"
	30="Windows Server 2003"
	31="Windows Server 2003 R2"
	44="Windows Server 2008"
	47="Windows Server 2008 R2"
	56="Windows Server 2012"
	69="Windows Server 2012 R2"
	82="Windows Server 2016 Technical Preview"
	87="Windows Server 2016"
}

#https://eightwone.com/references/ad-functional-levels/
#https://msdn.microsoft.com/en-us/library/cc223743.aspx
#https://msdn.microsoft.com/en-us/library/cc223741.aspx
$SchemaHashADFunctional = @{
	0="Windows 2000 Server"
	1="Windows Server 2003"
	2="Windows Server 2003 R2"
	3="Windows Server 2008"
	4="Windows Server 2008 R2"
	5="Windows Server 2012"
	6="Windows Server 2012 R2"
	7="Windows Server 2016"
}

#https://eightwone.com/references/schema-versions/
#https://technet.microsoft.com/en-us/library/bb125224%28v=exchg.150%29.aspx#Verify
#https://technet.microsoft.com/en-us/library/bb125224%28v=exchg.160%29.aspx#Verify
$SchemaHashExchange = @{
	4397="Exchange Server 2000 RTM"
	4406="Exchange Server 2000 SP3"
	6870="Exchange Server 2003 RTM"
	6936="Exchange Server 2003 SP3"
	10628="Exchange Server 2007 RTM"
	10637="Exchange Server 2007 RTM"
	11116="Exchange 2007 SP1"
	14622="Exchange 2007 SP2 or Exchange 2010 RTM"
	14625="Exchange 2007 SP3"
	14726="Exchange 2010 SP1"
	14732="Exchange 2010 SP2"
	14734="Exchange 2010 SP3"
	15137="Exchange 2013 RTM"
	15254="Exchange 2013 CU1"
	15281="Exchange 2013 CU2"
	15283="Exchange 2013 CU3"
	15292="Exchange 2013 SP1 (CU4)"
	15300="Exchange 2013 CU5"
	15303="Exchange 2013 CU6"
	15312="Exchange 2013 CU7-CU19"
	15317="Exchange 2016 RTM"
	15323="Exchange 2016 CU1"
	15325="Exchange 2016 CU2"
	15326="Exchange 2016 CU3-CU5"
	15330="Exchange 2016 CU6"
	15332="Exchange 2016 CU7-CU8"
}

#https://blogs.technet.microsoft.com/dodeitte/2009/09/24/how-to-verify-if-schema-prep-completed-successfully/
$SchemaHashCS = @{
	1006="LCS 2005"
	1007="OCS 2007 R1"
	1008="OCS 2007 R2"
	1100="Lync Server 2010"
	1150="Lync Server 2013/Skype for Business 2015"
}

#https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832%28v=vs.85%29.aspx
$VersionHashWin = @{
	"6.0"="Windows Server 2008"
	"6.1"="Windows Server 2008 R2"
	"6.2"="Windows Server 2012"
	"6.3"="Windows Server 2012 R2"
	"10.0"="Windows Server 2016"
}

#https://support.microsoft.com/en-us/kb/321185
$VersionHashSQL = @{
	"9.00"="SQL Server 2005"
	"10.0"="SQL Server 2008"
	"10.50"="SQL Server 2008 R2"
	"11.0"="SQL Server 2012"
	"12.0"="SQL Server 2014"
	"13.0"="SQL Server 2016"
	"14.0"="SQL Server 2017"
}

#.NET Framework version reference
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
	528040="4.8"
	528372="4.8"
	528049="4.8"
}



if (!($DownloadsOnly) -and !($PrereqsOnly) -and !($PostInstallTasks)){
	#Create working directory for logs and config
	$logDir = Split-Path $LogPath -Parent
	if (!(Test-Path $logDir)){
		New-Item $logDir -Type Directory | Out-Null
	}
	
	#Insert spacing
	if (Test-Path $LogPath){
		Write-Log
		Write-Log
		Write-Log "Resuming script."
		Write-Log
	}
	
	#Clean cached configuration and logs
	if ($Clean){
		Write-Log "Cleaning $TempDir" -Level "Verb"
		Get-ChildItem -Path $TempDir -Include *.xml -Recurse | ForEach-Object {Remove-Item $_.FullName -Confirm:$false}
	}
	
	#Create working directory for logs and config
	if (!(Test-Path $TempDir)){
		Write-Log "Creating temp directory: $TempDir" -Level "Verb"
		New-Item $TempDir -Type Directory | Out-Null
	}
	
	#Copy script to working directory if not running from working directory
	if ($PSScriptRoot -ne $TempDir){
		Write-Log "Copying script to $TempDir" -Level "Verb"
		$source = $PSScriptRoot+"\"+$MyInvocation.MyCommand.Name
		Copy-Item $source $TempDir\Install-CsServer.ps1
	}
	
	#Import/export variables to xml for continuty between reboots
	if (Test-Path $Clixml){
		Write-Log "Importing variables from clixml: $Clixml" -Level "Verb"
		Write-Log -Level "Verb"
		Import-Clixml $Clixml | Foreach-Object {Set-Variable $_.Name $_.Value -ErrorAction SilentlyContinue}
	}
	
	if (!($ServerType)){
		Write-Log "ServerType not set. Please set ServerType according to role: FEStd, FEEnt, Dir, PChat, Med, Edge, OOS, IISARR" -Level "Warn" -OutTo "Screen"
		return
	}
	
	#Check for hotfixes
	if (!(Get-HotFix "KB2919442" -ErrorAction SilentlyContinue)){
		$KB2919442Required = $true
	}
	if (!(Get-HotFix "KB2919355" -ErrorAction SilentlyContinue)){
		$KB2919355Required = $true
	}
	if (!(Get-HotFix "KB2982006" -ErrorAction SilentlyContinue)){
		$KB2982006Required = $true
	}
	#$KB2982006Required = Get-HotFix "KB2982006" -ErrorAction SilentlyContinue
	#$KB2919355Required = Get-HotFix "KB2919355" -ErrorAction SilentlyContinue
	
	#Test .NET Framework version
	if (Test-Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"){
		$ndpRelease = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release").Release
		#460798 is release for 4.7 on Server 2016, 460805 is release for all other OS
		#461308 is release for 4.7.1 on Server 2016, 461310 is release for all other OS
		if ($ndpRelease -lt 460805){
			$NDPUpgradeStatus = $true
		}elseif ($ndpRelease -ge 461310){
			$NDPDowngradeStatus = $true
		}
	}
	
	if ($Resume){
		$Script:Task = $Script:ResumeTask
		Toggle-ScheduledTask "CSDeploymentReboot" -Action "Disable" | Write-Log -Level "Verb"
		Write-Log -Level "Verb"

		if ($SetupPath){
			if (!(Test-Path $SetupPath)){
				if ($MediaPath -match ".iso|.img"){
					if ($Script:ImageMounted){
						Write-Log "Re-mounting disk image."
						Mount-DiskImage $MediaPath
						
						if (Test-Path $SetupPath){
							#Continue
						}else{
							Write-Log "$SetupPath not found." -Level "Error"
							return
						}
					}
				}else{
					if (Test-Path $SetupPath){
						#Continue
					}else{
						Write-Log "$SetupPath not found." -Level "Error"
						return
					}
				}
			}
		}
	}
}



#Preinstall verifications
if($Script:Task -eq "PrereqCheck"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	$errorPrereqs = @()
	$warnPrereqs = @()
	$recPrereqs = @()
	
	if (Test-Path $LogPath){
		Remove-Item $LogPath
	}
	if (Test-Path $StopWatchPath){
		Remove-Item $StopWatchPath
	}
	
	#Prepare saved credentials, scheduled tasks, and resume shortcut
	if (!($PrereqsOnly)){
		$Script:ResumeTask = $Script:Task
		#Save-Variables
		
		if ($Credential){
			$output = Export-UserCredential -Credential $Credential -ValidateOnly
		}else{
			$output = Export-UserCredential -Domain $env:userdomain -ValidateOnly
		}
		
		if ($output.Status){
			Write-Log "Credentials validated." -OutTo $LogOutTo
			$ADCreds = $output.Creds
		}else{
			Write-Log "Could not validate credentials. Verify username and password. Try DOMAIN\username and username@domain.com formats." -Level "Error" -OutTo $LogOutTo
			return
		}
	}
	
	#Verify monitoring reports service account
	if ($MonitoringReports){
		$output = Export-UserCredential -Domain $env:userdomain -Username $MonReportUser -Password $MonReportPassword -ValidateOnly
		$isValidMonCreds = $output.Status
		if (!($isValidMonCreds)){
			$errorPrereqs += "Monitoring report credentials could not be validated."
		}
	}
	
	#Check domain membership
	try {
		$domainjoined = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
	}catch{
		#Continue
		Write-Log "Catching error in GetComputerDomain." -Level "Verb"
	}
	if ($domainjoined){
		$isDomainJoined = $true
		if ($ServerType -match $ExtSrvTypes){
			$warnPrereqs += "Server is domain joined. It is recommended that Edge and reverese proxy servers are not domain joined."
		}
	}else{
		$isDomainJoined = $false
		if ($ServerType -match $IntSrvTypes){
			$errorPrereqs += "Server is not domain joined."
		}
	}
	
	#Check external file share
	if ($FileShareServer){
		if ((Test-NetConnection -ComputerName $FileShareServer -CommonTCPPort SMB -ErrorAction SilentlyContinue).TcpTestSucceeded){
			if ($FileShareName){
				$sharePath = "\\$FileShareServer\$FileShareName"
				$error.Clear()
				if (Test-Path $sharePath -ErrorAction SilentlyContinue){
					$isValidShare = $true
					if (New-Item $sharePath\TestDir -Type Directory -Force -ErrorAction SilentlyContinue){
						$hasChange = $true
						$Acl = Get-Acl "$sharePath\TestDir"
						$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("$env:UserDomain\Domain Users","FullControl","Allow")
						$Acl.SetAccessRule($Ar)
						Set-Acl $sharePath\TestDir $Acl -ErrorAction SilentlyContinue
						if (((Get-Acl "$sharePath\TestDir").Access | Where-Object IdentityReference -match "Domain Users").FileSystemRights -eq "FullControl"){
							$hasFullControl = $true
						}else{
							$hasFullControl = $false
							$errorPrereqs += "Insufficent permissions on $sharePath. Must have Full Control."
						}
					}else{
						$hasChange = $false
						$hasFullControl = $false
						$errorPrereqs += "Insufficent permissions on $sharePath. Must have Full Control."
					}
					Remove-Item $sharePath\TestDir -Force -ErrorAction SilentlyContinue
				}else{
					$isValidShare = $false
					$shareConnectivityError = $error[0].Exception.Message
					$errorPrereqs += "Error accessing ${sharePath}: $shareConnectivityError"
				}
			}
		}else{
			$isValidShare = $false
			$errorPrereqs += "Error connecting to $FileShareServer via TCP/445 (SMB)."
		}
	}elseif ($ServerType -match "FEEnt|Dir"){
		$warnPrereqs += "FileShareServer and FileSharePath must be specified in order to test validity."
	}
	
	#Check external SQL server
	#To Do: Need to validate ServerType
	if ($SQLServer){
		if ($SQLInstance){
			$sqlCheck = Test-SQLConnection -Server $SQLServer -Instance $SQLInstance -ServerRolesToCheck "sysadmin"
		}else{
			$sqlCheck = Test-SQLConnection -Server $SQLServer -ServerRolesToCheck "sysadmin"
		}
		if (!($sqlCheck.Clustered)){
			$smbPath = "\\$SQLServer\C$"
			if (Test-Path $smbPath -ErrorAction SilentlyContinue){
				$sqlSMB = $true
			}else{
				$sqlSMB = $false
				$errorPrereqs += "Error connecting to $SQLServer via TCP/445 (SMB)."
			}
		}else{
			$sqlSMB = $false
			$warnPrereqs += "$SQLServer is clustered, cannot automatically verify SMB access."
		}
		
		if ($sqlCheck.Error){
			$errorPrereqs += "Error connecting to ${SQLServer}: $($sqlCheck.Error)"
		}else{
			[string]$sqlVersion = [string]([version]$sqlCheck.Version).Major + "." + [string]([version]$sqlCheck.Version).Minor
			$sqlVersion = $VersionHashSQL.Item($sqlVersion)
		}
		if (!($sqlCheck.sysadmin)){
			$warnPrereqs += "User does not have SA rights on $SQLServer."
		}
		
		if ($MonitoringReports){
			if ($SQLInstance){
				$srsInstance = $SQLInstance
			}else{
				$srsInstance = "MSSQLSERVER"
			}
			
			$srsUrl = Get-SQLReportURL "root\Microsoft\SqlServer\ReportServer" $srsInstance $SQLServer
			try {
				$srsResult = Invoke-WebRequest $srsUrl -Method Head -UseDefaultCredentials -ErrorAction SilentlyContinue
			}catch{
				$errorPrereqs += "Unable to connect to SQL Reporting Services URL $srsUrl."
			}
			
			if ($srsResult.StatusCode -eq 200){
				$srsResult = $true
			}
		}
	}
	
	#If a domain joined machine check AD specific information
	if ($isDomainJoined){
		$adRoot = [ADSI]"LDAP://RootDSE"
		$adDN = $adRoot.Get("rootDomainNamingContext")
		$adSchemaPath = [ADSI]"LDAP://CN=Schema,CN=Configuration,$adDN"
		$adForestPath = [ADSI]"LDAP://CN=Partitions,CN=Configuration,$adDN"
		$adDomainPath = [ADSI]"LDAP://$adDN"
		$exchSchemaPath = [ADSI]"LDAP://CN=ms-Exch-Schema-Version-Pt,CN=Schema,CN=Configuration,$adDN"
		$csSchemaPath = [ADSI]"LDAP://CN=ms-RTC-SIP-SchemaVersion,CN=Schema,CN=Configuration,$adDN"
	
		#Check AD, Exchange, Lync/Skype4B versions
		#Check AD version
		if ($adSchemaPath.objectVersion){
			[int]$adSchemaVersion = $null
			[string]$string = $adSchemaPath.objectVersion
			[int32]::TryParse($string, [ref]$adSchemaVersion) | Out-Null
		}else{
			$adSchemaVersion = 0
		}
		$adVersion = $SchemaHashAD.Item($adSchemaVersion)
		
		#Check AD forest level
		if ($adForestPath."MSDS-Behavior-Version"){
			[int]$adForestVersion = $null
			[string]$string = $adForestPath."MSDS-Behavior-Version"
			[int32]::TryParse($string, [ref]$adForestVersion) | Out-Null
		}else{
			$adForestVersion = -1
		}
		$adForestMode = $SchemaHashADFunctional.Item($adForestVersion)
		
		#Check AD domain level
		if ($adDomainPath."MSDS-Behavior-Version"){
			[int]$adDomainVersion = $null
			[string]$string = $adDomainPath."MSDS-Behavior-Version"
			[int32]::TryParse($string, [ref]$adDomainVersion) | Out-Null
		}else{
			$adDomainVersion = -1
		}
		$adDomainMode = $SchemaHashADFunctional.Item($adDomainVersion)
		
		#Check Exchange version
		if ($exchSchemaPath.rangeUpper){
			[int]$exchSchemaVersion = $null
			[string]$string = $exchSchemaPath.rangeUpper
			[int32]::TryParse($string, [ref]$exchSchemaVersion) | Out-Null
			$exDeployed = $true
		}else{
			$exchSchemaVersion = 0
			#$exNotDeployed = $true
		}
		if ($exchSchemaVersion -lt 14625){
			if ($ServerType -match $IntCsSrvTypes){
				$warnPrereqs += "Exchange 2007 SP3 or Exchange 2010 SP1 and greater is required for full functionality."
			}
		}
		$exchVersion = $SchemaHashExchange.Item($exchSchemaVersion)
		
		#Check Lync/Skype4B version
		if ($csSchemaPath.rangeUpper){
			[int]$csSchemaVersion = $null
			[string]$string = $csSchemaPath.rangeUpper
			[int32]::TryParse($string, [ref]$csSchemaVersion) | Out-Null
			$csDeployed = $true
		}else{
			$csSchemaVersion = 0
			#$csNotDeployed = $true
		}
		$csVersion = $SchemaHashCS.Item($csSchemaVersion)
	
		#Check AD permissions
		if ((whoami /groups /fo list | findstr /i Schema) -match "Schema Admins"){
			$isSchemaAdmin = $true
		}else{
			$isSchemaAdmin = $false
			$PrepareAD = $false
		}
		
		if ((whoami /groups /fo list | findstr /i Enterprise) -match "Enterprise Admins"){
			$isEnterpriseAdmin = $true
		}else{
			$isEnterpriseAdmin = $false
			$PrepareAD = $false
		}
		
		if ((whoami /groups /fo list | findstr /i Domain) -match "Domain Admins"){
			$isDomainAdmin = $true
		}else{
			$isDomainAdmin = $false
			$PrepareAD = $false
		}
		
		if ($PrepareAD){
			if (!($isSchemaAdmin)){$errorPrereqs += "User is not a member of Schema Admins. Unable to prepare AD."}
			if (!($isEnterpriseAdmin)){$errorPrereqs += "User is not a member of Enterprise Admins. Unable to prepare AD."}
			if (!($isDomainAdmin)){$errorPrereqs += "User is not a member of Domain Admins. Unable to prepare AD."}
		}
		
		if ($csDeployed){
			if ((whoami /groups /fo list | findstr /i CsAdministrator) -match "CsAdministrator"){
				$isCsAdmin = $true
			}else{
				$isCsAdmin = $false
				if ($ServerType -match $IntCsSrvTypes){
					$warnPrereqs += "User is not a member of CsAdministrator."
				}
			}
			
			if ((whoami /groups /fo list | findstr /i RTCUniversalServerAdmins) -match "RTCUniversalServerAdmins"){
				$isRtcAdmin = $true
			}else{
				$isRtcAdmin = $false
				if ($ServerType -match $IntCsSrvTypes){
					$warnPrereqs += "User is not a member of RTCUniversalServerAdmins."
				}
			}
		}
		
		#Check Exchange permissions
		if ($exDeployed){
			if ((whoami /groups /fo list | findstr /i Organization) -match "Organization Management"){
				$isOrgAdmin = $true
			}else{
				$isOrgAdmin = $false
				$warnPrereqs += "User is not a member of Organization Management."
			}
			
			if (!($isOrgAdmin)){
				if ((whoami /groups /fo list | findstr /i UM) -match "UM Management"){
					$isUMAdmin = $true
				}else{
					$isUMAdmin = $false
					$warnPrereqs += "User is not a member of UM Management."
				}
				
				if ((whoami /groups /fo list | findstr /i Server) -match "Server Management"){
					$isSrvAdmin = $true
				}else{
					$isSrvAdmin = $false
					$warnPrereqs += "User is not a member of Server Management."
				}
			}
		}
	
		#Find internal CA
		if (!($OfflineRequest)){
			$adRoot = [ADSI]"LDAP://RootDSE"
			$adDN = $adRoot.Get("rootDomainNamingContext")
			$configRoot = [ADSI]"LDAP://CN=Configuration,$adDN"
			$query = new-object System.DirectoryServices.DirectorySearcher($configRoot)
			$query.filter = "(&(objectClass=PKIEnrollmentService)(CN=*))"
			$query.SearchScope = "subtree"
			$CAs = $query.findall()
			$CACount = $CAs.Count
			$CAList = @()
			$count = 0
			
			if ($CAs){
				$foundCA = $true
				foreach ($CA in $CAs){
					$count++
					$output = $CA.GetDirectoryEntry()
					$dnsName = $output.dnsHostName
					$cn = $output.cn
					
					$caOut = "" | Select-Object Server,CommonName,WebServerTemplate,Online
					$caOut.Server = $output.dnsHostName
					$caOut.CommonName = $output.cn
					
					if (!((Test-CAOnline -Config "$dnsName\$cn" -ErrorAction SilentlyContinue).ICertRequest)){
						$caOut.Online = $false
						$CAList += $caOut
						continue
					}else{
						$caOut.Online = $true
						$CAList += $caOut
					}
					
					if ($output.certificateTemplates -match "^WebServer$"){
						$caOut.WebServerTemplate = $true
					}else{
						$caOut.WebServerTemplate = $false
					}
					
					if (($cn -match $CAName) -or ($dnsName -match $CAName)){
						$CAFullName = "$dnsName\$cn"
						$CACN = $cn
						if (!($caOut.WebServerTemplate)){
							$errorPrereqs += "WebServer template is not available from selected CA. Choose a different CA or generate an offline request by specifying OfflineRequest."
						}
					}elseif (($count -eq $CACount) -and (!($CAFullName))){
						#If not match defined CAName then choose last discovered CA
						$CAFullName = "$dnsName\$cn"
						$CACN = $cn
						if (!($caOut.WebServerTemplate)){
							$errorPrereqs += "WebServer template is not available from selected CA. Choose a different CA or generate an offline request by specifying OfflineRequest."
						}
					}
				}
				if (!($CAFullName)){
					$warnPrereqs += "No online AD CA found. Resolve connectivity issues before continuing or offline requests will be created for submission to a third party CA."
				}
			}else{
				$warnPrereqs += "No AD CA found. Install an internal CA before continuing or offline requests will be created for submission to a third party CA."
			}
		
			#Check certificate is present in certificate store
			if ($foundCA){
				$trustedRoot = Get-ChildItem cert:\LocalMachine -Recurse | Where-Object Subject -match $CACN | Sort-Object NotAfter -Descending
				if ($trustedRoot){
					if ($trustedRoot.Count -gt 1){
						$trustedRootMultipleFound = $true
					}
					$trustedRootExpiration = $trustedRoot[0].NotAfter
					if ($trustedRootExpiration -lt (Get-Date).AddDays(365)){
						$warnPrereqs += "CA certificate expires in less than a year."
					}elseif ($trustedRootExpiration -lt (Get-Date).AddDays(180)){
						$errorPrereqs += "CA certificate expires in less than 6 months."
					}
					$trustedRootAlgorithm = $trustedRoot[0].SignatureAlgorithm.FriendlyName
					if ($trustedRootAlgorithm -match "sha1"){
						$warnPrereqs += "SHA1 certificates are being deprecated. It is recommended to renew the CA certificate as SHA2."
					}
					$trustedRootKeySize = $trustedRoot[0].PublicKey.Key.KeySize
					if ($trustedRoot){
						$isTrustedRoot = $true
					}else{
						$isTrustedRoot = $false
						$warnPrereqs += "CA certificate $CACN does not exist in certificate store."
					}
				}
			}
		}
	}
	
	#Check local permissions
	$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
	$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
	if (!($isAdmin)){
		$errorPrereqs += "This script must be run with elevated privileges."
	}
	
	#Determine .NET Framework version https://msdn.microsoft.com/en-us/library/hh925568%28v=vs.110%29.aspx
	if (Test-Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"){
		$ndpRelease = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release").Release
		$ndpVersion = $VersionHashNDP.Item($ndpRelease)
		if ($ndpRelease -gt 460805){
			$warnPrereqs += ".NET Framework $ndpVersion installed. Downgrading to 4.7."
		}
	}
	
	#Check OS version
	$OSVersion = (Get-WMIObject -Class Win32_OperatingSystem).Caption
	if($OSVersion -notmatch "Server (2012 R2|2012|2016)"){
		$errorPrereqs += "$OSVersion is not a supported operating system."
		#$isServer2016 = $false
	}elseif ($OSVersion -match "Server 2016"){
		$warnPrereqs += "$OSVersion requires CU5 to be supported."
		$isServer2016 = $true
	}elseif ($OSVersion -match "Server 2012 R2"){
		$isServer2012R2 = $true
	}else{
		#$isServer2016 = $false
	}
	
	#Check for Server Core
	
	#Check primary DNS suffix
	if (!($PrimaryDNSSuffix)){
		$suffix = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "NV Domain" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NV Domain"
		if ($suffix){
			$hasPriDNSSuffix = $true
			$dnsSuffix = $suffix
		}else{
			$hasPriDNSSuffix = $false
			$errorPrereqs += "Primary DNS suffix not configured. Specify PrimaryDNSSuffix."
			$dnsSuffix = ""
		}
	}else{
		$hasPriDNSSuffix = $true
		$dnsSuffix = $PrimaryDNSSuffix + " (Pending)"
	}
	
	#Check DNS registration
	if ($ServerType -match $IntSrvTypes){
		$serverFqdn = ([System.Net.Dns]::GetHostByName((hostname)).HostName)
		if (!(Resolve-DnsName $serverFqdn -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue)){
			$errorPrereqs += "$serverFqdn does not have an A record in DNS."
		}
	}
	
	#Check Windows Update configuration
	#https://p0w3rsh3ll.wordpress.com/2013/01/09/get-windows-update-client-configuration/
	$wuKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
	$AutoUpdateNotificationLevels = @{0="Not configured"; 1="Disabled"; 2="Notify before download"; 3="Notify before installation"; 4="Scheduled installation"}
	
	#Check for Windows Update enabled/disabled
	$auEnabled = (Get-ItemProperty $wuKey -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate
	if ($auEnabled){
		$muEnabled = $true
	}else{
		$muEnabled = $false
	}
	#Check Windows Update notification level
	$auOptions = (Get-ItemProperty $wuKey -Name "AUOptions" -ErrorAction SilentlyContinue).AUOptions
	if ($auOptions){
		$muNotificationLevel = $AutoUpdateNotificationLevels[$auOptions]
		if ($auOptions -eq 4){
			$warnPrereqs += "Windows Updates set to scheduled installation. To avoid unexpected outages this should be changed to disabled or notify."
		}
	}else{
		$muNotificationLevel = $AutoUpdateNotificationLevels[0]
	}
	#Check that opted in for Microsoft Updates
	$muOptinGUID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services" -Name "DefaultService" -ErrorAction SilentlyContinue).DefaultService
	if ($muOptinGUID -eq '7971f918-a847-4430-9279-4a52d1efe18d'){
		$muOptin = $true
	}else{
		$muOptin = $false
	}
	#Check for WSUS server
	if (Get-ItemProperty $wuKey -Name "UseWUServer" -ErrorAction SilentlyContinue){
		$muWSUS = $true
		
		$muWSUSServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue).WUServer
		#$muWSUSServerStatus = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -ErrorAction SilentlyContinue).WUStatusServer
	}else{
		$muWSUS = $false
	}
	
	#Check for virtualization
	$computer = Get-WmiObject Win32_ComputerSystem
	if ($computer.Manufacturer -match "VMware"){
		$virtState = $true
		$virtPlat = "VMware"
		if (Test-Path "HKLM:\Software\VMware, Inc.\VMware Tools"){
			$vmToolsPath = (Get-Item "HKLM:\Software\VMware, Inc.\VMware Tools").GetValue("InstallPath")
			Push-Location
			Set-Location $vmToolsPath
			$vmToolsStatus = Invoke-Expression ".\VMwareToolboxCmd.exe upgrade status"
			$vmToolsMemRes = Invoke-Expression ".\VMwareToolboxCmd.exe stat memres"
			#$vmToolsMemLimit = Invoke-Expression ".\VMwareToolboxCmd.exe stat memlimit"
			$vmToolsCPURes = Invoke-Expression ".\VMwareToolboxCmd.exe stat cpures"
			#$vmToolsCPULimit = Invoke-Expression ".\VMwareToolboxCmd.exe stat cpulimit"
			#$vmToolsSwap = Invoke-Expression ".\VMwareToolboxCmd.exe stat swap"
			#$vmToolsBalloon = Invoke-Expression ".\VMwareToolboxCmd.exe stat balloon"
			Pop-Location
		}else{
			$vmToolsStatus = "Not installed."
			$errorPrereqs += "VMware Tools must be installed for best performance and reliability."
		}
	}elseif ($computer.Manufacturer -match "Microsoft"){
		$virtState = $true
		$virtPlat = "Microsoft"
		$virtHost = (Get-Item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")
		[string]$osMajor = (Get-Item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostingSystemOsMajor")
		[string]$osMinor = (Get-Item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostingSystemOsMinor")
		$osVer = $osMajor+"."+$osMinor
		$virtHostOS = $VersionHashWin.Item($osVer)
		$virtMachineName = (Get-Item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("VirtualMachineName")
	}else{
		$virtState = $false
	}
	
	#If VMware, add specific recommendations
	if ($virtState){
		if ($virtPlat -match "VMware"){
			#https://blogs.vmware.com/vsphere/2013/10/microsoft-operating-system-time-sources-and-virtual-hardware-10.html
			$recPrereqs += "VMware VMs should use a minimum of VM hardware version 10."
			if (!(Get-NetAdapter | Where-Object InterfaceDescription -match "vmxnet3")){
				$recPrereqs += "VMware VMs should use the vmxnet3 network adapter."
			}
			if (!(Get-WmiObject -Class "Win32_SCSIController" | Where-Object Name -match "PVSCSI")){
				$recPrereqs += "VMware VMs should use the PVSCSI storage controller."
			}
		}
	}
	
	#Check power policy
	$powerPolicy = (Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "IsActive='$true'").ElementName
	
	#Check firewalls
	if ((Get-Service mpssvc).Status -eq "Running"){
		$isFWSvcRunning = $true
	}else{
		$isFWSvcRunning = $false
	}
	if ($isFWSvcRunning){
		$domainFW = (Get-NetFirewallProfile -Name Domain).Enabled
		$publicFW = (Get-NetFirewallProfile -Name Public).Enabled
		$privateFW = (Get-NetFirewallProfile -Name Private).Enabled
	}
	
	#Check CPUs
	$processors = Get-WmiObject Win32_Processor | Select-Object Name,MaxClockSpeed,CurrentClockSpeed,NumberOfCores,NumberOfLogicalProcessors
	$cpuModel = $processors[0].Name
	if ($processors.Name -match "E7-(4|8)8\d{2} v3"){$cpuMatched = $true}
	if ($processors.Name -match "E7-(2|4|8)8\d{2} v2"){$cpuMatched = $true}
	if ($processors.Name -match "E5-(2|4)6\d{2} v3"){$cpuMatched = $true}
	if ($processors.Name -match "E5-(2|4)6\d{2} v2"){$cpuMatched = $true}
	if ($processors.Name -match "E5-(2|4)6\d{2} !(v\d{1})"){$cpuMatched = $true}
	if ($processors.MaxClockSpeed[0] -le 2300){
		$cpuClockRec = $false
		$warnPrereqs += "2.3GHz is the recommended minimum clock speed."
	}else{
		$cpuClockRec = $true
	}
	if ($processors.CurrentClockSpeed[0] -lt ($processors.MaxClockSpeed[0]-10)){
		$cpuSpeedStep = $true
	}else{
		$cpuSpeedStep = $false
	}
	$cpuMaxSpeed = $processors.MaxClockSpeed[0]
	$cpuCount = ($processors | Measure-Object).Count
	$cpuCores = $processors[0].NumberOfCores * $cpuCount
	if (($ServerType -match $CsSrvTypes) -and ($virtState)){
		if ($cpuCount -eq $cpuCores){
			$warnPrereqs += "Verify that cores per socket is configured correctly. SQL Express will only utilize a single core if each vCPU is a presented as an individual CPU socket rather than multiple cores per socket."
		}
	}
	
	#Check memory
	$memory = (Get-WmiObject Win32_OperatingSystem | Select-Object @{l='TotalMemory';e={"{0:N2}GB" -f ($_.TotalVisibleMemorySize/1MB)}}).TotalMemory
	
	#Check network adapters
	$ipAdapter = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "IpEnabled=True"
	foreach ($ip in $ipAdapter){
		if ($ip.DHCPEnabled){
			$isDHCP = $true
			$errorPrereqs += "DHCP enabled. IP addresses must be statically assigned."
		}else{
			$isDHCP = $false
		}
	}
	
	if ($ServerType -match "Edge"){
		if (($ipAdapter).Count -lt 2){
			$dualNICs = $false
			$errorPrereqs += "Edge servers require two network adapters."
		}else{
			$dualNICs = $true
		}
	}
	
	#Check non-root certs in the trusted root store
	$nonRootCAs = Get-ChildItem Cert:\LocalMachine\Root -Recurse | Where-Object {$_.Issuer -ne $_.Subject} | Format-List *
	if ($nonRootCAs){
		$nonRootCAs | Out-File "$TempDir\nonRootCAs.txt"
		$errorPrereqs += "Non-root certificates found. Check $TempDir\nonRootCAs.txt for details."
		$errorPrereqs += "Non-root certificates in the trusted root certification store will cause the front end services to not start. Resolve ASAP."
	}
	
	#Check certificate parameters if no CA found or offline request
	if (!($foundCA) -or $OfflineRequest){
		if ($CertCountry -eq "" -or $CertState -eq "" -or $CertCity -eq "" -or $CertOrg -eq "" -or $CertOU -eq ""){
			$errorPrereqs += "Offline certificate requests must contain OU, Organization, City, State, and Country."
		}
	}
	
	#Discover OOS certificate friendly name
	if ($ServerType -match "OOS"){
		#Discovery OOS URL
		if (!($WACExternalUrl)){
			$WACExternalUrl = "https://oos.$($env:userdnsdomain.ToLower())"
			if (!($WACInternalUrl)){
				$WACInternalUrl = $WACExternalUrl
			}
		}
		
		if ($WACExternalUrl){
			if (!($FriendlyName)){
				$wacSubject = $WACExternalUrl
				$wacSubject = $wacSubject  -replace "https://",""
				$wacSubject = $wacSubject  -replace "/(.+)?",""
				$FriendlyName = (Get-ChildItem cert:\LocalMachine\My | Where-Object Subject -match $wacSubject).FriendlyName
				if (!($FriendlyName)){
					$errorPrereqs += "OOS certificate could not be found."
				}
			}else{
				if (!(Get-ChildItem cert:\LocalMachine\My | Where-Object FriendlyName -match $FriendlyName)){
					$errorPrereqs += "OOS certificate could not be found."
				}
			}
		}else{
			$errorPrereqs += "WACUrl must be defined."
		}
	}
	
	#Discover IIS ARR certificate friendly name
	if ($ServerType -match "IISARR"){
		if ($WebServicesExtFQDN){
			if (!($FriendlyName)){
				$FriendlyName = (Get-ChildItem cert:\LocalMachine\My | Where-Object Subject -match $WebServicesExtFQDN).FriendlyName
				if (!($FriendlyName)){
					$errorPrereqs += "ARR certificate could not be found."
				}
			}else{
				if (!(Get-ChildItem cert:\LocalMachine\My | Where-Object FriendlyName -match $FriendlyName)){
					$errorPrereqs += "ARR certificate could not be found."
				}
			}
		}else{
			$errorPrereqs += "WebServicesExtUrl must be defined for ServerType IISARR."
		}
		if (!($WebServicesIntFQDN)){
			$errorPrereqs += "WebServicesIntUrl must be defined for ServerType IISARR."
		}
	}
	
	#Determine if application drive exists, if so install to non-system drive
	if (!($InstallDrive)){
		$diskDrives = Get-WMIObject win32_logicaldisk | Where-Object {$_.DriveType -eq 3 -and $_.DeviceID -ne "C:"}
		if ($diskDrives){
			foreach ($diskDrive in $diskDrives){
				if ($diskDrive.FreeSpace/1GB -gt 35){
					$InstallDrive = $diskDrive.DeviceID
					break
				}
			}
		}else{
			$InstallDrive = "C:"
		}
	}
	
	#Check hard drive space
	$drives = Get-WmiObject Win32_Volume -Filter 'DriveType = 3' | Where-Object DriveLetter -ne $null | `
		Select-Object DriveLetter,Label,@{l='CapacityGB';e={$_.Capacity/1GB}},@{l='FreeSpaceGB';e={$_.FreeSpace/1GB}},@{l='FreeSpacePercent';e={($_.FreeSpace/$_.Capacity)*100}}
	foreach ($drive in $drives){
		if ($drive.FreeSpaceGB -lt 40){
			if ($ServerType -match $CsSrvTypes -and $InstallDrive -eq $drive.DriveLetter){
				$errorPrereqs += $drive.DriveLetter+" has less than 40GB. This will cause failure during installation."
			}else{
				$warnPrereqs += $drive.DriveLetter+" has less than 40GB. This may be insufficient space for installation."
			}
		}
	}
	
	#Test and resolve absolute path for media
	if ($MediaPath){
		if (Test-Path $MediaPath){
			$MediaPath = (Resolve-Path $MediaPath).ProviderPath
		}else{
			$errorPrereqs += "MediaPath is not accessible or does not exist."
		}
	}
	
	#Test and resolve Windows source path
	if (Test-Path $SourcePath){
		$SourcePath = (Resolve-Path $SourcePath).ProviderPath
	}else{
		$errorPrereqs += "SourcePath is not accessible or does not exist."
	}
	
	#Internet Access
	if (!($HasInternetAccess)){
		$warnPrereqs += "Could not detect internet connectivity. Source files must be prestaged to $SoftwareDir or specify SoftwareDir to define an alternate software repository."
	}
	
	#Warn about PCI 3.1 requirements
	if ($PCI31){
		$warnPrereqs += "PCI 3.1 disables TLS 1.0. Ensure that all connecting clients and servers support and are enabled for TLS 1.1 or higher. `
			More information here: https://blogs.msdn.microsoft.com/kaushal/2011/10/02/support-for-ssltls-protocols-on-windows/"
	}
	
	#Write output from prerequisite checks
	Write-Log "Username                 : $env:UserDomain\$env:UserName" -OutTo $LogOutTo
	Write-Log "Elevated Privileges      : $isAdmin" -OutTo $LogOutTo
	if ($isDomainJoined){
		Write-Log "Schema Admin             : $isSchemaAdmin" -OutTo $LogOutTo
		Write-Log "Enterprise Admin         : $isEnterpriseAdmin" -OutTo $LogOutTo
		Write-Log "Domain Admin             : $isDomainAdmin" -OutTo $LogOutTo
		if ($csDeployed){
			Write-Log "CSAdministrator          : $isCsAdmin" -OutTo $LogOutTo
			Write-Log "RTCUniversalServerAdmins : $isRtcAdmin" -OutTo $LogOutTo
		}
		if ($exDeployed){
			Write-Log "Organization Management  : $isOrgAdmin" -OutTo $LogOutTo
			if (!($isOrgAdmin)){
				Write-Log "UM Management            : $isUMAdmin" -OutTo $LogOutTo
				Write-Log "Server Management        : $isSrvAdmin" -OutTo $LogOutTo
			}
		}
		Write-Log -OutTo $LogOutTo
		
		Write-Log "AD Schema                : $adVersion" -OutTo $LogOutTo
		Write-Log "AD Forest Mode           : $adForestMode" -OutTo $LogOutTo
		Write-Log "AD Domain Mode           : $adDomainMode" -OutTo $LogOutTo
		Write-Log "Exchange Schema          : $exchVersion" -OutTo $LogOutTo
		Write-Log "Lync/Skype4B Schema      : $csVersion" -OutTo $LogOutTo
		Write-Log -OutTo $LogOutTo
		
		Write-Log "Certificate Authorities  : $CACount" -OutTo $LogOutTo
		if ($foundCA){
			foreach ($CA in $CAList){
				Write-Log "    Server               : $($CA.Server)" -OutTo $LogOutTo
				Write-Log "    CommonName           : $($CA.CommonName)" -OutTo $LogOutTo
				Write-Log "    WebServerTemplate    : $($CA.WebServerTemplate)" -OutTo $LogOutTo
				Write-Log "    Online               : $($CA.Online)" -OutTo $LogOutTo
				Write-Log -OutTo $LogOutTo
			}
			if ($CAFullName){
				Write-Log "Selected Server" -OutTo $LogOutTo
				Write-Log "    Server\Name          : $CAFullName" -OutTo $LogOutTo
				Write-Log "    Trusted              : $isTrustedRoot" -OutTo $LogOutTo
				if ($isTrustedRoot){
					Write-Log "    Expiration           : $trustedRootExpiration" -OutTo $LogOutTo
					Write-Log "    Algorithm            : $trustedRootAlgorithm" -OutTo $LogOutTo
					Write-Log "    Key Size             : $trustedRootKeySize" -OutTo $LogOutTo
					if ($trustedRootMultipleFound){
						Write-Log "    Multiple matches     : $trustedRootMultipleFound" -OutTo $LogOutTo
					}
				}
				Write-Log -OutTo $LogOutTo
			}
		}
	}
	if ($FileShareServer){
		Write-Log "File Share Path          : $sharePath" -OutTo $LogOutTo
		Write-Log "    Connectivity         : $isValidShare" -OutTo $LogOutTo
		if ($shareConnectivityError){
			Write-Log "    Connectivity Error   : $shareConnectivityError" -OutTo $LogOutTo
		}else{
			Write-Log "    Change               : $hasChange" -OutTo $LogOutTo
			Write-Log "    Full Control         : $hasFullControl" -OutTo $LogOutTo
		}
	}
	if ($SQLServer){
		if ($sqlCheck.errMsg){
			Write-Log "SQL Server               : $SQLServer" -OutTo $LogOutTo
			if ($SQLInstance){
				Write-Log "SQL Instance             : $SQLInstance" -OutTo $LogOutTo
			}
			Write-Log "SQL Connectivity         : $($sqlCheck.Connectivity)" -OutTo $LogOutTo
			Write-Log "    Connectivity Error       : $($sqlCheck.errMsg)" -OutTo $LogOutTo
		}else{
			Write-Log "SQL Server               : $SQLServer" -OutTo $LogOutTo
			if ($SQLInstance){
				Write-Log "    Instance             : $SQLInstance" -OutTo $LogOutTo
			}
			Write-Log "    Connectivity         : $($sqlCheck.Connectivity)" -OutTo $LogOutTo
			Write-Log "    Version              : $sqlVersion" -OutTo $LogOutTo
			Write-Log "    Build                : $($sqlCheck.Version)" -OutTo $LogOutTo
			Write-Log "    Clustered            : $($sqlCheck.Clustered)" -OutTo $LogOutTo
			Write-Log "    AlwaysOn             : $($sqlCheck.AlwaysOn)" -OutTo $LogOutTo
			Write-Log "    sysadmin             : $($sqlCheck.sysadmin)" -OutTo $LogOutTo
			if ($MonitoringReports){
				Write-Log "SRS Report URL           : $srsUrl" -OutTo $LogOutTo
				Write-Log "SRS Report URL Status    : $srsResult" -OutTo $LogOutTo
				Write-Log "Monitoring Report User   : $isValidMonCreds" -OutTo $LogOutTo
			}
		}
		Write-Log "SQL File Share Access    : $sqlSMB" -OutTo $LogOutTo
	}
	Write-Log -OutTo $LogOutTo
	
	Write-Log "Computer Name            : $env:ComputerName" -OutTo $LogOutTo
	Write-Log "Operating System         : $OSVersion" -OutTo $LogOutTo
	Write-Log "Internet Connectivty     : $HasInternetAccess" -OutTo $LogOutTo
	Write-Log "Domain Joined            : $isDomainJoined" -OutTo $LogOutTo
	Write-Log "Primary DNS Suffix       : $dnsSuffix" -OutTo $LogOutTo
	Write-Log "Windows Updates Enabled  : $muEnabled" -OutTo $LogOutTo
	Write-Log "    Configuration        : $muNotificationLevel" -OutTo $LogOutTo
	Write-Log "    Microsoft Updates    : $muOptin" -OutTo $LogOutTo
	Write-Log "    WSUS Configured      : $muWSUS" -OutTo $LogOutTo
	if ($muWSUS){
		Write-Log "    WSUS Server           : $muWSUSServer" -OutTo $LogOutTo
		#Write-Log "    WSUS Server Status    : $muWSUSServerStatus" -OutTo $LogOutTo
	}
	Write-Log ".NET Framework           : $ndpVersion" -OutTo $LogOutTo
	Write-Log "Virtualized              : $virtState" -OutTo $LogOutTo
	if ($virtState){
		Write-Log "Virtual Platform         : $virtPlat" -OutTo $LogOutTo
	}
	if ($vmToolsStatus){
		Write-Log "VMware Tools Status      : $vmToolsStatus" -OutTo $LogOutTo
	}
	if ($vmToolsMemRes){
		Write-Log "Memory Reservation       : $vmToolsMemRes" -OutTo $LogOutTo
	}
	if ($vmToolsCPURes){
		Write-Log "CPU Reservation          : $vmToolsCPURes" -OutTo $LogOutTo
	}
	if ($virtHost){
		Write-Log "Virtual Host             : $virtHost" -OutTo $LogOutTo
	}
	if ($virtHostOS){
		Write-Log "Virtual Host OS          : $virtHostOS" -OutTo $LogOutTo
	}
	if ($virtMachineName){
		Write-Log "Virtual Machine Name     : $virtMachineName" -OutTo $LogOutTo
	}
	Write-Log "Power Policy             : $powerPolicy" -OutTo $LogOutTo
	Write-Log "Firewall Service         : $isFWSvcRunning" -OutTo $LogOutTo
	if ($isFWSvcRunning){
		Write-Log "    Domain Profile       : $domainFW" -OutTo $LogOutTo
		Write-Log "    Private Profile      : $privateFW" -OutTo $LogOutTo
		Write-Log "    Public Profile       : $publicFW" -OutTo $LogOutTo
	}
	Write-Log -OutTo $LogOutTo
	
	Write-Log "CPU Model                : $cpuModel" -OutTo $LogOutTo
	Write-Log "    Clock Speed          : $cpuMaxSpeed" -OutTo $LogOutTo
	Write-Log "    2.3GHz+              : $cpuClockRec" -OutTo $LogOutTo
	#Write-Log "    SpeedStep            : $cpuSpeedStep" -OutTo $LogOutTo
	Write-Log "    Sockets              : $cpuCount" -OutTo $LogOutTo
	Write-Log "    Cores                : $cpuCores" -OutTo $LogOutTo
	Write-Log "Total Memory             : $memory" -OutTo $LogOutTo
	Write-Log "DHCP Enabled             : $isDHCP" -OutTo $LogOutTo
	if ($ServerType -match "Edge"){
		Write-Log "Dual NICs                : $dualNICs" -OutTo $LogOutTo
	}
	Write-Log "Disk Free Space" -OutTo $LogOutTo
	foreach ($drive in $drives){
		Write-Log "$($drive.DriveLetter) $("{0:N2}" -f ($drive.FreeSpaceGB))GB/$("{0:N2}" -f ($drive.CapacityGB))GB ($("{0:N2}" -f ($drive.FreeSpacePercent))%)" -OutTo $LogOutTo
	}
	Write-Log -OutTo $LogOutTo
	Write-Log -OutTo $LogOutTo
	
	Write-Log "Variables" -OutTo $LogOutTo
	Write-Log "ServerType               : $ServerType" -OutTo $LogOutTo
	Write-Log "PrimaryServer            : $PrimaryServer" -OutTo $LogOutTo
	Write-Log "PrepareAD                : $PrepareAD" -OutTo $LogOutTo
	Write-Log "PrepareFirstStd          : $PrepareFirstStd" -OutTo $LogOutTo
	Write-Log "MediaPath                : $MediaPath" -OutTo $LogOutTo
	Write-Log "SourcePath               : $SourcePath" -OutTo $LogOutTo
	Write-Log "SoftwareDir              : $SoftwareDir" -OutTo $LogOutTo
	Write-Log "InstallDrive             : $InstallDrive" -OutTo $LogOutTo
	Write-Log "PrimaryDNSSuffix         : $PrimaryDNSSuffix" -OutTo $LogOutTo
	Write-Log "FileShareServer          : $FileShareServer" -OutTo $LogOutTo
	Write-Log "FileSharePath            : $FileSharePath" -OutTo $LogOutTo
	Write-Log "FileShareName            : $FileShareName" -OutTo $LogOutTo
	Write-Log "SQLServer                : $SQLServer" -OutTo $LogOutTo
	Write-Log "SQLInstance              : $SQLInstance" -OutTo $LogOutTo
	Write-Log "MonReportUser            : $MonReportUser" -OutTo $LogOutTo
	#$MonReportPassword
	
	Write-Log "WebServicesIntIP         : $WebServicesIntIP" -OutTo $LogOutTo
	Write-Log "WebServicesExtIP         : $WebServicesExtIP" -OutTo $LogOutTo
	Write-Log "WebServicesIntURL        : $WebServicesIntFQDN" -OutTo $LogOutTo
	Write-Log "WebServicesExtURL        : $WebServicesExtFQDN" -OutTo $LogOutTo
	Write-Log "Domains                  : $Domains" -OutTo $LogOutTo
	
	Write-Log "CAName                   : $CAName" -OutTo $LogOutTo
	Write-Log "CertCity                 : $CertCity" -OutTo $LogOutTo
	Write-Log "CertState                : $CertState" -OutTo $LogOutTo
	Write-Log "CertCountry              : $CertCountry" -OutTo $LogOutTo
	Write-Log "CertOrg                  : $CertOrg" -OutTo $LogOutTo
	Write-Log "CertOU                   : $CertOU" -OutTo $LogOutTo
	Write-Log "CertKeySize              : $CertKeySize" -OutTo $LogOutTo
	Write-Log "OfflineRequest           : $OfflineRequest" -OutTo $LogOutTo
	
	Write-Log "PortAudioStart           : $PortAudioStart" -OutTo $LogOutTo
	Write-Log "PortAudioEnd             : $PortAudioEnd" -OutTo $LogOutTo
	Write-Log "PortVideoStart           : $PortVideoStart" -OutTo $LogOutTo
	Write-Log "PortVideoEnd             : $PortVideoEnd" -OutTo $LogOutTo
	Write-Log "PortAppShareStart        : $PortAppShareStart" -OutTo $LogOutTo
	Write-Log "PortAppShareEnd          : $PortAppShareEnd" -OutTo $LogOutTo
	Write-Log "PortFileTransferStart    : $PortFileTransferStart" -OutTo $LogOutTo
	Write-Log "PortFileTransferEnd      : $PortFileTransferEnd" -OutTo $LogOutTo
	Write-Log "QoSAudioDSCP             : $QoSAudioDSCP" -OutTo $LogOutTo
	Write-Log "QoSVideoDSCP             : $QoSVideoDSCP" -OutTo $LogOutTo
	Write-Log "QoSAppShareDSCP          : $QoSAppShareDSCP" -OutTo $LogOutTo
	Write-Log "QoSServer                : $QoSServer" -OutTo $LogOutTo
	Write-Log "QoSClient                : $QoSClient" -OutTo $LogOutTo
	Write-Log "Policies                 : $Policies" -OutTo $LogOutTo
	Write-Log "DialPlan                 : $DialPlan" -OutTo $LogOutTo
	
	Write-Log "ACSyslog                 : $ACSyslog" -OutTo $LogOutTo
	Write-Log "Wireshark                : $Wireshark" -OutTo $LogOutTo
	Write-Log "Firefox                  : $Firefox" -OutTo $LogOutTo
	Write-Log "Chrome                   : $Chrome" -OutTo $LogOutTo
	Write-Log "SQLMgmtStudio            : $SQLMgmtStudio" -OutTo $LogOutTo
	Write-Log "DeviceUpdates            : $DeviceUpdates" -OutTo $LogOutTo
	Write-Log "MonitoringReports        : $MonitoringReports" -OutTo $LogOutTo
	Write-Log "ABSNormNA                : $ABSNormNA" -OutTo $LogOutTo
	Write-Log "ABSNormIntl              : $ABSNormIntl" -OutTo $LogOutTo
	Write-Log "KeepPowerPlan            : $KeepPowerPlan" -OutTo $LogOutTo
	Write-Log "ShowServerManager        : $ShowServerManager" -OutTo $LogOutTo
	Write-Log "SkipWindowsUpdates       : $SkipWindowsUpdates" -OutTo $LogOutTo
	Write-Log "PCI31                    : $PCI31" -OutTo $LogOutTo
	
	Write-Log "WACPrimaryServer         : $WACPrimaryServer" -OutTo $LogOutTo
	Write-Log "WACExternalUrl           : $WACExternalUrl" -OutTo $LogOutTo
	Write-Log "WACInternalUrl           : $WACInternalUrl" -OutTo $LogOutTo
	Write-Log "FriendlyName             : $FriendlyName" -OutTo $LogOutTo
	
	Write-Log "OverridePrereqs          : $OverridePrereqs" -OutTo $LogOutTo
	
	Write-Log -OutTo $LogOutTo

	if ($recPrereqs){
		Write-Log "-----------------------------------------------------------" -OutTo $LogOutTo
		Write-Log "                      Recommendations                      " -OutTo $LogOutTo
		Write-Log "-----------------------------------------------------------" -OutTo $LogOutTo
		Write-Log -OutTo $LogOutTo
		foreach ($msg in $recPrereqs){
			Write-Log $msg -OutTo $LogOutTo
		}
		Write-Log -OutTo $LogOutTo
	}

	if ($warnPrereqs){
		Write-Log "-----------------------------------------------------------" -OutTo $LogOutTo
		Write-Log "                          Warnings                         " -OutTo $LogOutTo
		Write-Log "-----------------------------------------------------------" -OutTo $LogOutTo
		Write-Log -OutTo $LogOutTo
		foreach ($msg in $warnPrereqs){
			Write-Log $msg -OutTo $LogOutTo
		}
		Write-Log -OutTo $LogOutTo
	}
	
	if ($errorPrereqs){
		Write-Log "-----------------------------------------------------------" -OutTo $LogOutTo
		Write-Log "                           Errors                          " -OutTo $LogOutTo
		Write-Log "-----------------------------------------------------------" -OutTo $LogOutTo
		Write-Log -OutTo $LogOutTo
		foreach ($msg in $errorPrereqs){
			Write-Log $msg -OutTo $LogOutTo
		}
		Write-Log -OutTo $LogOutTo
	}

	if ($PrereqsOnly){
		#Stop at end of task
	}elseif ($errorPrereqs -and !($OverridePrereqs)){
		#Stop at end of task
		End-Task -NextTask "None" -Quiet -NoSave
		Write-Log
	}else{
		if ($OverridePrereqs){
			Write-Log "Overriding prerequisites."
		}
		#Insert instructions here
		Write-Log
		Write-Log "Once parameters are committed, do not rerun the script with full parameters"
		Write-Log "and do not delete the contents of $TempDir or the desktop icons."
		Write-Log
		Write-Log "To manage the script use the Stop and Start icons on the desktop"
		Write-Log "or run .\Install-CsServer.ps1 -Resume. "
		Write-Log
		while ($response -notmatch "Y|N"){
			Write-Host -NoNewLine "Commit parameters and continue? (Y/N) "
			$response = Read-Host
			if ($response -eq "Y"){
				End-Task -NextTask "Commit" -Quiet -NoSave
			}else{
				Write-Log
				break
			}
		}
		Write-Log
	}
}




if($Script:Task -eq "Commit"){
	#Create resume scheduled task
	if (!(Get-ScheduledTask "CSDeployment" -ErrorAction SilentlyContinue)){
		Write-Log "Creating scheduled tasks to resume script." -OutTo $LogOutTo
		Write-Log -OutTo $LogOutTo
		$arg = '-File "'+$TempDir+'\Install-CsServer.ps1" -Resume'
		Manage-ScheduledTask -TaskName "CSDeployment" -Action "Add" -StartupType OnDemand -Execute powershell -Argument $arg -Credential $ADCreds
	}
	
	#Create restart scheduled task
	if (!(Get-ScheduledTask "CSDeploymentReboot" -ErrorAction SilentlyContinue)){
		$arg = "-Command & {Start-ScheduledTask CSDeployment}"
		Manage-ScheduledTask -TaskName "CSDeploymentReboot" -Action "Add" -StartupType AtStartup -Execute powershell -Argument $arg -User "SYSTEM"
		Toggle-ScheduledTask -TaskName "CSDeploymentReboot" -Action "Disable"
	}
	
	#Create status shortcut
	New-Shortcut -Path "$env:Public\Desktop\Status.lnk" -TargetPath "powershell.exe" -Arguments "-Command & {Get-Content $LogPath -Wait}"
	
	#Create shortcut to TempDir
	New-Shortcut -Path "$env:Public\Desktop\Temp Directory.lnk" -TargetPath $TempDir
	
	#Create resume shortcut
	New-Shortcut -Path "$env:Public\Desktop\Resume.lnk" -TargetPath "powershell.exe" -Arguments "-Command & {Start-ScheduledTask CSDeployment}"
	
	#Create stop shortcut
	New-Shortcut -Path "$env:Public\Desktop\Stop.lnk" -TargetPath "powershell.exe" -Arguments "-Command & {Stop-ScheduledTask CSDeployment}"
	
	#Create certlm shortcut
	New-Shortcut -Path "$env:Public\Desktop\Certificates.lnk" -TargetPath "$env:windir\system32\certlm.msc"
	
	#Save parameters to Clixml after prerequisites have been reviewed
	if (!(Test-Path $Clixml)){
		Write-Log "Exporting variables to $Clixml"
		Write-Log
		Get-Variable `
		ServerType,`
		MediaPath,`
		SetupPath,`
		SoftwareDir,`
		InstallDrive,`
		PrimaryServer,`
		PrepareAD,`
		PrepareFirstStd,`
		PrimaryDNSSuffix,`
		FileShareServer,`
		FileSharePath,`
		FileShareName,`
		MonReportUser,`
		MonReportPassword,`
		WebServicesIntIP,`
		WebServicesExtIP,`
		WebServicesIntFQDN,`
		WebServicesExtFQDN,`
		Domains,`
		CAFullName,`
		CertCountry,`
		CertState,`
		CertCity,`
		CertKeySize,`
		CertOrg,`
		CertOU,`
		PortAudioStart,`
		PortAudioEnd,`
		PortVideoStart,`
		PortVideoEnd,`
		PortAppShareStart,`
		PortAppShareEnd,`
		PortFileTransferStart,`
		PortFileTransferEnd,`
		QoSAudioDSCP,`
		QoSVideoDSCP,`
		QoSAppShareDSCP,`
		QoSServer,`
		QoSClient,`
		Policies,`
		DialPlan,`
		DeviceUpdates,`
		MonitoringReports,`
		ABSNormNA,`
		ABSNormIntl,`
		ACSyslog,`
		Wireshark,`
		Firefox,`
		Chrome,`
		SQLMgmtStudio,`
		KeepPowerPlan,`
		ShowServerManager,`
		SkipWindowsUpdates,`
		PCI31,`
		WACPrimaryServer,`
		WACExternalUrl,`
		WACInternalUrl,`
		FriendlyName,`
		Manual,`
		ResumeTask,`
		ImageMounted,`
		StartTime,`
		isServer2016,`
		isServer2012R2 `
		-ErrorAction SilentlyContinue | Export-Clixml $Clixml
	}
	
	End-Task -NextTask "PrereqDownload" -Quiet -NoSave
}



#Prerequisite downloads
if($Script:Task -eq "PrereqDownload"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	#Start downloads
	#Remove failed BITS jobs
	Get-BitsTransfer | Where-Object DisplayName -eq "CSDownloads" | Remove-BitsTransfer
	
	#Allow TLS 1.2-1.0 for WinHTTP for BITS Transfers and for Invoke-WebRequest
	[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
	#https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DefaultSecureProtocols" -PropertyType DWORD -Value "0x000000a80" -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DefaultSecureProtocols" -PropertyType DWORD -Value "0x000000a80" -Force -ErrorAction SilentlyContinue | Out-Null
	
	#Required downloads
	$error.Clear()
	#7zip
	Write-Log "Downloading 7zip." -OutTo $LogOutTo
	Start-Download -JobName "CSDownloads" -Source $7zipExeUrl -Destination $SoftwareDir\7zip
	Start-Download -JobName "CSDownloads" -Source $7zipDllUrl -Destination $SoftwareDir\7zip
	
	#Security
	Write-Log "Downloading IISCrypto." -OutTo $LogOutTo
	Start-Download -Source $IISCryptoUrl -Destination $SoftwareDir
	
	#SQL Express 2014 SP2
	#CS Server Updates
	#Debugging Tools
	if ($ServerType -match "FEStd|FEEnt|Dir|PChat|Med|Edge|All"){
		Write-Log "Downloading SQL Express SP2." -OutTo $LogOutTo
		if (!(Test-Path $SoftwareDir\SQLEXPR_x64_ENU)){Start-Download -JobName "CSDownloads" -Source $SQLExp14SP2Url -Destination $SoftwareDir}
		Write-Log "Downloading SFB server updates." -OutTo $LogOutTo
		Start-Download -JobName "CSDownloads" -Source $CS15DebugSrcUrl -Destination $SoftwareDir
		Write-Log "Downloading SFB Debugging Tools." -OutTo $LogOutTo
		Start-Download -JobName "CSDownloads" -Source $CS15UpdatesSrcUrl -Destination $SoftwareDir
		#Write-Log "Downloading VC++ 2015 Update 3." -OutTo $LogOutTo
		#Start-Download -JobName "CSDownloads" -Source $DebugVC2015U3Url -Destination $SoftwareDir -FileName DebuggingTools_vc_redist.x64.exe
	}
	
	#IIS hotfix KB2982006 and KB2919355 and KB2919442 for Server 2012 R2 or URL Rewrite Module for Server 2016
	if ($ServerType -match "FEStd|FEEnt|Dir|All"){
		if ($isServer2016 -or ($ServerType -match "All")){
			Write-Log "Downloading URL Rewrite Module for Server 2016 support." -OutTo $LogOutTo
			Start-Download -JobName "CSDownloads" -Source $UrlRewriteUrl -Destination $SoftwareDir
		}
		if ($isServer2012R2 -or ($ServerType -match "All")){
			if ($KB2919442Required){
				Write-Log "Downloading KB2919442. Prerequisite for KB2919355." -OutTo $LogOutTo
				Start-Download -JobName "CSDownloads" -Source $KB2919442Url -Destination $SoftwareDir
			}
			if ($KB2919355Required){
				Write-Log "Downloading KB2919355. Prerequisite for KB2982006." -OutTo $LogOutTo
				Start-Download -JobName "CSDownloads" -Source $KB2919355Url -Destination $SoftwareDir
			}
			if ($KB2982006Required){
				Write-Log "Downloading KB2982006 (IIS Hotfix)." -OutTo $LogOutTo
				Start-Download -JobName "CSDownloads" -Source $KB2982006Url -Destination $SoftwareDir
			}
		}
	}
	
	#Resource Kit
	if ($ServerType -match "FEStd|FEEnt|All"){
		Write-Log "Downloading Resource Kit." -OutTo $LogOutTo
		Start-Download -JobName "CSDownloads" -Source $CS15ResKitURL -Destination $SoftwareDir
	}
	
	#KHI
	if ($ServerType -match $CsSrvTypes){
		Write-Log "Downloading KHIs." -OutTo $LogOutTo
		Start-Download -JobName "CSDownloads" -Source $CSKHIUrl -Destination $SoftwareDir
	}
	
	#Silverlight
	if ($ServerType -match "FEStd|FEEnt|Dir|All"){
		Write-Log "Downloading Silverlight." -OutTo $LogOutTo
		Start-Download -JobName "CSDownloads" -Source $SilverlightUrl -Destination $SoftwareDir
	}
	
	#Office Online Server, Language Pack, and Prerequistes
	if ($ServerType -match "OOS|All"){
		Write-Log "Downloading Office Online Server files." -OutTo $LogOutTo
		if (!($MediaPath)){
			#Start-Download -JobName "CSDownloads" -Source $OOSImgUrl -Destination $SoftwareDir
		}
		Start-Download -JobName "CSDownloads" -Source $OOSLanguagePackUrl -Destination $SoftwareDir
		Start-Download -JobName "CSDownloads" -Source $OOSPatchUrl -Destination $SoftwareDir
		Start-Download -JobName "CSDownloads" -Source $OOSVC2015Url -Destination $SoftwareDir
		#Start-Download -JobName "CSDownloads" -Source $VC2015Url -Destination $SoftwareDir
		Start-Download -JobName "CSDownloads" -Source $IdentityExtensionsUrl -Destination $SoftwareDir
	}
	
	#IIS ARR
	if ($ServerType -match "IISARR|All"){
		Write-Log "Downloading IIS ARR." -OutTo $LogOutTo
		Start-Download -JobName "CSDownloads" -Source $IISARRUrl -Destination $SoftwareDir
	}
	
	#.NET Framework 4.7
	if (($NDPUpgradeStatus) -or ($DownloadsOnly)){
		Write-Log "Downloading .NET Framework 4.7." -OutTo $LogOutTo
		Start-Download -JobName "CSDownloads" -Source $NDPUrl -Destination $SoftwareDir
	}
	
	#VC++ 2015 (OOS and Debugging Tools)
	Write-Log "Downloading VC++ 2015 (OOS and Debugging Tools)." -OutTo $LogOutTo
	Start-Download -JobName "CSDownloads" -Source $VC2015Url -Destination $SoftwareDir
	
	if ($error){
		$requiredDownloadFailed = $true
	}
	
	$error.Clear()
	#DigiCert utility
	Write-Log "Downloading DigiCert certificate utility." -OutTo $LogOutTo
	Start-Download -JobName "CSDownloads" -Source $DigiCertUtilUrl -Destination $SoftwareDir
	
	#Optional Downloads
	#SQL Management Studio
	if (($SQLMgmtStudio) -or ($DownloadsOnly)){
		Write-Log "Downloading SQL Management Studio." -OutTo $LogOutTo
		Start-Download -JobName "CSDownloads" -Source $SQLSMSUrl -Destination $SoftwareDir
	}
	
	#Wireshark
	if (($Wireshark) -or ($DownloadsOnly)){
		Write-Log "Downloading Wireshark." -OutTo $LogOutTo
		Start-Download -JobName "CSDownloads" -Source $WiresharkUrl -Destination $SoftwareDir
		Start-Download -JobName "CSDownloads" -Source $WinPcapUrl -Destination $SoftwareDir
	}
	
	#AudioCodes Syslog
	if (($ACSyslog) -or ($DownloadsOnly)){
		Write-Log "Downloading AudioCodes Syslog Viewer." -OutTo $LogOutTo
		Start-Download -JobName "CSDownloads" -Source $ACSyslogUrl -Destination $SoftwareDir
	}
	
	#Mozilla Firefox
	if (($Firefox) -or ($DownloadsOnly)){
		Write-Log "Downloading Mozilla Firefox." -OutTo $LogOutTo
		Start-Download -Source $FirefoxUrl -Destination $SoftwareDir -FileName firefox.exe -Web -SuppressProgress
	}
	
	#Google Chrome
	if (($Chrome) -or ($DownloadsOnly)){
		Write-Log "Downloading Google Chrome." -OutTo $LogOutTo
		Start-Download -Source $ChromeUrl -Destination $SoftwareDir -FileName chrome.msi -Web -SuppressProgress
	}
	Write-Log -OutTo $LogOutTo
	
	#Scripts
	Write-Log "Downloading scripts." -OutTo $LogOutTo
	if (!(Test-Path $ScriptsDir)){
		New-Item $ScriptsDir -Type Directory | Out-Null
	}
	#Check if scripts are prestaged in SoftwareDir, copy to local CsScripts folder
	if (Test-Path "$SoftwareDir\CsScripts"){
		Copy-Item "$SoftwareDir\CsScripts\*" $ScriptsDir -Force -ErrorAction SilentlyContinue
	}
	if ($ServerType -match "FEStd|FEEnt|Dir|OOS|All"){
		Start-Download -Source $CleanWACIISLogsUrl -Destination $ScriptsDir -FileName Clean-IISLogs.ps1 -Web -SuppressProgress
	}
	if ($ServerType -match "FEStd|FEEnt|Dir|All"){
		Start-Download -Source $CsClsLogSizeUrl -Destination $ScriptsDir -FileName Get-CsClsLogSize.ps1 -Web -SuppressProgress
		Start-Download -Source $CsDeviceUpdatesUrl -Destination $ScriptsDir -FileName Get-CsDeviceUpdates.v3.0.zip -Web -SuppressProgress
		Start-Download -Source $CsEndpointRegistrationsUrl -Destination $ScriptsDir -FileName Get-CsEndpointRegistrations.ps1 -Web -SuppressProgress
		Start-Download -Source $WindowsFabricLogSizeUrl -Destination $ScriptsDir -FileName Get-WindowsFabricLogSize.ps1 -Web -SuppressProgress
	}
	<# if ($ServerType -match "FEStd|FEEnt|Edge|All"){
		Start-Download -Source $CsEdgePortTesterUrl -Destination $ScriptsDir -FileName LyncEdgePortTester1.00.zip -Web
	} #>
	
	if ($error){
		$optionalDownloadFailed = $true
	}
	
	#Wait for downloads to complete
	if (Get-BitsTransfer "CSDownloads" -ErrorAction SilentlyContinue){
		Write-Log -OutTo $LogOutTo
		Write-Log "Waiting for downloads." -OutTo $LogOutTo
		$retryCount = 0
		while ((Get-BitsTransfer "CSDownloads").JobState -ne "Transferred"){
			if ((Get-BitsTransfer "CSDownloads").JobState -match "error|Suspended"){
				if ($retryCount -gt 3){
					Write-Log "Unable to process downloads. Run Get-BitsTransfer to see status. Quitting." -Level "Error" -OutTo $LogOutTo
					return
				}
				$retryCount++
				Write-Log "Retrying downloads. Retry: $retryCount" -OutTo $LogOutTo
				Get-BitsTransfer "CSDownloads" | Resume-BitsTransfer -Asynchronous
			}
			Start-Sleep -s 10
			$transfer = "Files: "+[string](Get-BitsTransfer "CSDownloads").FilesTransferred+"/"+[string](Get-BitsTransfer "CSDownloads").FilesTotal
			try {
				Write-Progress -Activity "Waiting for Downloads" -PercentComplete (((Get-BitsTransfer "CSDownloads").BytesTransferred / (Get-BitsTransfer "CSDownloads").BytesTotal) * 100) `
					-CurrentOperation $transfer -Status "Please wait."
			}catch{
				#Continue
				Write-Log "Catching error in Write-Progress." -Level "Verb" -OutTo $LogOutTo
			}
		}
		Write-Log "Completing BITS transfer." -OutTo $LogOutTo
		Write-Progress -Activity "Waiting for Downloads" -Completed
		Get-BitsTransfer "CSDownloads" | Complete-BitsTransfer
	}
	
	#Remove TLS 1.2 for WinHTTP for BITS Transfers
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DefaultSecureProtocols" -Force -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DefaultSecureProtocols" -Force -ErrorAction SilentlyContinue | Out-Null
	
	<# if ($requiredDownloadFailed){
		Write-Log "Required download failed. Quitting." -Level "Error"
		return
	}elseif ($optionalDownloadFailed){
		while ($response -notmatch "Y|N"){
			Write-Log "Optional download failed." -Level "Warn"
			Write-Host -NoNewLine "Continue? (Y/N) "
			$response = Read-Host
			if ($response -eq "Y"){
				End-Task -NextTask "Commit" -Quiet -NoSave
			}else{
				Write-Log "Quitting." -Level "Warn"
				break
			}
			Write-Log "Continuing." -Level "Warn"
		}
	} #>
	
	Write-Log -OutTo $LogOutTo

	if ($DownloadsOnly){
		#Stop at end of task
		End-Task -NextTask "None" -Quiet -NoSave
	}else{
		End-Task -NextTask "PrereqInstall" -Quiet
	}
}





#Prerequisite installation
if ($Script:Task -eq "PrereqInstall"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()

	#Setting power plan to high performance
	if ($ServerType -match "FEStd|FEEnt|Med|Edge"){
		if (!($KeepPowerPlan)){
			Write-Log "Setting power plan to High Performance."
			powercfg -S 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
		}
	}
	
	#Disable SSL 3.0 and weak ciphers in Windows
	Write-Log "Executing IISCrpyto to update SSL/TLS protocols and cipher suites."
	if ($PCI31){
		Write-Log "Disabling TLS 1.0 in compliance with PCI 3.1 requirements. Ensure that all connecting clients and servers support and are enabled for TLS 1.1 or higher. `
			More information here: https://blogs.msdn.microsoft.com/kaushal/2011/10/02/support-for-ssltls-protocols-on-windows/" -Level "Warn"
		$iisCrypto = "$SoftwareDir\iiscryptocli.exe /template pci31"
		
		#Update .NET Framework to use Strong Cryptography for OOS
		# Required for TLS 1.1 and 1.2
		if ($ServerType -match "OOS"){
			New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -PropertyType DWORD -Value "0x1" -Force -ErrorAction SilentlyContinue | Out-Null
			New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -PropertyType DWORD -Value "0x1" -Force -ErrorAction SilentlyContinue | Out-Null
		}
	}else{
		$iisCrypto = "$SoftwareDir\iiscryptocli.exe /template best"
	}
	Invoke-Expression $iisCrypto | Out-Null
	
	#Set Diffie-Hellman keysize to 2048 minimum
	Write-Log "Setting Diffie-Hellman keyzize to 2048 minimum."
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms" -Name "Diffie-Hellman" -Force | Out-Null
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name ServerMinKeyBitLength -Value 2048 -Force | Out-Null
	
	#Disable SMBv1 server and client support
	Write-Log "Disabling SMBv1 server support."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
	
	#Disable Xbox related services and scheduled tasks in Server 2016
	if ($isServer2016){
		Write-Log "Disabling Xbox related services and scheduled tasks."
		Set-Service XblAuthManager -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
		Set-Service XblGameSave -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
		
		Disable-ScheduledTask \Microsoft\XblGameSave\XblGameSaveTask -ErrorAction SilentlyContinue | Out-Null
		Disable-ScheduledTask \Microsoft\XblGameSave\XblGameSaveTaskLogon -ErrorAction SilentlyContinue | Out-Null
	}
	
	#Disable EKU check for Web Conferencing Service
	if ($ServerType -match "FE"){
		Write-Log "Disabling .NET Framework EKU check for Web Conferencing Service (KB4023993)."
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "System.Net.ServicePointManager.RequireCertificateEKUs" -Force -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\System.Net.ServicePointManager.RequireCertificateEKUs" `
			-Name "$InstallDrive\Program Files\Skype for Business Server 2015\Web Conferencing\DataMCUSvc.exe" -PropertyType DWORD -Value "0x0" -Force -ErrorAction SilentlyContinue | Out-Null
	}
	
	#Extract and move DigiCertUtil
	Write-Log "Extracting DigiCert certificate utility."
	$extractCmd = $SoftwareDir+"\7zip\7za.exe x "+$SoftwareDir+"\$(Split-Path $DigiCertUtilUrl -Leaf) -o"+$ScriptsDir+" -y -aoa"
	Invoke-Expression $extractCmd -ErrorAction Continue | Out-Null
	
	#Temporarily hide Server Manager
	Write-Log "Hiding Server Manager."
	New-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -PropertyType DWORD -Value "0x1" -Force -ErrorAction SilentlyContinue | Out-Null
	
	#Show known file extensions
	Write-Log "Showing known file extensions."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value "0x0" -Force -ErrorAction SilentlyContinue | Out-Null
	
	#Block .NET Framework updates
	#Support for 4.6.2 added in February 2017 update
	#Support for 4.7 added in December 2017 for CU5 or later
	#Support for 4.7.2 added in CU6 or later
	#Support for 4.8 added in CU9 or later
	#https://docs.microsoft.com/en-us/skypeforbusiness/plan-your-deployment/requirements-for-your-environment/server-requirements
	#https://www.ucmadscientist.com/supported-net-versions-for-lync-and-skype-for-business-server/
	#https://blogs.technet.microsoft.com/nexthop/2016/02/11/on-net-framework-4-6-2-and-skype-for-businesslync-server-compatibility/
	#https://blogs.technet.microsoft.com/exchange/2017/06/13/net-framework-4-7-and-exchange-server/
	#if ($ServerType -match $CsSrvTypes){
	#	Write-Log "Blocking .NET Framework 4.7.1 in Windows Update."
	#	New-Item -Path "HKLM:\Software\Microsoft\NET Framework Setup\NDP" -Name "WU" -Force -ErrorAction SilentlyContinue | Out-Null
	#	New-ItemProperty -Path "HKLM:\Software\Microsoft\NET Framework Setup\NDP\WU" -Name "BlockNetFramework471" -PropertyType DWORD -Value "0x1" -Force -ErrorAction SilentlyContinue | Out-Null
	#}
	
	#Check and set primary DNS suffix
	if ($ServerType -match "Edge|IISARR"){
		if ($PrimaryDNSSuffix){
			$suffix = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "NV Domain" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NV Domain"
			if ($suffix -ne $PrimaryDNSSuffix){
				Write-Log "Setting primary DNS suffix to $PrimaryDNSSuffix."
				Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "NV Domain" -Value $PrimaryDNSSuffix
			}
		}
	}
	
	#Stage scripts folder
	if ($ServerType -match "FEStd|FEEnt|Dir"){
		if (Test-Path "$ScriptsDir\Get-CsDeviceUpdates.v3.0.zip"){
			$extractCmd = $SoftwareDir+"\7zip\7za.exe x "+$ScriptsDir+"\Get-CsDeviceUpdates.v3.0.zip -o"+$ScriptsDir+"\Get-CsDeviceUpdates.v3.0 -y -aoa"
			Invoke-Expression $extractCmd -ErrorAction Continue | Out-Null
			Remove-Item "$ScriptsDir\Get-CsDeviceUpdates.v3.0.zip"
		}
	}
	Write-Log
	
	#Windows roles and features
	#Stop maintenance tasks that could prevent feature installation
	Get-ScheduledTask | Where-Object State -eq Running | Where-Object TaskName -notmatch "CSDeployment" | Stop-ScheduledTask -ErrorAction SilentlyContinue
	Start-Sleep -s 10
	
	if ($ServerType -match "FEStd|FEEnt"){
		Write-Log "Installing roles and features for Front End role:"
		$winFeatures = "RSAT-ADDS", "Windows-Identity-Foundation", "NET-Framework-Core", "Web-Server", "Web-Static-Content", "Web-Default-Doc", "Web-Http-Errors", "Web-Asp-Net", "Web-Net-Ext", `
			"Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-Http-Logging", "Web-Log-Libraries", "Web-Request-Monitor", "Web-Http-Tracing", "Web-Basic-Auth", "Web-Windows-Auth", "Web-Client-Auth", "Web-Filtering", `
			"Web-Stat-Compression", "Web-Dyn-Compression", "Web-Asp-Net45", "Web-Scripting-Tools", "Web-Mgmt-Compat", "Web-Mgmt-Tools", "NET-WCF-HTTP-Activation45", "Server-Media-Foundation", "Telnet-Client", "BITS"
	}
	if ($ServerType -eq "Dir"){
		Write-Log "Installing roles and features for Director role:"
		$winFeatures = "RSAT-ADDS", "Windows-Identity-Foundation", "Web-Server", "Web-Static-Content", "Web-Default-Doc", "Web-Http-Errors", "Web-Asp-Net", "Web-Net-Ext", "Web-ISAPI-Ext", `
			"Web-ISAPI-Filter", "Web-Http-Logging", "Web-Log-Libraries", "Web-Request-Monitor", "Web-Http-Tracing", "Web-Basic-Auth", "Web-Windows-Auth", "Web-Client-Auth", "Web-Cert-Auth", `
			"Web-Filtering", "Web-Stat-Compression", "Web-Dyn-Compression", "Web-Asp-Net45", "Web-Scripting-Tools", "Web-Mgmt-Compat", "NET-WCF-HTTP-Activation45", "Server-Media-Foundation", "Telnet-Client", "BITS"
	}
	if ($ServerType -eq "PChat"){
		Write-Log "Installing roles and features for Persistent Chat role:"
		$winFeatures = "Windows-Identity-Foundation", "NET-Framework-Core", "NET-WCF-HTTP-Activation45", "MSMQ", "MSMQ-Directory", "Telnet-Client", "BITS"
	}
	if ($ServerType -eq "Edge"){
		Write-Log "Installing roles and features for Edge role:"
		$winFeatures = "Windows-Identity-Foundation", "NET-Framework-Core", "NET-WCF-HTTP-Activation45", "Telnet-Client", "BITS"
	}
	if ($ServerType -eq "Med"){
		Write-Log "Installing roles and features for Mediation role:"
		$winFeatures = "Windows-Identity-Foundation", "NET-Framework-Core", "NET-WCF-HTTP-Activation45", "Telnet-Client", "BITS"
	}
	if ($ServerType -eq "OOS"){
		Write-Log "Installing roles and features for Office Online Server:"
		if ($isServer2016){
			$winFeatures = "Web-Server", "Web-Mgmt-Tools", "Web-Mgmt-Console", "Web-WebServer", "Web-Common-Http", "Web-Default-Doc", "Web-Static-Content", "Web-Performance", "Web-Stat-Compression", `
				"Web-Dyn-Compression", "Web-Security", "Web-Filtering", "Web-Windows-Auth", "Web-App-Dev", "Web-Net-Ext45", "Web-Asp-Net45", "Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-Includes", `
				"NET-Framework-Features", "NET-Framework-Core", "NET-WCF-HTTP-Activation45", "NET-HTTP-Activation", "NET-Non-HTTP-Activ", "Windows-Identity-Foundation", "Telnet-Client", "BITS"
		}else{
			$winFeatures = "Web-Server", "Web-Mgmt-Tools", "Web-Mgmt-Console", "Web-WebServer", "Web-Common-Http", "Web-Default-Doc", "Web-Static-Content", "Web-Performance", "Web-Stat-Compression", `
				"Web-Dyn-Compression", "Web-Security", "Web-Filtering", "Web-Windows-Auth", "Web-App-Dev", "Web-Net-Ext45", "Web-Asp-Net45", "Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-Includes", `
				"InkandHandwritingServices", "NET-Framework-Features", "NET-Framework-Core", "NET-WCF-HTTP-Activation45", "NET-HTTP-Activation", "NET-Non-HTTP-Activ", "Windows-Identity-Foundation", "Telnet-Client", "BITS"
		}
	}
	if ($ServerType -eq "IISARR"){
		Write-Log "Installing roles and features for IIS ARR:"
		$winFeatures = "Web-Static-Content", "Web-Default-Doc", "Web-Http-Errors", "Web-Asp-Net", "Web-Asp-Net45", "Web-Http-Logging", "Web-Log-Libraries", "Web-Http-Tracing", "Web-Windows-Auth", `
			"Web-Client-Auth", "Web-Filtering", "Web-Stat-Compression", "Web-Dyn-Compression", "Web-Mgmt-Console", "Web-Scripting-Tools", "NET-WCF-HTTP-Activation45", "Telnet-Client", "BITS"
	}
	$error.clear()
	if ($winFeatures){
		Write-Log ($winFeatures | Out-String)
		Install-WindowsFeature $winFeatures -Source $SourcePath -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
	}else{
		Write-Log "No roles and features selected. Quitting." -Level "Error"
		return
	}
	if ($error){
		Write-Log "Failed to install prerequisites. Retry in a few minutes." -Level "Error"
		Write-Log $error[0].Exception.Message -Level "Error"
		return
	}
	Write-Log
	
	#Upgrade .NET
	if ($NDPUpgradeStatus){
		Install-Software -File "$SoftwareDir\$(Split-Path $NDPUrl -Leaf)" -Switches "/q","/norestart" -Title ".NET Framework" -WaitForProcessName $((Split-Path $NDPUrl -Leaf) -split "\.")[0] -ErrorHandling "Stop"
	}
	
	#Downgrade .NET
	if ($NDPDowngradeStatus -and (Get-HotFix KB4033342 -ErrorAction SilentlyContinue)){
		Write-Log "Downgrading .NET Framework."
		Install-Software -File "wusa.exe" -Switches "/kb:4033342","/uninstall","/quiet","/norestart"
	}
	
	#Extract SQL Express 2014 SP2
	if ($ServerType -match "FEStd|FEEnt|Dir|PChat|Edge"){
		if (!(Test-Path $UserTempDir\SQLEXPR_x64_ENU)){
			if (Test-Path $SoftwareDir\SQLEXPR_x64_ENU.exe){
				Write-Log "Extracting SQL Express 2014 SP2."
				#$Process = Start-Process -FilePath "$SoftwareDir\SQLEXPR_x64_ENU.exe" -ArgumentList /q, /x:"$UserTempDir\SQLEXPR_x64_ENU" -Wait -Passthru -Verb RunAs
				$Process = Start-Process -FilePath "$SoftwareDir\SQLEXPR_x64_ENU.exe" -ArgumentList /q, /x:"$TempDir\SQLEXPR_x64_ENU" -Wait -Passthru -Verb RunAs
				if ($process.ExitCode -ne 0){throw "$SoftwareDir\SQLEXPR_x64_ENU.exe /x: returned error code: $($process.ExitCode)"}
			}else{
				#Write-Log "Unable to extract SQL Express. $UserTempDir\SQLEXPR_x64_ENU.exe does not exist and extracted folder not detected." -Level "Error"
				Write-Log "Unable to extract SQL Express. $TempDir\SQLEXPR_x64_ENU.exe does not exist and extracted folder not detected." -Level "Error"
				return
			}
		}
	}
	
	#IIS hotfix KB2982006 for Server 2012 R2
	#https://blogs.technet.microsoft.com/uclobby/2017/09/05/sfb-server-cannot-install-kb2982006-this-update-is-not-applicable-to-your-computer/
	#URL Rewrite for Server 2016
	# Requires IIS - Must happen after Windows prerequisites
	if ($ServerType -match "FEStd|FEEnt|Dir"){
		if ($isServer2016){
			Install-Software -File "msiexec.exe" -Switches "/i","$SoftwareDir\rewrite_amd64.msi","/quiet","/norestart" -Title "URL Rewrite Module" -ConfirmPath $UrlRewriteGUID -ErrorHandling "Stop"
		}elseif ($isServer2012R2){
			if ($KB2919442Required){
				Install-Software -File "wusa.exe" -Switches "$SoftwareDir\Windows8.1-KB2919442-x64.msu","/quiet","/norestart" -Title "KB2919442" -ConfirmHotfix "KB2919442"
			}
			if ($KB2919355Required){
				Install-Software -File "wusa.exe" -Switches "$SoftwareDir\Windows8.1-KB2919355-x64.msu","/quiet","/norestart" -Title "KB2919355" -ConfirmHotfix "KB2919355" -ErrorHandling "Stop"
			}
			if ($KB2982006Required){
				Write-Log "Extracting KB2982006 (IIS Hotfix)."
				$extractCmd = "expand -F:* $SoftwareDir\windows8.1-kb2982006-x64_d96bea78d5746c48cb712c8ef936c29b5077367f.msu $UserTempDir"
				Invoke-Expression $extractCmd -ErrorAction Continue | Out-Null
				
				Install-Software -File "dism.exe" -Switches "/Online","/Add-Package","/PackagePath:$UserTempDir\Windows8.1-KB2982006-x64.cab","/Quiet","/NoRestart" -Title "KB2982006" `
					-ConfirmHotfix "KB2982006" -ErrorHandling "Stop"
			}
		}
	}
	
	#IIS ARR
	# Requires IIS - Must happen after Windows prerequisites
	if ($ServerType -match "IISARR"){
		Install-Software -File "$SoftwareDir\ARRv3_setup_amd64_en-us.exe" -Switches "/Q" -Title "Application Request Routing 3.0" -ConfirmPath $IISARRGUID -ErrorHandling "Stop"
	}

	#Office Online Server VC++ 2015, Identity Extensions
	if ($ServerType -match "OOS"){
		#Install-Software -File "$SoftwareDir\vc_redist.x64.exe" -Switches "/install","/quiet" -Title "Visual C++ 2015" -ConfirmPath $OOSVC2015GUID -ErrorHandling "Stop"
		Install-Software -File "$SoftwareDir\vc_redist.x64.exe" -Switches "/install","/quiet" -Title "Visual C++ 2015" -ConfirmPath $VC2015GUID -ErrorHandling "Stop"
		Install-Software -File "msiexec.exe" -Switches "/i","$SoftwareDir\MicrosoftIdentityExtensions-64.msi","/qn","/norestart" -Title "Microsoft Identity Extensions" -ConfirmPath $MSIDEXGUID -ErrorHandling "Stop"
	}
	
	#SilverLight x64
	if ($ServerType -match "FEStd|FEEnt|Dir"){
		Install-Software -File "$SoftwareDir\Silverlight_x64.exe" -Switches "/q" -Title "Silverlight" -ConfirmName $Silverlightx64Name
	}
	Write-Log
	
	#Firewall rules for syslog
	if ($ServerType -match "FE|Med"){
		Write-Log "Creating firewall rules for syslog."
		New-NetFirewallRule -DisplayName "Syslog" -Direction Inbound -Action Allow -Profile Any -Protocol UDP -LocalPort 514 | Out-Null
		Write-Log
	}
	
	#Setup scheduled IIS log clean up task
	if ($ServerType -match "FEStd|FEEnt|Dir|OOS"){
		if (Test-Path $ScriptsDir\Clean-IISLogs.ps1){
			Write-Log "Creating scheduled task for IIS clean up script."
			$arg = "-Command "+'"'+"& '"+$ScriptsDir+"\Clean-IISLogs.ps1'"+'"'
			Manage-ScheduledTask -TaskName "Clean IIS Logs (Daily)" -Action "Add" -StartupType Scheduled -Recurrence Daily -Time "00:30:00" -Execute powershell -Argument $arg -User "SYSTEM"
		}else{
			Write-Log "Unable to create scheduled task. $ScriptsDir\Clean-IISLogs.ps1 does not exist." -Level "Warn"
		}
	}
	Write-Log
	
	<# if ((Get-ScheduledTask "CSDeployment").State -ne "Running"){
		Write-Log "Press any key to reboot." -OutTo "Screen"
		$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Write-Log -OutTo "Screen"
	} #>

	#Create scheduled task using AD credentials to continue into next task for CS servers
	if ($ServerType -match $CsSrvTypes){
		End-Task -Reboot -NextTask "CSCoreInstall" -Quiet
	}
	
	#Create scheduled task using AD credentials to continue into next task for OOS servers
	if ($ServerType -match "OOS"){
		End-Task -Reboot -NextTask "OWASInstall" -Quiet
	}
	
	#Create scheduled task using AD credentials to continue into next task for IIS ARR servers
	if ($ServerType -match "IISARR"){
		End-Task -Reboot -NextTask "ARRConfigure" -Quiet
	}
}




#Identifies media and installs core components (CS Servers Only)
if($Script:Task -eq "CSCoreInstall"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	if (!($SetupPath)){
		Invoke-DiscoverMedia -MediaPath $MediaPath -ExecutablePath "Setup\amd64\setup.exe"
		Save-Variables
	}
	if ($Script:Path){
		$SetupPath = $Script:Path
		Save-Variables
	}
	
	#Install Core Components and prerequisites
	$StopWatchCoreComponent = [system.diagnostics.stopwatch]::startNew()
	
	#Install Core Components and prerequisites
	Install-Software -File "$SetupPath\Setup\amd64\vcredist_x64.exe" -Switches "/quiet" -Title "VC++ 2013 redistributable" -ConfirmPath $VC2013GUID -ErrorHandling "Stop"
	
	$args = "/i","$SetupPath\Setup\amd64\Setup\ocscore.msi","/qn","REBOOT=ReallySuppress","ADDLOCAL=Feature_OcsCore","INSTALLDIR=`"$InstallDrive\Program Files\Skype for Business Server 2015`""
	Install-Software -File "msiexec.exe" -Switches $args -Title "OcsCore.msi" -ConfirmPath $SFBOcsCoreGUID -ErrorHandling "Stop"
	
	#Install Admin Tools and prerequisites, then patch
	$args = "/i","$SetupPath\Setup\amd64\sqlncli.msi","/qn","REBOOT=ReallySuppress","IACCEPTSQLNCLILICENSETERMS=YES"
	#Install-Software -File "msiexec.exe" -Switches $args -Title "SQL Server 2012 Native Client" -ConfirmPath $SQL12NativeClientGUID -ErrorHandling "Stop"
	Install-Software -File "msiexec.exe" -Switches $args -Title "SQL Server 2012 Native Client" -ConfirmName $SQL12NativeClientName -ErrorHandling "Stop"
	
	$args = "/i","$SetupPath\Setup\amd64\SQLSysClrTypes.msi","/qn","REBOOT=ReallySuppress"
	#Install-Software -File "msiexec.exe" -Switches $args -Title "SQL System CLR Types for SQL Server 2014" -ConfirmPath $SQLClrTypesGUID -ErrorHandling "Stop"
	Install-Software -File "msiexec.exe" -Switches $args -Title "SQL System CLR Types for SQL Server 2014" -ConfirmName $SQL14ClrTypesName -ErrorHandling "Stop"
	
	$args = "/i","$SetupPath\Setup\amd64\SharedManagementObjects.msi","/qn","REBOOT=ReallySuppress"
	Install-Software -File "msiexec.exe" -Switches $args -Title "SQL Server 2014 Shared Management Objects" -ConfirmPath $SQLMgmtObjectsGUID -ErrorHandling "Stop"
	
	$args = "/i","$SetupPath\Setup\amd64\Setup\UcmaRuntime.msi","/qn","REBOOT=ReallySuppress","EXCLUDETRACING=1","BOOT=1"
	Install-Software -File "msiexec.exe" -Switches $args -Title "UCMA Runtime 5.0" -ConfirmPath $UCMA5CoreRuntimeGUID -ErrorHandling "Stop"
	
	$args = "/i","$SetupPath\Setup\amd64\Setup\AdminTools.msi","/qn","ADDLOCAL=Feature_AdminTools","REBOOT=ReallySuppress","INSTALLDIR=`"$InstallDrive\Program Files\Skype for Business Server 2015`""
	Install-Software -File "msiexec.exe" -Switches $args -Title "AdminTools.msi" -ConfirmPath $SFBAdminToolsGUID -ErrorHandling "Stop"
	
	Install-Software -File "$SoftwareDir\SkypeServerUpdateInstaller.exe" -Switches "/silentmode" -Title "Skype for Business Updates" -ErrorHandling "Stop"
	
	$StopWatchCoreComponent.Stop()
	Write-Log
	
	#Install SQL Express with RTC instance for first Standard edition server
	$StopWatchInstallSQL = [system.diagnostics.stopwatch]::startNew()
	
	if ($PrepareFirstStd){
		if ($ServerType -eq "FEStd"){
			Write-Log "Installing SQL RTC instance."
			$StopWatchInstallSQLRTC = [system.diagnostics.stopwatch]::startNew()
			Install-CsSQLInstance -Instance RTC -SQLMediaDir "$TempDir" -SQLPath "$InstallDrive\Program Files\Microsoft SQL Server" -OpenPorts | Out-Null
			$StopWatchInstallSQLRTC.Stop()
		}
	}
	
	#Install RTCLOCAL instance
	$StopWatchInstallSQLRTCLOCAL = [system.diagnostics.stopwatch]::startNew()
	
	Write-Log "Installing SQL RTCLOCAL instance."
	if ($ServerType -match "FEStd|FEEnt"){
		Install-CsSQLInstance -Instance RTCLOCAL -SQLMediaDir "$TempDir" -SQLPath "$InstallDrive\Program Files\Microsoft SQL Server" -OpenPorts | Out-Null
	}else{
		Install-CsSQLInstance -Instance RTCLOCAL -SQLMediaDir "$TempDir" -SQLPath "$InstallDrive\Program Files\Microsoft SQL Server" | Out-Null
	}
	
	$StopWatchInstallSQLRTCLOCAL.Stop()
	
	#Install LYNCLOCAL instance
	$StopWatchInstallSQLLYNCLOCAL = [system.diagnostics.stopwatch]::startNew()
	
	Write-Log "Installing SQL LYNCLOCAL instance."
	Install-CsSQLInstance -Instance LYNCLOCAL -SQLMediaDir "$TempDir" -SQLPath "$InstallDrive\Program Files\Microsoft SQL Server" | Out-Null
	
	$StopWatchInstallSQLLYNCLOCAL.Stop()
	
	$StopWatchInstallSQL.Stop()
	Write-Log
	
	if ($ServerType -match "FE"){
		if (!(Get-NetFirewallRule -DisplayName "SQL Browser Service" -ErrorAction SilentlyContinue)){
			Write-Log "Creating firewall rule for SQL Browser Service."
			New-NetFirewallRule -DisplayName "SQL Browser Service" -Direction Inbound -Action Allow -Profile Any -Protocol UDP -LocalPort 1434 | Out-Null
			Write-Log
		}
	}
	
	if ($ServerType -match "Edge"){
		End-Task -NextTask "CSComponentInstall" -Quiet
	}else{
		End-Task -NextTask "CSADPrep" -Quiet
	}
	if ($TimingEnabled){
		"    Core Components runtime: "+$StopWatchCoreComponent.Elapsed.ToString('dd\.hh\:mm\:ss') | Out-File $StopWatchPath -Append
		if ($PrepareFirstStd){
			"    SQL RTC runtime: "+$StopWatchInstallSQLRTC.Elapsed.ToString('dd\.hh\:mm\:ss') | Out-File $StopWatchPath -Append
		}
		"    SQL RTCLOCAL runtime: "+$StopWatchInstallSQLRTCLOCAL.Elapsed.ToString('dd\.hh\:mm\:ss') | Out-File $StopWatchPath -Append
		"    SQL LYNCLOCAL runtime: "+$StopWatchInstallSQLLYNCLOCAL.Elapsed.ToString('dd\.hh\:mm\:ss') | Out-File $StopWatchPath -Append
		"    SQL Install runtime: "+$StopWatchInstallSQL.Elapsed.ToString('dd\.hh\:mm\:ss') | Out-File $StopWatchPath -Append
	}
}




#AD prep (CS Servers Only)
if($Script:Task -eq "CSADPrep"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	if ($ServerType -match "Edge"){
		Write-Log "This task is not applicable to Edge servers. Continue by running script with -Resume."
		return
	}
	
	Write-Log "Importing SFB PS module."
	try {
		Import-Module "C:\Program Files\Common Files\Skype for Business Server 2015\Modules\SkypeForBusiness"
	}catch{
		Write-Log "Unable to import SkypeForBusiness PS module. Quitting." -Level "Error"
		return
	}
	Write-Log
	
	#Perform AD prep if primary server
	if ($PrimaryServer){
		if ($PrepareAD -eq $true -and (Get-CsAdDomain -WarningAction SilentlyContinue) -ne "LC_DOMAINSETTINGS_STATE_READY"){
			Write-Log "Applying schema update."
			Install-CsAdServerSchema
			while ($status -ne "SCHEMA_VERSION_STATE_CURRENT"){
				Write-Log "Waiting for schema replication."
				Start-Sleep -s 10
				$status = Get-CsAdServerSchema
			}
			Write-Log "Applying forest prep."
			Enable-CsAdForest
			while ($status -ne "LC_FORESTSETTINGS_STATE_READY"){
				Write-Log "Waiting for forest replication."
				Start-Sleep -s 10
				$status = Get-CsAdForest
			}
			Write-Log "Applying domain prep."
			Enable-CsAdDomain
			while ($status -ne "LC_DOMAINSETTINGS_STATE_READY"){
				Write-Log "Waiting for domain replication."
				Start-Sleep -s 10
				$status = Get-CsAdDomain
			}
			Write-Log
			
			Write-Log "Sleeping for 2 minutes for replication."
			Write-Log
			for ($a=1; $a -lt 120; $a++) {
				$percent = (($a / 120) * 100)
				Write-Progress -Activity "Waiting for AD Replication" -PercentComplete $percent -CurrentOperation "$percent% complete" -Status "Please wait."
				Start-Sleep 1
			}
			Write-Progress -Activity "Waiting for AD Replication" -Completed
		}
		
		if ((whoami /groups /fo list | findstr /i Domain) -match "Domain Admins"){
			if ((Get-WindowsFeature RSAT-AD-Powershell).InstallState -eq "Installed"){
				Write-Log "Importing SFB PS module."
				try {
					Import-Module ActiveDirectory
				}catch{
					Write-Log "Unable to import ActiveDirectory PS module." -Level "Error"
				}
				
				Write-Log "Adding current user to CS and RTC AD groups."
				try {
					Add-AdGroupMember CsAdministrator -Members $env:username -ErrorAction SilentlyContinue
					Add-AdGroupMember CsUserAdministrator -Members $env:username -ErrorAction SilentlyContinue
					Add-AdGroupMember RTCUniversalServerAdmins -Members $env:username -ErrorAction SilentlyContinue
				}catch{
					Write-Log "Failure to add current user to CS and RTC AD groups. Quitting." -Level "Error"
					break
				}
			}else{
				Write-Log "AD tools not installed. Unable to add current user to CS and RTC AD groups. Quitting." -Level "Error"
				break
			}
			Write-Log
		}
	}else{
		$status = Get-CsAdDomain
		if ($status -ne "LC_DOMAINSETTINGS_STATE_READY"){
			Write-Log "Waiting for AD prep and replication."
			while ($status -ne "LC_DOMAINSETTINGS_STATE_READY"){
				Start-Sleep -s 10
				$status = Get-CsAdDomain
			}
			
			Write-Log "Sleeping for 3 minutes."
			Write-Log
			for ($a=1; $a -lt 180; $a++) {
				$percent = (($a / 180) * 100)
				Write-Progress -Activity "Waiting for AD Replication" -PercentComplete $percent -CurrentOperation "$percent% complete" -Status "Please wait."
				Start-Sleep -s 1
			}
			Write-Progress -Activity "Waiting for AD Replication" -Completed
		}
	}
	
	End-Task -Reboot -NextTask "CSComponentInstall" -Quiet
}




#CS component installation (CS Servers Only)
if($Script:Task -eq "CSComponentInstall"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	#Add RTCUniversalServerAdmins to local Administrators groups
	if ($ServerType -match $IntSrvTypes){
		Write-Log "Adding RTCUniversalServerAdmins group to local Administrators group."
		Write-Log
		
		$error.Clear()
		try {
			([ADSI]"WinNT://./Administrators,group").Add("WinNT://$env:userdnsdomain/RTCUniversalServerAdmins,group")
		}catch{
			$errOut = $error.Exception.InnerException
			if ($errOut -match "already a member"){
				Write-Log "RTCUniversalServerAdmins is already a member of the local Administrators group." -Level "Verb"
				Write-Log -Level "Verb"
			}else{
				Write-Log "RTCUniversalServerAdmins was not successfully added to the local Administrators group: $errOut" -Level "Error"
				Write-Log
			}
		}
	}
	
	
	#Check AD permissions for installation
	#To Do
	#Instead of return out script, wait a period of time, enable reboot scheduled task, then reboot server to resume with new permissions
	if ($ServerType -match $IntCsSrvTypes){
		if ((whoami /groups /fo list | findstr /i RTCUniversalServerAdmins) -match "RTCUniversalServerAdmins"){
			Write-Log "User is a member of RTCUniversalServerAdmins." -Level "Verb"
			Write-Log -Level "Verb"
		}else{
			#Write-Log "User not a member of RTCUniversalServerAdmins. Quitting." -Level "Error"
			#return
			
			Write-Log "User not a member of RTCUniversalServerAdmins. Waiting 5 minutes then rebooting to refresh group membership." -Level "Error"
			Start-Sleep -s 300
			Toggle-ScheduledTask -TaskName "CSDeploymentReboot" -Action "Enable" | Write-Log -Level "Verb" -OutTo $LogOutTo
			Write-Log "Rebooting"
			Write-Log
			Restart-Computer -Force
			return
		}
	}
	
	#Create local file share for FE Std server and assign permissions
	if ($ServerType -match "FEStd"){
		if (!(Test-Path $FileSharePath) -and !($FileShareServer)){
			Write-Log "Creating local file share and assigning permissions."
			New-Item $FileSharePath -Type Directory -Force | Out-Null
			try {
				New-SmbShare -Path $FileSharePath -Name $FileShareName -FullAccess RTCHSUniversalServices,RTCComponentUniversalServices,RTCUniversalServerAdmins,RTCUniversalConfigReplicator | Out-Null
			}catch{
				Write-Log "Unable to create file share. Quitting." -Level "Error"
				break
			}
		}
	}
	
	Write-Log "Importing SFB PS module."
	try {
		Import-Module "C:\Program Files\Common Files\Skype for Business Server 2015\Modules\SkypeForBusiness"
	}catch{
		Write-Log "Unable to import SkypeForBusiness PS module. Quitting." -Level "Error"
		return
	}
	Write-Log
	
	#Check if topology file exists
	if ($ServerType -match "Edge"){
		$topologyFile = "$TempDir\topology.zip"
		if (!(Test-Path $topologyFile)){
			Write-Log "Topology.zip file does not exist."
			Write-Log "Run 'Export-CsConfiguration -FileName topology.zip' on a front end server and place topology.zip in $TempDir."
			Write-Log "Waiting for topology file..."
			$retry = 0
			while (!(Test-Path $topologyFile)){
				if ($retry -eq 15){
					Write-Log "Waiting for topology file..."
					$retry = 0
				}
				Start-Sleep -s 60
				$retry++
			}
			Start-Sleep -s 60
			Write-Log
		}
	}
	
	#Install local management store
	$StopWatchBootstrapLocalMgmt = [system.diagnostics.stopwatch]::startNew()
	
	Write-Log "Running bootstrapper.exe /BootstrapLocalMgmt to install local management store."
	Install-Software -File "$InstallDrive\Program Files\Skype for Business Server 2015\Deployment\Bootstrapper.exe" -Switches "/BootstrapLocalMgmt","/SourceDirectory:$SetupPath\Setup\amd64\" -ErrorHandling "Stop"
	Write-Log
	
	$StopWatchBootstrapLocalMgmt.Stop()
	
	Write-Log "Enabling replication and starting replica service."
	Enable-CsReplica
	Start-CsWindowsService Replica
	
	#Export configuration and import to local store instead of waiting for replication
	$StopWatchTopology = [system.diagnostics.stopwatch]::startNew()
	
	Write-Log "Exporting configuration and importing into local store."
	Write-Log
	if ($ServerType -match "Edge"){
		Import-CsConfiguration -FileName $topologyFile -LocalStore
		
		Write-Log "Waiting for topology import."
		for ($a=1; $a -lt 60; $a++) {
			$percent = (($a / 60) * 100)
			Write-Progress -Activity "Waiting for topology import" -PercentComplete $percent -CurrentOperation "$percent% complete" -Status "Please wait."
			Start-Sleep 1
		}
		Write-Progress -Activity "Waiting for topology import" -Completed
		
		Write-Log "Getting CsTopology."
		try {
			$topology = Get-CsTopology -LocalStore
		}catch{
			Write-Log "No topology exists. Export topology.zip to $TempDir then re-run the script with -Resume." -Level "Error"
			return
		}
		#Write-Log
	}else{
		Write-Log "Getting CsTopology."
		try {
			$topology = Get-CsTopology
		}catch{
			Write-Log "No topology exists. The script will wait for the topology to be published."
			$retry = 0
			while (!($topology)){
				$waited = $true
				if ($retry -eq 15){
					Write-Log "Waiting for topology..."
					$retry = 0
				}
				Start-Sleep -s 60
				$retry++
				try {
					$topology = Get-CsTopology
				}catch{
					#Continue
					Write-Log "Catching error in Get-CsTopology." -Level "Verb"
				}
			}
			Start-Sleep -s 60
			#Write-Log
		}
		
		$config = Export-CsConfiguration -AsBytes
		Import-CsConfiguration -ByteInput $config -LocalStore
		
		Write-Log
	}
	
	if ($ServerType -match "Edge"){
		$csComputer = Get-CsTopology -LocalStore | Select-Object -ExpandProperty Machines | Where-Object Fqdn -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
	}else{
		$csComputer = Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
	}
	if (!($csComputer)){
		if ($ServerType -match "Edge"){
			Write-Log "Server does not exist in topology. Update topology file then re-run the script with -Resume." -Level "Error"
			return
		}else{
			Write-Log "Server does not exist in topology. The script will wait for the server to be added to topology." -Level "Warn"
		}
		$retry = 0
		while (!($csComputer)){
			if ($retry -eq 15){
				Write-Log "Waiting for server to be added to topology..."
				$retry = 0
			}
			Start-Sleep -s 60
			$retry++
			if ($ServerType -match "Edge"){
				$csComputer = Get-CsTopology -LocalStore | Select-Object -ExpandProperty Machines | Where-Object Fqdn -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
			}else{
				$csComputer = Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
			}
		}
		Write-Log
		
		$config = Export-CsConfiguration -AsBytes
		Import-CsConfiguration -ByteInput $config -LocalStore
	}
	
	$StopWatchTopology.Stop()
	
	#Export topology for Edge servers
	if ($PrimaryServer){
		if ($ServerType -match "FEStd|FEEnt"){
			$objIPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
			$serverFqdn = "{0}.{1}" -f $objIPProperties.HostName, $objIPProperties.DomainName
			
			$csPool = Get-CsPool | Where-Object Computers -match $serverFqdn
			$csEdge = Get-CsService -Registrar -PoolFqdn $csPool.Fqdn
			if ($csEdge.EdgeServer -ne $null){
				Write-Log "Exporting topology.zip to $TempDir for Edge servers."
				Write-Log
				Remove-Item "$TempDir\topology.zip" -Force -ErrorAction SilentlyContinue
				Export-CsConfiguration -FileName "$TempDir\topology.zip"
			}
		}
	}
	
	#Check if SQL databases are installed, else install them
	if ($PrimaryServer){
		if ($ServerType -match "FEEnt"){
			if ($waited){
				Write-Log "Sleeping for 5 minutes while topology and database install finishes in Topology Builder."
				Start-Sleep -s 300
				Write-Log
			}
			$csPool = Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
			$csDatabase = Get-CsService -UserDatabase | Where-Object DependentServiceList -match $csPool.Fqdn
			Write-Log "Databases for $($csPool.Fqdn):"
			Write-Log (Test-CsDatabase -ConfiguredDatabases -SqlServerFqdn $csDatabase.PoolFqdn -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Format-Table DatabaseName,*edVersion,Succeed | Out-String)
			if ($databases.Succeed -eq $false){
				Write-Log "Installing ConfiguredDatabases on $($csDatabase.PoolFqdn) for $($csPool.Fqdn)."
				try {
					Install-CsDatabase -ConfiguredDatabases -SqlServerFqdn $csDatabase.PoolFqdn -UseDefaultSqlPaths | Out-Null
				}catch{
					Write-Log "Failed to install ConfiguredDatabases on $($csDatabase.PoolFqdn) for $($csPool.Fqdn)." -Level "Error"
					return
				}
				Write-Log
			}
		}
	}
	
	#Run bootstrapper to install roles
	$StopWatchBootstrap = [system.diagnostics.stopwatch]::startNew()
	
	Write-Log "Running bootstrapper.exe to install CS roles."
	Install-Software -File "$InstallDrive\Program Files\Skype for Business Server 2015\Deployment\Bootstrapper.exe" -IgnoreExitCodes 1 -ErrorHandling "Stop"
	
	$StopWatchBootstrap.Stop()

	#Dismount media
	if ($MediaPath -match ".iso|.img"){
		Dismount-DiskImage $MediaPath
		$Script:ImageMounted = $false
		Save-Variables
	}
	Write-Log
	
	End-Task -NextTask "CSCertificates" -Quiet
	
	if ($TimingEnabled){
		"    Bootstrapper /BootstrapLocalMgmt runtime: "+$StopWatchBootstrapLocalMgmt.Elapsed.ToString('dd\.hh\:mm\:ss') | Out-File $StopWatchPath -Append
		"    Topology wait time: "+$StopWatchTopology.Elapsed.ToString('dd\.hh\:mm\:ss') | Out-File $StopWatchPath -Append
		"    Bootstrapper runtime: "+$StopWatchBootstrap.Elapsed.ToString('dd\.hh\:mm\:ss') | Out-File $StopWatchPath -Append
	}
}




#Request certificates (CS Servers Only)
if($Script:Task -eq "CSCertificates"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	$certificates = @()
	
	#Build sip.<domain> entries
	if ($ServerType -match "FE|Dir|Edge"){
		$addDomains = @()
		foreach ($domain in (Get-CsTopology -LocalStore).InternalDomains.Name){
			$addDomains += "sip.$domain"
		}
		$domainName = ($addDomains -join ",")
	}
	
	if ($ServerType -match "Edge"){
		Write-Log "Server type: $ServerType" -Level "Verb"
		$certInput = "" | Select-Object Name,Uses,DomainName,Assigned,Trusted
		$certInput.Name = "External"
		if (Get-Service RTCXMPPTGWPX -ErrorAction SilentlyContinue){
			$certInput.Uses = "AccessEdgeExternal","DataEdgeExternal","AudioVideoAuthentication","XmppServer"
		}else{
			$certInput.Uses = "AccessEdgeExternal","DataEdgeExternal","AudioVideoAuthentication"
		}
		$certInput.DomainName = $domainName
		$certInput.Assigned = $false
		Write-Log "Adding certificate input:" -Level "Verb"
		Write-Log "$certInput" -Level "Verb"
		$certificates += $certInput
		
		$certInput = "" | Select-Object Name,Uses,DomainName,Assigned,Trusted
		$certInput.Name = "Internal"
		$certInput.Uses = "Internal"
		$certInput.Assigned = $false
		Write-Log "Adding certificate input:" -Level "Verb"
		Write-Log "$certInput" -Level "Verb"
		$certificates += $certInput
	}elseif ($ServerType -match "FE|Dir"){
		Write-Log "Server type: $ServerType" -Level "Verb"
		$certInput = "" | Select-Object Name,Uses,DomainName,Assigned,Trusted
		$certInput.Name = "Default"
		$certInput.Uses = "Default","WebServicesInternal","WebServicesExternal"
		$certInput.DomainName = $domainName
		$certInput.Assigned = $false
		Write-Log "Adding certificate input:" -Level "Verb"
		Write-Log "$certInput" -Level "Verb"
		$certificates += $certInput
		
		$oauth = Get-CsCertificate -Identity global -Type OAuthTokenIssuer
		if (!($oauth) -and $PrimaryServer){
			$certInput = "" | Select-Object Name,Uses,DomainName,Assigned,Trusted
			$certInput.Name = "OAuthTokenIssuer"
			$certInput.Uses = "OAuthTokenIssuer"
			$certInput.Assigned = $false
			Write-Log "Adding certificate input:" -Level "Verb"
			Write-Log "$certInput" -Level "Verb"
			$certificates += $certInput
		}
	}elseif ($ServerType -match $IntCsSrvTypes){
		Write-Log "Server type: $ServerType" -Level "Verb"
		$certInput = "" | Select-Object Name,Uses,DomainName,Assigned,Trusted
		$certInput.Name = "Default"
		$certInput.Uses = "Default"
		$certInput.Assigned = $false
		Write-Log "Adding certificate input:" -Level "Verb"
		Write-Log "$certInput" -Level "Verb"
		$certificates += $certInput
	}
	
	Write-Log $certificates -Level "Verb"
	
	#Generate CSRs
	foreach ($certificate in $certificates){
		$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -match $certificate.Name
		if (!($cert)){
			Invoke-CsCertificateProcess -Request -Name $certificate.Name -Uses $certificate.Uses -DomainName $certificate.DomainName -OU $CertOU -Org $CertOrg -City $CertCity -State $CertState `
				-Country $CertCountry -KeySize $CertKeySize -OutDir $TempDir -CA $CAFullName
		}
	}
	
	if (!($CAFullName)){
		Write-Log
		Write-Log "Offline CSRs saved to $TempDir."
		Write-Log
		Write-Log "Submit the CSRs for signing to the appropriate certificate authority, import the signed certificate and certificate chain."
		Write-Log "Ensure that the friendly names contains the words Default, Internal, External, or OAuthTokenIssuer according to type."
		Write-Log "The script will wait for all certificates to be imported and trusted before proceeding."
		if ($ServerType -match "Edge"){
			Write-Log "Note: If there are multiple Edge servers, only submit one external request for signing, and install that certificate on all Edge servers."
		}
		Write-Log
	}
	
	#Waiting for certificates to be imported and assigned
	while ($certificates | Where-Object Assigned -eq $false){
		Write-Log $certificates -Level "Verb"
		foreach ($certificate in $certificates){
			Write-Log "Entering foreach for $($certificate.Name)." -Level "Verb"
			if (!($certificate.Trusted)){
				Write-Log "$($certificate.Name) is not yet trusted." -Level "Verb"
				$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -match $certificate.Name}
				if ($cert){
					Write-Log "$($certificate.Name) found in certificate store." -Level "Verb"
					$chain = $cert
					$tries = 0
					Write-Log "Attempting to resolve certificate chain." -Level "Verb"
					while (($chain.Subject -ne $chain.Issuer) -and ($tries -le 5)){
						Write-Log "Entering while for $($certificate.Subject)." -Level "Verb"
						Write-Log "Subject: $($chain.Subject)" -Level "Verb"
						Write-Log "Issuer: $($chain.Issuer)" -Level "Verb"
						
						$chain = (Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object {$_.Subject -eq $chain.Issuer})
						if ($chain){
							$chain = $chain[0]
							Write-Log "Result: $($chain.Subject)" -Level "Verb"
						}
						
						if (($chain.Subject -eq $chain.Issuer) -and ($chain.Subject -ne $null)){
							Write-Log "$($certificate.Name) is now trusted." -Level "Verb"
							$certificate.Trusted = $true
						}
						$tries++
					}
				}
			}
			if ($cert -and $certificate.Trusted){
				Write-Log "Assigning $($certificate.Name)." -Level "Verb"
				Invoke-CsCertificateProcess -Assign -Name $certificate.Name -Uses $certificate.Uses
				$certificate.Assigned = $true
			}
		}
		
		if ($certificates | Where-Object Assigned -match "false"){
			if ($while -eq $null){
				Write-Log "Waiting for certificates..." -OutTo $LogOutTo
			}
			if ($while -eq 15){
				Write-Log "Waiting for certificates..." -OutTo $LogOutTo
				$while = 0
			}
			Start-Sleep -s 60
			$while++
		}
	}
	Enable-CsComputer
	
	Write-Log
	
	End-Task -NextTask "CSUpdates" -Quiet
}	




#Install updates (CS Servers Only)
if ($Script:Task -eq "CSUpdates"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	#Install SFB Debugging Tools
	Install-Software -File "$SoftwareDir\vc_redist.x64.exe" -Switches "/install","/quiet","/norestart" -Title "VC++ 2015" -ConfirmPath $VC2015GUID
	Install-Software -File "msiexec.exe" -Switches "/i","$SoftwareDir\SkypeForBusinessDebugTools.msi","/qn","/norestart","INSTALLDIR=`"$InstallDrive\Program Files\Skype for Business Server 2015`"" `
		-Title "Skype for Business Debugging Tools" -ConfirmPath $SFBDebugToolsGUID
	Write-Log
	
	#Install SFB Resource Kit
	if ($ServerType -match "FEStd|FEEnt"){
		Install-Software -File "msiexec.exe" -Switches "/i","$SoftwareDir\OCSReskit.msi","/qn","/norestart","INSTALLDIR=`"$InstallDrive\Program Files\Skype for Business Server 2015`"" `
			-Title "Skype for Business Resource Kit" -ConfirmPath $SFBResKitGUID
		Write-Log
	}
	
	#Install SFB updates
	Write-Log "Stopping CS services for patching."
	$retry = 0
	while ((Get-CsWindowsService).Status -eq "Running"){
		Get-CsWindowsService | Stop-Service -Force
		$retry++
		if ($retry -eq 3){
			Write-Log "Unable to stop all CS services. Patching may fail with error code 2. Stop all services and retry." -Level "Warn"
			return
		}
	}
	Write-Log
	
	Install-Software -File "$SoftwareDir\SkypeServerUpdateInstaller.exe" -Switches "/silentmode" -Title "Skype for Business Updates" -ErrorHandling "Stop"
	Write-Log
	
	Write-Log "Component versions:"
	Write-Log (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Skype for Business Server*"} | Sort-Object DisplayName | `
		Select-Object DisplayName,DisplayVersion | Format-Table -AutoSize | Out-String)
	Write-Log
	
	if ($ServerType -match "FEStd|FEEnt"){
		$csPool = Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
		#Installing SLA application
		if (!(Get-CsServerApplication | Where-Object Identity -match "$($csPool.Fqdn)/SharedLineAppearance")){
			Write-Log "Enabling Shared Line Appearances for $($csPool.Fqdn)."
			New-CsServerApplication -Identity "Service:Registrar:$($csPool.Fqdn)/SharedLineAppearance" -Uri http://www.microsoft.com/LCS/SharedLineAppearance -Critical $false -Enabled $true `
				-Priority (Get-CsServerApplication -Identity "Service:Registrar:$($csPool.Fqdn)/UserServices").Priority | Out-Null
			Update-CsAdminRole
		}
		
		#Installing Busy Options application
		if (!(Get-CsServerApplication | Where-Object Identity -match "$($csPool.Fqdn)/BusyOptions")){
			Write-Log "Enabling Busy Options for $($csPool.Fqdn)."
			New-CsServerApplication -Identity "Service:Registrar:$($csPool.Fqdn)/BusyOptions" -Uri http://www.microsoft.com/LCS/BusyOptions -Critical $false -Enabled $true `
				-Priority (Get-CsServerApplication -Identity "Service:Registrar:$($csPool.Fqdn)/UserServices").Priority | Out-Null
			Update-CsAdminRole
			Write-Log
		}
	}
	
	End-Task -Reboot -NextTask "CSConfigure" -Quiet
}




if ($Script:Task -eq "CSConfigure"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	#Check IP addresses and rename interfaces
	if ($ServerType -match "Edge"){
		$csComputer = Get-CsTopology -LocalStore | Select-Object -ExpandProperty Machines | Where-Object Fqdn -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
		$netInterfaces = $csComputer | Select-Object -ExpandProperty NetInterfaces
		
		Write-Log "Checking network adapter configuration."
		foreach ($netInterface in $netInterfaces){
			$netAdapter = Get-NetIPAddress -IPAddress $netInterface.IPAddress -ErrorAction SilentlyContinue
			if ($netAdapter){
				if ($netInterface.InterfaceId -match "Internal:1"){
					Rename-NetAdapter -Name $netAdapter.InterfaceAlias -NewName "INTERNAL"
				}elseif ($netInterface.InterfaceId -match "External:1"){
					Rename-NetAdapter -Name $netAdapter.InterfaceAlias -NewName "EXTERNAL"
				}
				Write-Log "IP address in topology ($($netInterface.IPAddress)) for $($netInterface.InterfaceId) is configured."
			}else{
				Write-Log "IP address in topology ($($netInterface.IPAddress)) for $($netInterface.InterfaceId) is not configured. Quitting." -Level "Error"
				return
			}
		}
		
		#Create persistent routes and remove default from INTERNAL interface
		if (Get-NetRoute -InterfaceAlias "INTERNAL" -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue){
			[string]$ip = (Get-NetIPAddress -InterfaceAlias "INTERNAL").IPv4Address
			if (Test-RFC1918 -IPAddress $ip.Trim()){
				Write-Log "Adding internal static routes and removing default gateway."
				
				$defaultGW = (Get-NetRoute -InterfaceAlias "INTERNAL" -DestinationPrefix 0.0.0.0/0).NextHop
				New-NetRoute -InterfaceAlias "INTERNAL" -DestinationPrefix 10.0.0.0/8 -NextHop $defaultGW | Out-Null
				New-NetRoute -InterfaceAlias "INTERNAL" -DestinationPrefix 172.16.0.0/12 -NextHop $defaultGW | Out-Null
				New-NetRoute -InterfaceAlias "INTERNAL" -DestinationPrefix 192.168.0.0/16 -NextHop $defaultGW | Out-Null
				Remove-NetRoute -InterfaceAlias "INTERNAL" -DestinationPrefix 0.0.0.0/0 -Confirm:$false
				
				Write-Log
				Write-Log "Resulting routing table:"
				Write-Log (Get-NetRoute -AddressFamily IPv4 -Protocol NetMgmt | Out-String)
			}else{
				Write-Log "Internal interface does not have a RFC1918 address. Static routes must be added manually." -Level "Warn"
			}
		}
		
		#Disable NetBIOS and dynamic DNS registration
		$nics = Get-WMIObject Win32_NetworkAdapterConfiguration | Where-Object IPEnabled -eq $true
		foreach ($nic in $nics) {
			#Disable NetBIOS
			$nic.SetTcpipNetbios(2) | Out-Null
			#Disable dynamic DNS registration
			$nic.SetDynamicDNSRegistration($false,$false) | Out-Null
			
		}
		Write-Log
	}
	
	#Configure KHIs
	if ($ServerType -match $CsSrvTypes){
		Write-Log "Extracting KHI."
		$extractCmd = "$SoftwareDir\7zip\7za.exe x $SoftwareDir\$(Split-Path $CSKHIUrl -Leaf) -o"+$UserTempDir+"\KHI -y -aoa"
		Invoke-Expression $extractCmd -ErrorAction Continue | Out-Null
		Remove-Item "$ScriptsDir\$(Split-Path $CSKHIUrl -Leaf)" -ErrorAction SilentlyContinue
		
		Write-Log "Creating KHI data collector and updating schedule."
		Invoke-Expression "PowerShell -ExecutionPolicy Bypass -File $UserTempDir\KHI\Create_KHI_Data_Collector.ps1 -Version Skype4B"
		
		$logmanCmd = "logman.exe update KHI -si 60 -b (Get-Date).AddDays(1).ToString('M/dd/yyyy') 00:00:00AM -rf 23:59:00 -r"
		Invoke-Expression $logmanCmd
		
		Write-Log "Creating scheduled task to truncate KHI log files."
		$scriptBlock = {Get-ChildItem -Path C:\PerfLogs -Include KHI*.csv -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).addDays(-14)} | Foreach-Object {Remove-Item $_.FullName}}
		$scriptBlock | Out-File -Width 500 "$ScriptsDir\Clean-KHILogs.ps1"
		
		$arg = "-Command "+'"'+"& '"+$ScriptsDir+"\Clean-KHILogs.ps1'"+'"'
		Manage-ScheduledTask -TaskName "Clean KHI Logs (Daily)" -Action "Add" -StartupType Scheduled -Recurrence Daily -Time "00:30:00" -Execute powershell -Argument $arg -User "SYSTEM"
		Write-Log
	}
	
	End-Task -NextTask "CSServices" -Quiet
}




#Start services (CS Servers Only)
if($Script:Task -eq "CSServices"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	if ($ServerType -match "FEStd|Dir|PChat"){
		if (Get-CsCertificate | Where-Object Use -match "Default"){
			Write-Log "Starting CS services."
			$error.Clear()
			try {
				Start-CsWindowsService
			}catch{
				$errOut = $error.Exception.InnerException
				Write-Log "Error occurred while starting services: $errOut" -Level "Error"
			}
		}else{
			Write-Log "Certificates not applied. Verify certificate installation before starting services." -Level "Error"
			return
		}
	}elseif ($ServerType -match "FEEnt"){
		Write-Log "Pool is Enterprise. Start pool services manually using Start-CsPool." -Level "Warn"
		Write-Log "Disabling services until all reboots have been completed."
		Get-CsWindowsService | Set-Service -StartupType Disabled
	}elseif ($ServerType -match "Edge"){
		if ((Get-CsCertificate | Where-Object Use -match "Internal") -and (Get-CsCertificate | Where-Object Use -match "External")){
			Write-Log "Starting CS services."
			$error.Clear()
			try {
				Start-CsWindowsService
			}catch{
				$errOut = $error.Exception.InnerException
				Write-Log "Error occurred while starting services: $errOut" -Level "Error"
			}
		}else{
			Write-Log "Certificates not applied. Verify certificate installation before starting services." -Level "Error"
			return
		}
	}
	Write-Log
	
	End-Task -NextTask "CSCustomize" -Quiet
}




#Policies & customizations (CS Servers Only)
if ($Script:Task -eq "CSCustomize"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	Write-Log "Importing SFB PS module."
	try {
		Import-Module "C:\Program Files\Common Files\Skype for Business Server 2015\Modules\SkypeForBusiness"
	}catch{
		Write-Log "Unable to import SkypeForBusiness PS module. Quitting." -Level "Error"
		return
	}
	Write-Log
	
	if ($MonitoringReports){
		if ($PrimaryServer){
			Write-Log "Deploying monitoring reports."
			$csPool = (Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)).Fqdn
			$monSQL = Get-CsService -MonitoringDatabase | Where-Object DependentServiceList -match $csPool
			
			Push-Location
			Set-Location "$InstallDrive\Program Files\Skype for Business Server 2015\Deployment\Setup\"
			$deployReports = ".\DeployReports.ps1 -storedUserName '"+$MonReportUser+"' -storedPassword '"+$MonReportPassword+"' -readOnlyGroupName 'RTCUniversalReadOnlyAdmins' -reportServerSqlInstance '"+$monSQL.PoolFqdn+"' -monitoringDatabaseId '"+$monSQL.Identity+"'"
			if (Test-NetConnection -ComputerName $monSQL.PoolFqdn -CommonTCPPort HTTP){
				try {
					Invoke-Expression $deployReports
				}catch{
					Write-Log "Failed to deploy monitoring reports." -Level "Error"
					Write-Log $error[0] -Level "Error"
				}
			}else{
				Write-Log "Failed to deploy monitoring reports due to connectivity issues on TCP/80." -Level "Error"
			}
			Pop-Location
		}
		Write-Log
	}
	
	if ($QoSServer){
		if ($PrimaryServer){
			$portAudioCount = $PortAudioEnd - $PortAudioStart
			$portVideoCount = $PortVideoEnd - $PortVideoStart
			$portAppShareCount = $PortAppShareEnd - $PortAppShareStart
			
			Write-Log "Configuring conferencing port ranges."
			$csPool = (Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)).Fqdn
			Set-CsConferenceServer -Identity $csPool -AudioPortStart $PortAudioStart -AudioPortCount $portAudioCount
			Set-CsConferenceServer -Identity $csPool -VideoPortStart $PortVideoStart -VideoPortCount $portVideoCount
			Set-CsConferenceServer -Identity $csPool -AppSharingPortStart $PortAppShareStart -AppSharingPortCount $portAppShareCount
			Set-CsApplicationServer -Identity $csPool -AudioPortStart $PortAudioStart -AudioPortCount $portAudioCount
			Set-CsApplicationServer -Identity $csPool -VideoPortStart $PortVideoStart -VideoPortCount $portVideoCount
			Set-CsApplicationServer -Identity $csPool -AppSharingPortStart $PortAppShareStart -AppSharingPortCount $portAppShareCount
			if ((Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)).Services -match "Mediation"){
				Set-CsMediationServer -Identity $csPool -AudioPortStart $PortAudioStart -AudioPortCount $portAudioCount
			}
			
			Write-Log "Enabling QoS for LPE phones and setting DSCP value."
			Set-CsMediaConfiguration -EnableQoS $true
			Set-CsUCPhoneConfiguration -VoiceDiffServTag $QoSAudioDSCP
			
			Write-Log "Enabling mid-call QoS statistics."
			Set-CsMediaConfiguration -EnableInCallQoS $true -InCallQoSIntervalSeconds 60
		}
		
		$error.Clear()
		if ($ServerType -match "FE"){
			Write-Log "Creating QoS policies for Front End server."
			New-NetQosPolicy CSServerConfAudioQoS -App AVMCUSvc.exe -Protocol Both -IPSrcPortStart $PortAudioStart -IPSrcPortEnd $PortAudioEnd -DSCP $QoSAudioDSCP -ErrorAction SilentlyContinue | Out-Null
			New-NetQosPolicy CSServerConfVideoQoS -App AVMCUSvc.exe -Protocol Both -IPSrcPortStart $PortVideoStart -IPSrcPortEnd $PortVideoEnd -DSCP $QoSVideoDSCP -ErrorAction SilentlyContinue | Out-Null
			New-NetQosPolicy CSServerConfAppSharingQoS -App ASMCUSvc.exe -Protocol Both -IPSrcPortStart $PortAppShareStart -IPSrcPortEnd $PortAppShareEnd -DSCP $QoSAppShareDSCP -ErrorAction SilentlyContinue | Out-Null
			New-NetQosPolicy CSServerAppSrvAudioQoS -App OcsAppServerHost.exe -Protocol Both -IPSrcPortStart $PortAudioStart -IPSrcPortEnd $PortAudioEnd -DSCP $QoSAudioDSCP -ErrorAction SilentlyContinue | Out-Null
			New-NetQosPolicy CSServerAppSrvVideoQoS -App OcsAppServerHost.exe -Protocol Both -IPSrcPortStart $PortVideoStart -IPSrcPortEnd $PortVideoEnd -DSCP $QoSVideoDSCP -ErrorAction SilentlyContinue | Out-Null
			New-NetQosPolicy CSServerMedAudioQoS -App MediationServerSvc.exe -Protocol Both -IPSrcPortStart $PortAudioStart -IPSrcPortEnd $PortAudioEnd -DSCP $QoSAudioDSCP -ErrorAction SilentlyContinue | Out-Null
		}
		
		if ($ServerType -match "Med"){
			Write-Log "Creating QoS policies for Mediation server."
			New-NetQosPolicy CSServerMedAudioQoS -App MediationServerSvc.exe -Protocol Both -IPSrcPortStart $PortAudioStart -IPSrcPortEnd $PortAudioEnd -DSCP $QoSAudioDSCP -ErrorAction SilentlyContinue | Out-Null
		}
		
		if ($ServerType -match "Edge"){
			Write-Log "Creating QoS policies for Edge server."
			[string]$edgeIntIP = (Get-NetIPAddress -InterfaceAlias "INTERNAL").IPv4address
			New-NetQosPolicy CSEdgeAudioQoS -Protocol Both -IPSrcPortStart $PortAudioStart -IPSrcPortEnd $PortAudioEnd -IPSrcPrefix $edgeIntIP.Trim() -DSCP $QoSAudioDSCP -ErrorAction SilentlyContinue | Out-Null
			New-NetQosPolicy CSEdgeVideoQoS -Protocol Both -IPSrcPortStart $PortVideoStart -IPSrcPortEnd $PortVideoEnd -IPSrcPrefix $edgeIntIP.Trim() -DSCP $QoSVideoDSCP -ErrorAction SilentlyContinue | Out-Null
		}
		
		if ($error){
			Write-Log "Error creating QoS policies." -Level "Error"
			Write-Log $error[0].Exception.Message -Level "Error"
		}
		
		Write-Log
		Write-Log "Resulting QoS policies:"
		Write-Log (Get-NetQosPolicy | Where-Object Name -match "CSServer|CSEdge" | Format-Table Name,@{Label="Application";Expression={$_.AppPathNameMatchCondition}},`
			@{Label="DSCP";Expression={$_.DSCPAction}},@{Label="Protocol";Expression={$_.IPProtocol}},@{Label="SrcPrefix";Expression={$_.IPSrcPrefixMatchCondition}},`
			@{Label="StartSrcPort";Express={$_.IPSrcPortStart}},@{Label="EndSrcPort";Expression={$_.IPSrcPortEnd}},@{Label="DstPrefix";Expression={$_.IPDstPrefixMatchCondition}},`
			@{Label="StartDstPort";Expression={$_.IPDstPortStart}},@{Label="EndDstPort";Expression={$_.IPDstPortEnd}} -AutoSize | Out-String)
		Write-Log
	}
	
	if ($QoSClient){
		if ($PrimaryServer){
			Write-Log "Configuring client port ranges."
			Set-CsConferencingConfiguration -ClientMediaPortRangeEnabled $true
			Set-CsConferencingConfiguration -ClientAudioPort $PortAudioStart -ClientAudioPortRange 100 -ClientVideoPort $PortVideoStart -ClientVideoPortRange 100 -ClientAppSharingPort $PortAppShareStart `
				-ClientAppSharingPortRange 100 -ClientFileTransferPort $PortFileTransferStart -ClientFileTransferPortRange 100
			Write-Log
			Write-Log "Resulting client port configuration:"
			Write-Log (Get-CsConferencingConfiguration | Format-List Identity,ClientMediaPortRangeEnabled,ClientAudioPort,ClientAudioPortRange,ClientVideoPort,ClientVideoPortRange,`
				ClientAppSharingPort,ClientAppSharingPortRange,ClientFileTransferPort,ClientFileTransferPortRange | Out-String)
			Write-Log
		}
	}
	
	if ($Policies){
		if ($PrimaryServer){
			#PIN Policy
			Write-Log "Updating PIN policy."
			Set-CsPinPolicy -AllowCommonPatterns $false -PINLifetime 0 -MinPasswordLength 4 -WarningAction SilentlyContinue
			
			#Mobility Policy
			#Write-Log "Creating mobility policies."
			#New-CsMobilityPolicy "Enable Mobility" -EnableMobility $true -EnableOutsideVoice $false -ErrorAction SilentlyContinue | Out-Null
			#New-CsMobilityPolicy "Enable Mobility+Call via Work" -EnableMobility $true -EnableOutsideVoice $true -ErrorAction SilentlyContinue | Out-Null
			#New-CsMobilityPolicy "No Mobility" -EnableMobility $false -EnableOutsideVoice $false -ErrorAction SilentlyContinue | Out-Null
			
			#Access Edge Configuration
			Write-Log "Updating Access Edge configuration."
			Set-CsAccessEdgeConfiguration -AllowOutsideUsers $true -AllowFederatedUsers $true -AllowAnonymousUsers $true
			
			#Push Notifications
			Write-Log "Enabling push notifications."
			Set-CsPushNotificationConfiguration -EnableApplePushNotificationService $true -EnableMicrosoftPushNotificationService $true
			
			#Public IM Provider
			Write-Log "Updating public provider."
			Set-CsPublicProvider Skype -Enabled $true
			if (Get-CsHostingProvider LyncOnlineFederation -ErrorAction SilentlyContinue){
				Remove-CsHostingProvider LyncOnlineFederation
				New-CsHostingProvider SkypeForBusinessOnline -Enabled $true -ProxyFqdn sipfed.online.lync.com | Out-Null
			} elseif (Get-CsHostingProvider SkypeForBusinessOnline -ErrorAction SilentlyContinue){
				Set-CsHostingProvider SkypeForBusinessOnline -Enabled $true
			}
			
			#Conferencing Policy
			Write-Log "Updating conferencing policy to allow non-EV users to dial out."
			Set-CsConferencingPolicy -AllowNonEnterpriseVoiceUsersToDialOut $true
			
			#Persistent Chat Policy
			if (Get-CsService -PersistentChatServer | Out-Null){
				Write-Log "Enabling persistent chat globally."
				Set-CsPersistentChatPolicy -EnablePersistentChat $true
			}
			
			#Archiving Policy
			If (Get-CsService -ArchivingDatabase){
				Write-Log "Enabling IM archiving."
				Set-CsArchivingConfiguration -EnableArchiving ImAndWebConf
				Set-CsArchivingPolicy -ArchiveInternal $true -ArchiveExternal $true
			}
			
			#Client Policy
			Write-Log "Updating global client policy for MOH and SkypeUI."
			Set-CsClientPolicy -EnableSkypeUI $true -EnableClientMusicOnHold $true
			
			#External Access Policies
			Write-Log "Creating external access policies."
			New-CsExternalAccessPolicy -Identity "Tag:Allow Federation+Public+Remote Access" -EnableFederationAccess $True -EnablePublicCloudAccess $True -EnablePublicCloudAudioVideoAccess $False -EnableOutsideAccess $True -ErrorAction SilentlyContinue | Out-Null
			New-CsExternalAccessPolicy -Identity "Tag:Allow Federation+Public Access" -EnableFederationAccess $True -EnablePublicCloudAccess $True -EnablePublicCloudAudioVideoAccess $False -EnableOutsideAccess $False -ErrorAction SilentlyContinue | Out-Null
			New-CsExternalAccessPolicy -Identity "Tag:Allow Federation+Remote Access" -EnableFederationAccess $True -EnablePublicCloudAccess $False -EnablePublicCloudAudioVideoAccess $False -EnableOutsideAccess $True -ErrorAction SilentlyContinue | Out-Null
			New-CsExternalAccessPolicy -Identity "Tag:Allow Federation Access" -EnableFederationAccess $True -EnablePublicCloudAccess $False -EnablePublicCloudAudioVideoAccess $False -EnableOutsideAccess $False -ErrorAction SilentlyContinue | Out-Null
			New-CsExternalAccessPolicy -Identity "Tag:Allow Public+Remote Access" -EnableFederationAccess $False -EnablePublicCloudAccess $True -EnablePublicCloudAudioVideoAccess $False -EnableOutsideAccess $True -ErrorAction SilentlyContinue | Out-Null
			New-CsExternalAccessPolicy -Identity "Tag:Allow Remote Access" -EnableFederationAccess $False -EnablePublicCloudAccess $False -EnablePublicCloudAudioVideoAccess $False -EnableOutsideAccess $True -ErrorAction SilentlyContinue | Out-Null
			New-CsExternalAccessPolicy -Identity "Tag:Allow Public Access" -EnableFederationAccess $False -EnablePublicCloudAccess $True -EnablePublicCloudAudioVideoAccess $False -EnableOutsideAccess $False -ErrorAction SilentlyContinue | Out-Null
			New-CsExternalAccessPolicy -Identity "Tag:Allow No Access" -EnableFederationAccess $False -EnablePublicCloudAccess $False -EnablePublicCloudAudioVideoAccess $False -EnableOutsideAccess $False -ErrorAction SilentlyContinue | Out-Null
		}
		Write-Log
	}
	
	if ($DialPlan){
		if ($PrimaryServer){
			Write-Log "Creating voice configuration."
			
			#Remove default voice configuration
			Write-Log "Removing existing voice configurations."
			Get-CsVoiceNormalizationRule "Global/Keep All" | Remove-CsVoiceNormalizationRule
			Get-CsVoiceRoute "LocalRoute" | Remove-CsVoiceRoute
			Set-CsPstnUsage global -Usage @{Remove="Internal"}
			Set-CsPstnUsage global -Usage @{Remove="Local"}
			Set-CsPstnUsage global -Usage @{Remove="Long Distance"}
			
			#Create generic US user dial plan
			Write-Log "Creating generic US dial plan."
			New-CsDialPlan "US" -Description "Generic US normalization rules" -ErrorAction SilentlyContinue | Out-Null
			Get-CsVoiceNormalizationRule "US/Keep All" | Remove-CsVoiceNormalizationRule
			New-CsVoiceNormalizationRule -Name 'US-National' -Parent "US" -Pattern '^1?([2-9]\d\d[2-9]\d{6})\d*(\D+\d+)?$' -Translation '+1$1' -Description "National number normalization for United States" -ErrorAction SilentlyContinue | Out-Null
			New-CsVoiceNormalizationRule -Name 'US-Service' -Parent "US" -Pattern '^([2-9]11)$' -Translation '$1' -Description "Service number normalization for United States" -ErrorAction SilentlyContinue | Out-Null
			New-CsVoiceNormalizationRule -Name 'US-International' -Parent "US" -Pattern '^011(1|7|2[07]|3[0-46]|39\d|4[013-9]|5[1-8]|6[0-6]|8[1246]|9[0-58]|2[1235689]\d|24[013-9]|242\d|3[578]\d|42|5[09]\d|6[789]\d|8[035789]\d|9[679]\d)(?:0)?(\d{6,14})(\D+\d+)?$' -Translation '+$1$2' -Description "International number normalization for United States" -ErrorAction SilentlyContinue | Out-Null
			
			#Add generic normalization rules to Global dial plan
			New-CsVoiceNormalizationRule -Name 'US-National' -Parent global -Pattern '^1?([2-9]\d\d[2-9]\d{6})\d*(\D+\d+)?$' -Translation '+1$1' -Description "National number normalization for United States" -ErrorAction SilentlyContinue | Out-Null
			New-CsVoiceNormalizationRule -Name 'US-Service' -Parent global -Pattern '^([2-9]11)$' -Translation '$1' -Description "Service number normalization for United States" -ErrorAction SilentlyContinue | Out-Null
			New-CsVoiceNormalizationRule -Name 'US-International' -Parent global -Pattern '^011(1|7|2[07]|3[0-46]|39\d|4[013-9]|5[1-8]|6[0-6]|8[1246]|9[0-58]|2[1235689]\d|24[013-9]|242\d|3[578]\d|42|5[09]\d|6[789]\d|8[035789]\d|9[679]\d)(?:0)?(\d{6,14})(\D+\d+)?$' -Translation '+$1$2' -Description "International number normalization for United States" -ErrorAction SilentlyContinue | Out-Null
			
			#Create PSTN usages
			Write-Log "Creating generic PSTN usages."
			Set-CsPSTNUsage -Identity global -Usage @{Add="US-Local"} -WarningAction:SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
			Set-CsPSTNUsage -Identity global -Usage @{Add="US-Service"} -WarningAction:SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
			Set-CsPSTNUsage -Identity global -Usage @{Add="US-National"} -WarningAction:SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
			Set-CsPSTNUsage -Identity global -Usage @{Add="US-Premium"} -WarningAction:SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
			Set-CsPSTNUsage -Identity global -Usage @{Add="US-International"} -WarningAction:SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
			
			#Create generic voice routes without gateway
			Write-Log "Creating generic routes without gateway."
			New-CsVoiceRoute "US-TollFree" -PSTNUsages "US-Local" -NumberPattern '^\+18(00|8\d|77|66|55|44|33|22)\d{7}$' -Description "TollFree routing" -ErrorAction SilentlyContinue | Out-Null
			New-CsVoiceRoute "US-Premium" -PSTNUsages "US-Premium" -NumberPattern '^\+1(900|976)[2-9]\d{6}$' -Description "Premium routing" -ErrorAction SilentlyContinue | Out-Null
			New-CsVoiceRoute "US-National" -PSTNUsages "US-National" -NumberPattern '^\+1(?!(900|976))(20[^04]|21[^1]|22[4589]|23[149]|24[08]|25[12346]|26[0279]|27[026]|30[^06]|31[^1]|32[0135]|33[^2358]|34[067]|35[12]|36[01]|38[56]|40[^03]|41[^168]|42[345]|43[0245]|44[023]|47[0589]|48[04]|50[^06]|51[^149]|53[0149]|54[01]|55[19]|56[12347]|57[01345]|58[056]|60[^04]|61[^13]|62[03689]|63[016]|64[16]|65[017]|66[01279]|67[018]|68[124]|70[^059]|71[^01]|72[0457]|73[1247]|74[07]|75[47]|76[02359]|77[^1678]|78[1567]|80[^079]|81[^19]|83[012]|84[3578]|85[^1235]|86[02345]|87[028]|90[^025]|91[^1]|92[0589]|93[16789]|94[0179]|95[12469]|97[^4567]|98[0459]|281|458|469|520|828)[2-9]\d{6}$' -Description "National routing" -ErrorAction SilentlyContinue | Out-Null
			New-CsVoiceRoute "US-International" -PSTNUsages "US-International" -NumberPattern '^\+((1(?!(900|976))[2-9]\d\d[2-9]\d{6})|([2-9]\d{6,14}))$' -Description "International routing" -ErrorAction SilentlyContinue | Out-Null
			New-CsVoiceRoute "US-Service" -PSTNUsages "US-Service" -NumberPattern '^\+?([2-9]11)$' -Description "Service routing" -ErrorAction SilentlyContinue | Out-Null
			
			#Create generic voice policies
			Write-Log "Creating generic voice policies."
			New-CsVoicePolicy "US-National" -Description "Allows local/national calls" -PstnUsages @{Replace="US-Local","US-National","US-Service"} -WarningAction:SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
			New-CsVoicePolicy "US-International" -Description "Allows local/national/international calls" -PstnUsages @{Replace="US-Local","US-National","US-Service","US-International"} -WarningAction:SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
			
			#Create generic outbound translations
			Write-Log "Creating trunk configurations."
			New-CsOutboundCallingNumberTranslationRule -Name "US-Outbound" -Parent global -Priority 0 -Pattern '^\+1(\d+)(;ext=\d+)?$' -Translation '$1' -Description "" -ErrorAction SilentlyContinue | Out-Null
			New-CsOutboundTranslationRule -Name "US-Service" -Parent global -Priority 2 -Pattern '^\+([2-9]11)$' -Translation '$1' -Description "Remove + for service calls" -ErrorAction SilentlyContinue | Out-Null
			New-CsOutboundTranslationRule -Name "US-National" -Parent global -Priority 3 -Pattern '^\+1([2-9]\d\d[2-9]\d{6})(;ext=\d+)?$' -Translation '1$1' -Description "Remove + and country code for national calls" -ErrorAction SilentlyContinue | Out-Null
			New-CsOutboundTranslationRule -Name "US-International" -Parent global -Priority 4 -Pattern '^\+(1|7|2[07]|3[0-46]|39\d|4[013-9]|5[1-8]|6[0-6]|8[1246]|9[0-58]|2[1235689]\d|24[013-9]|242\d|3[578]\d|42|5[09]\d|6[789]\d|8[035789]\d|9[679]\d)(?:0)?(\d{6,14})(;ext=\d+)?$' -Translation '011$1$2' -Description "Adds 011 for international calls" -ErrorAction SilentlyContinue | Out-Null
			
			#Set trunk configuration
			Set-CsTrunkConfiguration -EnableReferSupport $false -SRTPMode Optional -WarningAction SilentlyContinue
		}
		Write-Log
	}
	
	if ($ABSNormNA -or $ABSNormIntl){
		if ($PrimaryServer){
			Get-CsAddressBookNormalizationRule | Where-Object Name -ne "Generic_E164" | Remove-CsAddressBookNormalizationRule
			
			Write-Log "Creating ABS normalizations."
			if ($ABSNormIntl){
				New-CsAddressBookNormalizationRule -Parent Global -Name "Global" -Pattern "((1[2-9]\d\d[2-9]\d{6})|([2-9]\d{6,14}))" -Translation '+$1' -Priority 1 | Out-Null
				New-CsAddressBookNormalizationRule -Parent Global -Name "Global-Ext" -Pattern "((1[2-9]\d\d[2-9]\d{6})|([2-9]\d{6,14}))\D+(\d+)" -Translation '+$1;ext=$2' -Priority 2 | Out-Null
			}
			if ($ABSNormNA){
				New-CsAddressBookNormalizationRule -Parent Global -Name "NANPA-10-Digit" -Pattern "1?([2-9]\d{9})" -Translation '+1$1' -Priority 1 | Out-Null
				New-CsAddressBookNormalizationRule -Parent Global -Name "NANPA-10-Digit-Ext" -Pattern "1?([2-9]\d{9})\D+(\d+)" -Translation '+1$1;ext=$2' -Priority 2 | Out-Null
			}
		}
		Write-Log
	}
	
	#Enable Skype Meetings App
	if ($PrimaryServer){
		Write-Log "Configuring Skype Meetings App."
		Set-CsWebServiceConfiguration -MeetingUxUseCdn $true -JoinLauncherCdnTimeout (New-TimeSpan -Seconds 10)
	}
	
	#Disable IE ESC to set trusted sites for Control Panel
	if ($ServerType -match "FEStd|FEEnt|Dir"){
		Write-Log "Disabling IE ESC."
		Disable-InternetExplorerESC
		Write-Log
	}
	
	#Set Trusted Sites for integrated auth to Control Panel
	if ($ServerType -match "FEStd|FEEnt|Dir"){
		$TrustedSites = (Get-CsService -WebServer).CscpInternalUri
		foreach ($TrustedSite in $TrustedSites){
			Write-Log "Adding internal web services URL to Local Intranet zone."
			New-TrustedIESite -Url $TrustedSite.AbsoluteUri -Zone 1
		}
		Write-Log
	}
	
	#Set next task
	End-Task -NextTask "Applications" -Quiet
}





#OOS Installation
#---To do---
#Request certificate function
if ($Script:Task -eq "OWASInstall"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	Toggle-ScheduledTask -TaskName "CSDeploymentReboot" -Action "Disable" | Write-Log -Level "Verb"
	
	#If media path not set, continue to search for mounted media
	if (!($SetupPath)){
		Invoke-DiscoverMedia -MediaPath $MediaPath -ExecutablePath "setup.exe"
		Save-Variables
	}
	if ($Script:Path){
		$SetupPath = $Script:Path
		Save-Variables
	}
	
	Write-Log "Installing OOS with silent install config."
	Install-Software -File "$SetupPath\setup.exe" -Switches "/config $SetupPath\files\setupsilent\config.xml" -ConfirmPath $OOSGUID -ErrorHandling "Stop"
	
	Write-Log "Extracting and installing OOS language pack."
	if (!(Test-Path $SoftwareDir\wacserverlanguagepack)){
		$process = Start-Process -FilePath "$SoftwareDir\wacserverlanguagepack.exe" -ArgumentList "/extract:$UserTempDir\wacserverlanguagepack /quiet" -Wait -Passthru -Verb RunAs
	}
	Install-Software -File "$UserTempDir\wacserverlanguagepack\setup.exe" -Switches "/config $UserTempDir\wacserverlanguagepack\files\setupsilent\config.xml" -ConfirmPath $OOSLangPackGUID -ErrorHandling "Stop"
	
	#Install OOS patch
	$oosPatchFileName = (Split-Path $OOSPatchUrl -Leaf)
	$oosPatchFolderName = ($oosPatchFileName -replace ".exe","")
	if (!(Test-Path $SoftwareDir\$oosPatchFolderName)){
		Write-Log "Extracting OOS security patch."
		$process = Start-Process -FilePath "$SoftwareDir\$oosPatchFileName" -ArgumentList "/extract:$UserTempDir\$oosPatchFolderName /quiet" -Wait -Passthru -Verb RunAs
	}
	$args = "/update","$UserTempDir\$oosPatchFolderName\wacserver-x-none.msp","/qn","/norestart"
	Install-Software -File "msiexec.exe" -Switches $args -Title "$oosPatchFolderPath" -ConfirmPath $OOSPatchGUID
	Write-Log
	
	End-Task -NextTask "OWASConfigure" -Quiet
}





if ($Script:Task -eq "OWASConfigure"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	Write-Log "Importing Office Web Apps module."
	try {
		Import-Module "C:\Program Files\Microsoft Office Web Apps\AdminModule\OfficeWebApps\OfficeWebApps"
	}catch{
		Write-Log "Unable to import OfficeWebApps PS module. Quitting." -Level "Error"
		return
	}
	Write-Log
	
	if (!(Get-WebSite HTTP80)){
		if ($WACPrimaryServer){
			Write-Log "Joining server $($WACPrimaryServer)."
			New-OfficeWebAppsMachine -MachineToJoin $WACPrimaryServer | Out-Null
		}else{
			Write-Log "Creating Office Web Apps farm for $WACExternalUrl."
			try {
				New-OfficeWebAppsFarm -InternalURL $WACInternalUrl -ExternalURL $WACExternalUrl -CertificateName $FriendlyName -Confirm:$false | Out-Null
			}catch{
				Write-Log "Error creating OfficeWebAppsFarm. $Error" -Level "Error"
				return
			}
			$wacDomain = $WACExternalUrl
			$wacDomain = $wacDomain -replace "https://\w+.",""
			$wacDomain = $wacDomain -replace "/(.+)?",""
			try {
				New-OfficeWebAppsHost -Domain $wacDomain | Out-Null
			}catch{
				Write-Log "Error configuring OfficeWebAppsHost. $Error" -Level "Error"
				return
			}
		}
	}else{
		Write-Log "Office Web Apps farm already configured."
	}
	Write-Log
	
	#Dismount media
	if ($MediaPath -match ".iso|.img"){
		Dismount-DiskImage $MediaPath
		$Script:ImageMounted = $false
		Save-Variables
	}
	
	#Set next task
	End-Task -Reboot -NextTask "Applications" -Quiet
}





#IIS ARR Installation
#---To do---
#Request certificate function
if ($Script:Task -eq "ARRConfigure"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()

	Write-Log "Importing WebAdministration PS module."
	try {
		Import-Module WebAdministration
	}catch{
		Write-Log "Unable to import WebAdministration PS module. Quitting." -Level "Error"
		return
	}
	Write-Log
	
	if (!(Get-WebBinding -Protocol HTTPS -Name "Default Web Site")){
		Write-Log "Creating HTTPS binding for Default Web Site"
		New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https | Out-Null
	}
	
	if (!(Get-Item "IIS:\SslBindings\0.0.0.0!443" -ErrorAction SilentlyContinue)){
		Write-Log "Binding certificate $FriendlyName"
		$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -match $FriendlyName
		$cert | New-Item "IIS:\SslBindings\0.0.0.0!443" -Force -ErrorAction SilentlyContinue | Out-Null
	}
	Write-Log
	
	if ($WACExternalUrl){
		$wacExtUrl = $WACExternalUrl -replace "https://",""
		$wacExtUrl = $wacExtUrl -replace "/(.+)?",""
		$wacIntUrl = $WACInternalUrl -replace "https://",""
		$wacIntUrl = $wacIntUrl -replace "/(.+)?",""
		Write-Log "Creating ARR rule for $WACExternalUrl"
		New-IISARRRule -Url $wacExtUrl -HTTPPort 80 -HTTPSPort 443 -Destination $wacIntUrl
	}
	Write-Log "Creating ARR rule for $WebServicesExtFQDN"
	New-IISARRRule -Url $WebServicesExtFQDN -HTTPPort 8080 -HTTPSPort 4443 -Destination $WebServicesIntFQDN
	
	$csHosts = "meet","dialin","lyncdiscover"
	foreach ($hostname in $csHosts){
		foreach ($domain in $Domains){
			$fqdn = $hostname+"."+$domain
			Write-Log "Creating ARR rule for $fqdn"
			New-IISARRRule -Url $fqdn -HTTPPort 8080 -HTTPSPort 4443 -Destination $WebServicesIntFQDN
		}
	}
	Write-Log
	
	#Set next task
	End-Task -NextTask "Applications" -Quiet
}



#Install third party applications
if ($Script:Task -eq "Applications"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	if ($SQLMgmtStudio -or $Wireshark -or $ACSyslog -or $Firefox -or $Chrome){
		Write-Log
		Write-Log "Installing third party applications"
		Write-Log
	}
	
	#SQL Management Studio
	# Requires no pending reboots
	if ($SQLMgmtStudio){
		Install-Software -File "$SoftwareDir\SSMS-Setup-ENU.exe" -Switches "/install","/quiet","/norestart" -Title "SQL Management Studio" -ConfirmPath $SQLSMSPath
	}
	
	#Wireshark
	if ($Wireshark){
		Install-Software -File "$SoftwareDir\$(Split-Path $WiresharkUrl -Leaf)" -Switches "/S","/desktopicon=no" -Title "Wireshark ($SoftwareDir\$(Split-Path $WiresharkUrl -Leaf))" -ConfirmPath $WiresharkGUID
		
		#WinPcap
		$extractCmd = $SoftwareDir+"\7zip\7za.exe x "+$SoftwareDir+"\$(Split-Path $WinPcapUrl -Leaf) -o"+$UserTempDir+"\WinPcap -y -aou"
		Invoke-Expression $extractCmd -ErrorAction Continue | Out-Null
		
		#Copy by hash
		Get-FileHash -Path "$UserTempDir\WinPcap\`$SYSDIR\drivers\*" -Algorithm SHA1 | Where-Object Hash -eq $npf32SHA1Hash | `
			Copy-Item -Destination $env:SystemRoot\System32\drivers\npf.sys -ErrorAction SilentlyContinue
		Get-FileHash -Path "$UserTempDir\WinPcap\`$SYSDIR\*" -Algorithm SHA1 | Where-Object Hash -eq $pthreadVC64SHA1Hash | `
			Copy-Item -Destination $env:SystemRoot\SysWOW64\pthreadVC.dll -ErrorAction SilentlyContinue
		Get-FileHash -Path "$UserTempDir\WinPcap\`$SYSDIR\*" -Algorithm SHA1 | Where-Object Hash -eq $Packet32SHA1Hash | `
			Copy-Item -Destination $env:SystemRoot\System32\Packet.dll -ErrorAction SilentlyContinue
		Get-FileHash -Path "$UserTempDir\WinPcap\`$SYSDIR\*" -Algorithm SHA1 | Where-Object Hash -eq $Packet64SHA1Hash | `
			Copy-Item -Destination $env:SystemRoot\SysWOW64\Packet.dll -ErrorAction SilentlyContinue
		Get-FileHash -Path "$UserTempDir\WinPcap\`$SYSDIR\*" -Algorithm SHA1 | Where-Object Hash -eq $wpcap32SHA1Hash | `
			Copy-Item -Destination $env:SystemRoot\System32\wpcap.dll -ErrorAction SilentlyContinue
		Get-FileHash -Path "$UserTempDir\WinPcap\`$SYSDIR\*" -Algorithm SHA1 | Where-Object Hash -eq $wpcap64SHA1Hash | `
			Copy-Item -Destination $env:SystemRoot\SysWOW64\wpcap.dll -ErrorAction SilentlyContinue
		
		Remove-Item "$UserTempDir\WinPcap" -Recurse -Confirm:$false -ErrorAction SilentlyContinue
		
		$error.Clear()
		try {
			sc.exe create npf binPath="C:\Windows\System32\drivers\npf.sys" type=kernel start=auto error=normal tag=no DisplayName="NetGroup Packet Filter Driver"
		}catch{
			Write-Log "Failed to create NPF service." -Indent $Indent -Level "Error"
			Write-Log $error[0].Exception.Message -Indent $Indent -Level "Error"
		}
	}
	
	#AudioCodes Syslog Viewer
	if ($ACSyslog){
		Install-Software -File "$SoftwareDir\syslogViewer-setup.exe" -Switches "/verysilent","/norestart" -Title "AudioCodes Syslog Viewer" -DontWait -ConfirmPath $ACSyslogGUID -WaitForProcessName "syslogViewer-setup"
		Stop-Process -Name "syslogViewer" -Force -ErrorAction SilentlyContinue
		New-Item -Path "HKCU:\Software\AudioCodes\syslogViewer" -Name "Syslog" -Force | Out-Null
		New-ItemProperty -Path "HKCU:\Software\AudioCodes\syslogViewer\Syslog" -Name "WriteLog" -Value "false" -Force | Out-Null
	}
	
	#Mozilla Firefox
	if ($Firefox){
		#https://wiki.mozilla.org/Installer:Command_Line_Arguments
		$firefoxConfig = "[Install]
						; InstallDirectoryName=Mozilla Firefox
						; InstallDirectoryPath=c:\firefox\
						QuickLaunchShortcut=false
						TaskbarShortcut=false
						DesktopShortcut=false
						; StartMenuShortcuts=false
						; StartMenuDirectoryName=Mozilla Firefox
						; MaintenanceService=false
						; OptionalExtensions=false"
		$firefoxConfig | Set-Content $UserTempDir\firefoxConfig.ini
		
		Install-Software -File "$SoftwareDir\firefox.exe" -Switches "/ini=$UserTempDir\firefoxConfig.ini" -Title "Mozilla Firefox" -ConfirmName $FirefoxName
		#Install-Software -File "$SoftwareDir\firefox.exe" -Switches "-ms" -Title "Mozilla Firefox" -ConfirmName $FirefoxName
	}
	
	#Google Chrome
	if ($Chrome){
		Install-Software -File "msiexec.exe" -Switches "/q","/I $SoftwareDir\chrome.msi" -Title "Google Chrome" -ConfirmName $ChromeName
	}
	
	if ($SQLMgmtStudio -or $Wireshark -or $ACSyslog -or $Firefox -or $Chrome){
		Write-Log
	}
	
	#Set next task
	End-Task -NextTask "WindowsUpdates" -Quiet
}



#Windows Updates
if ($Script:Task -eq "WindowsUpdates"){
	$StopWatch = [system.diagnostics.stopwatch]::startNew()
	
	Write-Log "Opting into Microsoft Updates"
	#https://morgansimonsen.com/2013/01/15/how-to-opt-in-to-microsoft-update-with-powershell/
	$mu = New-Object -ComObject Microsoft.Update.ServiceManager -Strict 
	$mu.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"") | Out-Null
	Write-Log
	
	if (!($SkipWindowsUpdates)){
		#Add WU Spectre/Meltdown AV compatibility registry entry if not present
		if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -ErrorAction SilentlyContinue)."cadca5fe-87d3-4b96-b7fb-a231484277cc" -ne 0){
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "QualityCompat" -Force | Out-Null
			New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -PropertyType DWORD -Value "0x00000000" -Force -ErrorAction SilentlyContinue | Out-Null
			New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "WUAVCOMPATADDED" -PropertyType DWORD -Value "0x00000001" -Force -ErrorAction SilentlyContinue | Out-Null
		}
		
		Invoke-WindowsUpdates
	}
	Write-Log
	
	if ($ServerType -match "FEEnt"){
		Write-Log "All reboots complete, enabling services."
		Get-CsWindowsService | Set-Service -StartupType Automatic
		Write-Log
	}
	
	#Set next task
	End-Task -NextTask "None" -Quiet
	
	Complete-Script
}




if ($Script:Task -eq "Logon"){
	#Pin items to taskbar
	$OSVersion = (Get-WMIObject -Class Win32_OperatingSystem).Caption
	if($OSVersion -notmatch "Server 2016"){
		Write-Log "Pinning taskbar items."
		#if ($Firefox){Pin-Taskbar -Item "C:\Program Files\Mozilla Firefox\firefox.exe" -Action Unpin}
		if ($Chrome){Pin-Taskbar -Item "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" -Action Unpin}
		if ($ServerType -match "FEStd|FEEnt|Dir"){Pin-Taskbar -Item "$InstallDrive\Program Files\Skype for Business Server 2015\Administrative Tools\Microsoft.Rtc.Management.TopologyBuilder.exe" -Action Pin}
		if ($ServerType -match $CsSrvTypes){Pin-Taskbar -Item "$InstallDrive\Program Files\Skype for Business Server 2015\Deployment\Deploy.exe" -Action Pin}
		if ($ServerType -match $CsSrvTypes){Pin-Taskbar -Item "$InstallDrive\Program Files\Skype for Business Server 2015\Deployment\Bootstrapper.exe" -Action Pin}
		if ($ServerType -match $CsSrvTypes){Pin-Taskbar -Item "$env:AllUsersProfile\Microsoft\Windows\Start Menu\Programs\Skype for Business Server 2015\Skype for Business Server Management Shell.lnk" -Action Pin}
		if ($ServerType -match "FEStd|FEEnt|Dir"){Pin-Taskbar -Item "C:\Program Files\Common Files\Skype for Business Server 2015\AdminUIHost.exe" -Action Pin}
		if ($ServerType -match "FEStd|FEEnt|Dir"){Pin-Taskbar -Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Active Directory PowerShell Snap-In.lnk" -Action Pin}
		if ($ServerType -match "FEStd|FEEnt|Dir"){Pin-Taskbar -Item "$env:systemroot\system32\dsa.msc" -Action Pin}
		Pin-Taskbar -Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Event Viewer.lnk" -Action Pin
		Pin-Taskbar -Item "$env:windir\system32\services.msc" -Action Pin
		Pin-Taskbar -Item "$env:windir\system32\certlm.msc" -Action Pin
		if ($ServerType -match $CsSrvTypes){Pin-Taskbar -Item "$InstallDrive\Program Files\Skype for Business Server 2015\Debugging Tools\ClsLogger.exe" -Action Pin}
		if ($ServerType -match $CsSrvTypes){Pin-Taskbar -Item "$InstallDrive\Program Files\Skype for Business Server 2015\Debugging Tools\Snooper.exe" -Action Pin}
		if ($ACSyslog){Pin-Taskbar -Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\AudioCodes\Syslog Viewer\Syslog Viewer.lnk" -Action Pin}
		if ($Wireshark){Pin-Taskbar -Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Wireshark.lnk" -Action Pin}
		if ($SQLMgmtStudio){Pin-Taskbar -Item "C:\Program Files (x86)\Microsoft SQL Server\130\Tools\Binn\ManagementStudio\Ssms.exe" -Action Pin}
		if ($ServerType -match "IISARR|FEStd|FEEnt|Dir|OOS|WAC"){Pin-Taskbar -Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\IIS Manager.lnk" -Action Pin}
		Write-Log
	}
	
	#Import device updates using Get-CsDeviceUpdates script
	if ($ServerType -match "FE"){
		if ($DeviceUpdates){
			if ($PrimaryServer){
				#$csPool = (Get-CsPool | Where-Object Computers -match $env:computerName).Fqdn
				$csPool = (Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)).Fqdn
				if (!(Get-CsDeviceUpdateRule | Where-Object Identity -match $csPool)){
					Write-Log "Importing device updates."
					Write-Log "Running Get-CsDeviceUpdates.ps1."
					Push-Location
					Set-Location "$ScriptsDir\Get-CsDeviceUpdates.v3.0"
					Invoke-Expression ".\Get-CsDeviceUpdates.ps1 -Pool $csPool -Polycom -Download -Import -Approve -Cleanup" | Out-Null
					Pop-Location
					Write-Log
				}
			}
		}
	}

	#Install root certificates from public CAs
	if ($ServerType -match $ExtSrvTypes){
		#https://stackoverflow.com/questions/41618766/powershell-invoke-webrequest-fails-with-ssl-tls-secure-channel
		[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
		"https://www.comodo.com","https://digicert.com","https://www.entrust.net","https://geotrust.com","https://www.globalsign.com","https://godaddy.com","https://www.symantec.com","https://thawte.com","https://www.wisekey.com" | ForEach-Object {Invoke-WebRequest -Uri $_ -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null}
	}
	
	#Unhide Server Manager
	if ($ShowServerManager){
		New-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -PropertyType DWORD -Value "0x0" -Force -ErrorAction SilentlyContinue | Out-Null
	}
	
	Write-Log "Completing deployment."
	return
}



#Post deploy To Dos (DNS, DHCP, OAuth)
if ($Script:Task -eq "PostInstallTasks"){
	#Output DNS commands
	$postTaskFile = "$env:Public\Desktop\PostInstallTasks.txt"
	if (Test-Path $postTaskFile){
		Remove-Item $postTaskFile -Force
	}
	
	"Commands to create DNS records:" | Out-File $postTaskFile -Append
	$csPool = Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
	
	$csPoolComputers = $csPool | Select-Object -ExpandProperty Computers
	$hostname = ($csPool.Fqdn).Split(".",2)[0]
	$domain = ($csPool.Fqdn).Split(".",2)[1]
	foreach ($computer in $csPoolComputers){
		"dnscmd . /RecordAdd "+$domain+" "+$hostname+" A "+(Resolve-DnsName $computer -Type A).IP4Address | Out-File $postTaskFile -Append
	}
	
	#Identify web servivces IPs based on FE server IP
	<# if (!($WebServicesIntIP)){
		if ($csPoolComputers.Count -eq 1){
			$WebServicesIntIP = (Resolve-DnsName $csPoolComputers -Type A).IP4Address
		}else{
			$WebServicesIntIP = (Resolve-DnsName $csPoolComputers[0] -Type A).IP4Address
		}
	} #>
	
	#Identify web services URLs
	$csWebServer = Get-CsService -WebServer -PoolFqdn $csPool.Fqdn
	#Generate DNS commands for web services URLs
	if ($csWebServer){
		if (($csWebServer).InternalFqdn){
			[string]$csWebServerInt = ($csWebServer).InternalFqdn
			$hostname = $csWebServerInt.Split(".",2)[0]
			$domain = $csWebServerInt.Split(".",2)[1]
			#"dnscmd . /RecordAdd "+$domain+" "+$hostname+" A "+$WebServicesIntIP | Out-File $postTaskFile -Append
			"dnscmd . /RecordAdd "+$domain+" "+$hostname+" A [WebServicesIntIP]" | Out-File $postTaskFile -Append
		}
		
		[string]$csWebServerExt = ($csWebServer).ExternalFqdn
		$hostname = $csWebServerExt.Split(".",2)[0]
		$domain = $csWebServerExt.Split(".",2)[1]
		#if ($WebServicesExtIP){
			#"dnscmd . /RecordAdd "+$domain+" "+$hostname+" A "+$WebServicesExtIP | Out-File $postTaskFile -Append
			"dnscmd . /RecordAdd "+$domain+" "+$hostname+" A [WebServicesExtIP]" | Out-File $postTaskFile -Append
		#}
	}
	
	#Generate DNS commands for simple URLs
	$simpleUrls = (Get-CsSimpleUrlConfiguration).SimpleUrl.ActiveUrl
	$simpleUrls = $simpleUrls -replace "https://",""
	$simpleUrls = $simpleUrls -replace "/(.+)?",""
	foreach ($simpleUrl in $simpleUrls){
		$hostname = $simpleUrl.Split(".",2)[0]
		$domain = $simpleUrl.Split(".",2)[1]
		#"dnscmd . /RecordAdd "+$domain+" "+$hostname+" A "+$WebServicesIntIP | Out-File $postTaskFile -Append
		"dnscmd . /RecordAdd "+$domain+" "+$hostname+" A [WebServicesIntIP]" | Out-File $postTaskFile -Append
	}
	
	#Generate DNS commands for lyncdiscover URLs
	$csSipDomains = (Get-CsSipDomain).Name
	foreach ($csSipDomain in $csSipDomains){
		#"dnscmd . /RecordAdd "+$csSipDomain+" lyncdiscoverinternal A "+$WebServicesIntIP | Out-File $postTaskFile -Append
		"dnscmd . /RecordAdd "+$csSipDomain+" lyncdiscoverinternal A [WebServicesIntIP]" | Out-File $postTaskFile -Append
	}
	
	#Generate DNS commands for WAC/OOS URLs
	$csWacPool = (Get-CsService -WacServer | Where-Object DependentServiceList -match $csPool.Fqdn).PoolFqdn
	if ($csWacPool){
		$csWacPool = $csWacPool -replace "https://",""
		$csWacPool = $csWacPool -replace "/(.+)",""
		$hostname = $csWacPool.Split(".",2)[0]
		$domain = $csWacPool.Split(".",2)[1]
		#"dnscmd . /RecordAdd "+$domain+" "+$hostname+" A "+$WACIP | Out-File $postTaskFile -Append
		"dnscmd . /RecordAdd "+$domain+" "+$hostname+" A [WACIP]" | Out-File $postTaskFile -Append
	}

	#Generate DNS commands for edge servers
	$csEdgePool = Get-CsService -EdgeServer | Where-Object Registrar -match $csPool.Fqdn
	if ($csEdgePool){
		$csEdgePoolComputers = Get-CsPool $csEdgePool.PoolFqdn | Select-Object -ExpandProperty Computers
		foreach ($computer in $csEdgePoolComputers){
			$csComputer = Get-CsTopology -LocalStore | Select-Object -ExpandProperty Machines | Where-Object Fqdn -match $computer
			$netInterface = $csComputer | Select-Object -ExpandProperty NetInterfaces | Where-Object InterfaceId -match "Internal"
			$hostname = $computer.Split(".",2)[0]
			$domain = $computer.Split(".",2)[1]
			$edgeHostname = ($csEdgePool.PoolFqdn).Split(".",2)[0]
			$csDomain = ($csEdgePool.PoolFqdn).Split(".",2)[1]
			"dnscmd . /RecordAdd "+$domain+" "+$hostname+" A "+$netInterface.IPAddress | Out-File $postTaskFile -Append
			if ($edgeHostname -ne $hostname){
				"dnscmd . /RecordAdd "+$csDomain+" "+$edgeHostname+" A "+$netInterface.IPAddress | Out-File $postTaskFile -Append
			}
		}
	}
	
	"`n" | Out-File $postTaskFile -Append
	"`n" | Out-File $postTaskFile -Append
	
	#Output DHCP commands
	$csPool = Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
	$sipServer = "-SipServer "+$csPool.Fqdn
	
	$csWebServer = Get-CsService -WebServer -PoolFqdn $csPool.Fqdn
	$csWebServerInt = $csWebServer.InternalFqdn
	$webServer = "-WebServer "+$csWebServerInt
	
	Push-Location
	Set-Location "C:\Program Files\Common Files\Skype for Business Server 2015"
	
	$expression = ".\DHCPUtil.exe "+$sipServer+" "+$webServer
	$out = Invoke-Expression $expression
	
	Pop-Location
	
$string = @"
Commands to create DHCP options:
$($out[18])


"@

	$string | Out-File $postTaskFile -Append
	
	#Configure OAuth and OWA Integration
	$adRoot = [ADSI]"LDAP://RootDSE"
	$adDN = $adRoot.Get("rootDomainNamingContext")
	$exchSchemaPath = [ADSI]"LDAP://CN=ms-Exch-Schema-Version-Pt,CN=Schema,CN=Configuration,$adDN"
	
	#Check Exchange version
	if ($exchSchemaPath.rangeUpper){
		[int]$exchSchemaVersion = $null
		[string]$string = $exchSchemaPath.rangeUpper
		[int32]::TryParse($string, [ref]$exchSchemaVersion) | Out-Null
	}else{
		$exchSchemaVersion = 0
	}
	$exchVersion = $SchemaHashExchange.Item($exchSchemaVersion)
	
	if ($exchVersion -match "2013|2016"){
		$csPool = Get-CsPool | Where-Object Computers -match ([System.Net.Dns]::GetHostByName((hostname)).HostName)
		$csWebServer = Get-CsService -WebServer -PoolFqdn $csPool.Fqdn
		$csSite = $csPool.Site -replace "Site:",""
		$exchAppPool = "autodiscover.$((Get-CsSipDomain | Where-Object IsDefault -eq $true).Name)"
		if ($csWebServer.InternalFqdn){
			$csWebServerInt = $csWebServer.InternalFqdn
		}else{
			$csWebServerInt = $csWebServer.PoolFqdn
		}
		
$string = @"
OAuth Configuration
On a Skype for Business Front End server run the following command:
Set-CsOAuthConfiguration -Identity global -ExchangeAutodiscoverUrl https://autodiscover.$((Get-CsSipDomain | Where-Object IsDefault -eq $true).Name)/autodiscover/autodiscover.svc

On an Exchange server run the following command:
`$ExScripts\Configure-EnterprisePartnerApplication.ps1 -AuthMetaDataUrl 'https://$csWebServerInt/metadata/json/1' -ApplicationType Lync

When complete, perform an iisreset on each CAS and MBX server when possible.

Once this has been completed, run the following on a Skype for Business Front End server:
New-CsPartnerApplication -Identity Exchange -ApplicationTrustLevel Full -MetadataUrl "https://autodiscover.$((Get-CsSipDomain | Where-Object IsDefault -eq $true).Name)/autodiscover/metadata/json/1"

When complete, perform an iisreset on each Skype for Business Front End server when possible.


Office Online Server Integration
On a Skype for Business Front End server run the following commands:
New-CsTrustedApplicationPool -Identity $exchAppPool -Registrar $($csPool.Fqdn) -Site $csSite -RequiresReplication `$false
New-CsTrustedApplication -ApplicationId OutlookWebApp -TrustedApplicationPoolFqdn $exchAppPool -Port 5199
Enable-CsTopology

On an Exchange server run the following commands:
Get-OwaVirtualDirectory | Set-OwaVirtualDirectory -InstantMessagingEnabled `$true -InstantMessagingType OCS
Get-ExchangeCertificate | Where-Object {`$_.Services -match "IIS"}

On each Exchange server add the following line to the Outlook Web App web.config after replacing the certificate thumbprint:
<add key="IMCertificateThumbprint" value="exchange_thumbprint_here"/> <add key="IMServerName" value="$($csPool.Fqdn)"/>

When complete, recycle the OWA app pool on each CAS and MBX server when possible:
C:\Windows\System32\Inetsrv\Appcmd.exe recycle apppool /apppool.name:"MSExchangeOWAAppPool"
"@
		
		$string | Out-File $postTaskFile -Append
	}
	
	Write-Log "See $postTaskFile for output." -OutTo "Screen"
}