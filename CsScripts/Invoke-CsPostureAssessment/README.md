# Invoke-CsPostureAssessment

## Run on a Domain Controller or Lync/Skype4B server with RSAT-ADDS in PS
```powershell
$CollectPath = "$env:userprofile\Desktop\AssessmentCollection"
if(!(Test-Path $CollectPath)){New-Item $CollectPath -ItemType directory | Out-Null}

###  Print AD forest properties
Get-ADForest | select Name,RootDomain,ForestMode,DomainNamingMaster,SchemaMaster,@{name='Sites';expression={$_.Sites -join ','}},@{name='GlobalCatalogs';expression={$_.GlobalCatalogs -join ','}},@{name='UPNSuffixes';expression={$_.UPNSuffixes -join ','}} | Out-File $CollectPath\ADInfo.txt

###  Print AD domain properties
Get-ADDomain | select Name,Forest,NetBIOSName,ParentDomain,@{name='ChildDomains';expression={$_.ChildDomains -join ','}},DomainMode,PDCEmulator,RIDMaster,InfrastructureMaster,@{name='ReadOnlyReplicaDirectoryServers';expression={$_.ReadOnlyReplicaDirectoryServers -join ','}} | Out-File $CollectPath\ADInfo.txt -Append

###  Print list of domain controllers in domain
Get-ADDomainController -Filter * | select HostName,Site,Enabled,IPv4Address,OperatingSystem,OperatingSystemVersion,@{name='OperationMasterRoles';expression={$_.OperationMasterRoles -join ','}} | Out-File $CollectPath\ADInfo.txt -Append

###  Print list of subnets
Get-ADReplicationSubnet -Filter * | select Name,Location,Site | Out-File $CollectPath\ADInfo.txt -Append

###  Test if RTC Service object exists in System container
$RTCDN = "AD:\CN=RTC Service,CN=Microsoft,CN=System," + (Get-ADDomain).DistinguishedName
$RTCDN | Out-File $CollectPath\ADInfo.txt -Append
Test-Path -Path $RTCDN | Out-File $CollectPath\ADInfo.txt -Append

###  Test if RTC Service object exists in Configuration container
$RTCDN = "AD:\CN=RTC Service,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName
$RTCDN | Out-File $CollectPath\ADInfo.txt -Append
Test-Path -Path $RTCDN | Out-File $CollectPath\ADInfo.txt -Append

###  Print CA details and algorithms
certutil -TCAInfo | Out-File $CollectPath\CAInfo.txt
certutil -TCAInfo | where {$_ -match "Machine Name: (.*)"} | foreach {certutil -config $matches[1] -getreg ca\csp\CNGHashAlgorithm;certutil -config $matches[1] -getreg ca\csp\CNGPublicKeyAlgorithm;certutil -config $matches[1] -getreg ca\CRLPublicationURLs} | Out-File $CollectPath\CAInfo.txt -Append

###  Print users where SIP address and SMTP address do not match
Get-CsAdUser | Where-Object {($_.WindowsEmailAddress -and $_.SipAddress) -and ($_.WindowsEmailAddress -ne ($_.SipAddress -replace "sip:",""))} | Select-Object DisplayName,WindowsEmailAddress,SIPAddress

###  Print list of phone numbers for format check; Must review on screen, not saved to file
Get-ADUser -Filter * -Properties OfficePhone | where OfficePhone -ne $null | fw OfficePhone -AutoSize
```



## Run on one Lync/Skype4B server in PS
```powershell
$CollectPath = "$env:userprofile\Desktop\AssessmentCollection"
if(!(Test-Path $CollectPath)){New-Item $CollectPath -ItemType directory | Out-Null}

###  Gather user counts
"Total users (EV/RCC/Total): " + (Get-CsUser | where {$_.EnterpriseVoiceEnabled -eq $true}).Count + "/" + (Get-CsUser | where {$_.RemoteCallControlTelephonyEnabled -eq $true}).Count + "/" + (Get-CsUser).Count | Out-File $CollectPath\CsOverview.txt
foreach ($registrar in Get-CsService -Registrar){$registrar.PoolFqdn + " (EV/RCC/Total): " + (Get-CsUser | where {$_.RegistrarPool -match $registrar.PoolFqdn -and $_.EnterpriseVoiceEnabled -eq $true}).Count + "/" + (Get-CsUser | where {$_.RegistrarPool -match $registrar.PoolFqdn -and $_.RemoteCallControlTelephonyEnabled -eq $true}).Count + "/" + (Get-CsUser | where {$_.RegistrarPool -match $registrar.PoolFqdn}).Count | Out-File $CollectPath\CsOverview.txt -Append}

###  Gather media information
Get-CsService -ConferencingServer | select Identity,AudioPort*,VideoPort*,AppSharingPort*,SiteId | Out-File $CollectPath\CsMediaConfig.txt
Get-CsService -ApplicationServer | select Identity,AudioPort*,VideoPort*,AppSharingPort*,SiteId | Out-File $CollectPath\CsMediaConfig.txt -Append
Get-CsConferencingConfiguration | select Identity,Client* | Out-File $CollectPath\CsMediaConfig.txt -Append
Get-CsMediaConfiguration | Out-File $CollectPath\CsMediaConfig.txt -Append
Get-CsUCPhoneConfiguration | Out-File $CollectPath\CsMediaConfig.txt -Append

###  Gather device updates
Get-CsDeviceUpdateRule | ft DeviceType,Brand,Model,*Version -AutoSize | Out-file $CollectPath\CsDeviceUpdates.txt

###  Gather conferencing policies
Get-CsConferencingPolicy | Export-Clixml $CollectPath\CsConferencingPolicy.xml

###  Gather PIN policies
Get-CsPinPolicy | Out-File $CollectPath\CsPINPolicy.txt

###  Gather client policies
Get-CsClientPolicy | Export-Clixml $CollectPath\CsClientPolicy.xml

###  Gather location policies
Get-CsLocationPolicy | Export-Clixml $CollectPath\CsLocationPolicy.xml

###  Gather mobility policies
Get-CsMobilityPolicy | Export-Clixml $CollectPath\CsMobilityPolicy.xml

###  Gather access edge configuration
Get-CsAccessEdgeConfiguration | Export-Clixml $CollectPath\CsAccessEdgeConfiguration.xml

###  Gather external access policies
Get-CsExternalAccessPolicy | Export-Clixml $CollectPath\CsExternalAccessPolicy.xml

###  Gather allowed SIP domains
Get-CsAllowedDomain | select Domain,ProxyFqdn,Comment | Export-Csv $CollectPath\CsAllowedDomains.csv -NoTypeInformation

###  Gather blocked SIP domains
Get-CsBlockedDomain | select Domain,ProxyFqdn,Comment | Export-Csv $CollectPath\CsBlockedDomains.csv -NoTypeInformation

###  Gather database versions
 Test for server version
 Test-CsDatabase

###  Gather network information
Get-CsNetworkRegion | select NetworkRegionID,CentralSite,Description,@{name='BWAlternatePaths';expression={$_.BWAlternatePaths -join ','}} | Export-Csv $CollectPath\CsNetworkRegions.csv -NoTypeInformation
Get-CsNetworkSite | select NetworkSiteID,NetworkRegionID,Description,BWPolicyProfileID,LocationPolicy,EnableLocationBasedRouting,VoiceRoutingPolicy | Export-Csv $CollectPath\CsNetworkSites.csv -NoTypeInformation
Get-CsNetworkSubnet | select SubnetID,MaskBits,NetworkSiteID,Description | Export-Csv $CollectPath\CsNetworkSubnets.csv -NoTypeInformation
Get-CsNetworkBandwidthPolicyProfile | select BWPolicyProfileID,Description,@{name='BWPolicy';expression={$_.BWPolicy -join ','}} | Export-Csv $CollectPath\CsNetworkBandwidthPolicies.csv -NoTypeInformation

###  Gather CLS information
Get-CsClsConfiguration | Out-File $CollectPath\CsOverview.txt -Append
Show-CsClsLogging | fl | Out-File $CollectPath\CsOverview.txt -Append
```
  
  
## Run on each Lync\Skype4B component server in PS (FE, Edge, Med, PC, Dir, Backend, OWAS/OOS, UM)
```powershell
$CollectPath = "$env:userprofile\Desktop\AssessmentCollection"
if(!(Test-Path $CollectPath)){New-Item $CollectPath -ItemType directory | Out-Null}

###  Download Lync 2013 BPA
 Start-BitsTransfer "http://download.microsoft.com/download/2/E/4/2E4CF74C-B323-4912-9ADD-C684E6346A6F/rtcbpa.msi" $CollectPath

###  Gather systeminfo output
systeminfo | Out-File $CollectPath\$env:computername.txt

###  Gather CPU information
Get-WmiObject Win32_Processor | select Name,SocketDesignation,NumberOfCores,NumberOfLogicalProcessors,CurrentClockSpeed,MaxClockSpeed | Out-File $CollectPath\$env:computername.txt -Append

###  Gather power plan
(Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "IsActive='$true'").ElementName  | Out-File $CollectPath\$env:computername.txt -Append

###  Get firewall state
(netsh advfirewall show allprofiles) -match "Profile|State" | Out-File $CollectPath\$env:computername.txt -Append

###  Gather hard drive information
Get-WmiObject Win32_Volume -Filter 'DriveType = 3' | where {$_.DriveLetter -ne $null} | select DriveLetter,Label,@{l='CapacityGB';e={"{0:N2}" -f ($_.Capacity/1GB)}},@{l='FreeSpaceGB';e={"{0:N2}" -f ($_.FreeSpace/1GB)}},@{l='FreeSpacePercent';e={"{0:N2}" -f (($_.FreeSpace/$_.Capacity)*100)}} | Out-File $CollectPath\$env:computername.txt -Append

###  Gather current Lync/SfB versions
(Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" | foreach {Get-ItemProperty $_.pspath} | where {($_.DisplayName -imatch "Microsoft Lync Server") -or ($_.DisplayName -imatch "Microsoft Office Web Apps Server 2013") -or ($_.DisplayName -imatch "Skype for Business Server")}) | ft DisplayName,DisplayVersion -AutoSize | Out-File $CollectPath\$env:computername.txt -Append

###  Get Lync/SfB install path
(Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" | foreach {Get-ItemProperty $_.pspath} | where {$_.DisplayName -imatch ", Core Components"}) | fl InstallLocation | Out-File $CollectPath\$env:computername.txt -Append

###  Gather QoS policies
if (Get-ChildItem "HKLM:\Software\Policies\Microsoft\Windows\QoS"){Get-ChildItem "HKLM:\Software\Policies\Microsoft\Windows\QoS" | Out-File $CollectPath\$env:computername.txt -Append}else{"No QoS policies" | Out-File $CollectPath\$env:computername.txt -Append}

###  Gather Certificates
Get-ChildItem Cert:\LocalMachine\My | select Subject,DnsNameList,Issuer,FriendlyName,NotBefore,NotAfter,EnhancedKeyUsageList,@{l='SignatureAlgorithm';e={$_.SignatureAlgorithm.FriendlyName}},HasPrivateKey,@{l='PrivateKeySize';e={$_.PrivateKey.KeySize}},@{l='KeyExchangeAlgorithm';e={$_.PrivateKey.KeyExchangeAlgorithm}},Thumbprint | Out-File $CollectPath\$env:computername.txt -Append
Get-CsCertificate | fl | Out-File $CollectPath\$env:computername.txt -Append

### Get ipconfig
ipconfig /all | Out-File $CollectPath\$env:computername.txt -Append

###  Get routes
route print | Out-File $CollectPath\$env:computername.txt -Append

###  Get hosts file
Get-Content C:\Windows\system32\drivers\etc\hosts | Out-File $CollectPath\$env:computername.txt -Append

###  Export event viewer Lync Server events
function GetMilliseconds ($date){
    $ts = New-TimeSpan -Start $date -End (Get-Date)
    [math]::Round($ts.TotalMilliseconds)
}
$startDate = GetMilliseconds((Get-Date).addDays(-2))
$endDate = GetMilliseconds(Get-Date)
wevtutil epl "Lync Server" $CollectPath\$env:computername.evtx /q:"*[System[TimeCreated[timediff(@SystemTime) >= $endDate] and TimeCreated[timediff(@SystemTime) <= $startDate]]]"
```
##  Manually save copy of topology

##  Manually run BPA and collect output

##  Manually collect KHI files after 24 hours
