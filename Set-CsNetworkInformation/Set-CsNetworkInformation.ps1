# Title: Configure-CsNetworkInformation
# Version: 1.4
# Author: Andy Giesen
# Date: 1/19/15
# 
# Change Log
# 3/8/16
# -Added options for realtime and interactive class of service (CoS) bandwidths on provider networks. Overrides WAN bandwidth derived calculations.
#
# 7/22/15
# -Added automatic sanitization of network region, sites, and subnet names
# -Added Get-Help information
# -Modified default value for AudioBWSessionLimit from 175 to 110 to reflect common audio codec usage and restricting G.722 Stereo used by LRS
# -Error handling improvements
# 
# 1/30/15
# -Added CalculateBandwidthPolicies parameter
# -Added BandwidthPolicies paramter
# -Added preset values for AudioBWSessionLimit, VideoBWSessionLimit, AudioBandwidthPercentage, and VideoBandwidthPercentage
# 

<#
    .SYNOPSIS
      This script uses CSV containing region, site, subnet, bandwidth and address information to populate the LIS database, create network regions, sites, and subnets, as well as create and apply bandwidth policies.
	  
	  The LisSubnets, NetworkSites, LocationPolicies, and BandwidthPolicies operations may be run together or individually. Running one of these operations over an existing configuration may result in incorrect or lost configurations. It is recommended these be run first in a lab or in a pre-production environment.
	  
	  This script requires the use of a specifically formatted CSV and does not create region links.
	.PARAMETER CsvPath
	  Path to a CSV file with the following specific column headers:
	  Description, NetworkRegionID, CentralSite, NetworkSiteID, BandwidthPolicy, WANBandwidthInKbps, RealtimeClassInKbps, InteractiveClassInKbps, Subnet, MaskBits, CompanyName, Location, HouseNumber, HouseNumberSuffix, PreDirectional, StreetName, StreetSuffix, PostDirectional, City, State, PostalCode, Country
    .PARAMETER LisSubnets
	  Populates and publishes the LIS database using the Subnet and address columns.
	.PARAMETER NetworkSites
	  Creates network regions, sites, and subnets for each site. Region links must be created manually.
	.PARAMETER LocationPolicies
	  Creates and assigns location policies for each site. Further configuration must be done manually.
	.PARAMETER CalculateBandwidthPolicies
	  Calulcates and displays the maximum call counts for each site using the WANBandwidthInKbps column from the CSV as well as the AudioBWSessionLimit, VideoBWSessionLimit, AudioBandwidthPercentage, and VideoBandwidthPercentage parameters.
	.PARAMETER BandwidthPolicies
	  Creates and assigns bandwidth policies for each site based on the BandwidthPolicy and WANBandwidthInKbps columns from the CSV as well as the AudioBWSessionLimit, VideoBWSessionLimit, AudioBandwidthPercentage, and VideoBandwidthPercentage parameters.
	.PARAMETER AudioBWSessionLimit
	  Bandwidth limit of each audio session. The default is value is 110kbps, this differs from Microsoft's default for the AudioBWSessionLimit bandwidth policy parameter which is 175kbps and allows for G.722 Stereo used by an LRS. This is set to allow for the maximum quality.
	  
	  Peer to peer calls - Lync 2013 CU4+ and SfB clients prefer SILK Super Wideband which consumes ~80kbps. Clients prior to Lync 2013 CU4 prefer RTAudio Wideband which consumes ~70kbps. RTAudio Narrowband and SILK Narrowband are fallback codecs, and also used in calls to the PSTN, that consume ~50 and ~60kbps respectively. Polycom VVX IP phones prefer G.722 which consumes ~105kbps.
	  
	  Conference calls, clients prefer G.722 which consumes ~105kbps. Siren is the fallback codec which consumes ~60kbps. Siren will be used in two scenarios, if the bandwidth pollicy is set too low for G.722 to be used or if a OCS 2007 or 2007 R2 client connects to the conferencing service.
	  
	  In Conference calls, a Lync Room System (LRS) prefer G.722 Stereo which consumes ~170kbps.
	  
	  The gateway leg of a PSTN call or a media bypass call uses G.711 consuming ~98kbps.
	  
	  These bandwidth requirements include Ethernet, IP, UDP, RTP, SRTP, and RTCP overhead. Additional information is available here: https://technet.microsoft.com/en-us/library/Gg398529%28v=ocs.16%29.aspx
	  
	  If this value exceeds the calculated AudioBWLimit this value will be set to 0 disabling voice calls across the connection.
	.PARAMETER VideoBWSessionLimit
	  Bandwidth limit of each video session. The default is 700kbps which is Microsoft's default for the VideoBWSessionLimit bandwidth policy parameter. This value allows for video streams up to, but not including 1280x720 (16:9) per the network bandwidth requirements described here: https://technet.microsoft.com/en-us/library/jj688118%28v=ocs.15%29.aspx
	  
	  If this value exceeds the calculated VideoBWLimit this value will be set to 0 disabling video calls across the connection.
	.PARAMETER AudioBandwidthPercentage
	  Percentage of WANBandwidthInKbps to calculate AudioBWLimit bandwidth policy parameter. The default is 18% based on Cisco QoS best practices (Of no more than 33% overall connection bandwidth allocation to RTC traffic).
	.PARAMETER VideoBandwidthPercentage
	  Percentage of WANBandwidthInKbps to calculate VideoBWLimit bandwidth policy parameter. The default is 15% based on Cisco QoS best practices (Of no more than 33% overall connection bandwidth allocation to RTC traffic).
	.PARAMETER EnableCAC
	  Enables Call Admission Control globally. CAC must be configured in topology.
	.EXAMPLE
      Configure-CsNetworkInformation -CsvPath C:\Customer-Networks.csv -LisSubnets -NetworkSites -BandwidthPolicies
	  This command will use Customer-Networks.csv to populate the LIS database, create network regions, sites, and subnets, and create and apply bandwidth policies to each site.
	.EXAMPLE
	  Configure-CsNetworkInformation -CsvPath C:\Customer-Networks.csv -CalculateBandwidthPolicies
	  This command will calculate and display maximum call counts for each site using the bandwidth provided in the CSV and the audio and video session limits.
#>

[CmdLetBinding(DefaultParameterSetName="None")]
param(
	# path of CSV with network sites or LIS
	[Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[ValidateNotNullOrEmpty()]
	[string]$CsvPath,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[switch]$LisSubnets,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[switch]$NetworkSites,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[switch]$LocationPolicies,
	[Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='CalculateBandwidthPolicies')]
	[switch]$CalculateBandwidthPolicies,
	[Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='BandwidthPolicies')]
	[switch]$BandwidthPolicies,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='BandwidthPolicies')]
	[Parameter(ParameterSetName='CalculateBandwidthPolicies')]
	[ValidateRange(45,175)]
	[int]$AudioBWSessionLimit=110,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='BandwidthPolicies')]
	[Parameter(ParameterSetName='CalculateBandwidthPolicies')]
	[ValidateNotNullOrEmpty()]
	[int]$VideoBWSessionLimit=700,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='BandwidthPolicies')]
	[Parameter(ParameterSetName='CalculateBandwidthPolicies')]
	[ValidateNotNullOrEmpty()]
	[decimal]$AudioBandwidthPercentage=0.18,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='BandwidthPolicies')]
	[Parameter(ParameterSetName='CalculateBandwidthPolicies')]
	[ValidateNotNullOrEmpty()]
	[decimal]$VideoBandwidthPercentage=0.15,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='BandwidthPolicies')]
	[switch]$EnableCAC
)

function SanitizeString($string){
	$pattern = '[^a-zA-Z0-9._ ]'
	return $string -Replace $pattern,' '
}

if (Test-Path $CsvPath){
	$Locations = Import-Csv -Path $CsvPath
}else{
	Write-Host
	Write-Host "CsvPath is not valid. Quiting." -ForgroundColor Red
	Write-Host
	break;
}

if ($LisSubnets.isPresent){
	foreach ($Location in $Locations){
		Set-CsLisSubnet -Subnet $Location.Subnet -Description $Location.Description -CompanyName $Location.CompanyName -Location $Location.Location -HouseNumber $Location.HouseNumber -HouseNumberSuffix $Location.HouseNumberSuffix -PreDirectional $Location.PreDirectional -StreetName $Location.StreetName -StreetSuffix $Location.StreetSuffix -PostDirectional $Location.PostDirectional -City $Location.City -State $Location.State -PostalCode $Location.PostalCode -Country $Location.Country | Out-Null
		Write-Host "Creating subnet" $Location.Subnet
	}
	
	Write-Host
	Write-Warning "Sleeping script for 30 seconds to allow LIS entries to instantiate."
	Start-Sleep 30
	Publish-CsLisConfiguration
	Write-Host "Publishing LIS configuration."
	Write-Host
}

if ($NetworkSites.isPresent){
	foreach ($Location in $Locations){
		$Location.CentralSite = SanitizeString($Location.CentralSite)
		$Location.NetworkRegionID = SanitizeString($Location.NetworkRegionID)
		
		if (!(Get-CsNetworkRegion $Location.NetworkRegionID -ErrorAction SilentlyContinue)){
			New-CsNetworkRegion -Identity $Location.NetworkRegionID -Description "" -CentralSite $Location.CentralSite | Out-Null
			Write-Host "Creating region" $Location.NetworkRegionID
		}
	}

	Write-Host
	Write-Warning "Sleeping script for 15 seconds to allow network regions to instantiate."
	Start-Sleep 15
	Write-Host

	foreach ($Location in $Locations){
		$Location.NetworkRegionID = SanitizeString($Location.NetworkRegionID)
		$Location.NetworkSiteID = SanitizeString($Location.NetworkSiteID)
		
		if (!(Get-CsNetworkSite $Location.NetworkSiteID -ErrorAction SilentlyContinue)){
			New-CsNetworkSite -Identity $Location.NetworkSiteID -NetworkRegionID $Location.NetworkRegionID | Out-Null
			Write-Host "Creating site" $Location.NetworkSiteID "for region" $Location.NetworkRegionID
		}
	}

	Write-Host
	Write-Warning "Sleeping script for 15 seconds to allow network sites to instantiate."
	Start-Sleep 15
	Write-Host

	foreach ($Location in $Locations){
		$Location.NetworkSiteID = SanitizeString($Location.NetworkSiteID)
		$Location.Subnet = SanitizeString($Location.Subnet)
		
		if (!(Get-CsNetworkSubnet $Location.Subnet -ErrorAction SilentlyContinue)){
			New-CsNetworkSubnet -Identity $Location.Subnet -Description $Location.Description -MaskBits $Location.MaskBits -NetworkSiteID $Location.NetworkSiteID | Out-Null
			Write-Host "Creating subnet" $Location.Subnet "for site" $Location.NetworkSiteID
		}
	}
}

if ($LocationPolicies.isPresent){
	foreach ($Location in $Locations){
		$Location.NetworkSiteID = SanitizeString($Location.NetworkSiteID)
		
		if (!(Get-CsLocationPolicy $Location.NetworkSiteID -ErrorAction SilentlyContinue)){
			New-CsLocationPolicy $Location.NetworkSiteID | Out-Null
			
			if (!(Get-CsNetworkSite $Location.NetworkSiteID -ErrorAction SilentlyContinue)){
				Set-CsNetworkSite $Location.NetworkSiteID -LocationPolicy $Location.NetworkSiteID | Out-Null
			}
			
			Write-Host "Creating location policy for" $Location.NetworkSiteID
		}
	}
}

if ($BandwidthPolicies.isPresent){
	foreach ($Location in $Locations){
		$Location.NetworkSiteID = SanitizeString($Location.NetworkSiteID)
		
		if ($Location.RealtimeClassInKpbs -gt 0){
			[int]$AudioBWLimit = $Location.RealtimeClassInKpbs
		}else{
			[int]$AudioBWLimit = ([int]$Location.WANBandwidthInKbps * $AudioBandwidthPercentage)
		}
		if ($Location.InteractiveClassInKbps -gt 0){
			[int]$VideoBWLimit = $Location.InteractiveClassInKbps
		}else{
			[int]$VideoBWLimit = ([int]$Location.WANBandwidthInKbps * $VideoBandwidthPercentage)
		}
		
		if ($AudioBWLimit -lt $AudioBWSessionLimit){$AudioBWLimit = 0}
		if ($VideoBWLimit -lt $VideoBWSessionLimit){$VideoBWLimit = 0}
		
		if (Get-CsNetworkSite $Location.NetworkSiteID -ErrorAction SilentlyContinue){
			if (!(Get-CsNetworkBandwidthPolicyProfile $Location.BandwidthPolicy -ErrorAction SilentlyContinue)){
				New-CsNetworkBandwidthPolicyProfile $Location.BandwidthPolicy | Out-Null
				Set-CsNetworkBandwidthPolicyProfile $Location.BandwidthPolicy -AudioBWLimit $AudioBWLimit -AudioBWSessionLimit $AudioBWSessionLimit -VideoBWLimit $VideoBWLimit -VideoBWSessionLimit $VideoBWSessionLimit | Out-Null				
				Write-Host "Creating bandwidth policy:" $Location.BandwidthPolicy
			}
			
			Set-CsNetworkSite $Location.NetworkSiteID -BWPolicyProfileID $Location.BandwidthPolicy
			Write-Host "Assigning bandwidth policy for" $Location.NetworkSiteID
		}
	}
}

if ($CalculateBandwidthPolicies.isPresent){
	$Table = New-Object system.Data.DataTable "Calculated Bandwidth Policies"

	$col1 = New-Object system.Data.DataColumn NetworkSiteID,([string])
	$col2 = New-Object system.Data.DataColumn AudioCalls,([string])
	$col3 = New-Object system.Data.DataColumn VideoCalls,([string])
	$Table.Columns.Add($col1)
	$Table.Columns.Add($col2)
	$Table.Columns.Add($col3)

	foreach ($Location in $Locations){
		if ($Table.Rows -contains $Location.NetworkSiteID){
			Write-Host "Duplicate"
			continue;
		}

		if ($Location.WANBandwidthInKbps -gt 0){
			if ($Location.RealtimeClassInKpbs -gt 0){
				$AudioCalls = $Location.RealtimeClassInKpbs / $AudioBWSessionLimit
			}else{
				$AudioCalls = ([int]$Location.WANBandwidthInKbps * $AudioBandwidthPercentage) / $AudioBWSessionLimit
			}
			if ($Location.InteractiveClassInKbps -gt 0){
				$VideoCalls = $Location.InteractiveClassInKbps / $VideoBWSessionLimit
			}else{
				$VideoCalls = ([int]$Location.WANBandwidthInKbps * $VideoBandwidthPercentage) / $VideoBWSessionLimit
			}
			
			$row = $Table.NewRow()
			$row.NetworkSiteID = $Location.NetworkSiteID
			$row.AudioCalls = [math]::floor($AudioCalls)
			$row.VideoCalls = [math]::floor($VideoCalls)
			$Table.Rows.Add($row)

		}
	}
	$Table | ft -AutoSize
}

if ($EnableCAC.isPresent){
	Set-CsNetworkConfiguration -EnableBandwidthPolicyCheck $true
}
