# Set-CsNetworkInformation

### SYNOPSIS
This script uses CSV containing region, site, subnet, bandwidth and address information to populate the LIS database, create network regions, sites, and subnets, as well as create and apply bandwidth policies.

The LisSubnets, NetworkSites, LocationPolicies, and BandwidthPolicies operations may be run together or individually. Running one of these operations over an existing configuration may result in incorrect or lost configurations. It is recommended these be run first in a lab or in a pre-production environment.

This script requires the use of a specifically formatted CSV and does not create region links.

### PARAMETERS
```
CsvPath
  Path to a CSV file with the following specific column headers:
  Description, NetworkRegionID, CentralSite, NetworkSiteID, BandwidthPolicy, WANBandwidthInKbps, RealtimeClassInKbps, InteractiveClassInKbps, Subnet, MaskBits, CompanyName, Location, HouseNumber, HouseNumberSuffix, PreDirectional, StreetName, StreetSuffix, PostDirectional, City, State, PostalCode, Country
LisSubnets
  Populates and publishes the LIS database using the Subnet and address columns.
NetworkSites
  Creates network regions, sites, and subnets for each site. Region links must be created manually.
LocationPolicies
  Creates and assigns location policies for each site. Further configuration must be done manually.
CalculateBandwidthPolicies
  Calulcates and displays the maximum call counts for each site using the WANBandwidthInKbps column from the CSV as well as the AudioBWSessionLimit, VideoBWSessionLimit, AudioBandwidthPercentage, and VideoBandwidthPercentage parameters.
BandwidthPolicies
  Creates and assigns bandwidth policies for each site based on the BandwidthPolicy and WANBandwidthInKbps columns from the CSV as well as the AudioBWSessionLimit, VideoBWSessionLimit, AudioBandwidthPercentage, and VideoBandwidthPercentage parameters.
AudioBWSessionLimit
  Bandwidth limit of each audio session. The default is value is 110kbps, this differs from Microsoft's default for the AudioBWSessionLimit bandwidth policy parameter which is 175kbps and allows for G.722 Stereo used by an LRS. This is set to allow for the maximum quality.

  Peer to peer calls - Lync 2013 CU4+ and SfB clients prefer SILK Super Wideband which consumes ~80kbps. Clients prior to Lync 2013 CU4 prefer RTAudio Wideband which consumes ~70kbps. RTAudio Narrowband and SILK Narrowband are fallback codecs, and also used in calls to the PSTN, that consume ~50 and ~60kbps respectively. Polycom VVX IP phones prefer G.722 which consumes ~105kbps.

  Conference calls, clients prefer G.722 which consumes ~105kbps. Siren is the fallback codec which consumes ~60kbps. Siren will be used in two scenarios, if the bandwidth pollicy is set too low for G.722 to be used or if a OCS 2007 or 2007 R2 client connects to the conferencing service.

  In Conference calls, a Lync Room System (LRS) prefer G.722 Stereo which consumes ~170kbps.

  The gateway leg of a PSTN call or a media bypass call uses G.711 consuming ~98kbps.

  These bandwidth requirements include Ethernet, IP, UDP, RTP, SRTP, and RTCP overhead. Additional information is available here: https://technet.microsoft.com/en-us/library/Gg398529%28v=ocs.16%29.aspx

  If this value exceeds the calculated AudioBWLimit this value will be set to 0 disabling voice calls across the connection.
VideoBWSessionLimit
  Bandwidth limit of each video session. The default is 700kbps which is Microsoft's default for the VideoBWSessionLimit bandwidth policy parameter. This value allows for video streams up to, but not including 1280x720 (16:9) per the network bandwidth requirements described here: https://technet.microsoft.com/en-us/library/jj688118%28v=ocs.15%29.aspx

  If this value exceeds the calculated VideoBWLimit this value will be set to 0 disabling video calls across the connection.
AudioBandwidthPercentage
  Percentage of WANBandwidthInKbps to calculate AudioBWLimit bandwidth policy parameter. The default is 18% based on Cisco QoS best practices (Of no more than 33% overall connection bandwidth allocation to RTC traffic).
VideoBandwidthPercentage
  Percentage of WANBandwidthInKbps to calculate VideoBWLimit bandwidth policy parameter. The default is 15% based on Cisco QoS best practices (Of no more than 33% overall connection bandwidth allocation to RTC traffic).
EnableCAC
  Enables Call Admission Control globally. CAC must be configured in topology.
```

### EXAMPLE
```
Set-CsNetworkInformation -CsvPath C:\Customer-Networks.csv -LisSubnets -NetworkSites -BandwidthPolicies
```
This command will use Customer-Networks.csv to populate the LIS database, create network regions, sites, and subnets, and create and apply bandwidth policies to each site.
    
### EXAMPLE
```
Set-CsNetworkInformation -CsvPath C:\Customer-Networks.csv -CalculateBandwidthPolicies
```
This command will calculate and display maximum call counts for each site using the bandwidth provided in the CSV and the audio and video session limits.
