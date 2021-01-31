# Install-CsServer

This script automates deployment of Skype for Business Server roles and adjunct components including Office Web Apps/Office Online Server and IIS Application Request Routing.

### Prerequisites per ServerType
#### FEStd, FEEnt, Dir, PChat, Med:
* SFB media mounted via hypervisor or MediaPath defined with to path of setup.exe or .iso/.img.
  * **Note: Mounting ISO within Windows is not supported as it is not persistant across reboots.**
* SourcePath should be defined with path to Windows sources folder.

#### Edge:
* SFB media mounted via hypervisor or MediaPath defined with to path of setup.exe or .iso/.img.
  * **Note: Mounting ISO within Windows is not supported as it is not persistant across reboots.**
* SourcePath should be defined with path to Windows sources folder.
* CertOrg, CertCity, CertState, CertCountry, and CertOU must be specified for External certificate request.
* PrimaryDNSSuffix must be defined.

#### WAC, OOS:
* WAC/OOS media mounted via hypervisor or MediaPath defined with to path of setup.exe or .iso/.img.
  * **Note: Mounting ISO within Windows is not supported as it is not persistant across reboots.**
* Certificate created and imported with chain.
* FriendlyName may be defined with the friendly name.
* WACExternalUrl should be defined. Otherwise defaults to https://<wac|oos>.addomain.com.
* WACPrimaryServer must be defined if this is not the first WAC/OOS server in the farm.

#### IISARR:
* Certificate created and imported with chain.
* FriendlyName may be defined with the friendly name.
* WebServicesIntFQDN must be defined.
* WebServicesExtFQDN must be defined.
* PrimaryDNSSuffix must be defined.
* Domains must be defined with list of SIP domains.


### Tasks
#### PrereqCheck
Runs prerequisite checks and reports. Applicable to all ServerType.

#### PrereqDownload
Downloads prerequisite software and files. Applicable to all ServerType.

#### PrereqInstall
Installs prerequisite software, roles/features, and additional software (eg. Wireshark). Applicable to all ServerType.

#### CSCoreInstall
Installs Skype for Business core components, Admin Tools, and SQL Express. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge

#### CSADPrep
Active Directory preparation for Schema, Forest, and Domain. Adds current user to CS and RTC groups. Requires PrimaryServer switch and Domain Admins, Enterprise Admins, and Schema Admins membership. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med

#### CSComponentInstall
Creates file share for Standard edition servers, exports topology file for Edge servers/imports topology file on Edge servers, installs local management store, runs bootstrapper to install Skype for Business components, and installs SQL databases if not already. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge

#### CSCertificates
Performs online or offline certificate requests, assigns to services. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge

#### CSUpdates
Installs Debugging Tools and Resource Kit. Applies Skype for Business Server updates and installs database updates. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge

#### CSConfigure
On Edge servers, verifies IP addresses gainst the topology, renames the interfaces INTERNAL and EXTERNAL, creates static routes for RFC1918 address ranges, disables NetBIOS and dynamic DNS registration. Deploys KHIs to all roles. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge

#### CSServices
Starts Skype for Business Server services. Enterprise Pools must be started manually. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge

#### CSCustomize
Deploy monitoring reports, configure ports and QoS policies, misc. policies, dial plan, ABS normalization rules, disable IE ESC, add internal web services URLs to trusted sites. Applicable to ServerType: FEStd, FEEnt, Dir, PChat, Med, Edge

#### OWASInstall
Installs OWA/OOS software and patches. Applicable to ServerType: WAC, OOS

#### OWASConfigure
Create OfficeWebAppsFarm. Requires certificate to already be imported and trusted. Applicable to ServerType: WAC, OOS

#### ARRConfigure
Configures IIS ARR rules. Requires certificate to already be imported and trusted. Applicable to ServerType: IISARR

#### Applications
Installs third party applications. Applicable to all ServerType.

#### Logon
Customizes user profile with pinned taskbar items. Applicable to all ServerType.

#### PostInstallTasks
**Currently under development**
Creates PostInstallTasks.txt on the desktop with commands for Microsoft DNS server record creation, DHCPUtil output, OAuth configuration, and OWA integration configuration.
