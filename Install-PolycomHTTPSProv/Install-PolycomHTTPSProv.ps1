param (
	[string]$ProvUrl = $hostname,
	[string]$HttpPath = "C:\inetpub\wwwroot",
	[string]$HttpsPath = "C:\inetpub\wwwhttps",
	[string]$HttpsSiteName = "HTTPS Web Site",
	[int]$HttpsPort = 443,
	[ValidateSet("Digest", "Certificate")]
	[string]$AuthType = "Certificate",
	[switch]$NoReset,
	[Parameter(Mandatory=$true)]
	[PSCredential]$Credential
)

if ($AuthType -eq "Digest"){
	$iisFeatures = Web-Server,`
	Web-WebServer,`
	Web-Common-Http,`
	Web-Default-Doc,`
	Web-Dir-Browsing,`
	Web-Http-Errors,`
	Web-Static-Content,`
	Web-DAV-Publishing,`
	Web-Health,`
	Web-Http-Logging,`
	Web-Performance,`
	Web-Stat-Compression,`
	Web-Security,`
	Web-Filtering,`
	Web-Digest-Auth,`
	Web-Mgmt-Tools,`
	Web-Mgmt-Console
}elseif ($AuthType -eq "Certificate"){
	$iisFeatures = Web-Server,`
	Web-WebServer,`
	Web-Common-Http,`
	Web-Default-Doc,`
	Web-Dir-Browsing,`
	Web-Http-Errors,`
	Web-Static-Content,`
	Web-DAV-Publishing,`
	Web-Health,`
	Web-Http-Logging,`
	Web-Performance,`
	Web-Stat-Compression,`
	Web-Security,`
	Web-Filtering,`
	Web-Cert-Auth,`
	Web-Mgmt-Tools,`
	Web-Mgmt-Console
}

Write-Output "Installing IIS role"
$error.Clear()
Install-WindowsFeature $iisFeatures -WarningAction SilentlyContinue | Out-Null
if ($error){
	Write-Warning "Unable to install IIS role"
	Write-Warning "$($error[0].Exception.Message)"
	return
}

$thumbprint = (Get-ChildItem Cert:\LocalMachine\My | where Subject -match $ProvUrl).Thumbprint
if (!($thumbprint)){
	Write-Warning "Unable to find certificate with subject matching $ProvUrl"
	return
}
	
if (!(Test-Path $HttpPath)){
	Write-Output "Creating HTTP path $HttpPath and sub-folder"
	New-Item $HttpPath -Type Directory | Out-Null
	New-Item $HttpPath\site1 -Type Directory | Out-Null
}
if (!(Test-Path $HttpsPath)){
	Write-Output "Creating HTTPS path $HttpsPath and sub-folders"
	New-Item $HttpsPath -Type Directory | Out-Null
	New-Item $HttpsPath\site1 -Type Directory | Out-Null
	New-Item $HttpsPath\site1\logs -Type Directory | Out-Null
	New-Item $HttpsPath\site1\calls -Type Directory | Out-Null
	New-Item $HttpsPath\site1\contacts -Type Directory | Out-Null
	New-Item $HttpsPath\site1\overrides -Type Directory | Out-Null
	New-Item $HttpsPath\site1\core -Type Directory | Out-Null
}


#Set folder permissions
#http://www.tomsitpro.com/articles/powershell-manage-file-system-acl,2-837.html
Write-Output "Adding Read, Write, and Modify permissions for $($Credential.Username) to $HttpsPath"
try {
	$Acl = Get-Acl $HttpsPath
	$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule($Credential.Username,"Read, Write, Modify","ContainerInherit,ObjectInherit","None","Allow")
	$Acl.SetAccessRule($Ar)
	Set-Acl $HttpsPath $Acl -ErrorAction SilentlyContinue
}catch{
	Write-Warning "Failed to set permissions"
}

#Download and install Polycom root certificate to trust factory installed client certificates
#https://stackoverflow.com/questions/36581481/how-to-install-a-certificates-using-powershell-script
Write-Output "Downloading and installing Polycom Root CA"
try {
	Start-BitsTransfer "http://pki.polycom.com/pki/Polycom%20Root%20CA.crt" -Destination PolycomRoot.crt -ErrorAction SilentlyContinue
	Import-Certificate -FilePath PolycomRoot.crt -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
}catch{
	Write-Warning "Failed to download or import Polycom Root CA certificate to Trusted Certificate Store"
	Write-Warning "Please download and install it manually from http://pki.polycom.com/pki/Polycom%20Root%20CA.crt"
}
Remove-Item PolycomRoot.crt -ErrorAction SilentlyContinue -Force

if ($HttpsPort -ne 443){
	New-NetFirewallRule -DisplayName "World Wide Web Services (HTTPS Traffic-In) ($HttpsPort)" -Direction Inbound -Action Allow -Profile Domain -Protocol TCP -LocalPort $HttpsPort | Out-Null
}

#Create website and update binding to 443
if (!(Get-Website -Name $HttpsSiteName)){
	Write-Output "Creating site $HttpsSiteName"
	New-WebSite -Name $HttpsSiteName -PhysicalPath $HttpsPath | Out-Null
}
if (Get-WebSite -Name $HttpsSiteName | Get-WebBinding){
	Write-Output "Removing existing bindings from $HttpsSiteName"
	Get-WebSite -Name $HttpsSiteName | Get-WebBinding | Remove-WebBinding
}
if (!(Get-WebSite -Name $HttpsSiteName | Get-WebBinding -Port $HttpsPort -Protocol https)){
	Write-Output "Creating $HttpsPort binding for $HttpsSiteName"
	New-WebBinding -Name $HttpsSiteName -Port $HttpsPort -Protocol https
}

Write-Output "Binding certificate to $HttpsSiteName"
#https://social.technet.microsoft.com/Forums/Lync/en-US/c83d72eb-4215-40ab-aa53-56f75ee52250/newwebbinding-syntax-to-add-ssl-binding-to-specific-iis-web-site?forum=winserverpowershell
Write-Output "Binding certificate matching $ProvUrl to $HttpsSiteName $HttpsPort binding"
Remove-Item IIS:\SslBindings\0.0.0.0!$HttpsPort -ErrorAction SilentlyContinue
New-Item IIS:\SslBindings\0.0.0.0!$HttpsPort -Thumbprint $thumbprint | Out-Null

Write-Output "Starting site $HttpsSiteName"
try {
	Start-WebSite -Name $HttpsSiteName
}catch{
	Write-Warning "Failed to start $HttpsSiteName"
}

#https://forums.iis.net/t/1192371.aspx
Write-Output "Adding .cfg MIME Type"
try {
	Add-WebConfigurationProperty -Filter "/system.webServer/staticContent" `
		-Name "." `
		-Value @{fileExtension='.cfg'; mimeType='text/plain'}
}catch{
	Write-Warning ".cfg MIME Type already exists or failed to set"
}
Write-Output "Adding .log MIME Type"
try {
	Add-WebConfigurationProperty -Filter "/system.webServer/staticContent" `
		-Name "." `
		-Value @{fileExtension='.log'; mimeType='text/plain'}
}catch{
	Write-Warning ".log MIME Type already exists or failed to set"
}
Write-Output "Adding .ld MIME Type"
try {
	Add-WebConfigurationProperty -Filter "/system.webServer/staticContent" `
		-Name "." `
		-Value @{fileExtension='.ld'; mimeType='text/plain'}
}catch{
	Write-Warning ".ld MIME Type already exists or failed to set"
}

Write-Output "Adding physical path credentials"
#https://powershell.org/forums/topic/iis-webadministration-set-physical-path-credentials-locked/
Set-WebConfiguration -Filter "/system.applicationHost/sites/site[@name=`"$HttpsSiteName`"]/application[@path='/']/virtualDirectory[@path='/']" `
	-Value @{userName="$($Credential.Username)"; password="$($Credential.GetNetworkCredential().Password)"}

Write-Output "Requiring SSL and client certificate"
#https://blogs.msdn.microsoft.com/timomta/2013/06/22/iis-ssl-how-to-powershell-script-client-cert-required/
Set-WebConfigurationProperty -Filter "system.webServer/security/access" `
	-Name "sslFlags" `
	-Value "Ssl,SslNegotiateCert,SslRequireCert" `
	-PSPath "IIS:\" `
	-Location $HttpsSiteName
	
Write-Output "Disabling anonymous authentication on $HttpsSiteName"
#https://stackoverflow.com/questions/24535200/enable-authentication-for-iis-app-in-powershell
#Disable anonymous auth on HTTPS site
Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
	-Name Enabled `
	-Value False `
	-PSPath "IIS:\" `
	-Location $HttpsSiteName
#Disable basic auth on HTTPS site
<# Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/basicAuthentication" `
	-Name Enabled `
	-Value False `
	-PSPath "IIS:\" `
	-Location $HttpsSiteName #>

Write-Output "Enabling WebDav"
#https://blogs.technet.microsoft.com/bernhard_frank/2011/07/13/iis7-how-to-enable-webdav-for-multiple-a-websites-via-script/
#Enable webdav on a site basis
Set-WebConfigurationProperty -Filter "/system.webServer/webdav/authoring" `
	-Name Enabled `
	-Value True `
	-PSPath "IIS:\" `
	-Location $HttpsSiteName

#"appcmd.exe set config -section:system.webserver/serverruntime/uploadreadaheadsize: 10485760 /commit:apphost"
#Increase upload size to correct 413 error
#May only be needed for larger log files
<# Set-WebConfigurationProperty -Filter "/system.webServer/serverRuntime" `
	-Name uploadReadAheadSize `
	-Value 10485760 `
	-PSPath "IIS:\" `
	-Location $HttpsSiteName #>

<# Set-WebConfigurationProperty -Filter "/system.serviceModel/bindings/basicHttpBinding/binding" `
	-Name "maxReceivedMessageSize" `
	-Value "10485760"
	-PSPath "IIS:\" `
	-Location $HttpsSiteName #>

Write-Output "Configuring many-to-one client certificate mapping authentication"
#appcmd.exe set config "HTTPS Web Site" -section:system.webServer/security/authentication/iisClientCertificateMappingAuthentication /enabled:"True" /manyToOneCertificateMappingsEnabled:"True"  /commit:apphost
Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/iisClientCertificateMappingAuthentication" `
	-Name Enabled `
	-Value True `
	-PSPath "IIS:\" `
	-Location $HttpsSiteName
Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/iisClientCertificateMappingAuthentication" `
	-Name manyToOneCertificateMappingsEnabled `
	-Value True `
	-PSPath "IIS:\" `
	-Location $HttpsSiteName
Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" `
	-Name oneToOneCertificateMappingsEnabled `
	-Value False `
	-PSPath "IIS:\" `
	-Location $HttpsSiteName

Write-Output "Configuring certificate mapping to $($Credential.Username)"
#appcmd.exe set config "Default Web Site" -section:system.webServer/security/authentication/iisClientCertificateMappingAuthentication /+"manyToOneMappings.[name='My 1st  Mapping',description='1st User Mapping',userName='mydomain\testuser',password='abcdef']" /commit:apphost
#https://blogs.iis.net/webtopics/configuring-many-to-one-client-certificate-mappings-for-iis-7-7-5
$certMapping = @{
  name          = "Certificate Mapping User"
  description   = "Service account for access to folder structure"
  userName      = $Credential.Username
  password      = $Credential.GetNetworkCredential().Password
}
Add-WebConfiguration -Filter "/system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings" `
	-Value $certMapping `
	-PSPath "IIS:\" `
	-Location $HttpsSiteName

Write-Output "Configuring WebDav authoring rule for $($Credential.Username)"
#Create a webdav allow rule for the user
#https://gist.github.com/pkirch/2261bdc668a19fa9b613
$accessRule = @{
  users  = $Credential.Username
  path   = '*'
  access = 'Read,Write'
}
try {
	Add-WebConfiguration -Filter "/system.webServer/webdav/authoringRules" `
		-Value $accessRule `
		-PSPath "IIS:\" `
		-Location $HttpsSiteName
}catch{
	Write-Warning "WebDav authoring rule already exists or failed to set"
}

if (!($NoReset)){
	Write-Output "Performing iisreset"
	try {
		iisreset | Out-Null
	}catch{
		Write-Warning "iisreset did not complete successfully"
	}
}
