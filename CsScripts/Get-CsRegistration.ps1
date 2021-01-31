# Title: Get-CsRegistration
# Version: 1.1
# Author: Andy Giesen
# Date: 1/19/15
# 
# Change Log
# 3/2/16
# -Added CSV export parameters

[CmdLetBinding(DefaultParameterSetName="None")]
param(
	[parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='PSView')]
	[switch]$GridView,
	[parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='PSView')]
	[switch]$RawOutput,
	[Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='CSVExport')]
	[switch]$CSVExport,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='CSVExport')]
	[string]$CSVPath = "EndpointRegistrations.csv"
)

#Get Registrar Identity
$RegistrarPool = Get-CsService -Registrar | where {$_.Version -ge 5}

#List available registrar servers
if ($RegistrarPool.Count -gt 1){
	Write-Host "PoolFqdn"
	Write-Host "--------"
	
	for ($i=0; $i -lt $RegistrarPool.Count; $i++){
		$a = $i + 1
		$b = $a + 1
		Write-Host ($a, $RegistrarPool[$i].PoolFqdn)
		if ($i -eq ($RegistrarPool.Count - 1)){Write-Host ($b, "All pools")}
	}
	
	$range = '(1-' + ($RegistrarPool.Count + 1) + ')'
	Write-Host
	$select = Read-Host "Select pool:" $range
	$select = $select - 1
	
	if (($select -gt $RegistrarPool.Count) -or ($select -lt 0)){
		Write-Host
		Write-Host "Invalid selection." -ForegroundColor Red
		Return
	}elseif ($select -ne $RegistrarPool.Count){
		$RegistrarPool = $RegistrarPool[$select]
	}
}

#Get all the CS pool information
foreach ($pool in $RegistrarPool){
	$Computers += (Get-CsPool $pool.poolFqdn).Computers
}

#Create empty variable that will contain the user registration records
$overallResults = $null

#Loop through a front end computers in the pool
foreach ($Computer in $Computers){
    #Get computer name from fqdn
    $ComputerName = $Computer.Split(".")[0]

    #Defined Connection String
    $connstring = "server=$ComputerName\rtclocal;database=rtcdyn;trusted_connection=true;"

    #Define SQL Command    
    $command = New-Object System.Data.SqlClient.SqlCommand
    $command.CommandText = "Select (cast (RE.ClientApp as varchar (100))) as ClientApp, `
		R.UserAtHost as UserName, RE.EndpointId as EndpointId, `
		EP.ExpiresAt, '$computer' as Server `
        From rtcdyn.dbo.RegistrarEndpoint RE `
		Inner Join rtc.dbo.Resource R on R.ResourceId = RE.OwnerId `
		Inner Join rtcdyn.dbo.Endpoint EP on EP.EndpointId = RE.EndpointId `
        Order By ClientApp, UserName"

    #Make the connection to Server    
    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connstring
    $connection.Open()
    $command.Connection = $connection
    
    #Get the results
    $sqladapter = New-Object System.Data.SqlClient.SqlDataAdapter
    $sqladapter.SelectCommand = $command
    $results = New-Object System.Data.Dataset
    $recordcount=$sqladapter.Fill($results)
    
    #Close the connection
    $connection.Close()
    
    #Append the results to the reuslts from the previous servers
    $overallResults = $overallResults + $Results.Tables[0]
}

$output = $overallResults | foreach {
	New-Object -TypeName PSObject -Property @{
		"ClientApp"			= [System.String]	$_.ClientApp
		"ClientVersion"		= [System.String]	$null
		"UserAgent"			= [System.String]	$null
		"UserName"			= [System.String]	$_.UserName
		"Server"			= [System.String]	$_.Server
		"EndpointId"		= [System.String]	$_.EndpointId
		"ExpiresAt"			= [System.String]	$_.ExpiresAt
	}
}

$output = $output | Select-Object `
	ClientApp,`
	ClientVersion,`
	UserAgent,`
	UserName,`
	Server,`
	EndpointId,`
	ExpiresAt `
	| Sort-Object ClientApp

#Process output to separate client versions and user agents
foreach ($entry in $output | Sort-Object -Descending) {
	$index = ($entry.ClientApp).indexof(" ")

	if ($index -eq "-1") {
		# No second part
		$entry.ClientVersion = $entry.ClientApp
		$entry.UserAgent = " "
	} else {
		# Client version/agent has two main parts
		$entry.ClientVersion = ($entry.ClientApp).substring(0, $index)
		$entry.UserAgent = ($entry.ClientApp).substring($index + 1)
	}
}


if ($RawOutput.isPresent){
	$output | Select-Object `
		ClientVersion,`
		UserAgent,`
		UserName,`
		Server,`
		EndpointId,`
		ExpiresAt
}
elseif ($GridView.isPresent){
	$output | Select-Object `
		ClientVersion,`
		UserAgent,`
		UserName,`
		Server,`
		EndpointId,`
		ExpiresAt | Out-GridView -Title "All Registrations"
}
elseif ($CSVExport.isPresent){
	$output | Select-Object `
		ClientVersion,`
		UserAgent,`
		UserName,`
		Server,`
		EndpointId,`
		ExpiresAt | Export-Csv -Path $CSVPath -NoTypeInformation
}
else{
	$summaryOutput = @()
	
	$output | `
	Select-Object ClientVersion,UserAgent -Unique | `
	foreach {
		$sum = "" | Select-Object `
		ClientVersion,`
		UserAgent,`
		Count
		
		$sum.ClientVersion = $_.ClientVersion.trim()
		if ($sum.UserAgent -eq ""){$sum.UserAgent = $_.ClientVersion.trim()}
		$sum.Count = ($output | where UserAgent -eq $_.UserAgent).Count
		if (!($sum.Count)){$sum.Count = 1}
		
		if (!($ShowFullUserAgent)){
			$sum.UserAgent = $_.UserAgent.trim()
			$sum.UserAgent = ($sum.UserAgent).replace("Microsoft ","")
			$sum.UserAgent = ($sum.UserAgent).replace("Office ","")
			$sum.UserAgent = ($sum.UserAgent).replace("AndroidLync","Android")
			$sum.UserAgent = ($sum.UserAgent).replace("iPadLync","iPad")
			$sum.UserAgent = ($sum.UserAgent).replace("iPhoneLync","iPhone")
			$sum.UserAgent = ($sum.UserAgent).replace("WPLync","WP")
		}
		
		$summaryOutput += $sum
	}
}

<# 	$output | Select-Object UserAgent | `
	Group-Object -Property UserAgent | `
	Select-Object Name,Count | `
	Sort-Object Name
	
	$output | Select-Object UserName | `
	Group-Object -Property UserName | `
	Select-Object Name,Count | `
	Sort-Object Name
} #>


<# 
if ($RawOutput.isPresent){
	$output | Select-Object `
	ClientVersion,`
	UserAgent,`
	UserName,`
	Server,`
	EndpointId,`
	ExpiresAt
}
elseif ($PSView.isPresent){
	$output | Select-Object `
	ClientVersion | Group-Object -Property ClientVersion | `
	Select-Object Name,Count | `
	Sort-Object Name
	
	$output | Select-Object UserAgent | `
	Group-Object -Property UserAgent | `
	Select-Object Name,Count | `
	Sort-Object Name
	
	$output | Select-Object UserName | `
	Group-Object -Property UserName | `
	Select-Object Name,Count | `
	Sort-Object Name
}
elseif ($CSVExport.isPresent){
	$output | Select-Object `
	ClientVersion,`
	UserAgent,`
	UserName,`
	Server,`
	EndpointId,`
	ExpiresAt | Export-Csv -Path $CSVPath -NoTypeInformation
}
else {
	$output | Select-Object `
	ClientVersion | Group-Object -Property ClientVersion | `
	Select-Object Name,Count | `
	Sort-Object Name | Out-GridView -Title "Client Versions"
	
	$output | Select-Object `
	UserAgent | Group-Object -Property UserAgent | `
	Select-Object Name,Count | `
	Sort-Object Name | Out-GridView -Title "User Agents"
	
	$output | Select-Object `
	UserName | Group-Object -Property UserName | `
	Select-Object Name,Count | `
	Sort-Object Name | Out-GridView -Title "User Connections"

	$output | Select-Object `
	ClientVersion,`
	UserAgent,`
	UserName,`
	Server,`
	EndpointId,`
	ExpiresAt | Out-GridView -Title "All Registrations"
}
 #>