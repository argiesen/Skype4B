# Title: Get-CsEndpointRegistrations
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
	[switch]$PSView,
	[Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='CSVExport')]
	[switch]$CSVExport,
	[Parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='CSVExport')]
	[string]$CSVPath = "EndpointRegistrations.csv"
)

#Get Registrar Identity
$RegistrarPool = Get-CsService -Registrar | where {$_.Version -ge 5}

if ($RegistrarPool.Count -gt 1){
	Write-Host "PoolFqdn"
	Write-Host "--------"
	
	for ($i=0; $i -lt $RegistrarPool.Count; $i++){
		$a = $i + 1
		Write-Host ($a, $RegistrarPool[$i].PoolFqdn)
	}
	
	$Range = '(1-' + $RegistrarPool.Count + ')'
	Write-Host
	$Select = Read-Host "Select pool:" $Range
	$Select = $Select - 1
	
	if (($Select -gt $RegistrarPool.Count - 1) -or ($Select -lt 0)){
		Write-Host "Invalid selection." -ForegroundColor Red
		Exit
	}
	else{
		$RegistrarPool = $RegistrarPool[$Select]
	}
}

#Get all the CS pool information
$CSPool = Get-CSPool $RegistrarPool.PoolFqdn

#Create empty variable that will contain the user registration records
$output = $null

#Loop through a front end computers in the pool
Foreach ($Computer in $CSPool.Computers){

    #Get computer name from fqdn
    $ComputerName = $Computer.Split(".")[0]

    #Defined Connection String
    $connstring = "server=$ComputerName\rtclocal;database=rtcdyn;trusted_connection=true;"

    #Define SQL Command    
    $command = New-Object System.Data.SqlClient.SqlCommand
    $command.CommandText = "Select (cast (RE.ClientApp as varchar (100))) as ClientVersion, R.UserAtHost as UserName, RE.EndpointId as EndpointId, EP.ExpiresAt, '$computer' as RegistrarFQDN `
        From rtcdyn.dbo.RegistrarEndpoint RE `
		Inner Join rtc.dbo.Resource R on R.ResourceId = RE.OwnerId `
		Inner Join rtcdyn.dbo.Endpoint EP on EP.EndpointId = RE.EndpointId `
        Order By ClientVersion, UserName"

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
    $output = $output + $Results.Tables[0]
}

if ($PSView.isPresent){
	$output
}
elseif ($CSVExport.isPresent){
	$output | Export-Csv -Path $CSVPath -NoTypeInformation
}
else {
	$output | Out-GridView
}