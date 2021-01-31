# Modified based on Windows Fabric script found here: http://tomtalks.uk/2014/10/check-you-lync-server-windows-fabric-log-size-with-powershell/

# Gathers the CLS log file size of a Lync Server 2013
# Use at your own risk. Test before using in production
# Assumes CLS is at the default location

#$VerbosePreference = 'Continue'
$FinalOutput = @()
$services = Get-CsService | Where-Object {($_.Role -like '*Registrar*') -or ($_.Role -like '*MediationServer*') -or ($_.Role -like '*PersistentChatServer*') -and ($_.Version -ge 6)}
foreach ($service in $services){$computers += Get-CsPool $service.PoolFqdn | Select-Object -ExpandProperty Computers}
$computers | ForEach-Object -Process {
	Write-Verbose -Message "Testing $_"
	$TestPath = $null

	# Note, No CLS on 2010 Pool, Test_Path Covers this, since the path does not exist on a 2010 server
	$Path1 = "\\$_\C$\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\Tracing"
	$TestPath = Test-Path -Path "$Path1"
	Write-Verbose -Message "Test Path 1 Result: $TestPath"

	if ($TestPath){
		$Size = Get-ChildItem -Path "$Path1" | Measure-Object -Property length -Sum
		$Path = $Path1
		$FolderSizeMB = $Size.sum / 1MB
		$FolderSizeMB = [Math]::Round($FolderSizeMB,2)
		Write-Verbose -Message "Server $_"
		Write-Verbose -Message "Path $Path"
		Write-Verbose -Message "Size $FolderSizeMB MB"
		$output = New-Object -TypeName PSobject
		$output | Add-Member -MemberType NoteProperty -Name 'Computer' -Value $_
		$output | Add-Member -MemberType NoteProperty -Name 'ClsLogSizeMB' -Value $FolderSizeMB
		$FinalOutput += $output
	}
} # Close Foreach-Object

$FinalOutput | Format-Table -AutoSize