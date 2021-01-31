#http://tomtalks.uk/2014/10/check-you-lync-server-windows-fabric-log-size-with-powershell/

# 0.3
# Gathers the Windows Fabric log file size of a Lync Server 2013
# Use at your own risk. Test before using in production
# Assumes Windows Fabric is on C:\

#$VerbosePreference = 'Continue'
$FinalOutput = @()
$registrars = Get-CsService -Registrar | Where-Object {$_.Version -ge 5}
foreach ($registrar in $registrars){$computers += Get-CsPool $registrar.PoolFqdn | Select-Object -ExpandProperty Computers}
$computers | ForEach-Object -Process {
	Write-Verbose -Message "Testing $_"
	$TestPath = $null
	$TestPath2 = $null

	# Note, No Windows Fabric on 2010 Pool, Test_Path Covers this, since the path does not exist on a 2010 server
	$Path1 = "\\$_\C$\ProgramData\Windows Fabric\Fabric\log\Traces"
	$TestPath = Test-Path -Path "$Path1"
	Write-Verbose -Message "Test Path 1 Result: $TestPath"

	# Alternate Path
	$Path2 = "\\$_\c$\ProgramData\Windows Fabric\Log\Traces"
	$TestPath2 = Test-Path -Path "$path2"
	Write-Verbose -Message "Test Path 2 Result: $TestPath2"

	if ($TestPath) {
		$Size = Get-ChildItem -Path "$Path1" | Measure-Object -Property length -Sum
		$Path = $Path1
		$FolderSizeMB = $Size.sum / 1MB
		$FolderSizeMB = [Math]::Round($FolderSizeMB,2)
		Write-Verbose -Message "Server $_"
		Write-Verbose -Message "Path $Path"
		Write-Verbose -Message "Size $FolderSizeMB MB"
		$output = New-Object -TypeName PSobject
		$output | Add-Member -MemberType NoteProperty -Name 'Computer' -Value $_
		$output | Add-Member -MemberType NoteProperty -Name 'WinFabricLogSizeMB' -Value $FolderSizeMB
		$FinalOutput += $output
	}
	if ($TestPath2) {
		$Size = Get-ChildItem -Path "$Path2" | Measure-Object -Property length -Sum
		$Path = $Path2
		$FolderSizeMB = $Size.sum / 1MB
		$FolderSizeMB = [Math]::Round($FolderSizeMB,2)
		Write-Verbose -Message "Server $_"
		Write-Verbose -Message "Path $Path"
		Write-Verbose -Message "Size $FolderSizeMB MB"
		$output = New-Object -TypeName PSobject
		$output | Add-Member -MemberType NoteProperty -Name 'Computer' -Value $_
		$output | Add-Member -MemberType NoteProperty -Name 'WinFabricLogSizeMB' -Value $FolderSizeMB
		$FinalOutput += $output
	}
} # Close Foreach-Object

$FinalOutput | Format-Table -AutoSize