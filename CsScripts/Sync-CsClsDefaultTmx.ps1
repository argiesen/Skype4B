$SourceTMXFile = 'C:\Program Files\Common Files\Microsoft Lync Server 2013\Tracing\default.tmx'
$SourceXMLFile = 'C:\Program Files\Common Files\Microsoft Lync Server 2013\Tracing\default.xml'
$DestinationTMXFile = 'C:\Program Files\Microsoft Lync Server 2013\Debugging Tools\default.tmx'
$DestinationFolder = 'C:\Program Files\Microsoft Lync Server 2013\Debugging Tools'

if((Get-FileHash $SourceFile).Hash -ne (Get-FileHash $DestinationFile).Hash){
	Copy-Item $SourceTMXFile $DestinationFolder
	Copy-Item $SourceXMLFile $DestinationFolder
}