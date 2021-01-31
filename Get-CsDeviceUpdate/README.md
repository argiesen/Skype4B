# Get-CsDeviceUpdate

This script automatically downloads, extracts, imports, approves, and cleans up device updates for LPE devices. Automatic import, approval and clean up is supported for 3PIP devices.

Executing this script without any parameters will result in an interactive experience. However parameters are provided for non-interactive execution.

### PARAMETER
```
Pool
  Define a single pool to which updates will be imported and approved.
HP
  Processes updates for HP LPE devices.
Aastra
  Processes updates for Aastra LPE devices.
Polycom
  Processes updates for Polycom Aries LPE devices.
Tanjay
  Processes updates for Polycom Tanjay (CX700) LPE devices.
3PIP
  Processes updates for 3PIP phones placed in the 3PIP folder.
Download
  Automatically downloads the latest selected LPE firmware directly from Microsoft.
Import
  Automatically import updates to selected pool.
ImportToAllPools
  Automatically import updates to all pools.
Approve
  Automatically approve ALL pending firmware updates on selected pools.
  Note: This does not discriminate from already existing pending updates.
Cleanup
  Searches the pool file share for firmware files that do not match the currently approved, pending, or restore firmware versions.
```

### EXAMPLE
```
Get-CsDeviceUpdates.ps1 -Pool cspool1.domain.com -Polycom -Download -Import -Approve -Cleanup
```
This command will download the Polycom LPE updates from Microsoft, import them to pool cspool1, approve the updates, and clean up old firmware files on the file share.

### EXAMPLE
```
Get-CsDeviceUpdates.ps1 -Polycom -3PIP -ImportToAllPools -Approve -Cleanup
```
This command will import pre-staged Polycom LPE and any 3PIP update files from the 3PIP folder to all pools, approve the updates, and clean up old firmware files on the file share.
