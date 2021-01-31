# Get-CsRegistration

This script will query the RTCLOCAL SQL Express instance on registrar servers and pull a list of all registered endpoints including SIP address and user agent. This is useful in determining what users are registered, how many times, where, and what type of endpoint and software version.

The script presents a menu of available pools to query and offers a selection of outputs via parameters.

Default output is GridView

* PSView - Outputs to PowerShell
* CsvExport - Exports output to a CSV
* CsvPath - Sets CSV path, defaults to .\EndpointRegistrations.csv
