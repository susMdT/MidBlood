<#
Run this on each joinee. Specify a first argument of the new computer name
#>
param
(
    [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Supply a Computer Name")]
    [String]$ComputerName
)

Rename-Computer -NewName $ComputerName 
$secStringPassword = ConvertTo-SecureString "SecurePassword1" -AsPlainText -Force
$credObject = New-Object System.Management.Automation.PSCredential ("Administrator", $secStringPassword)
Add-Computer -DomainName lab.local -Server DC01.lab.local -Restart -Credential $credObject
