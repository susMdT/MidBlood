<#
Run on Primary DC. Sets up Active Directory Domain Services
#>
#-------------
#- Variables -                                         
#-------------

# Active Directory Variables
$domainname = 'lab.local'
$safemodepassword = "SuperSecurePassword1"
$adminpass = "SecurePassword1"
#------------
#- Settings -
#------------
net user Administrator /passwordreq:yes
net user Administrator $adminpass
# Install Active Directory Services
Try{
    Add-WindowsFeature AD-Domain-Services -ErrorAction Stop
    Install-WindowsFeature RSAT-ADDS -ErrorAction Stop
    Write-Host "Active Directory Domain Services installed successfully" -ForegroundColor Green
    }
Catch{
     Write-Warning -Message $("Failed to install Active Directory Domain Services. Error: "+ $_.Exception.Message)
     Break;
     }

# Configure Active Directory
Try{
    Import-Module ADDSDeployment
    $sp = ConvertTo-SecureString $safemodepassword -AsPlainText -Force

    Install-ADDSForest -DomainName $domainname -InstallDNS -ErrorAction Stop -NoRebootOnCompletion -CreateDnsDelegation:$false -SafeModeAdministratorPassword $sp
    Write-Host "Active Directory Domain Services have been configured successfully" -ForegroundColor Green
    }
Catch{
     Write-Warning -Message $("Failed to configure Active Directory Domain Services. Error: "+ $_.Exception.Message)
     Break;
     }

# Reboot Computer to apply settings
Write-Host "Save all your work, computer rebooting in 5 seconds"
Sleep 5

Try{
    Restart-Computer -ComputerName $env:computername -ErrorAction Stop
    Write-Host "Rebooting Now!!" -ForegroundColor Green
    }
Catch{
     Write-Warning -Message $("Failed to restart computer $($env:computername). Error: "+ $_.Exception.Message)
     Break;
     }