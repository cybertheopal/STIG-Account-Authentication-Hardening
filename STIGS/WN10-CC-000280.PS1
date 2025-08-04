<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Opal Ratanayatigune
    LinkedIn        : linkedin.com/in/opal-ratanayatigune/
    GitHub          : github.com/cybertheopal
    Date Created    : 2025-08-03
    Last Modified   : 2025-08-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000280

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-CC-000280).ps1 
#>

# Requires: Run as Administrator

# Define registry path and target value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "fPromptForPassword"
$desiredValue = 1

# Ensure the key exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value to 1 (Enable "Always prompt for password upon connection")
Set-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -Type DWord

# Verify
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName

if ($currentValue -eq $desiredValue) {
    Write-Host "fPromptForPassword set to 1 successfully at $regPath" -ForegroundColor Green
} else {
    Write-Host "Failed to set fPromptForPassword correctly." -ForegroundColor Red
}
