<#
.SYNOPSIS
    This PowerShell script creates a .inf template that sets MinimumPasswordLength = 14.

.NOTES
    Author          : Opal Ratanayatigune
    LinkedIn        : linkedin.com/in/opal-ratanayatigune/
    GitHub          : github.com/cybertheopal
    Date Created    : 2025-08-04
    Last Modified   : 2025-08-04
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000035

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AC-000035).ps1 
#>

# Requires: Run as Administrator

# Create temporary security template
$tempFile = "$env:Temp\secpol.inf"
$outFile = "$env:Temp\secpol.sdb"

@"
[System Access]
MinimumPasswordLength = 14
"@ | Set-Content -Encoding ASCII -Path $tempFile

# Apply the new setting using secedit
secedit /configure /db $outFile /cfg $tempFile /areas SECURITYPOLICY

# Cleanup
Remove-Item $tempFile -Force
Remove-Item $outFile -Force

Write-Host "`n✅ Minimum password length set to 14 characters successfully." -ForegroundColor Green
