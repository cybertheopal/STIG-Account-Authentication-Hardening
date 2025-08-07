<#
.SYNOPSIS
This PowerShell script disables insecure guest logons by setting the `AllowInsecureGuestAuth` registry value to `0`, aligning the system with security policy requirements.


.NOTES
    Author          : Opal Ratanayatigune
    LinkedIn        : linkedin.com/in/opal-ratanayatigune/
    GitHub          : github.com/cybertheopal
    Date Created    : 2025-08-08
    Last Modified   : 2025-08-08
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000040

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-CC-000040).ps1 
#>

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord

