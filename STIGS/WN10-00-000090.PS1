<#
.SYNOPSIS
    This PowerShell script uses Get-LocalUser to identify all enabled local user accounts, checks whether the "Password never expires" flag is set, and disables it by setting PasswordNeverExpires to false, ensuring that all local account passwords are required to expire.

.NOTES
    Author          : Opal Ratanayatigune
    LinkedIn        : linkedin.com/in/opal-ratanayatigune/
    GitHub          : github.com/cybertheopal
    Date Created    : 2025-08-04
    Last Modified   : 2025-08-04
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000090

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-00-000090).ps1 
#>

# Requires: Run as Administrator
# Purpose: Uncheck "Password never expires" for all enabled local user accounts

# Get all local users
$users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }

foreach ($user in $users) {
    if ($user.PasswordNeverExpires) {
        try {
            Write-Host "🔄 Updating user: $($user.Name) (removing 'Password never expires' flag)..."
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
            Write-Host "✅ User $($user.Name) updated." -ForegroundColor Green
        }
        catch {
            Write-Host "❌ Failed to update $($user.Name): $_" -ForegroundColor Red
        }
    } else {
        Write-Host "✅ User $($user.Name) already compliant." -ForegroundColor DarkGray
    }
}
