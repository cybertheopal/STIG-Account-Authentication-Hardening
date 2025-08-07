<#
.SYNOPSIS
    This PowerShell script enables detailed audit of subcategory settings and configures auditing for failed credential validations to enhance log visibility for security monitoring.
.NOTES
    Author          : Opal Ratanayatigune
    LinkedIn        : linkedin.com/in/opal-ratanayatigune/
    GitHub          : github.com/cybertheopal
    Date Created    : 2025-08-07
    Last Modified   : 2025-08-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000005).ps1 
#>

# Enable 'Force audit policy subcategory settings'
secedit /export /cfg "$env:TEMP\audit_policy.cfg"

$auditPolicy = Get-Content "$env:TEMP\audit_policy.cfg"
if ($auditPolicy -notcontains "SCENoApplyLegacyAuditPolicy = 1") {
    Add-Content "$env:TEMP\audit_policy.cfg" "SCENoApplyLegacyAuditPolicy = 1"
}

secedit /configure /db secedit.sdb /cfg "$env:TEMP\audit_policy.cfg" /quiet

# Set 'Audit Credential Validation' to Failure
$auditSetting = (AuditPol /get /subcategory:"Credential Validation" | Select-String "Failure")
if ($auditSetting -notmatch "Failure") {
    AuditPol /set /subcategory:"Credential Validation" /failure:enable
}
