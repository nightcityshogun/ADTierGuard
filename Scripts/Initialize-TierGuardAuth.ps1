<#
.SYNOPSIS
    ADTierGuard - Initialize Authentication Infrastructure
    
.DESCRIPTION
    Creates the Kerberos Authentication Policies and Authentication Policy Silos
    required for the AD Tier Model.
    
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                    !! IMPORTANT - FOREST ROOT REQUIRED !!                     ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                                                                               ║
    ║  This script MUST be run from a Domain Controller in the FOREST ROOT domain  ║
    ║  by a user with Enterprise Admin permissions (or delegated Configuration NC  ║
    ║  write access).                                                               ║
    ║                                                                               ║
    ║  Authentication Policies and Silos are stored in the Configuration Naming    ║
    ║  Context which is FOREST-WIDE:                                                ║
    ║                                                                               ║
    ║    CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,              ║
    ║      CN=Configuration,DC=forestroot,DC=com                                    ║
    ║                                                                               ║
    ║  After initialization, the Invoke-TierUserSync script can be run from        ║
    ║  ANY domain to apply the policies to privileged users.                        ║
    ║                                                                               ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
    
.PARAMETER Prefix
    Naming prefix for policies and silos (default: TierGuard).
    
.PARAMETER CreateTier0
    Create Tier 0 authentication policy and optionally silo.
    
.PARAMETER CreateTier1
    Create Tier 1 authentication policy and optionally silo.
    
.PARAMETER UseSilos
    Create Authentication Policy Silos in addition to policies.
    Silos provide stronger isolation by grouping users/computers.
    
.PARAMETER Tier0TGTLifetimeMinutes
    TGT lifetime for Tier 0 accounts (default: 240 = 4 hours).
    
.PARAMETER Tier1TGTLifetimeMinutes
    TGT lifetime for Tier 1 accounts (default: 480 = 8 hours).
    
.PARAMETER AuditOnly
    Create policies in audit-only mode (not enforced).
    Recommended for initial deployment to verify impact.
    
.PARAMETER PAWGroupDN
    DN of the group containing PAW workstations.
    Used to restrict authentication to Tier 0 PAWs only.
    
.PARAMETER Force
    Skip confirmation prompts and forest root warnings.
    
.EXAMPLE
    # Standard initialization (run from forest root DC as Enterprise Admin)
    .\Initialize-TierGuardAuth.ps1 -CreateTier0 -CreateTier1 -UseSilos -AuditOnly
    
.EXAMPLE
    # Production deployment with enforcement
    .\Initialize-TierGuardAuth.ps1 -CreateTier0 -CreateTier1 -UseSilos
    
.EXAMPLE
    # With PAW restrictions
    .\Initialize-TierGuardAuth.ps1 -CreateTier0 -UseSilos `
        -PAWGroupDN "CN=Tier0-PAWs,OU=Groups,OU=Tier0,DC=corp,DC=contoso,DC=com"
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.2.0
    
    After running this script:
    1. Verify policies exist: Get-TierAuthenticationStatus
    2. Run sync from any domain: Invoke-TierUserSync -TierLevel 0
    3. After audit period, enable enforcement: Set-TierAuthenticationPolicy -Name "..." -Enforced $true
    
.LINK
    https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$Prefix = 'TierGuard',
    
    [Parameter()]
    [switch]$CreateTier0,
    
    [Parameter()]
    [switch]$CreateTier1,
    
    [Parameter()]
    [switch]$UseSilos,
    
    [Parameter()]
    [ValidateRange(60, 43200)]
    [int]$Tier0TGTLifetimeMinutes = 240,  # 4 hours
    
    [Parameter()]
    [ValidateRange(60, 43200)]
    [int]$Tier1TGTLifetimeMinutes = 480,  # 8 hours
    
    [Parameter()]
    [switch]$AuditOnly,
    
    [Parameter()]
    [string]$PAWGroupDN,
    
    [Parameter()]
    [switch]$Force
)

#region Initialization

$ErrorActionPreference = 'Stop'

# Import ADTierGuard module
$modulePath = Split-Path -Parent $PSScriptRoot
$moduleFile = Join-Path $modulePath 'ADTierGuard.psd1'

if (Test-Path $moduleFile) {
    Import-Module $moduleFile -Force
}
else {
    # Try relative to script
    $moduleFile = Join-Path $PSScriptRoot '..\ADTierGuard.psd1'
    if (Test-Path $moduleFile) {
        Import-Module $moduleFile -Force
    }
    else {
        throw "ADTierGuard module not found. Ensure script is in the Scripts folder."
    }
}

#endregion

#region Main

Write-Host @"

╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ████████╗██╗███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗    ║
║     ╚══██╔══╝██║██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗   ║
║        ██║   ██║█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║   ║
║        ██║   ██║██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║   ║
║        ██║   ██║███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝   ║
║        ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝    ║
║                                                                               ║
║              Authentication Infrastructure Initialization                      ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow
$prereq = Test-AuthPolicyPrerequisites -RequireForestRoot

Write-Host ""
Write-Host "Forest Information:" -ForegroundColor Cyan
Write-Host "  Forest Root Domain:  $($prereq.Context.ForestRootDns)" -ForegroundColor White
Write-Host "  Current Domain:      $($prereq.Context.CurrentDomainDns)" -ForegroundColor White
Write-Host "  Is Forest Root:      $($prereq.IsForestRoot)" -ForegroundColor $(if ($prereq.IsForestRoot) { 'Green' } else { 'Yellow' })
Write-Host "  Configuration NC:    $($prereq.Context.ConfigurationNC)" -ForegroundColor Gray
Write-Host "  Supports AuthN Pol:  $($prereq.SupportsAuthPolicies)" -ForegroundColor $(if ($prereq.SupportsAuthPolicies) { 'Green' } else { 'Red' })
Write-Host ""

if ($prereq.Issues.Count -gt 0) {
    Write-Host "Issues Found:" -ForegroundColor Yellow
    foreach ($issue in $prereq.Issues) {
        Write-Host "  ! $issue" -ForegroundColor Yellow
    }
    Write-Host ""
}

if (-not $prereq.CanProceed) {
    Write-Host "ERROR: Prerequisites not met. Cannot continue." -ForegroundColor Red
    exit 1
}

if (-not $prereq.IsForestRoot -and -not $Force) {
    Write-Host @"

WARNING: You are NOT running from the forest root domain!

Authentication Policies and Silos are stored in the Configuration Naming Context
and should typically be created from the forest root domain.

Current Domain:    $($prereq.Context.CurrentDomainDns)
Forest Root:       $($prereq.Context.ForestRootDns)

You can proceed if you have Enterprise Admin permissions, but it is recommended
to run this script from a DC in: $($prereq.Context.ForestRootDns)

"@ -ForegroundColor Yellow

    $continue = Read-Host "Continue anyway? (y/N)"
    if ($continue -ne 'y') {
        Write-Host "Aborted." -ForegroundColor Red
        exit 0
    }
}

# Validate at least one tier selected
if (-not $CreateTier0 -and -not $CreateTier1) {
    Write-Host "ERROR: Specify -CreateTier0 and/or -CreateTier1" -ForegroundColor Red
    exit 1
}

# Summary of what will be created
Write-Host "Configuration Summary:" -ForegroundColor Cyan
Write-Host "  Prefix:          $Prefix" -ForegroundColor White
Write-Host "  Create Tier 0:   $CreateTier0" -ForegroundColor $(if ($CreateTier0) { 'Green' } else { 'Gray' })
Write-Host "  Create Tier 1:   $CreateTier1" -ForegroundColor $(if ($CreateTier1) { 'Green' } else { 'Gray' })
Write-Host "  Create Silos:    $UseSilos" -ForegroundColor $(if ($UseSilos) { 'Green' } else { 'Gray' })
Write-Host "  Mode:            $(if ($AuditOnly) { 'AUDIT-ONLY' } else { 'ENFORCED' })" -ForegroundColor $(if ($AuditOnly) { 'Yellow' } else { 'Green' })
if ($CreateTier0) {
    Write-Host "  Tier 0 TGT:      $Tier0TGTLifetimeMinutes minutes ($([math]::Round($Tier0TGTLifetimeMinutes/60, 1)) hours)" -ForegroundColor White
}
if ($CreateTier1) {
    Write-Host "  Tier 1 TGT:      $Tier1TGTLifetimeMinutes minutes ($([math]::Round($Tier1TGTLifetimeMinutes/60, 1)) hours)" -ForegroundColor White
}
if ($PAWGroupDN) {
    Write-Host "  PAW Group:       $PAWGroupDN" -ForegroundColor White
}
Write-Host ""

if (-not $Force) {
    $confirm = Read-Host "Proceed with creation? (y/N)"
    if ($confirm -ne 'y') {
        Write-Host "Aborted." -ForegroundColor Red
        exit 0
    }
}

Write-Host ""
Write-Host "Creating authentication infrastructure..." -ForegroundColor Yellow
Write-Host ""

$results = @{
    Tier0Policy = $null
    Tier0Silo   = $null
    Tier1Policy = $null
    Tier1Silo   = $null
    Errors      = @()
}

# Create Tier 0 if requested
if ($CreateTier0) {
    Write-Host "=== Tier 0 ===" -ForegroundColor Cyan
    
    try {
        $result = Initialize-TierAuthenticationPolicy `
            -TierLevel 0 `
            -Prefix $Prefix `
            -TGTLifetimeMinutes $Tier0TGTLifetimeMinutes `
            -UseSilo:$UseSilos `
            -PAWGroupDN $PAWGroupDN
        
        if (-not $AuditOnly) {
            # Already enforced by default in Initialize-TierAuthenticationPolicy
            Write-Host "  Mode: ENFORCED" -ForegroundColor Green
        }
        else {
            # Set to audit-only
            Set-TierAuthenticationPolicy -Name $result.PolicyName -Enforced $false
            Write-Host "  Mode: AUDIT-ONLY (not enforced)" -ForegroundColor Yellow
            
            if ($UseSilos) {
                Set-TierAuthenticationSilo -Name $result.SiloName -Enforced $false
            }
        }
        
        $results.Tier0Policy = $result.PolicyDN
        $results.Tier0Silo = $result.SiloDN
        
        Write-Host "  [SUCCESS] Tier 0 initialized" -ForegroundColor Green
        Write-Host "    Policy: $($result.PolicyDN)" -ForegroundColor Gray
        if ($result.SiloDN) {
            Write-Host "    Silo:   $($result.SiloDN)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  [ERROR] Tier 0: $_" -ForegroundColor Red
        $results.Errors += "Tier 0: $_"
    }
    
    Write-Host ""
}

# Create Tier 1 if requested
if ($CreateTier1) {
    Write-Host "=== Tier 1 ===" -ForegroundColor Cyan
    
    try {
        $result = Initialize-TierAuthenticationPolicy `
            -TierLevel 1 `
            -Prefix $Prefix `
            -TGTLifetimeMinutes $Tier1TGTLifetimeMinutes `
            -UseSilo:$UseSilos
        
        if (-not $AuditOnly) {
            Write-Host "  Mode: ENFORCED" -ForegroundColor Green
        }
        else {
            Set-TierAuthenticationPolicy -Name $result.PolicyName -Enforced $false
            Write-Host "  Mode: AUDIT-ONLY (not enforced)" -ForegroundColor Yellow
            
            if ($UseSilos) {
                Set-TierAuthenticationSilo -Name $result.SiloName -Enforced $false
            }
        }
        
        $results.Tier1Policy = $result.PolicyDN
        $results.Tier1Silo = $result.SiloDN
        
        Write-Host "  [SUCCESS] Tier 1 initialized" -ForegroundColor Green
        Write-Host "    Policy: $($result.PolicyDN)" -ForegroundColor Gray
        if ($result.SiloDN) {
            Write-Host "    Silo:   $($result.SiloDN)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  [ERROR] Tier 1: $_" -ForegroundColor Red
        $results.Errors += "Tier 1: $_"
    }
    
    Write-Host ""
}

# Summary
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "INITIALIZATION COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Show current status
Write-Host "Current Authentication Policy Status:" -ForegroundColor Yellow
Get-TierAuthenticationStatus -Prefix $Prefix | ForEach-Object {
    Write-Host "  $($_.Type): $($_.Name)" -ForegroundColor White
    Write-Host "    DN: $($_.DistinguishedName)" -ForegroundColor Gray
    Write-Host "    Enforced: $($_.Enforced)" -ForegroundColor $(if ($_.Enforced) { 'Green' } else { 'Yellow' })
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Verify configuration matches TierGuard.json (KerberosAuthPolicyName)" -ForegroundColor White
Write-Host "  2. Run user sync: Invoke-TierUserSync -TierLevel 0" -ForegroundColor White
Write-Host "  3. Review audit logs (if AuditOnly mode)" -ForegroundColor White
Write-Host "  4. Enable enforcement: Set-TierAuthenticationPolicy -Name '...' -Enforced `$true" -ForegroundColor White
Write-Host ""

if ($results.Errors.Count -gt 0) {
    Write-Host "Errors occurred:" -ForegroundColor Red
    $results.Errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

exit 0

#endregion
