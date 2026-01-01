<#
.SYNOPSIS
    ADTierGuard Installation Script
    
.DESCRIPTION
    Deploys ADTierGuard to an Active Directory environment with optional:
    - Group Managed Service Account (GMSA) setup
    - GPO creation with scheduled tasks
    - Script deployment to SYSVOL
    - Kerberos Authentication Policy creation
    
    This script should be run from the forest root domain as an Enterprise Admin.
    
.PARAMETER Scope
    Which tiers to configure: Tier-0, Tier-1, or All-Tiers
    
.PARAMETER InstallPath
    Local installation path. Default: C:\ADTierGuard
    
.PARAMETER UseGMSA
    Create and configure a Group Managed Service Account
    
.PARAMETER GMSAName
    Name of the GMSA to create. Default: ADTierGuard-svc
    Must be 15 characters or less.
    
.PARAMETER DeployGPO
    Create and link GPO with scheduled tasks to Domain Controllers OU
    
.PARAMETER GPOName
    Name of the GPO to create. Default: ADTierGuard Tier Isolation
    
.PARAMETER SkipAuthPolicies
    Skip creation of Kerberos Authentication Policies (if already exist)
    
.PARAMETER ConfigOnly
    Only create configuration file, skip all AD changes
    
.EXAMPLE
    .\Install-ADTierGuard.ps1 -Scope All-Tiers -UseGMSA -DeployGPO
    Full installation with GMSA and GPO deployment.
    
.EXAMPLE
    .\Install-ADTierGuard.ps1 -Scope Tier-0 -ConfigOnly
    Create configuration file only for Tier 0.
    
.EXAMPLE
    .\Install-ADTierGuard.ps1 -Scope All-Tiers
    Basic installation without GMSA/GPO (manual scheduled task setup).
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.3.0
    Requires: Enterprise Admin for full installation
              Domain Admin for single-domain installation
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Tier-0', 'Tier-1', 'All-Tiers')]
    [string]$Scope = 'All-Tiers',
    
    [Parameter(Mandatory = $false)]
    [string]$InstallPath = 'C:\ADTierGuard',
    
    [Parameter(Mandatory = $false)]
    [switch]$UseGMSA,
    
    [Parameter(Mandatory = $false)]
    [ValidateLength(1, 15)]
    [string]$GMSAName = 'ADTierGuard-svc',
    
    [Parameter(Mandatory = $false)]
    [switch]$DeployGPO,
    
    [Parameter(Mandatory = $false)]
    [string]$GPOName = 'ADTierGuard Tier Isolation',
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipAuthPolicies,
    
    [Parameter(Mandatory = $false)]
    [switch]$ConfigOnly
)

#region Script Setup
$ErrorActionPreference = 'Stop'
$ScriptVersion = '2.3.0'
$ScriptPath = $PSScriptRoot

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                      ADTierGuard Installation Script                         ║" -ForegroundColor Cyan
Write-Host "║                              Version $ScriptVersion                                 ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Load required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    if ($DeployGPO) {
        Import-Module GroupPolicy -ErrorAction Stop
    }
}
catch {
    Write-Host "ERROR: Required PowerShell modules not found." -ForegroundColor Red
    Write-Host "Install RSAT: Active Directory and Group Policy modules." -ForegroundColor Yellow
    exit 1
}
#endregion

#region Helper Functions
function Test-IsEnterpriseAdmin {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    # Enterprise Admins SID ends with -519
    return ($currentUser.Groups -like "*-519")
}

function Test-IsDomainAdmin {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    # Domain Admins SID ends with -512
    return ($currentUser.Groups -like "*-512")
}

function Get-ForestRootDomain {
    try {
        return (Get-ADForest).RootDomain
    }
    catch {
        Write-Warning "Cannot determine forest root domain"
        return $null
    }
}

function Test-IsForestRoot {
    $forestRoot = Get-ForestRootDomain
    $currentDomain = (Get-ADDomain).DNSRoot
    return ($forestRoot -eq $currentDomain)
}

function New-KdsRootKeyIfNeeded {
    if (-not (Get-KdsRootKey)) {
        Write-Host "Creating KDS Root Key (required for GMSA)..." -ForegroundColor Yellow
        # EffectiveTime in the past allows immediate use (lab only - production should wait 10 hours)
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
        Write-Host "KDS Root Key created." -ForegroundColor Green
    }
    else {
        Write-Host "KDS Root Key already exists." -ForegroundColor Green
    }
}
#endregion

#region Permission Checks
Write-Host "Checking permissions..." -ForegroundColor Cyan

if (-not (Test-IsDomainAdmin)) {
    Write-Host "ERROR: Domain Admin privileges required." -ForegroundColor Red
    exit 1
}

$isForestRoot = Test-IsForestRoot
$isEnterpriseAdmin = Test-IsEnterpriseAdmin

if (-not $isForestRoot) {
    Write-Host "WARNING: Not running from forest root domain." -ForegroundColor Yellow
    Write-Host "         Some features (Auth Policies, GMSA) require forest root." -ForegroundColor Yellow
    
    if ($UseGMSA -or (-not $SkipAuthPolicies)) {
        $confirm = Read-Host "Continue anyway? (y/N)"
        if ($confirm -notlike 'y*') {
            Write-Host "Aborted." -ForegroundColor Yellow
            exit 0
        }
    }
}

if (-not $isEnterpriseAdmin) {
    Write-Host "WARNING: Not running as Enterprise Admin." -ForegroundColor Yellow
    Write-Host "         Auth Policy creation may fail." -ForegroundColor Yellow
}

Write-Host "  Domain Admin: Yes" -ForegroundColor Green
Write-Host "  Enterprise Admin: $(if ($isEnterpriseAdmin) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($isEnterpriseAdmin) { 'Green' } else { 'Yellow' })
Write-Host "  Forest Root: $(if ($isForestRoot) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($isForestRoot) { 'Green' } else { 'Yellow' })
Write-Host ""
#endregion

#region Domain Selection
Write-Host "Selecting target domains..." -ForegroundColor Cyan

$allDomains = (Get-ADForest).Domains
Write-Host ""
for ($i = 0; $i -lt $allDomains.Count; $i++) {
    Write-Host "  [$i] $($allDomains[$i])"
}
Write-Host "  [$($allDomains.Count)] All domains"
Write-Host ""

$selection = Read-Host "Select domains (comma-separated, or press Enter for all)"
if ([string]::IsNullOrWhiteSpace($selection)) {
    $selectedDomains = $allDomains
}
else {
    $selectedDomains = @()
    foreach ($idx in ($selection -split ',')) {
        $idx = $idx.Trim()
        if ($idx -eq $allDomains.Count.ToString()) {
            $selectedDomains = $allDomains
            break
        }
        elseif ([int]::TryParse($idx, [ref]$null) -and [int]$idx -lt $allDomains.Count) {
            $selectedDomains += $allDomains[[int]$idx]
        }
    }
}

Write-Host "Selected domains: $($selectedDomains -join ', ')" -ForegroundColor Green
Write-Host ""
#endregion

#region Configuration Collection
Write-Host "Collecting configuration..." -ForegroundColor Cyan

$config = @{
    SchemaVersion = '2.3'
    Scope = $Scope
    Domains = $selectedDomains
    General = @{
        ForestScope = ($selectedDomains.Count -gt 1)
        LogLevel = 'Information'
        EventLogSource = 'ADTierGuard'
    }
    ServiceAccount = @{
        UseGMSA = $UseGMSA.IsPresent
        GMSAName = $GMSAName
    }
}

# Tier 0 Configuration
if ($Scope -in @('Tier-0', 'All-Tiers')) {
    Write-Host ""
    Write-Host "=== Tier 0 Configuration ===" -ForegroundColor Yellow
    
    $defaultT0AdminOU = "OU=Admins,OU=Tier 0,OU=Admin"
    $defaultT0ServiceOU = "OU=Service Accounts,OU=Tier 0,OU=Admin"
    $defaultT0ComputerOU = "OU=Servers,OU=Tier 0,OU=Admin"
    
    $t0AdminOUs = @()
    do {
        $input = Read-Host "Tier 0 Admin OU [$defaultT0AdminOU]"
        if ([string]::IsNullOrWhiteSpace($input)) { $input = $defaultT0AdminOU }
        $t0AdminOUs += $input
        $more = Read-Host "Add another Tier 0 Admin OU? (y/N)"
    } while ($more -like 'y*')
    
    $t0ServiceOUs = @()
    do {
        $input = Read-Host "Tier 0 Service Account OU [$defaultT0ServiceOU]"
        if ([string]::IsNullOrWhiteSpace($input)) { $input = $defaultT0ServiceOU }
        $t0ServiceOUs += $input
        $more = Read-Host "Add another Tier 0 Service Account OU? (y/N)"
    } while ($more -like 'y*')
    
    $t0ComputerOUs = @()
    do {
        $input = Read-Host "Tier 0 Computer OU [$defaultT0ComputerOU]"
        if ([string]::IsNullOrWhiteSpace($input)) { $input = $defaultT0ComputerOU }
        $t0ComputerOUs += $input
        $more = Read-Host "Add another Tier 0 Computer OU? (y/N)"
    } while ($more -like 'y*')
    
    $t0PolicyName = Read-Host "Tier 0 Auth Policy Name [Tier0-RestrictedAuth]"
    if ([string]::IsNullOrWhiteSpace($t0PolicyName)) { $t0PolicyName = "Tier0-RestrictedAuth" }
    
    $t0GroupName = Read-Host "Tier 0 Computer Group Name [Tier0-Computers]"
    if ([string]::IsNullOrWhiteSpace($t0GroupName)) { $t0GroupName = "Tier0-Computers" }
    
    $config.Tier0 = @{
        Enabled = $true
        AdminOUs = $t0AdminOUs
        ServiceAccountOUs = $t0ServiceOUs
        ComputerOUs = $t0ComputerOUs
        KerberosAuthPolicyName = $t0PolicyName
        ComputerGroupName = $t0GroupName
        AddToProtectedUsers = $true
        EnforcePrivilegedGroupCleanup = $true
        IncludeDomainControllers = $true
    }
}

# Tier 1 Configuration
if ($Scope -in @('Tier-1', 'All-Tiers')) {
    Write-Host ""
    Write-Host "=== Tier 1 Configuration ===" -ForegroundColor Yellow
    
    $defaultT1AdminOU = "OU=Admins,OU=Tier 1,OU=Admin"
    $defaultT1ServiceOU = "OU=Service Accounts,OU=Tier 1,OU=Admin"
    $defaultT1ComputerOU = "OU=Servers,OU=Tier 1,OU=Admin"
    
    $t1AdminOUs = @()
    do {
        $input = Read-Host "Tier 1 Admin OU [$defaultT1AdminOU]"
        if ([string]::IsNullOrWhiteSpace($input)) { $input = $defaultT1AdminOU }
        $t1AdminOUs += $input
        $more = Read-Host "Add another Tier 1 Admin OU? (y/N)"
    } while ($more -like 'y*')
    
    $t1ServiceOUs = @()
    do {
        $input = Read-Host "Tier 1 Service Account OU [$defaultT1ServiceOU]"
        if ([string]::IsNullOrWhiteSpace($input)) { $input = $defaultT1ServiceOU }
        $t1ServiceOUs += $input
        $more = Read-Host "Add another Tier 1 Service Account OU? (y/N)"
    } while ($more -like 'y*')
    
    $t1ComputerOUs = @()
    do {
        $input = Read-Host "Tier 1 Computer OU [$defaultT1ComputerOU]"
        if ([string]::IsNullOrWhiteSpace($input)) { $input = $defaultT1ComputerOU }
        $t1ComputerOUs += $input
        $more = Read-Host "Add another Tier 1 Computer OU? (y/N)"
    } while ($more -like 'y*')
    
    $t1PolicyName = Read-Host "Tier 1 Auth Policy Name [Tier1-RestrictedAuth]"
    if ([string]::IsNullOrWhiteSpace($t1PolicyName)) { $t1PolicyName = "Tier1-RestrictedAuth" }
    
    $t1GroupName = Read-Host "Tier 1 Computer Group Name [Tier1-Computers]"
    if ([string]::IsNullOrWhiteSpace($t1GroupName)) { $t1GroupName = "Tier1-Computers" }
    
    $config.Tier1 = @{
        Enabled = $true
        AdminOUs = $t1AdminOUs
        ServiceAccountOUs = $t1ServiceOUs
        ComputerOUs = $t1ComputerOUs
        KerberosAuthPolicyName = $t1PolicyName
        ComputerGroupName = $t1GroupName
        AddToProtectedUsers = $false
        EnforcePrivilegedGroupCleanup = $false
        IncludeDomainControllers = $false
    }
}

# Protected Users configuration
Write-Host ""
Write-Host "=== Protected Users Configuration ===" -ForegroundColor Yellow
Write-Host "[0] Tier 0 users added to Protected Users"
Write-Host "[1] Tier 1 users added to Protected Users"
Write-Host "[2] Both Tier 0 and Tier 1"
Write-Host "[3] None (manual management)"
$protectedChoice = Read-Host "Select option [0]"
if ([string]::IsNullOrWhiteSpace($protectedChoice)) { $protectedChoice = "0" }

switch ($protectedChoice) {
    "0" { 
        if ($config.Tier0) { $config.Tier0.AddToProtectedUsers = $true }
        if ($config.Tier1) { $config.Tier1.AddToProtectedUsers = $false }
    }
    "1" {
        if ($config.Tier0) { $config.Tier0.AddToProtectedUsers = $false }
        if ($config.Tier1) { $config.Tier1.AddToProtectedUsers = $true }
    }
    "2" {
        if ($config.Tier0) { $config.Tier0.AddToProtectedUsers = $true }
        if ($config.Tier1) { $config.Tier1.AddToProtectedUsers = $true }
    }
    default {
        if ($config.Tier0) { $config.Tier0.AddToProtectedUsers = $false }
        if ($config.Tier1) { $config.Tier1.AddToProtectedUsers = $false }
    }
}

# Privileged Group Cleanup
Write-Host ""
$cleanupChoice = Read-Host "Enable Tier 0 privileged group cleanup? (Y/n)"
if ($config.Tier0) {
    $config.Tier0.EnforcePrivilegedGroupCleanup = ($cleanupChoice -notlike 'n*')
}

Write-Host ""
Write-Host "Configuration collected." -ForegroundColor Green
#endregion

#region Stop here if ConfigOnly
if ($ConfigOnly) {
    Write-Host ""
    Write-Host "=== Creating Configuration File Only ===" -ForegroundColor Cyan
    
    $configPath = Join-Path $ScriptPath "ADTierGuard.config"
    $config | ConvertTo-Json -Depth 10 | Out-File $configPath -Encoding UTF8
    
    Write-Host "Configuration saved to: $configPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "To complete installation manually:" -ForegroundColor Yellow
    Write-Host "  1. Copy ADTierGuard folder to target server" -ForegroundColor Yellow
    Write-Host "  2. Run Initialize-TierGuardAuth.ps1 from forest root (Enterprise Admin)" -ForegroundColor Yellow
    Write-Host "  3. Create scheduled task to run Invoke-TierUserSync.ps1" -ForegroundColor Yellow
    exit 0
}
#endregion

#region SYSVOL Deployment
Write-Host ""
Write-Host "=== Deploying to SYSVOL ===" -ForegroundColor Cyan

$currentDomain = (Get-ADDomain).DNSRoot
$sysvolScriptPath = "\\$currentDomain\SYSVOL\$currentDomain\scripts"
$sysvolConfigPath = "$sysvolScriptPath\ADTierGuard.config"

Write-Host "SYSVOL Path: $sysvolScriptPath" -ForegroundColor Gray

# Copy scripts to SYSVOL
try {
    $scriptsToCopy = @(
        'Invoke-TierUserSync.ps1',
        'Invoke-TierComputerSync.ps1',
        'Initialize-TierGuardAuth.ps1'
    )
    
    foreach ($script in $scriptsToCopy) {
        $sourcePath = Join-Path $ScriptPath "Scripts\$script"
        if (Test-Path $sourcePath) {
            Copy-Item $sourcePath $sysvolScriptPath -Force
            Write-Host "  Copied: $script" -ForegroundColor Green
        }
        else {
            Write-Host "  Not found: $script" -ForegroundColor Yellow
        }
    }
    
    # Save configuration to SYSVOL
    $config | ConvertTo-Json -Depth 10 | Out-File $sysvolConfigPath -Encoding UTF8
    Write-Host "  Saved: ADTierGuard.config" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to copy files to SYSVOL: $_" -ForegroundColor Red
    exit 1
}
#endregion

#region GMSA Setup
if ($UseGMSA) {
    Write-Host ""
    Write-Host "=== Setting up Group Managed Service Account ===" -ForegroundColor Cyan
    
    # Ensure KDS Root Key exists
    New-KdsRootKeyIfNeeded
    
    # Check if GMSA already exists
    $existingGMSA = Get-ADServiceAccount -Filter "Name -eq '$GMSAName'" -ErrorAction SilentlyContinue
    
    if ($existingGMSA) {
        Write-Host "GMSA '$GMSAName' already exists." -ForegroundColor Green
    }
    else {
        Write-Host "Creating GMSA '$GMSAName'..." -ForegroundColor Yellow
        
        # Get Domain Controllers group for PrincipalsAllowedToRetrieveManagedPassword
        $dcGroup = Get-ADGroup -Identity "$((Get-ADDomain).DomainSID)-516"
        
        try {
            New-ADServiceAccount -Name $GMSAName `
                -DNSHostName "$GMSAName.$currentDomain" `
                -KerberosEncryptionType AES256 `
                -PrincipalsAllowedToRetrieveManagedPassword $dcGroup `
                -Description "ADTierGuard service account for tier isolation management"
            
            Write-Host "GMSA created successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "ERROR: Failed to create GMSA: $_" -ForegroundColor Red
            Write-Host "Continuing without GMSA..." -ForegroundColor Yellow
            $UseGMSA = $false
        }
    }
    
    # Add GMSA to Enterprise Admins (required for cross-domain management)
    if ($UseGMSA -and $isForestRoot) {
        try {
            $gmsa = Get-ADServiceAccount -Identity $GMSAName
            $eaGroup = Get-ADGroup -Identity "$((Get-ADDomain -Server (Get-ADForest).RootDomain).DomainSID)-519" -Server (Get-ADForest).RootDomain
            
            if ($eaGroup.Members -notcontains $gmsa.DistinguishedName) {
                Add-ADGroupMember -Identity $eaGroup -Members $gmsa -Server (Get-ADForest).RootDomain
                Write-Host "GMSA added to Enterprise Admins." -ForegroundColor Green
            }
            else {
                Write-Host "GMSA already in Enterprise Admins." -ForegroundColor Green
            }
        }
        catch {
            Write-Host "WARNING: Could not add GMSA to Enterprise Admins: $_" -ForegroundColor Yellow
            Write-Host "         Add manually if cross-domain management is needed." -ForegroundColor Yellow
        }
    }
}
#endregion

#region Computer Groups
Write-Host ""
Write-Host "=== Creating Computer Groups ===" -ForegroundColor Cyan

$currentDC = (Get-ADDomainController -Discover).HostName[0]

if ($config.Tier0) {
    $t0Group = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier0.ComputerGroupName)'" -ErrorAction SilentlyContinue
    if (-not $t0Group) {
        try {
            New-ADGroup -Name $config.Tier0.ComputerGroupName `
                -GroupScope Universal `
                -Description "Tier 0 computers for Kerberos Authentication Policy" `
                -Server $currentDC
            
            # Set adminCount to protect from accidental changes
            $t0Group = Get-ADGroup -Identity $config.Tier0.ComputerGroupName
            Set-ADObject -Identity $t0Group -Replace @{adminCount = 1}
            
            Write-Host "  Created: $($config.Tier0.ComputerGroupName)" -ForegroundColor Green
        }
        catch {
            Write-Host "  ERROR creating $($config.Tier0.ComputerGroupName): $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  Exists: $($config.Tier0.ComputerGroupName)" -ForegroundColor Green
    }
}

if ($config.Tier1) {
    $t1Group = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier1.ComputerGroupName)'" -ErrorAction SilentlyContinue
    if (-not $t1Group) {
        try {
            New-ADGroup -Name $config.Tier1.ComputerGroupName `
                -GroupScope Universal `
                -Description "Tier 1 computers for Kerberos Authentication Policy" `
                -Server $currentDC
            
            $t1Group = Get-ADGroup -Identity $config.Tier1.ComputerGroupName
            Set-ADObject -Identity $t1Group -Replace @{adminCount = 1}
            
            Write-Host "  Created: $($config.Tier1.ComputerGroupName)" -ForegroundColor Green
        }
        catch {
            Write-Host "  ERROR creating $($config.Tier1.ComputerGroupName): $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  Exists: $($config.Tier1.ComputerGroupName)" -ForegroundColor Green
    }
}
#endregion

#region Authentication Policies
if (-not $SkipAuthPolicies) {
    Write-Host ""
    Write-Host "=== Creating Kerberos Authentication Policies ===" -ForegroundColor Cyan
    
    $defaultTGTLifetime = 240  # 4 hours
    
    if ($config.Tier0) {
        $t0Policy = Get-ADAuthenticationPolicy -Filter "Name -eq '$($config.Tier0.KerberosAuthPolicyName)'" -ErrorAction SilentlyContinue
        if (-not $t0Policy) {
            try {
                $t0ComputerGroup = Get-ADGroup -Identity $config.Tier0.ComputerGroupName
                $sddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)}) || (Member_of_any {SID($($t0ComputerGroup.SID))})))"
                
                New-ADAuthenticationPolicy -Name $config.Tier0.KerberosAuthPolicyName `
                    -Enforce `
                    -UserTGTLifetimeMins $defaultTGTLifetime `
                    -UserAllowedToAuthenticateFrom $sddl `
                    -ProtectedFromAccidentalDeletion $true `
                    -Description "Tier 0 isolation - users can only authenticate to Domain Controllers or Tier 0 servers"
                
                Write-Host "  Created: $($config.Tier0.KerberosAuthPolicyName)" -ForegroundColor Green
            }
            catch {
                Write-Host "  ERROR creating $($config.Tier0.KerberosAuthPolicyName): $_" -ForegroundColor Red
            }
        }
        else {
            Write-Host "  Exists: $($config.Tier0.KerberosAuthPolicyName)" -ForegroundColor Green
        }
    }
    
    if ($config.Tier1) {
        $t1Policy = Get-ADAuthenticationPolicy -Filter "Name -eq '$($config.Tier1.KerberosAuthPolicyName)'" -ErrorAction SilentlyContinue
        if (-not $t1Policy) {
            try {
                $t0ComputerGroup = Get-ADGroup -Identity $config.Tier0.ComputerGroupName
                $t1ComputerGroup = Get-ADGroup -Identity $config.Tier1.ComputerGroupName
                $sddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;(((Member_of {SID(ED)}) || (Member_of_any {SID($($t0ComputerGroup.SID))})) || (Member_of_any {SID($($t1ComputerGroup.SID))})))"
                
                New-ADAuthenticationPolicy -Name $config.Tier1.KerberosAuthPolicyName `
                    -Enforce `
                    -UserTGTLifetimeMins $defaultTGTLifetime `
                    -UserAllowedToAuthenticateFrom $sddl `
                    -ProtectedFromAccidentalDeletion $true `
                    -Description "Tier 1 isolation - users can only authenticate to Tier 0, Tier 1 servers, or Domain Controllers"
                
                Write-Host "  Created: $($config.Tier1.KerberosAuthPolicyName)" -ForegroundColor Green
            }
            catch {
                Write-Host "  ERROR creating $($config.Tier1.KerberosAuthPolicyName): $_" -ForegroundColor Red
            }
        }
        else {
            Write-Host "  Exists: $($config.Tier1.KerberosAuthPolicyName)" -ForegroundColor Green
        }
    }
}
#endregion

#region GPO Deployment
if ($DeployGPO) {
    Write-Host ""
    Write-Host "=== Deploying Group Policy ===" -ForegroundColor Cyan
    
    # Read and customize the scheduled tasks template
    $templatePath = Join-Path $ScriptPath "GPO\ScheduledTasks.xml"
    
    if (Test-Path $templatePath) {
        try {
            $taskXml = Get-Content $templatePath -Raw
            $taskXml = $taskXml.Replace('#ScriptPath', $sysvolScriptPath)
            $taskXml = $taskXml.Replace('#GMSAName', $GMSAName)
            
            # Disable tasks based on scope
            [xml]$xmlDoc = $taskXml
            
            if ($Scope -eq 'Tier-0') {
                # Disable Tier 1 tasks
                $t1CompTask = $xmlDoc.ScheduledTasks.TaskV2 | Where-Object { $_.uid -eq '{D9E485BC-145A-47BC-B6C0-A3457662E002}' }
                if ($t1CompTask) { $t1CompTask.disabled = "1" }
                $t1UserTask = $xmlDoc.ScheduledTasks.TaskV2 | Where-Object { $_.uid -eq '{019C1A3C-7B7A-4C6B-8A81-5DF205198004}' }
                if ($t1UserTask) { $t1UserTask.disabled = "1" }
            }
            elseif ($Scope -eq 'Tier-1') {
                # Disable Tier 0 tasks
                $t0CompTask = $xmlDoc.ScheduledTasks.TaskV2 | Where-Object { $_.uid -eq '{B1168190-7E2C-4177-9391-B1FFBCDF4001}' }
                if ($t0CompTask) { $t0CompTask.disabled = "1" }
                $t0UserTask = $xmlDoc.ScheduledTasks.TaskV2 | Where-Object { $_.uid -eq '{54CA3192-AF32-4C83-98BF-370533359003}' }
                if ($t0UserTask) { $t0UserTask.disabled = "1" }
            }
            
            # If no GMSA, disable the context switch task
            if (-not $UseGMSA) {
                $contextTask = $xmlDoc.ScheduledTasks.TaskV2 | Where-Object { $_.uid -eq '{832DD5A2-5AA7-4F99-8663-0D4855E5DA05}' }
                if ($contextTask) { $contextTask.disabled = "1" }
            }
            
            # Create GPO
            $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
            if (-not $gpo) {
                $gpo = New-GPO -Name $GPOName -Comment "ADTierGuard Tier Level Isolation - Scheduled Tasks for automated tier management"
                Write-Host "  Created GPO: $GPOName" -ForegroundColor Green
            }
            else {
                Write-Host "  GPO exists: $GPOName" -ForegroundColor Green
            }
            
            # Save customized XML to GPO
            $gpoPath = "\\$currentDomain\SYSVOL\$currentDomain\Policies\{$($gpo.Id)}\Machine\Preferences\ScheduledTasks"
            
            if (-not (Test-Path $gpoPath)) {
                New-Item -Path $gpoPath -ItemType Directory -Force | Out-Null
            }
            
            $xmlDoc.Save("$gpoPath\ScheduledTasks.xml")
            Write-Host "  Configured scheduled tasks in GPO" -ForegroundColor Green
            
            # Link to Domain Controllers OU
            $dcOU = (Get-ADDomain).DomainControllersContainer
            $existingLink = Get-GPInheritance -Target $dcOU | 
                Select-Object -ExpandProperty GpoLinks | 
                Where-Object { $_.GpoId -eq $gpo.Id }
            
            if (-not $existingLink) {
                New-GPLink -Guid $gpo.Id -Target $dcOU -LinkEnabled Yes | Out-Null
                Write-Host "  Linked GPO to: $dcOU" -ForegroundColor Green
            }
            else {
                Write-Host "  GPO already linked to Domain Controllers OU" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  ERROR deploying GPO: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  WARNING: GPO template not found: $templatePath" -ForegroundColor Yellow
        Write-Host "           Create scheduled tasks manually." -ForegroundColor Yellow
    }
}
#endregion

#region Enable Kerberos Claims
Write-Host ""
Write-Host "=== Kerberos Claims Support ===" -ForegroundColor Cyan
Write-Host "Kerberos claims must be enabled for Authentication Policies to work."
Write-Host ""
$enableClaims = Read-Host "Enable Kerberos claims via Default Domain/DC policies? (Y/n)"

if ($enableClaims -notlike 'n*') {
    foreach ($domain in $selectedDomains) {
        try {
            # Default Domain Controller Policy GUID
            $dcPolicyGuid = '6AC1786C-016F-11D2-945F-00C04FB984F9'
            # Default Domain Policy GUID  
            $domainPolicyGuid = '31B2F340-016D-11D2-945F-00C04FB984F9'
            
            # Enable on Domain Controllers
            Set-GPRegistryValue -Domain $domain -Guid $dcPolicyGuid `
                -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters' `
                -ValueName 'EnableCbacAndArmor' -Value 1 -Type DWord -ErrorAction SilentlyContinue
            
            Set-GPRegistryValue -Domain $domain -Guid $dcPolicyGuid `
                -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
                -ValueName 'EnableCbacAndArmor' -Value 1 -Type DWord -ErrorAction SilentlyContinue
            
            # Enable on clients
            Set-GPRegistryValue -Domain $domain -Guid $domainPolicyGuid `
                -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
                -ValueName 'EnableCbacAndArmor' -Value 1 -Type DWord -ErrorAction SilentlyContinue
            
            Write-Host "  Enabled Kerberos claims in: $domain" -ForegroundColor Green
        }
        catch {
            Write-Host "  WARNING: Could not enable claims in $domain : $_" -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host "  Skipped. Enable manually via Group Policy:" -ForegroundColor Yellow
    Write-Host "    Computer Configuration > Policies > Admin Templates > System > Kerberos" -ForegroundColor Gray
    Write-Host "    Computer Configuration > Policies > Admin Templates > System > KDC" -ForegroundColor Gray
}
#endregion

#region Summary
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                         Installation Complete                                ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Configuration saved to: $sysvolConfigPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. VERIFY Computer Groups have members:" -ForegroundColor White
Write-Host "   - Run Computer Sync manually or wait for scheduled task" -ForegroundColor Gray
Write-Host "   - Verify Tier 0 computers are in '$($config.Tier0.ComputerGroupName)'" -ForegroundColor Gray
Write-Host ""
Write-Host "2. REBOOT Tier 0 servers to pick up new group membership" -ForegroundColor White
Write-Host ""
Write-Host "3. TEST with a single user before enabling User Sync:" -ForegroundColor White
Write-Host "   Set-ADUser -Identity 'TestAdmin' -AuthenticationPolicy '$($config.Tier0.KerberosAuthPolicyName)'" -ForegroundColor Gray
Write-Host "   - Verify user can log on to Tier 0 servers" -ForegroundColor Gray
Write-Host "   - Verify user CANNOT log on to workstations" -ForegroundColor Gray
Write-Host ""
Write-Host "4. ENABLE User Sync tasks in GPO (currently disabled for safety)" -ForegroundColor White
Write-Host ""
Write-Host "5. HAVE A BREAK-GLASS ACCOUNT ready (not in Tier 0 OU, excluded from policy)" -ForegroundColor White
Write-Host ""
#endregion
