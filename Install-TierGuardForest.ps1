<#
.SYNOPSIS
    TierGuard Forest Installation Script
    
.DESCRIPTION
    One-time setup script to deploy TierGuard across an Active Directory forest.
    Must be run from the forest root domain as Enterprise Administrator.
    
    This script:
    1. Creates KDS Root Key (if needed)
    2. Creates Group Managed Service Account
    3. Creates Tier 0 and Tier 1 computer groups
    4. Creates Kerberos Authentication Policies
    5. Deploys scripts and configuration to SYSVOL
    6. Creates and links GPO with scheduled tasks
    7. Enables Kerberos Armoring (optional)
    
.PARAMETER ConfigOnly
    Only generate configuration file without deploying
    
.PARAMETER SkipGpo
    Skip GPO creation (for manual GPO import)
    
.PARAMETER SkipKerberosArmoring
    Skip enabling Kerberos Armoring via GPO
    
.PARAMETER GmsaName
    Name for the Group Managed Service Account (max 15 characters)
    
.PARAMETER Force
    Skip confirmation prompts
    
.EXAMPLE
    .\Install-TierGuardForest.ps1
    
    Interactive installation with all prompts.
    
.EXAMPLE
    .\Install-TierGuardForest.ps1 -GmsaName 'TierGuard-Svc' -Force
    
    Non-interactive installation with specified GMSA name.
    
.NOTES
    Version: 1.0.0
    Author: TierGuard Team
    Requires: Enterprise Admin, PowerShell 5.1+, AD PowerShell Module, GP PowerShell Module
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [switch]$ConfigOnly,
    
    [Parameter()]
    [switch]$SkipGpo,
    
    [Parameter()]
    [switch]$SkipKerberosArmoring,
    
    [Parameter()]
    [ValidateLength(1, 15)]
    [string]$GmsaName = 'TierGuard-Svc',
    
    [Parameter()]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Script Variables

$Script:Version = '1.0.0'
$Script:ScriptPath = $PSScriptRoot

# Default OU paths
$Script:Defaults = @{
    Tier0AdminOU = 'OU=Admins,OU=Tier 0,OU=Admin'
    Tier0ServiceAccountOU = 'OU=Service Accounts,OU=Tier 0,OU=Admin'
    Tier0ComputerOU = 'OU=Servers,OU=Tier 0,OU=Admin'
    Tier0ComputerGroup = 'TierGuard-Tier0-Computers'
    Tier0PolicyName = 'TierGuard-Tier0-AuthPolicy'
    Tier0TGTLifetime = 240
    
    Tier1AdminOU = 'OU=Admins,OU=Tier 1,OU=Admin'
    Tier1ServiceAccountOU = 'OU=Service Accounts,OU=Tier 1,OU=Admin'
    Tier1ComputerOU = 'OU=Servers,OU=Tier 1,OU=Admin'
    Tier1ComputerGroup = 'TierGuard-Tier1-Computers'
    Tier1PolicyName = 'TierGuard-Tier1-AuthPolicy'
    Tier1TGTLifetime = 480
    
    GpoName = 'TierGuard Isolation'
    SyncIntervalMinutes = 10
}

#endregion

#region Helper Functions

function Write-Banner {
    param([string]$Text, [ConsoleColor]$Color = 'Cyan')
    
    $line = '=' * 70
    Write-Host ""
    Write-Host $line -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Write-Host $line -ForegroundColor $Color
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "[*] $Text" -ForegroundColor Green
}

function Write-SubStep {
    param([string]$Text)
    Write-Host "    - $Text" -ForegroundColor Gray
}

function Read-HostWithDefault {
    param(
        [string]$Prompt,
        [string]$Default
    )
    
    $result = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($result)) {
        return $Default
    }
    return $result.Trim()
}

function Read-HostMultiple {
    param(
        [string]$Prompt,
        [string]$Default,
        [string]$AddMorePrompt = 'Add another'
    )
    
    $results = @()
    $first = Read-HostWithDefault -Prompt $Prompt -Default $Default
    $results += $first
    
    while ($true) {
        $more = Read-Host "$AddMorePrompt? (y/[n])"
        if ($more -notlike 'y*') { break }
        
        $additional = Read-Host "Enter path"
        if (-not [string]::IsNullOrWhiteSpace($additional)) {
            $results += $additional.Trim()
        }
    }
    
    return $results
}

function Read-HostSelection {
    param(
        [string[]]$Options,
        [string]$Prompt,
        [int]$Default = 0
    )
    
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "[$i] $($Options[$i])"
    }
    
    do {
        $selection = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($selection)) {
            return $Default
        }
        $index = [int]$selection
    } while ($index -lt 0 -or $index -ge $Options.Count)
    
    return $index
}

function Test-OUExists {
    param(
        [string]$OUPath,
        [string]$DomainDN,
        [string]$Server
    )
    
    $fullPath = if ($OUPath -match 'DC=') { $OUPath } else { "$OUPath,$DomainDN" }
    
    try {
        Get-ADOrganizationalUnit -Identity $fullPath -Server $Server -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function New-OUPath {
    param(
        [string]$OUPath,
        [string]$DomainDN,
        [string]$Server
    )
    
    # Remove domain component if present
    $relativePath = $OUPath -replace ',DC=.*$', ''
    $ous = $relativePath -split ',' | Where-Object { $_ -match '^OU=' }
    [array]::Reverse($ous)
    
    $currentPath = $DomainDN
    
    foreach ($ou in $ous) {
        $ouName = $ou -replace '^OU=', ''
        $targetPath = "$ou,$currentPath"
        
        try {
            Get-ADOrganizationalUnit -Identity $targetPath -Server $Server -ErrorAction Stop | Out-Null
        }
        catch {
            Write-SubStep "Creating OU: $ouName in $currentPath"
            New-ADOrganizationalUnit -Name $ouName -Path $currentPath -Server $Server -ErrorAction Stop
        }
        
        $currentPath = $targetPath
    }
}

#endregion

#region Module Loading

function Import-TierGuardModules {
    $modulePath = Join-Path $Script:ScriptPath 'Core\ForestDeployment.psm1'
    if (-not (Test-Path $modulePath)) {
        throw "ForestDeployment.psm1 not found at $modulePath"
    }
    
    Import-Module $modulePath -Force -ErrorAction Stop
    Write-SubStep "Loaded ForestDeployment module"
}

#endregion

#region Main Installation

function Install-TierGuardForest {
    Write-Banner "TierGuard Forest Installation v$($Script:Version)"
    
    Write-Host "This script will deploy TierGuard tier isolation across your AD forest." -ForegroundColor Yellow
    Write-Host "Ensure you are running as Enterprise Administrator from the forest root domain." -ForegroundColor Yellow
    Write-Host ""
    
    #region Prerequisites Check
    
    Write-Step "Checking prerequisites..."
    
    # Load modules
    Import-TierGuardModules
    
    # Check permissions
    $prereqs = Test-ForestDeploymentPrerequisites
    
    if (-not $prereqs.IsEnterpriseAdmin) {
        Write-Warning "Current user is NOT an Enterprise Administrator."
        if (-not $Force) {
            $continue = Read-Host "Continue anyway? (y/[n])"
            if ($continue -notlike 'y*') {
                Write-Host "Aborted." -ForegroundColor Red
                return
            }
        }
    }
    else {
        Write-SubStep "Enterprise Admin: OK"
    }
    
    if (-not $prereqs.SupportsAuthPolicies) {
        throw "Domain functional level does not support Authentication Policies (requires 2012 R2 or higher)"
    }
    Write-SubStep "Functional level: $($prereqs.DomainFunctionalLevel) - OK"
    
    # Check/create KDS Root Key
    if (-not $prereqs.KdsRootKey) {
        Write-Host ""
        Write-Warning "No KDS Root Key found. A key is required for GMSA."
        
        if (-not $Force) {
            Write-Host "[0] Create key effective immediately (LAB ONLY)"
            Write-Host "[1] Create key with 10 hour wait (PRODUCTION)"
            Write-Host "[2] Abort"
            $choice = Read-Host "Select option [2]"
        }
        else {
            $choice = "0"
        }
        
        switch ($choice) {
            "0" { 
                New-TierGuardKdsRootKey -EffectiveImmediately
                Write-SubStep "KDS Root Key created (immediate)"
            }
            "1" { 
                New-TierGuardKdsRootKey
                Write-Host "KDS Root Key created. Wait 10 hours before continuing." -ForegroundColor Yellow
                return
            }
            default { 
                Write-Host "Aborted." -ForegroundColor Red
                return
            }
        }
    }
    elseif (-not $prereqs.KdsRootKey.IsEffective) {
        Write-Warning "KDS Root Key exists but not yet effective. Wait $($prereqs.KdsRootKey.HoursUntilEffective) hours."
        return
    }
    else {
        Write-SubStep "KDS Root Key: OK"
    }
    
    #endregion
    
    #region Domain Selection
    
    Write-Host ""
    Write-Step "Domain Selection"
    
    $forest = Get-ADForest
    $allDomains = $forest.Domains
    $forestRoot = $forest.RootDomain
    
    Write-Host "Forest: $($forest.Name)" -ForegroundColor Cyan
    Write-Host "Forest Root: $forestRoot" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Available domains:"
    for ($i = 0; $i -lt $allDomains.Count; $i++) {
        $marker = if ($allDomains[$i] -eq $forestRoot) { " (Forest Root)" } else { "" }
        Write-Host "[$i] $($allDomains[$i])$marker"
    }
    Write-Host "[$($allDomains.Count)] All domains"
    
    if (-not $Force) {
        $selection = Read-Host "Select domains to manage (comma-separated) [$($allDomains.Count)]"
    }
    else {
        $selection = "$($allDomains.Count)"
    }
    
    if ([string]::IsNullOrWhiteSpace($selection)) {
        $selection = "$($allDomains.Count)"
    }
    
    $selectedDomains = @()
    foreach ($idx in $selection -split ',') {
        $idx = $idx.Trim()
        if ($idx -eq "$($allDomains.Count)") {
            $selectedDomains = $allDomains
            break
        }
        elseif ([int]$idx -lt $allDomains.Count) {
            $selectedDomains += $allDomains[[int]$idx]
        }
    }
    
    Write-SubStep "Selected: $($selectedDomains -join ', ')"
    
    #endregion
    
    #region Scope Selection
    
    Write-Host ""
    Write-Step "Scope Selection"
    
    $scopeOptions = @('Tier-0 only', 'Tier-1 only', 'Both Tier-0 and Tier-1')
    $scopeChoice = Read-HostSelection -Options $scopeOptions -Prompt "Select scope" -Default 2
    $scope = switch ($scopeChoice) {
        0 { 'Tier-0' }
        1 { 'Tier-1' }
        2 { 'All-Tiers' }
    }
    
    Write-SubStep "Scope: $scope"
    
    #endregion
    
    #region Tier 0 Configuration
    
    $tier0Config = @{
        AdminOUs = @()
        ServiceAccountOUs = @()
        ComputerOUs = @()
        ComputerGroup = $Script:Defaults.Tier0ComputerGroup
        PolicyName = $Script:Defaults.Tier0PolicyName
        TGTLifetimeMinutes = $Script:Defaults.Tier0TGTLifetime
    }
    
    if ($scope -eq 'Tier-0' -or $scope -eq 'All-Tiers') {
        Write-Host ""
        Write-Step "Tier 0 Configuration"
        
        $tier0Config.AdminOUs = Read-HostMultiple -Prompt "Tier 0 Admin OU" -Default $Script:Defaults.Tier0AdminOU
        $tier0Config.ServiceAccountOUs = Read-HostMultiple -Prompt "Tier 0 Service Account OU" -Default $Script:Defaults.Tier0ServiceAccountOU
        $tier0Config.ComputerOUs = Read-HostMultiple -Prompt "Tier 0 Computer OU" -Default $Script:Defaults.Tier0ComputerOU
        $tier0Config.ComputerGroup = Read-HostWithDefault -Prompt "Tier 0 Computer Group name" -Default $Script:Defaults.Tier0ComputerGroup
        $tier0Config.PolicyName = Read-HostWithDefault -Prompt "Tier 0 Auth Policy name" -Default $Script:Defaults.Tier0PolicyName
    }
    
    #endregion
    
    #region Tier 1 Configuration
    
    $tier1Config = @{
        AdminOUs = @()
        ServiceAccountOUs = @()
        ComputerOUs = @()
        ComputerGroup = $Script:Defaults.Tier1ComputerGroup
        PolicyName = $Script:Defaults.Tier1PolicyName
        TGTLifetimeMinutes = $Script:Defaults.Tier1TGTLifetime
    }
    
    if ($scope -eq 'Tier-1' -or $scope -eq 'All-Tiers') {
        Write-Host ""
        Write-Step "Tier 1 Configuration"
        
        $tier1Config.AdminOUs = Read-HostMultiple -Prompt "Tier 1 Admin OU" -Default $Script:Defaults.Tier1AdminOU
        $tier1Config.ServiceAccountOUs = Read-HostMultiple -Prompt "Tier 1 Service Account OU" -Default $Script:Defaults.Tier1ServiceAccountOU
        $tier1Config.ComputerOUs = Read-HostMultiple -Prompt "Tier 1 Computer OU" -Default $Script:Defaults.Tier1ComputerOU
        $tier1Config.ComputerGroup = Read-HostWithDefault -Prompt "Tier 1 Computer Group name" -Default $Script:Defaults.Tier1ComputerGroup
        $tier1Config.PolicyName = Read-HostWithDefault -Prompt "Tier 1 Auth Policy name" -Default $Script:Defaults.Tier1PolicyName
    }
    
    #endregion
    
    #region Additional Options
    
    Write-Host ""
    Write-Step "Additional Options"
    
    $protectedOptions = @('Tier 0 only', 'Tier 1 only', 'Both tiers', 'None')
    $protectedChoice = Read-HostSelection -Options $protectedOptions -Prompt "Add to Protected Users" -Default 0
    $protectedUsers = switch ($protectedChoice) {
        0 { 'Tier-0' }
        1 { 'Tier-1' }
        2 { 'All-Tiers' }
        3 { 'None' }
    }
    
    $cleanupChoice = Read-Host "Enable privileged group cleanup for Tier 0? ([y]/n)"
    $enableCleanup = $cleanupChoice -notlike 'n*'
    
    $gmsaNameInput = Read-HostWithDefault -Prompt "GMSA Name (max 15 chars)" -Default $GmsaName
    while ($gmsaNameInput.Length -gt 15) {
        Write-Warning "GMSA name must be 15 characters or less"
        $gmsaNameInput = Read-Host "GMSA Name"
    }
    
    #endregion
    
    #region Build Configuration
    
    Write-Host ""
    Write-Step "Building configuration..."
    
    $configuration = New-TierGuardConfiguration `
        -Domains $selectedDomains `
        -Tier0AdminOUs $tier0Config.AdminOUs `
        -Tier0ServiceAccountOUs $tier0Config.ServiceAccountOUs `
        -Tier0ComputerOUs $tier0Config.ComputerOUs `
        -Tier0ComputerGroup $tier0Config.ComputerGroup `
        -Tier0PolicyName $tier0Config.PolicyName `
        -Tier1AdminOUs $tier1Config.AdminOUs `
        -Tier1ServiceAccountOUs $tier1Config.ServiceAccountOUs `
        -Tier1ComputerOUs $tier1Config.ComputerOUs `
        -Tier1ComputerGroup $tier1Config.ComputerGroup `
        -Tier1PolicyName $tier1Config.PolicyName `
        -Scope $scope `
        -AddToProtectedUsers $protectedUsers `
        -EnablePrivilegedGroupCleanup $enableCleanup
    
    if ($ConfigOnly) {
        $configPath = Join-Path $Script:ScriptPath 'TierGuard.config'
        $configuration | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding UTF8
        Write-Host "Configuration saved to: $configPath" -ForegroundColor Green
        return
    }
    
    #endregion
    
    #region Create OUs
    
    Write-Host ""
    Write-Step "Creating OUs (if needed)..."
    
    foreach ($domain in $selectedDomains) {
        $domainObj = Get-ADDomain -Server $domain
        $domainDN = $domainObj.DistinguishedName
        $dc = $domainObj.PDCEmulator
        
        Write-SubStep "Processing domain: $domain"
        
        $allOUs = @()
        $allOUs += $tier0Config.AdminOUs
        $allOUs += $tier0Config.ServiceAccountOUs
        $allOUs += $tier0Config.ComputerOUs
        $allOUs += $tier1Config.AdminOUs
        $allOUs += $tier1Config.ServiceAccountOUs
        $allOUs += $tier1Config.ComputerOUs
        
        foreach ($ou in $allOUs) {
            if (-not $ou) { continue }
            
            # Skip if fully qualified for different domain
            if ($ou -match 'DC=' -and $ou -notlike "*$domainDN") { continue }
            
            if (-not (Test-OUExists -OUPath $ou -DomainDN $domainDN -Server $dc)) {
                New-OUPath -OUPath $ou -DomainDN $domainDN -Server $dc
            }
        }
    }
    
    #endregion
    
    #region Create GMSA
    
    Write-Host ""
    Write-Step "Creating Group Managed Service Account..."
    
    $gmsa = New-TierGuardServiceAccount -Name $gmsaNameInput `
        -DomainControllersCanRetrieve `
        -AddToEnterpriseAdmins
    
    Write-SubStep "GMSA: $($gmsa.Name)"
    
    #endregion
    
    #region Create Computer Groups
    
    Write-Host ""
    Write-Step "Creating tier computer groups..."
    
    if ($scope -eq 'Tier-0' -or $scope -eq 'All-Tiers') {
        $t0Group = New-TierComputerGroup -TierLevel 0 -GroupName $tier0Config.ComputerGroup
        Write-SubStep "Tier 0 Group: $($t0Group.Name) (SID: $($t0Group.SID))"
    }
    
    if ($scope -eq 'Tier-1' -or $scope -eq 'All-Tiers') {
        $t1Group = New-TierComputerGroup -TierLevel 1 -GroupName $tier1Config.ComputerGroup
        Write-SubStep "Tier 1 Group: $($t1Group.Name) (SID: $($t1Group.SID))"
    }
    
    # Wait for replication
    Start-Sleep -Seconds 3
    
    #endregion
    
    #region Create Authentication Policies
    
    Write-Host ""
    Write-Step "Creating Kerberos Authentication Policies..."
    
    if ($scope -eq 'Tier-0' -or $scope -eq 'All-Tiers') {
        $t0Group = Get-ADGroup -Identity $tier0Config.ComputerGroup
        $t0Policy = New-TierAuthPolicy -Name $tier0Config.PolicyName `
            -TierLevel 0 `
            -ComputerGroupSID $t0Group.SID.Value `
            -TGTLifetimeMinutes $tier0Config.TGTLifetimeMinutes `
            -Enforce:$false
        
        Write-SubStep "Tier 0 Policy: $($t0Policy.Name)"
    }
    
    if ($scope -eq 'Tier-1' -or $scope -eq 'All-Tiers') {
        $t0Group = Get-ADGroup -Identity $tier0Config.ComputerGroup
        $t1Group = Get-ADGroup -Identity $tier1Config.ComputerGroup
        
        $t1Policy = New-TierAuthPolicy -Name $tier1Config.PolicyName `
            -TierLevel 1 `
            -ComputerGroupSID $t1Group.SID.Value `
            -IncludeTier0Computers `
            -Tier0ComputerGroupSID $t0Group.SID.Value `
            -TGTLifetimeMinutes $tier1Config.TGTLifetimeMinutes `
            -Enforce:$false
        
        Write-SubStep "Tier 1 Policy: $($t1Policy.Name)"
    }
    
    #endregion
    
    #region Deploy to SYSVOL
    
    Write-Host ""
    Write-Step "Deploying to SYSVOL..."
    
    $deployment = Publish-TierGuardToSysvol -SourcePath $Script:ScriptPath -Configuration $configuration
    Write-SubStep "Scripts deployed to: $($deployment.BasePath)"
    Write-SubStep "Config: $($deployment.ConfigPath)"
    
    #endregion
    
    #region Create GPO
    
    if (-not $SkipGpo) {
        Write-Host ""
        Write-Step "Creating Group Policy Object..."
        
        $gpo = New-TierGuardGpo -Name $Script:Defaults.GpoName `
            -ScriptsPath $deployment.BasePath `
            -GmsaName $gmsaNameInput `
            -Tier0Enabled:($scope -eq 'Tier-0' -or $scope -eq 'All-Tiers') `
            -Tier1Enabled:($scope -eq 'Tier-1' -or $scope -eq 'All-Tiers')
        
        Write-SubStep "GPO: $($gpo.Name)"
        
        # Link to Domain Controllers OU
        Set-TierGuardGpoLink -GpoName $Script:Defaults.GpoName -Enabled:$false
        Write-SubStep "GPO linked (DISABLED) to Domain Controllers OU"
        
        Write-Host ""
        Write-Warning @"
GPO SCHEDULED TASKS MUST BE CONFIGURED MANUALLY:

1. Open Group Policy Management
2. Edit '$($Script:Defaults.GpoName)'
3. Navigate to: Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks
4. Create the following tasks:

   Task: 'TierGuard Computer Sync - Tier 0'
   - Action: Start a program
   - Program: powershell.exe
   - Arguments: -ExecutionPolicy Bypass -NoProfile -File "$($deployment.BasePath)\Sync-TierComputers.ps1" -Scope Tier-0
   - Run as: SYSTEM
   - Trigger: Daily, repeat every 10 minutes

   Task: 'TierGuard Computer Sync - Tier 1'
   - (Same as above with -Scope Tier-1)

   Task: 'TierGuard User Sync - Tier 0'
   - Action: Start a program
   - Program: powershell.exe
   - Arguments: -ExecutionPolicy Bypass -NoProfile -File "$($deployment.BasePath)\Sync-TierUsers.ps1" -Scope Tier-0
   - Run as: $($gmsaNameInput)$
   - Trigger: Daily, repeat every 10 minutes

   Task: 'TierGuard User Sync - Tier 1'
   - (Same as above with -Scope Tier-1)

5. Enable the GPO link when ready
"@
    }
    
    #endregion
    
    #region Enable Kerberos Armoring
    
    if (-not $SkipKerberosArmoring) {
        Write-Host ""
        if (-not $Force) {
            $enableArmoring = Read-Host "Enable Kerberos Armoring via GPO? ([y]/n)"
        }
        else {
            $enableArmoring = 'y'
        }
        
        if ($enableArmoring -notlike 'n*') {
            Write-Step "Enabling Kerberos Armoring..."
            
            foreach ($domain in $selectedDomains) {
                Enable-KerberosArmoring -DomainDNS $domain
            }
        }
    }
    
    #endregion
    
    #region Completion
    
    Write-Host ""
    Write-Banner "Installation Complete" -Color Green
    
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "1. Configure scheduled tasks in the GPO (see instructions above)" -ForegroundColor White
    Write-Host "2. Move computer groups to protected OUs" -ForegroundColor White
    Write-Host "3. Wait for computer sync to run and populate groups" -ForegroundColor White
    Write-Host "4. Reboot all Tier 0/1 servers to refresh Kerberos tickets" -ForegroundColor White
    Write-Host "5. Test authentication with a tier admin account" -ForegroundColor White
    Write-Host "6. Enable the GPO link when ready" -ForegroundColor White
    Write-Host "7. Enable user sync scheduled tasks (currently disabled)" -ForegroundColor White
    Write-Host ""
    Write-Host "Configuration file: $($deployment.ConfigPath)" -ForegroundColor Cyan
    Write-Host "GMSA: $gmsaNameInput" -ForegroundColor Cyan
    Write-Host ""
    
    #endregion
}

#endregion

# Run installation
Install-TierGuardForest
