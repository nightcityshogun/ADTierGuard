<#
.SYNOPSIS
    TierGuard Computer Synchronization Script for Domain Controllers
    
.DESCRIPTION
    This script runs on Domain Controllers via GPO-deployed scheduled tasks.
    It synchronizes computer objects into tier-specific groups for use in
    Kerberos Authentication Policy claims.
    
    The script:
    - Scans configured OUs for computer objects
    - Adds computers to the appropriate tier group
    - Removes computers that are no longer in tier OUs
    - Logs all operations to Windows Event Log
    
.PARAMETER ConfigFile
    Path to TierGuard.config. Defaults to SYSVOL location.
    
.PARAMETER Scope
    Which tier to process: Tier-0, Tier-1, or All-Tiers
    
.PARAMETER WhatIf
    Show what would happen without making changes
    
.NOTES
    Version: 1.0.0
    Runs as: NT AUTHORITY\SYSTEM
    Schedule: Every 10 minutes via GPO
    
    Event IDs:
    1000 - Script started
    1001 - Script completed
    1100 - Computer added to group
    1101 - Computer removed from group
    1200 - Error occurred
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$ConfigFile,
    
    [Parameter()]
    [ValidateSet('Tier-0', 'Tier-1', 'All-Tiers')]
    [string]$Scope
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Constants

$Script:EventSource = 'TierGuard'
$Script:EventLogName = 'Application'
$Script:LogFile = $null

# Event IDs
$Script:EventIds = @{
    ScriptStarted = 1000
    ScriptCompleted = 1001
    ComputerAdded = 1100
    ComputerRemoved = 1101
    ErrorOccurred = 1200
    ConfigLoaded = 1010
    GroupNotFound = 1201
    OUNotFound = 1202
}

#endregion

#region Logging Functions

function Initialize-EventLog {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Script:EventSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource($Script:EventSource, $Script:EventLogName)
        }
    }
    catch {
        # May fail if not running as admin first time - continue anyway
    }
}

function Write-TierGuardLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity = 'Information',
        
        [Parameter()]
        [int]$EventId = 1000
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Severity] $Message"
    
    # Write to debug log file
    if ($Script:LogFile) {
        try {
            Add-Content -Path $Script:LogFile -Value $logMessage -ErrorAction SilentlyContinue
        }
        catch { }
    }
    
    # Write to Event Log
    try {
        $entryType = switch ($Severity) {
            'Warning' { [System.Diagnostics.EventLogEntryType]::Warning }
            'Error' { [System.Diagnostics.EventLogEntryType]::Error }
            default { [System.Diagnostics.EventLogEntryType]::Information }
        }
        
        Write-EventLog -LogName $Script:EventLogName -Source $Script:EventSource `
            -EventId $EventId -EntryType $entryType -Message $Message -ErrorAction SilentlyContinue
    }
    catch { }
    
    # Console output
    switch ($Severity) {
        'Warning' { Write-Warning $Message }
        'Error' { Write-Host $Message -ForegroundColor Red }
        default { Write-Verbose $Message }
    }
}

#endregion

#region Configuration Functions

function Get-TierGuardConfig {
    param([string]$Path)
    
    if (-not $Path) {
        $domainDns = (Get-ADDomain).DNSRoot
        $Path = "\\$domainDns\SYSVOL\$domainDns\scripts\TierGuard\TierGuard.config"
    }
    
    if (-not (Test-Path $Path)) {
        throw "Configuration file not found: $Path"
    }
    
    $config = Get-Content -Path $Path -Raw | ConvertFrom-Json
    
    # Convert to hashtable for easier manipulation
    $result = @{
        SchemaVersion = $config.SchemaVersion
        Scope = $config.Scope
        Domains = @($config.Domains)
        ProtectedUsers = $config.ProtectedUsers
        PrivilegedGroupCleanup = $config.PrivilegedGroupCleanup
        Tier0 = @{
            AdminOUs = @($config.Tier0.AdminOUs)
            ServiceAccountOUs = @($config.Tier0.ServiceAccountOUs)
            ComputerOUs = @($config.Tier0.ComputerOUs)
            ComputerGroup = $config.Tier0.ComputerGroup
            PolicyName = $config.Tier0.PolicyName
            TGTLifetimeMinutes = $config.Tier0.TGTLifetimeMinutes
        }
        Tier1 = @{
            AdminOUs = @($config.Tier1.AdminOUs)
            ServiceAccountOUs = @($config.Tier1.ServiceAccountOUs)
            ComputerOUs = @($config.Tier1.ComputerOUs)
            ComputerGroup = $config.Tier1.ComputerGroup
            PolicyName = $config.Tier1.PolicyName
            TGTLifetimeMinutes = $config.Tier1.TGTLifetimeMinutes
        }
    }
    
    # Set log path
    if ($config.LogPath) {
        $Script:LogFile = Join-Path $config.LogPath "TierGuard-Computer-$(Get-Date -Format 'yyyyMMdd').log"
    }
    else {
        $Script:LogFile = Join-Path $env:LOCALAPPDATA "TierGuard\TierGuard-Computer-$(Get-Date -Format 'yyyyMMdd').log"
        $logDir = Split-Path $Script:LogFile -Parent
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    }
    
    return $result
}

#endregion

#region OU Path Functions

function Resolve-TierOU {
    param(
        [Parameter(Mandatory)]
        [string]$OUPath,
        
        [Parameter(Mandatory)]
        [string]$DomainDN
    )
    
    # If already fully qualified, return as-is if it matches this domain
    if ($OUPath -match 'DC=') {
        if ($OUPath -like "*$DomainDN") {
            return $OUPath
        }
        return $null  # Different domain
    }
    
    # Relative path - append domain DN
    return "$OUPath,$DomainDN"
}

function Get-ComputersInOU {
    param(
        [Parameter(Mandatory)]
        [string]$SearchBase,
        
        [Parameter(Mandatory)]
        [string]$Server
    )
    
    try {
        $computers = Get-ADComputer -Filter * -SearchBase $SearchBase -SearchScope Subtree `
            -Properties DistinguishedName, Name, Enabled -Server $Server -ErrorAction Stop
        
        return @($computers | Where-Object { $_.Enabled })
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-TierGuardLog -Message "OU not found: $SearchBase" -Severity Warning -EventId $Script:EventIds.OUNotFound
        return @()
    }
    catch {
        Write-TierGuardLog -Message "Error searching OU $SearchBase`: $_" -Severity Error -EventId $Script:EventIds.ErrorOccurred
        return @()
    }
}

#endregion

#region Group Management Functions

function Get-TierComputerGroupMembers {
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,
        
        [Parameter()]
        [string]$Server
    )
    
    try {
        $params = @{
            Identity = $GroupName
            Properties = 'Members'
        }
        if ($Server) { $params.Server = $Server }
        
        $group = Get-ADGroup @params -ErrorAction Stop
        $members = @{}
        
        foreach ($memberDN in $group.Members) {
            $members[$memberDN] = $true
        }
        
        return @{
            Group = $group
            Members = $members
            MemberCount = $group.Members.Count
        }
    }
    catch {
        Write-TierGuardLog -Message "Failed to get group $GroupName`: $_" -Severity Error -EventId $Script:EventIds.GroupNotFound
        return $null
    }
}

function Add-ComputerToTierGroup {
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADComputer]$Computer,
        
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$Group,
        
        [Parameter()]
        [string]$Server
    )
    
    if ($WhatIfPreference) {
        Write-Host "WhatIf: Would add $($Computer.Name) to $($Group.Name)" -ForegroundColor Cyan
        return $true
    }
    
    try {
        $params = @{
            Identity = $Group
            Members = $Computer
        }
        if ($Server) { $params.Server = $Server }
        
        Add-ADGroupMember @params -ErrorAction Stop
        
        Write-TierGuardLog -Message "Added computer $($Computer.Name) to group $($Group.Name)" `
            -Severity Information -EventId $Script:EventIds.ComputerAdded
        
        return $true
    }
    catch {
        Write-TierGuardLog -Message "Failed to add $($Computer.Name) to $($Group.Name): $_" `
            -Severity Error -EventId $Script:EventIds.ErrorOccurred
        return $false
    }
}

function Remove-ComputerFromTierGroup {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerDN,
        
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$Group,
        
        [Parameter()]
        [string]$Server
    )
    
    if ($WhatIfPreference) {
        Write-Host "WhatIf: Would remove $ComputerDN from $($Group.Name)" -ForegroundColor Cyan
        return $true
    }
    
    try {
        $params = @{
            Identity = $Group
            Members = $ComputerDN
        }
        if ($Server) { $params.Server = $Server }
        
        Remove-ADGroupMember @params -Confirm:$false -ErrorAction Stop
        
        Write-TierGuardLog -Message "Removed computer $ComputerDN from group $($Group.Name)" `
            -Severity Information -EventId $Script:EventIds.ComputerRemoved
        
        return $true
    }
    catch {
        Write-TierGuardLog -Message "Failed to remove $ComputerDN from $($Group.Name): $_" `
            -Severity Error -EventId $Script:EventIds.ErrorOccurred
        return $false
    }
}

#endregion

#region Main Sync Function

function Sync-TierComputers {
    param(
        [Parameter(Mandatory)]
        [int]$TierLevel,
        
        [Parameter(Mandatory)]
        [hashtable]$Config,
        
        [Parameter(Mandatory)]
        [string]$Domain
    )
    
    $tierConfig = if ($TierLevel -eq 0) { $Config.Tier0 } else { $Config.Tier1 }
    $groupName = $tierConfig.ComputerGroup
    
    Write-TierGuardLog -Message "Starting Tier $TierLevel computer sync for domain $Domain" `
        -Severity Information -EventId $Script:EventIds.ScriptStarted
    
    # Get domain info
    $domainObj = Get-ADDomain -Server $Domain
    $domainDN = $domainObj.DistinguishedName
    $dc = $domainObj.PDCEmulator
    
    # Get current group members
    $groupInfo = Get-TierComputerGroupMembers -GroupName $groupName -Server $dc
    if (-not $groupInfo) {
        Write-TierGuardLog -Message "Tier $TierLevel computer group '$groupName' not found" `
            -Severity Error -EventId $Script:EventIds.GroupNotFound
        return @{ Added = 0; Removed = 0; Errors = 1 }
    }
    
    $currentMembers = $groupInfo.Members
    $group = $groupInfo.Group
    $expectedMembers = @{}
    
    # Collect all computers from tier OUs
    foreach ($ouPath in $tierConfig.ComputerOUs) {
        $resolvedOU = Resolve-TierOU -OUPath $ouPath -DomainDN $domainDN
        if (-not $resolvedOU) { continue }
        
        $computers = Get-ComputersInOU -SearchBase $resolvedOU -Server $dc
        foreach ($computer in $computers) {
            $expectedMembers[$computer.DistinguishedName] = $computer
        }
    }
    
    # For Tier 0, include Domain Controllers
    if ($TierLevel -eq 0) {
        $dcs = Get-ADComputer -Filter * -SearchBase $domainObj.DomainControllersContainer `
            -Server $dc -Properties DistinguishedName, Name, Enabled
        foreach ($dcComputer in $dcs) {
            if ($dcComputer.Enabled) {
                $expectedMembers[$dcComputer.DistinguishedName] = $dcComputer
            }
        }
    }
    
    $stats = @{ Added = 0; Removed = 0; Errors = 0 }
    
    # Add missing computers
    foreach ($computerDN in $expectedMembers.Keys) {
        if (-not $currentMembers.ContainsKey($computerDN)) {
            $success = Add-ComputerToTierGroup -Computer $expectedMembers[$computerDN] -Group $group -Server $dc
            if ($success) { $stats.Added++ } else { $stats.Errors++ }
        }
    }
    
    # Remove computers no longer in tier OUs
    foreach ($memberDN in $currentMembers.Keys) {
        if (-not $expectedMembers.ContainsKey($memberDN)) {
            # Verify this computer is from our domain
            if ($memberDN -like "*$domainDN") {
                $success = Remove-ComputerFromTierGroup -ComputerDN $memberDN -Group $group -Server $dc
                if ($success) { $stats.Removed++ } else { $stats.Errors++ }
            }
        }
    }
    
    Write-TierGuardLog -Message "Tier $TierLevel sync complete. Added: $($stats.Added), Removed: $($stats.Removed), Errors: $($stats.Errors)" `
        -Severity Information -EventId $Script:EventIds.ScriptCompleted
    
    return $stats
}

#endregion

#region Main Entry Point

try {
    Initialize-EventLog
    
    # Load configuration
    $config = Get-TierGuardConfig -Path $ConfigFile
    
    Write-TierGuardLog -Message "TierGuard Computer Sync started. Config loaded from $ConfigFile" `
        -Severity Information -EventId $Script:EventIds.ConfigLoaded
    
    # Determine scope
    $effectiveScope = if ($Scope) { $Scope } else { $config.Scope }
    
    # Validate scope against config
    if ($effectiveScope -ne 'All-Tiers' -and $effectiveScope -ne $config.Scope -and $config.Scope -ne 'All-Tiers') {
        Write-TierGuardLog -Message "Scope '$effectiveScope' not enabled in configuration (config scope: $($config.Scope))" `
            -Severity Warning -EventId $Script:EventIds.ErrorOccurred
        exit 0
    }
    
    $totalStats = @{ Added = 0; Removed = 0; Errors = 0 }
    
    # Process each domain
    foreach ($domain in $config.Domains) {
        try {
            # Tier 0
            if ($effectiveScope -eq 'Tier-0' -or $effectiveScope -eq 'All-Tiers') {
                $stats = Sync-TierComputers -TierLevel 0 -Config $config -Domain $domain
                $totalStats.Added += $stats.Added
                $totalStats.Removed += $stats.Removed
                $totalStats.Errors += $stats.Errors
            }
            
            # Tier 1
            if ($effectiveScope -eq 'Tier-1' -or $effectiveScope -eq 'All-Tiers') {
                $stats = Sync-TierComputers -TierLevel 1 -Config $config -Domain $domain
                $totalStats.Added += $stats.Added
                $totalStats.Removed += $stats.Removed
                $totalStats.Errors += $stats.Errors
            }
        }
        catch {
            Write-TierGuardLog -Message "Error processing domain $domain`: $_" `
                -Severity Error -EventId $Script:EventIds.ErrorOccurred
            $totalStats.Errors++
        }
    }
    
    Write-TierGuardLog -Message "TierGuard Computer Sync complete. Total - Added: $($totalStats.Added), Removed: $($totalStats.Removed), Errors: $($totalStats.Errors)" `
        -Severity Information -EventId $Script:EventIds.ScriptCompleted
    
    if ($totalStats.Errors -gt 0) {
        exit 1
    }
}
catch {
    Write-TierGuardLog -Message "Fatal error: $_" -Severity Error -EventId $Script:EventIds.ErrorOccurred
    exit 1
}

exit 0
