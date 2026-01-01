<#
.SYNOPSIS
    ADTierGuard - Tier Computer Synchronization
    
.DESCRIPTION
    Manages computer objects for Tier 0 and Tier 1 isolation by synchronizing
    group membership based on OU location. Computers in configured OUs are 
    automatically added to the tier computer group; computers no longer in 
    those OUs are removed.
    
    Uses pure ADSI operations with runspace-based parallel processing for
    high performance in large environments.
    
.PARAMETER ConfigurationPath
    Path to the ADTierGuard configuration JSON file.
    
.PARAMETER TierLevel
    The tier level to process (0 or 1).
    
.PARAMETER ForestScope
    Process all domains in the forest (overrides configuration setting).
    
.PARAMETER ThrottleLimit
    Maximum concurrent operations. Defaults to configuration value.
    
.PARAMETER WhatIf
    Shows what changes would be made without executing them.
    
.PARAMETER Confirm
    Prompts for confirmation before each change.
    
.EXAMPLE
    .\Invoke-TierComputerSync.ps1 -ConfigurationPath "C:\ADTierGuard\config.json" -TierLevel 0
    
    Synchronizes Tier 0 computer group membership.
    
.EXAMPLE
    .\Invoke-TierComputerSync.ps1 -ConfigurationPath "C:\ADTierGuard\config.json" -TierLevel 0 -WhatIf
    
    Shows what changes would be made without executing them.
    
.EXAMPLE
    .\Invoke-TierComputerSync.ps1 -ConfigurationPath "C:\ADTierGuard\config.json" -TierLevel 1 -ForestScope
    
    Processes all domains in the forest for Tier 1.
    
.OUTPUTS
    PSCustomObject with sync results including:
    - TierLevel, Duration, DomainsProcessed
    - TotalComputers, Added, Removed, Errors
    - DomainResults array with per-domain details
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.0.0
    License: GPL-3.0
    
    Prerequisites:
    - PowerShell 5.1 or later
    - Domain connectivity
    - Appropriate permissions to modify group membership
    
.LINK
    https://github.com/ADTierGuard/ADTierGuard
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'Path to configuration JSON file')]
    [ValidateScript({ 
        if (-not (Test-Path $_)) { throw "Configuration file not found: $_" }
        if ($_ -notmatch '\.json$') { throw "Configuration must be a JSON file" }
        $true
    })]
    [string]$ConfigurationPath,
    
    [Parameter(Mandatory = $true, Position = 1, HelpMessage = 'Tier level (0 or 1)')]
    [ValidateSet(0, 1)]
    [int]$TierLevel,
    
    [Parameter(HelpMessage = 'Process all domains in forest')]
    [switch]$ForestScope,
    
    [Parameter(HelpMessage = 'Maximum concurrent operations')]
    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 0
)

#region Script Initialization

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Script-level state
$Script:StartTime = [DateTime]::UtcNow
$Script:ModulePath = Split-Path -Parent $PSScriptRoot
$Script:Config = $null
$Script:TierConfig = $null

# Import required modules (order matters - ForestTopology before SyncUtilities)
$requiredModules = @(
    'Core\AdsiOperations.psm1'
    'Core\ConfigurationManager.psm1'
    'Core\ForestTopology.psm1'
    'Core\SyncUtilities.psm1'
    'Engine\RunspaceEngine.psm1'
)

foreach ($moduleName in $requiredModules) {
    $modulePath = Join-Path $Script:ModulePath $moduleName
    if (-not (Test-Path $modulePath)) {
        throw "Required module not found: $modulePath"
    }
    Import-Module $modulePath -Force -ErrorAction Stop
}

#endregion

#region Computer Discovery Functions

<#
.SYNOPSIS
    Discovers computers in a specific OU.
#>
function Get-ComputersFromOU {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [string]$SearchBase,
        
        [Parameter(Mandatory)]
        [string]$Server,
        
        [Parameter()]
        [bool]$IncludeDomainControllers = $false
    )
    
    $computers = [System.Collections.Generic.List[hashtable]]::new()
    
    try {
        Write-SyncLog -Message "Discovering computers in: $SearchBase" -Level Verbose
        
        $results = Get-AdsiComputer -SearchBase $SearchBase -Server $Server
        
        foreach ($computer in $results) {
            $isDC = Test-AdsiDomainController -ComputerObject $computer
            
            if ($isDC -and -not $IncludeDomainControllers) {
                Write-SyncLog -Message "Excluding domain controller: $($computer.sAMAccountName)" -Level Verbose
                continue
            }
            
            $computers.Add($computer)
        }
        
        Write-SyncLog -Message "Found $($computers.Count) computers in: $SearchBase" -Level Verbose
    }
    catch {
        Write-SyncLog -Message "Error searching OU '$SearchBase': $($_.Exception.Message)" -Level Warning
    }
    
    return $computers
}

<#
.SYNOPSIS
    Collects all computers from configured tier OUs for a domain.
#>
function Get-TierComputersForDomain {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN,
        
        [Parameter(Mandatory)]
        [string]$DomainDnsName,
        
        [Parameter(Mandatory)]
        [string[]]$ComputerOUs,
        
        [Parameter()]
        [bool]$IncludeDomainControllers = $false
    )
    
    $allComputers = [System.Collections.Generic.List[hashtable]]::new()
    
    foreach ($ouPath in $ComputerOUs) {
        $fullPath = Resolve-OUPathForDomain -OUPath $ouPath -DomainDN $DomainDN
        
        if ($null -eq $fullPath) {
            # OU belongs to different domain, skip
            continue
        }
        
        $computers = Get-ComputersFromOU -SearchBase $fullPath -Server $DomainDnsName `
            -IncludeDomainControllers $IncludeDomainControllers
        
        foreach ($computer in $computers) {
            $allComputers.Add($computer)
        }
    }
    
    return $allComputers
}

#endregion

#region Group Management Functions

<#
.SYNOPSIS
    Locates the tier computer group in a domain.
#>
function Get-TierGroupDN {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,
        
        [Parameter(Mandatory)]
        [string]$DomainDN,
        
        [Parameter()]
        [string]$Server
    )
    
    $filter = "(&(objectClass=group)(sAMAccountName=$GroupName))"
    $results = Search-AdsiDirectory -SearchBase $DomainDN -LdapFilter $filter `
        -Properties @('distinguishedName') -Server $Server
    
    if ($results.Count -gt 0) {
        return $results[0].distinguishedName
    }
    
    return $null
}

<#
.SYNOPSIS
    Synchronizes computer group membership using parallel operations.
#>
function Sync-ComputerGroupMembership {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$TargetComputers,
        
        [Parameter(Mandatory)]
        [string]$GroupDN,
        
        [Parameter(Mandatory)]
        [string]$Server,
        
        [Parameter()]
        [int]$ThrottleLimit = 4
    )
    
    $eventIds = Get-TierGuardEventIds
    $stats = @{
        Added   = 0
        Removed = 0
        Errors  = 0
    }
    
    # Build target set from computers
    $targetDNs = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($computer in $TargetComputers) {
        [void]$targetDNs.Add($computer.distinguishedName)
    }
    
    # Get current group members
    Write-SyncLog -Message "Retrieving current members of: $GroupDN" -Level Verbose
    $currentMembers = Get-AdsiGroupMember -GroupDistinguishedName $GroupDN -Server $Server
    
    $currentMemberSet = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($member in $currentMembers) {
        [void]$currentMemberSet.Add($member)
    }
    
    # Calculate differential
    $toAdd = $TargetComputers | Where-Object { 
        -not $currentMemberSet.Contains($_.distinguishedName) 
    }
    
    $toRemove = $currentMembers | Where-Object { 
        -not $targetDNs.Contains($_) 
    }
    
    Write-SyncLog -Message "Differential: $($toAdd.Count) to add, $($toRemove.Count) to remove" -Level Information
    
    # Process additions
    if ($toAdd.Count -gt 0) {
        Write-SyncLog -Message "Adding $($toAdd.Count) computers to group" -Level Information
        
        $addScriptBlock = {
            param($GroupDN, $Server)
            try {
                Add-AdsiGroupMember -GroupDistinguishedName $GroupDN `
                    -MemberDistinguishedName $_.distinguishedName `
                    -Server $Server -Confirm:$false
                @{ Success = $true; DN = $_.distinguishedName; Name = $_.sAMAccountName }
            }
            catch {
                @{ Success = $false; DN = $_.distinguishedName; Name = $_.sAMAccountName; Error = $_.Exception.Message }
            }
        }
        
        if ($PSCmdlet.ShouldProcess("$($toAdd.Count) computers", "Add to group '$GroupDN'")) {
            $addResults = $toAdd | Invoke-ParallelOperation -ScriptBlock $addScriptBlock `
                -ThrottleLimit $ThrottleLimit `
                -ArgumentList @{ GroupDN = $GroupDN; Server = $Server } `
                -ShowProgress -ProgressActivity "Adding computers to tier group"
            
            foreach ($result in $addResults) {
                if ($result.Output.Success) {
                    $stats.Added++
                    Write-SyncLog -Message "Added: $($result.Output.Name)" -Level Verbose `
                        -EventId $eventIds.ComputerAddedToGroup
                }
                else {
                    $stats.Errors++
                    Write-SyncLog -Message "Failed to add $($result.Output.Name): $($result.Output.Error)" -Level Warning
                }
            }
        }
    }
    
    # Process removals
    if ($toRemove.Count -gt 0) {
        Write-SyncLog -Message "Removing $($toRemove.Count) computers from group" -Level Information
        
        $removeScriptBlock = {
            param($GroupDN, $Server)
            try {
                Remove-AdsiGroupMember -GroupDistinguishedName $GroupDN `
                    -MemberDistinguishedName $_ `
                    -Server $Server -Confirm:$false
                @{ Success = $true; DN = $_ }
            }
            catch {
                @{ Success = $false; DN = $_; Error = $_.Exception.Message }
            }
        }
        
        if ($PSCmdlet.ShouldProcess("$($toRemove.Count) computers", "Remove from group '$GroupDN'")) {
            $removeResults = $toRemove | Invoke-ParallelOperation -ScriptBlock $removeScriptBlock `
                -ThrottleLimit $ThrottleLimit `
                -ArgumentList @{ GroupDN = $GroupDN; Server = $Server } `
                -ShowProgress -ProgressActivity "Removing computers from tier group"
            
            foreach ($result in $removeResults) {
                if ($result.Output.Success) {
                    $stats.Removed++
                    Write-SyncLog -Message "Removed: $($result.Output.DN)" -Level Verbose `
                        -EventId $eventIds.ComputerRemovedFromGroup
                }
                else {
                    $stats.Errors++
                    Write-SyncLog -Message "Failed to remove $($result.Output.DN): $($result.Output.Error)" -Level Warning
                }
            }
        }
    }
    
    return $stats
}

#endregion

#region Domain Processing

<#
.SYNOPSIS
    Processes a single domain for computer synchronization.
#>
function Invoke-DomainComputerSync {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Domain,
        
        [Parameter(Mandatory)]
        [hashtable]$TierConfig,
        
        [Parameter()]
        [int]$ThrottleLimit = 4
    )
    
    $domainDN = $Domain.DistinguishedName
    $domainDns = $Domain.DnsName
    
    Write-SyncLog -Message "Processing domain: $domainDns" -Level Information
    
    # Discover computers in tier OUs
    $computers = Get-TierComputersForDomain -DomainDN $domainDN -DomainDnsName $domainDns `
        -ComputerOUs $TierConfig.ComputerOUs `
        -IncludeDomainControllers ($TierConfig.IncludeDomainControllers -eq $true)
    
    Write-SyncLog -Message "Found $($computers.Count) computers in Tier $TierLevel OUs" -Level Information
    
    # Locate tier group
    $groupDN = Get-TierGroupDN -GroupName $TierConfig.ComputerGroupName `
        -DomainDN $domainDN -Server $domainDns
    
    if (-not $groupDN) {
        $msg = "Computer group '$($TierConfig.ComputerGroupName)' not found in $domainDns"
        Write-SyncLog -Message $msg -Level Warning
        return New-SyncOperationResult -Domain $domainDns -Success $false -Message $msg
    }
    
    # Synchronize membership
    $syncStats = Sync-ComputerGroupMembership -TargetComputers $computers.ToArray() `
        -GroupDN $groupDN -Server $domainDns -ThrottleLimit $ThrottleLimit
    
    return New-SyncOperationResult -Domain $domainDns -Success $true -AdditionalProperties @{
        ComputersFound = $computers.Count
        Added          = $syncStats.Added
        Removed        = $syncStats.Removed
        Errors         = $syncStats.Errors
    }
}

#endregion

#region Main Execution

try {
    # Load and validate configuration
    $Script:Config = Import-TierGuardConfiguration -Path $ConfigurationPath
    
    # Initialize shared utilities
    Initialize-SyncUtilities -Configuration $Script:Config -LogPrefix 'ComputerSync'
    
    # Initialize event logging
    Initialize-TierGuardEventLog -Source $Script:Config.General.EventLogSource
    
    $eventIds = Get-TierGuardEventIds
    Write-SyncLog -Message "=== Starting Tier $TierLevel Computer Sync ===" -Level Information `
        -EventId $eventIds.ComputerSyncStarted
    Write-SyncLog -Message "Configuration: $ConfigurationPath" -Level Verbose
    
    # Validate tier is enabled
    if (-not (Test-TierEnabled -Configuration $Script:Config -TierLevel $TierLevel)) {
        Write-SyncLog -Message "Tier $TierLevel is disabled in configuration. Exiting." -Level Warning
        exit 0
    }
    
    # Get tier-specific configuration
    $Script:TierConfig = Get-TierSpecificConfiguration -Configuration $Script:Config -TierLevel $TierLevel
    
    # Determine target domains (auto-discovered from forest topology)
    $useForestScope = $ForestScope.IsPresent -or $Script:Config.General.ForestScope
    $excludeDomains = if ($Script:Config.General.ExcludeDomains) { $Script:Config.General.ExcludeDomains } else { @() }
    $targetDomains = Get-SyncTargetDomains -ForestScope:$useForestScope -ExcludeDomains $excludeDomains
    
    Write-SyncLog -Message "Target domains: $($targetDomains.Count)" -Level Information
    foreach ($d in $targetDomains) {
        Write-SyncLog -Message "  - $($d.DnsName)" -Level Verbose
    }
    
    # Determine throttle limit
    $effectiveThrottle = Get-EffectiveThrottleLimit -ExplicitLimit $ThrottleLimit `
        -Configuration $Script:Config -Default 4
    Write-SyncLog -Message "Throttle limit: $effectiveThrottle" -Level Verbose
    
    # Process each domain
    $results = [System.Collections.Generic.List[hashtable]]::new()
    
    foreach ($domain in $targetDomains) {
        $result = Invoke-DomainComputerSync -Domain $domain -TierConfig $Script:TierConfig `
            -ThrottleLimit $effectiveThrottle
        $results.Add($result)
    }
    
    # Calculate totals
    $duration = [DateTime]::UtcNow - $Script:StartTime
    $totalComputers = ($results | Measure-Object -Property ComputersFound -Sum).Sum
    $totalAdded = ($results | Measure-Object -Property Added -Sum).Sum
    $totalRemoved = ($results | Measure-Object -Property Removed -Sum).Sum
    $totalErrors = ($results | Measure-Object -Property Errors -Sum).Sum
    $successfulDomains = ($results | Where-Object { $_.Success }).Count
    
    # Generate and log summary
    $summary = Format-SyncSummary -OperationType 'Computer' -TierLevel $TierLevel `
        -Duration $duration -Results $results.ToArray() -Metrics @{
            'Computers Found'   = 'ComputersFound'
            'Computers Added'   = 'Added'
            'Computers Removed' = 'Removed'
            'Errors'            = 'Errors'
        }
    
    Write-SyncLog -Message $summary -Level Information -EventId $eventIds.ComputerSyncCompleted
    
    # Return structured result object
    [PSCustomObject]@{
        TierLevel         = $TierLevel
        StartTime         = $Script:StartTime
        Duration          = $duration
        DomainsProcessed  = $targetDomains.Count
        SuccessfulDomains = $successfulDomains
        TotalComputers    = [int]$totalComputers
        Added             = [int]$totalAdded
        Removed           = [int]$totalRemoved
        Errors            = [int]$totalErrors
        DomainResults     = $results.ToArray()
    }
}
catch {
    $eventIds = Get-TierGuardEventIds
    $errorMessage = "FATAL: Tier $TierLevel Computer Sync failed: $($_.Exception.Message)"
    
    if (Test-SyncUtilitiesInitialized) {
        Write-SyncLog -Message $errorMessage -Level Error -EventId $eventIds.ComputerSyncFailed
        Write-SyncLog -Message "Stack trace: $($_.ScriptStackTrace)" -Level Error
    }
    else {
        Write-Error $errorMessage
    }
    
    throw
}

#endregion
