<#
.SYNOPSIS
    ADTierGuard - Tier Computer Management
    
.DESCRIPTION
    Manages computer objects for Tier 0 and Tier 1 isolation.
    Automatically adds/removes computers from tier groups based on OU location.
    Uses pure ADSI operations with runspace-based parallel processing.
    
.PARAMETER ConfigurationPath
    Path to the ADTierGuard configuration JSON file.
    
.PARAMETER TierLevel
    The tier level to process (0 or 1).
    
.PARAMETER ForestScope
    Process all domains in the forest (overrides config).
    
.PARAMETER WhatIf
    Shows what changes would be made without executing them.
    
.EXAMPLE
    .\Invoke-TierComputerSync.ps1 -ConfigurationPath "C:\ADTierGuard\config.json" -TierLevel 0
    
.EXAMPLE
    .\Invoke-TierComputerSync.ps1 -ConfigurationPath "C:\ADTierGuard\config.json" -TierLevel 0 -WhatIf
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.0.0
    License: GPL-3.0
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ConfigurationPath,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet(0, 1)]
    [int]$TierLevel,
    
    [Parameter()]
    [switch]$ForestScope,
    
    [Parameter()]
    [int]$ThrottleLimit = 0
)

#region Script Initialization

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Script:StartTime = [DateTime]::Now
$Script:ModulePath = Split-Path -Parent $PSScriptRoot

# Import modules
$modulesToImport = @(
    (Join-Path $Script:ModulePath 'Core\AdsiOperations.psm1'),
    (Join-Path $Script:ModulePath 'Engine\RunspaceEngine.psm1'),
    (Join-Path $Script:ModulePath 'Core\ConfigurationManager.psm1')
)

foreach ($module in $modulesToImport) {
    if (Test-Path $module) {
        Import-Module $module -Force
    }
    else {
        throw "Required module not found: $module"
    }
}

#endregion

#region Logging Functions

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Verbose', 'Information', 'Warning', 'Error')]
        [string]$Level = 'Information',
        
        [Parameter()]
        [int]$EventId = 0
    )
    
    $timestamp = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss.fff')
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Verbose'     { Write-Verbose $logMessage }
        'Information' { Write-Information $logMessage -InformationAction Continue }
        'Warning'     { Write-Warning $logMessage }
        'Error'       { Write-Error $logMessage }
    }
    
    # Write to log file if configured
    if ($Script:Config -and $Script:Config.General.LogPath) {
        $logFile = Join-Path $Script:Config.General.LogPath "ComputerSync_$(Get-Date -Format 'yyyyMMdd').log"
        Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    }
    
    # Write to event log
    if ($EventId -gt 0 -and $Script:Config) {
        $entryType = switch ($Level) {
            'Error'   { 'Error' }
            'Warning' { 'Warning' }
            default   { 'Information' }
        }
        Write-TierGuardEvent -Message $Message -EntryType $entryType `
            -EventId $EventId -Source $Script:Config.General.EventLogSource
    }
}

#endregion

#region Main Processing Functions

function Get-TierConfiguration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Tier
    )
    
    return switch ($Tier) {
        0 { $Script:Config.Tier0 }
        1 { $Script:Config.Tier1 }
    }
}

function Get-TargetDomains {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()
    
    $allDomains = Get-AdsiForestDomains
    
    # Filter by target domains if specified
    if ($Script:Config.Domains.TargetDomains.Count -gt 0) {
        $allDomains = $allDomains | Where-Object {
            $_.DnsName -in $Script:Config.Domains.TargetDomains -or
            $_.NetBIOSName -in $Script:Config.Domains.TargetDomains
        }
    }
    
    # Exclude specified domains
    if ($Script:Config.Domains.ExcludedDomains.Count -gt 0) {
        $allDomains = $allDomains | Where-Object {
            $_.DnsName -notin $Script:Config.Domains.ExcludedDomains -and
            $_.NetBIOSName -notin $Script:Config.Domains.ExcludedDomains
        }
    }
    
    return @($allDomains)
}

function Get-ComputersFromOU {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OUPath,
        
        [Parameter()]
        [string]$DomainDnsName
    )
    
    $computers = [System.Collections.Generic.List[hashtable]]::new()
    
    try {
        Write-Log "Searching for computers in OU: $OUPath" -Level Verbose
        
        $results = Get-AdsiComputer -SearchBase $OUPath -Server $DomainDnsName
        
        foreach ($computer in $results) {
            # Skip domain controllers unless explicitly configured
            if (-not (Test-AdsiDomainController -ComputerObject $computer)) {
                $computers.Add($computer)
            }
            elseif ($Script:TierConfig.IncludeDomainControllers -eq $true) {
                $computers.Add($computer)
            }
        }
        
        Write-Log "Found $($computers.Count) computers in OU: $OUPath" -Level Verbose
    }
    catch {
        Write-Log "Error searching OU '$OUPath': $_" -Level Warning
    }
    
    return $computers
}

function Get-TierGroupDistinguishedName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$DomainDN
    )
    
    $filter = "(&(objectClass=group)(sAMAccountName=$GroupName))"
    $results = Search-AdsiDirectory -SearchBase $DomainDN -LdapFilter $filter `
        -Properties @('distinguishedName')
    
    if ($results.Count -gt 0) {
        return $results[0].distinguishedName
    }
    
    return $null
}

function Sync-ComputerGroupMembership {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable[]]$TargetComputers,
        
        [Parameter(Mandatory = $true)]
        [string]$GroupDN,
        
        [Parameter(Mandatory = $true)]
        [string]$DomainDnsName
    )
    
    $eventIds = Get-TierGuardEventIds
    $addedCount = 0
    $removedCount = 0
    $errorCount = 0
    
    # Get current group members
    Write-Log "Getting current members of group: $GroupDN" -Level Verbose
    $currentMembers = Get-AdsiGroupMember -GroupDistinguishedName $GroupDN -Server $DomainDnsName
    $currentMemberSet = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($member in $currentMembers) {
        [void]$currentMemberSet.Add($member)
    }
    
    # Build target member set
    $targetMemberSet = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($computer in $TargetComputers) {
        [void]$targetMemberSet.Add($computer.distinguishedName)
    }
    
    # Determine additions and removals
    $toAdd = $TargetComputers | Where-Object { -not $currentMemberSet.Contains($_.distinguishedName) }
    $toRemove = $currentMembers | Where-Object { -not $targetMemberSet.Contains($_) }
    
    # Process additions in parallel
    if ($toAdd.Count -gt 0) {
        Write-Log "Adding $($toAdd.Count) computers to group" -Level Information
        
        $addScript = {
            param($GroupDN, $DomainDnsName)
            
            try {
                Add-AdsiGroupMember -GroupDistinguishedName $GroupDN `
                    -MemberDistinguishedName $_.distinguishedName `
                    -Server $DomainDnsName -Confirm:$false
                
                return @{
                    Success = $true
                    Computer = $_.distinguishedName
                    Action = 'Added'
                }
            }
            catch {
                return @{
                    Success = $false
                    Computer = $_.distinguishedName
                    Action = 'Add'
                    Error = $_.Exception.Message
                }
            }
        }
        
        $throttle = if ($ThrottleLimit -gt 0) { $ThrottleLimit } else { $Script:Config.General.MaxParallelOperations }
        
        if ($PSCmdlet.ShouldProcess("$($toAdd.Count) computers", "Add to group '$GroupDN'")) {
            $addResults = $toAdd | Invoke-ParallelOperation -ScriptBlock $addScript `
                -ThrottleLimit $throttle `
                -ArgumentList @{ GroupDN = $GroupDN; DomainDnsName = $DomainDnsName } `
                -ShowProgress -ProgressActivity "Adding computers to tier group"
            
            foreach ($result in $addResults) {
                if ($result.Output.Success) {
                    $addedCount++
                    Write-Log "Added computer to group: $($result.Output.Computer)" -Level Verbose `
                        -EventId $eventIds.ComputerAddedToGroup
                }
                else {
                    $errorCount++
                    Write-Log "Failed to add computer: $($result.Output.Computer) - $($result.Output.Error)" -Level Warning
                }
            }
        }
    }
    
    # Process removals in parallel
    if ($toRemove.Count -gt 0) {
        Write-Log "Removing $($toRemove.Count) computers from group" -Level Information
        
        $removeScript = {
            param($GroupDN, $DomainDnsName)
            
            try {
                Remove-AdsiGroupMember -GroupDistinguishedName $GroupDN `
                    -MemberDistinguishedName $_ `
                    -Server $DomainDnsName -Confirm:$false
                
                return @{
                    Success = $true
                    Computer = $_
                    Action = 'Removed'
                }
            }
            catch {
                return @{
                    Success = $false
                    Computer = $_
                    Action = 'Remove'
                    Error = $_.Exception.Message
                }
            }
        }
        
        if ($PSCmdlet.ShouldProcess("$($toRemove.Count) computers", "Remove from group '$GroupDN'")) {
            $removeResults = $toRemove | Invoke-ParallelOperation -ScriptBlock $removeScript `
                -ThrottleLimit $throttle `
                -ArgumentList @{ GroupDN = $GroupDN; DomainDnsName = $DomainDnsName } `
                -ShowProgress -ProgressActivity "Removing computers from tier group"
            
            foreach ($result in $removeResults) {
                if ($result.Output.Success) {
                    $removedCount++
                    Write-Log "Removed computer from group: $($result.Output.Computer)" -Level Verbose `
                        -EventId $eventIds.ComputerRemovedFromGroup
                }
                else {
                    $errorCount++
                    Write-Log "Failed to remove computer: $($result.Output.Computer) - $($result.Output.Error)" -Level Warning
                }
            }
        }
    }
    
    return @{
        Added   = $addedCount
        Removed = $removedCount
        Errors  = $errorCount
    }
}

function Invoke-DomainComputerSync {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Domain
    )
    
    $domainDN = $Domain.DistinguishedName
    $domainDns = $Domain.DnsName
    
    Write-Log "Processing domain: $domainDns" -Level Information
    
    # Get all computers from configured OUs
    $allComputers = [System.Collections.Generic.List[hashtable]]::new()
    
    foreach ($ouPath in $Script:TierConfig.ComputerOUs) {
        $fullPath = if ($ouPath -match 'DC=') {
            # Full DN - check if it belongs to this domain
            $pathDomain = Get-AdsiDomainFromDN -DistinguishedName $ouPath
            if ($pathDomain -ne $domainDN) { continue }
            $ouPath
        }
        else {
            "$ouPath,$domainDN"
        }
        
        $computers = Get-ComputersFromOU -OUPath $fullPath -DomainDnsName $domainDns
        foreach ($computer in $computers) {
            $allComputers.Add($computer)
        }
    }
    
    Write-Log "Found $($allComputers.Count) total computers in Tier $TierLevel OUs for domain $domainDns" -Level Information
    
    # Get or create tier group
    $groupDN = Get-TierGroupDistinguishedName -GroupName $Script:TierConfig.ComputerGroupName -DomainDN $domainDN
    
    if (-not $groupDN) {
        Write-Log "Tier $TierLevel computer group '$($Script:TierConfig.ComputerGroupName)' not found in domain $domainDns" -Level Warning
        return @{
            Domain  = $domainDns
            Success = $false
            Message = "Computer group not found"
        }
    }
    
    # Sync group membership
    $syncResult = Sync-ComputerGroupMembership -TargetComputers $allComputers.ToArray() `
        -GroupDN $groupDN -DomainDnsName $domainDns
    
    return @{
        Domain         = $domainDns
        Success        = $true
        ComputersFound = $allComputers.Count
        Added          = $syncResult.Added
        Removed        = $syncResult.Removed
        Errors         = $syncResult.Errors
    }
}

#endregion

#region Main Execution

try {
    # Load configuration
    Write-Log "Loading configuration from: $ConfigurationPath" -Level Information
    $Script:Config = Import-TierGuardConfiguration -Path $ConfigurationPath
    
    # Initialize event logging
    Initialize-TierGuardEventLog -Source $Script:Config.General.EventLogSource
    
    $eventIds = Get-TierGuardEventIds
    Write-Log "Starting Tier $TierLevel Computer Sync" -Level Information -EventId $eventIds.ComputerSyncStarted
    
    # Get tier-specific configuration
    $Script:TierConfig = Get-TierConfiguration -Tier $TierLevel
    
    if (-not $Script:TierConfig.Enabled) {
        Write-Log "Tier $TierLevel is not enabled in configuration. Exiting." -Level Warning
        exit 0
    }
    
    # Override forest scope if specified
    if ($ForestScope) {
        $Script:Config.General.ForestScope = $true
    }
    
    # Get target domains
    $targetDomains = if ($Script:Config.General.ForestScope) {
        Get-TargetDomains
    }
    else {
        $rootDse = Get-AdsiRootDse
        @(@{
            DistinguishedName = $rootDse.DefaultNamingContext
            DnsName           = $rootDse.DnsHostName -replace '^[^.]+\.'
            NetBIOSName       = ($rootDse.DefaultNamingContext -split ',' | 
                Where-Object { $_ -like 'DC=*' } | 
                Select-Object -First 1) -replace 'DC='
        })
    }
    
    Write-Log "Processing $($targetDomains.Count) domain(s)" -Level Information
    
    # Process each domain
    $results = [System.Collections.Generic.List[hashtable]]::new()
    
    foreach ($domain in $targetDomains) {
        $result = Invoke-DomainComputerSync -Domain $domain
        $results.Add($result)
    }
    
    # Generate summary
    $totalComputers = ($results | Measure-Object -Property ComputersFound -Sum).Sum
    $totalAdded = ($results | Measure-Object -Property Added -Sum).Sum
    $totalRemoved = ($results | Measure-Object -Property Removed -Sum).Sum
    $totalErrors = ($results | Measure-Object -Property Errors -Sum).Sum
    $successfulDomains = ($results | Where-Object { $_.Success }).Count
    
    $duration = [DateTime]::Now - $Script:StartTime
    
    $summary = @"
Tier $TierLevel Computer Sync Completed
========================================
Duration: $($duration.ToString('hh\:mm\:ss'))
Domains Processed: $($targetDomains.Count) (Success: $successfulDomains)
Total Computers Found: $totalComputers
Computers Added to Group: $totalAdded
Computers Removed from Group: $totalRemoved
Errors: $totalErrors
"@
    
    Write-Log $summary -Level Information -EventId $eventIds.ComputerSyncCompleted
    
    # Output results object
    [PSCustomObject]@{
        TierLevel        = $TierLevel
        Duration         = $duration
        DomainsProcessed = $targetDomains.Count
        SuccessfulDomains = $successfulDomains
        TotalComputers   = $totalComputers
        Added            = $totalAdded
        Removed          = $totalRemoved
        Errors           = $totalErrors
        DomainResults    = $results
    }
}
catch {
    $eventIds = Get-TierGuardEventIds
    Write-Log "Critical error during Tier $TierLevel Computer Sync: $_" -Level Error `
        -EventId $eventIds.ComputerSyncFailed
    throw
}

#endregion
