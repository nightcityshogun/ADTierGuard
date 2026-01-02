<#
.SYNOPSIS
    ADTierGuard - Shared Sync Utilities Module
    
.DESCRIPTION
    Common utilities shared between Computer and User synchronization scripts.
    Provides logging, configuration access, and domain enumeration functions.
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.0.0
    License: GPL-3.0
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest

#region Module State

# Thread-safe logging state using synchronized hashtable
$Script:LoggingState = [hashtable]::Synchronized(@{
    Config      = $null
    LogPrefix   = 'TierGuard'
    Initialized = $false
    LogLock     = [System.Object]::new()
})

#endregion

#region Initialization

<#
.SYNOPSIS
    Initializes the sync utilities module with configuration.
    
.DESCRIPTION
    Must be called before using other functions in this module.
    Sets up logging configuration and validates prerequisites.
    
.PARAMETER Configuration
    The ADTierGuard configuration hashtable.
    
.PARAMETER LogPrefix
    Prefix for log files (e.g., 'ComputerSync', 'UserSync').
    
.EXAMPLE
    Initialize-SyncUtilities -Configuration $config -LogPrefix 'ComputerSync'
#>
function Initialize-SyncUtilities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogPrefix
    )
    
    $Script:LoggingState.Config = $Configuration
    $Script:LoggingState.LogPrefix = $LogPrefix
    $Script:LoggingState.Initialized = $true
    
    # Ensure log directory exists
    if ($Configuration.General.LogPath) {
        $logDir = $Configuration.General.LogPath
        if (-not (Test-Path $logDir)) {
            try {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            catch {
                Write-Warning "Failed to create log directory '$logDir': $_"
            }
        }
    }
}

<#
.SYNOPSIS
    Tests if the sync utilities module has been initialized.
    
.OUTPUTS
    Boolean indicating initialization state.
#>
function Test-SyncUtilitiesInitialized {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    return $Script:LoggingState.Initialized
}

#endregion

#region Logging

<#
.SYNOPSIS
    Writes a log message to console, file, and optionally Windows Event Log.
    
.DESCRIPTION
    Thread-safe logging function that writes to multiple destinations.
    Automatically timestamps messages and handles concurrent access.
    
.PARAMETER Message
    The message to log.
    
.PARAMETER Level
    Log level: Verbose, Information, Warning, or Error.
    
.PARAMETER EventId
    Optional Windows Event Log event ID. If specified and > 0, writes to Event Log.
    
.PARAMETER NoConsole
    Suppresses console output (file and event log only).
    
.EXAMPLE
    Write-SyncLog -Message "Starting sync" -Level Information
    
.EXAMPLE
    Write-SyncLog -Message "Critical failure" -Level Error -EventId 9001
#>
function Write-SyncLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Verbose', 'Information', 'Warning', 'Error')]
        [string]$Level = 'Information',
        
        [Parameter()]
        [int]$EventId = 0,
        
        [Parameter()]
        [switch]$NoConsole
    )
    
    # Validate initialization
    if (-not $Script:LoggingState.Initialized) {
        # Fallback to basic logging if not initialized
        $timestamp = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss.fff')
        Write-Warning "[$timestamp] SyncUtilities not initialized. Message: $Message"
        return
    }
    
    $config = $Script:LoggingState.Config
    $logPrefix = $Script:LoggingState.LogPrefix
    
    # Format timestamp with high precision
    $timestamp = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss.fff')
    $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    $logMessage = "[$timestamp] [TID:$threadId] [$Level] $Message"
    
    # Console output (unless suppressed)
    if (-not $NoConsole) {
        switch ($Level) {
            'Verbose' { 
                Write-Verbose $logMessage 
            }
            'Information' { 
                Write-Information $logMessage -InformationAction Continue 
            }
            'Warning' { 
                Write-Warning ($logMessage -replace '^\[.*?\] \[TID:\d+\] \[Warning\] ', '')
            }
            'Error' { 
                Write-Error ($logMessage -replace '^\[.*?\] \[TID:\d+\] \[Error\] ', '') -ErrorAction Continue
            }
        }
    }
    
    # File logging (thread-safe)
    if ($config -and $config.General.LogPath) {
        $logFile = Join-Path $config.General.LogPath "${logPrefix}_$(Get-Date -Format 'yyyyMMdd').log"
        
        # Use lock for thread-safe file access
        [System.Threading.Monitor]::Enter($Script:LoggingState.LogLock)
        try {
            Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
        }
        finally {
            [System.Threading.Monitor]::Exit($Script:LoggingState.LogLock)
        }
    }
    
    # Windows Event Log
    if ($EventId -gt 0 -and $config) {
        $entryType = switch ($Level) {
            'Error'   { 'Error' }
            'Warning' { 'Warning' }
            default   { 'Information' }
        }
        
        try {
            Write-TierGuardEvent -Message $Message -EntryType $entryType `
                -EventId $EventId -Source $config.General.EventLogSource
        }
        catch {
            # Silently ignore event log failures - don't break the sync
        }
    }
}

#endregion

#region Configuration Access

<#
.SYNOPSIS
    Gets the tier-specific configuration section.
    
.DESCRIPTION
    Returns the Tier0 or Tier1 configuration based on the specified tier level.
    
.PARAMETER Configuration
    The full ADTierGuard configuration hashtable.
    
.PARAMETER TierLevel
    The tier level (0 or 1).
    
.OUTPUTS
    Hashtable containing the tier-specific configuration.
    
.EXAMPLE
    $tierConfig = Get-TierSpecificConfiguration -Configuration $config -TierLevel 0
#>
function Get-TierSpecificConfiguration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1)]
        [int]$TierLevel
    )
    
    $tierConfig = switch ($TierLevel) {
        0 { $Configuration.Tier0 }
        1 { $Configuration.Tier1 }
    }
    
    if ($null -eq $tierConfig) {
        throw "Tier $TierLevel configuration section not found"
    }
    
    return $tierConfig
}

<#
.SYNOPSIS
    Validates that a tier is enabled in configuration.
    
.DESCRIPTION
    Checks if the specified tier is enabled and throws if not.
    
.PARAMETER Configuration
    The full ADTierGuard configuration hashtable.
    
.PARAMETER TierLevel
    The tier level to validate.
    
.PARAMETER ThrowOnDisabled
    If specified, throws an exception when tier is disabled.
    
.OUTPUTS
    Boolean indicating if tier is enabled.
    
.EXAMPLE
    if (Test-TierEnabled -Configuration $config -TierLevel 0) { ... }
#>
function Test-TierEnabled {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1)]
        [int]$TierLevel,
        
        [Parameter()]
        [switch]$ThrowOnDisabled
    )
    
    $tierConfig = Get-TierSpecificConfiguration -Configuration $Configuration -TierLevel $TierLevel
    $isEnabled = $tierConfig.Enabled -eq $true
    
    if (-not $isEnabled -and $ThrowOnDisabled) {
        throw "Tier $TierLevel is not enabled in configuration"
    }
    
    return $isEnabled
}

#endregion

#region Domain Enumeration

<#
.SYNOPSIS
    Gets the list of target domains based on configuration.
    
.DESCRIPTION
    Enumerates domains in the forest and filters based on:
    - TargetDomains whitelist (if specified)
    - ExcludedDomains blacklist
    Returns domains as hashtables with DN, DnsName, and NetBIOSName.
    
.PARAMETER Configuration
    The full ADTierGuard configuration hashtable.
    
.PARAMETER ForestScope
    If true, processes all domains in forest (subject to filters).
    If false, processes only the current domain.
    
.OUTPUTS
    Array of hashtables, each containing:
    - DistinguishedName (DefaultNC from Get-ForestInfo)
    - DnsName  
    - NetBIOSName (if available)
    - DomainSid
    - Type (Forest Root, Child Domain, Tree Root)
    - IsForestRoot
    - OnlineDCs
    
.EXAMPLE
    $domains = Get-SyncTargetDomains -ForestScope
    
.EXAMPLE
    $domains = Get-SyncTargetDomains -ExcludeDomains @("test.contoso.com")
#>
function Get-SyncTargetDomains {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter()]
        [switch]$ForestScope,
        
        [Parameter()]
        [string[]]$ExcludeDomains = @()
    )
    
    # Always use Get-ForestTopology for domain discovery
    try {
        $topology = Initialize-ForestTopology
    }
    catch {
        Write-SyncLog -Message "Failed to initialize forest topology: $($_.Exception.Message)" -Level Error
        throw "Cannot discover forest topology. Ensure domain connectivity."
    }
    
    if (-not $topology -or -not $topology.Domains -or $topology.Domains.Count -eq 0) {
        throw "No domains discovered in forest topology"
    }
    
    Write-SyncLog -Message "Forest topology: $($topology.Domains.Count) domains, root = $($topology.ForestRootFQDN)" -Level Information
    
    # Log all discovered domains
    foreach ($domain in $topology.Domains) {
        Write-SyncLog -Message "  Domain: $($domain.DnsName) [$($domain.Type)]" -Level Verbose
    }
    
    if ($ForestScope) {
        # Forest-wide: return all domains with normalized property names
        $domains = $topology.Domains | ForEach-Object {
            @{
                DnsName           = $_.DnsName
                DistinguishedName = $_.DefaultNC
                DomainSid         = $_.DomainSid
                Type              = $_.Type
                IsForestRoot      = $_.IsForestRoot
                IsChildDomain     = $_.IsChildDomain
                IsTreeRoot        = $_.IsTreeRoot
                OnlineDCs         = $_.OnlineDCs
            }
        }
        
        # Apply exclusion filter
        if ($ExcludeDomains.Count -gt 0) {
            $domains = $domains | Where-Object {
                $_.DnsName -notin $ExcludeDomains
            }
            Write-SyncLog -Message "After exclusions: $(($domains | Measure-Object).Count) domains" -Level Verbose
        }
        
        Write-SyncLog -Message "ForestScope enabled: processing $(($domains | Measure-Object).Count) domains" -Level Information
        return @($domains)
    }
    else {
        # Single domain: current domain only
        $rootDse = Get-AdsiRootDse
        $currentDomainDN = $rootDse.DefaultNamingContext
        
        # Find current domain in topology
        $currentDomain = $topology.Domains | Where-Object {
            $_.DefaultNC -eq $currentDomainDN
        } | Select-Object -First 1
        
        if ($currentDomain) {
            # Normalize property names
            $result = @{
                DnsName           = $currentDomain.DnsName
                DistinguishedName = $currentDomain.DefaultNC
                DomainSid         = $currentDomain.DomainSid
                Type              = $currentDomain.Type
                IsForestRoot      = $currentDomain.IsForestRoot
                IsChildDomain     = $currentDomain.IsChildDomain
                IsTreeRoot        = $currentDomain.IsTreeRoot
                OnlineDCs         = $currentDomain.OnlineDCs
            }
        }
        else {
            # Fallback: construct from RootDSE
            $dnsName = ($currentDomainDN -split ',' | 
                Where-Object { $_ -like 'DC=*' } | 
                ForEach-Object { $_ -replace '^DC=' }) -join '.'
            
            $result = @{
                DnsName           = $dnsName
                DistinguishedName = $currentDomainDN
                DomainSid         = $null
                Type              = 'Unknown'
                IsForestRoot      = ($topology.ForestRootFQDN -eq $dnsName)
                IsChildDomain     = $false
                IsTreeRoot        = $false
                OnlineDCs         = @()
            }
        }
        
        Write-SyncLog -Message "Single domain mode: $($result.DnsName) [$($result.Type)]" -Level Information
        return @($result)
    }
}

#endregion

#region OU Path Resolution

<#
.SYNOPSIS
    Resolves an OU path to a full distinguished name for a specific domain.
    
.DESCRIPTION
    Takes a relative OU path (e.g., "OU=Admins,OU=Tier0") or full DN and:
    - If relative, appends the domain DN
    - If full DN, validates it belongs to the specified domain
    
.PARAMETER OUPath
    The OU path (relative or full DN).
    
.PARAMETER DomainDN
    The domain distinguished name.
    
.OUTPUTS
    The full distinguished name, or $null if path doesn't belong to domain.
    
.EXAMPLE
    $fullDN = Resolve-OUPathForDomain -OUPath "OU=Admins" -DomainDN "DC=corp,DC=local"
#>
function Resolve-OUPathForDomain {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OUPath,
        
        [Parameter(Mandatory = $true)]
        [string]$DomainDN
    )
    
    if ($OUPath -match 'DC=') {
        # Full DN - verify it belongs to this domain
        $pathDomain = Get-AdsiDomainFromDN -DistinguishedName $OUPath
        if ($pathDomain -ne $DomainDN) {
            return $null
        }
        return $OUPath
    }
    else {
        # Relative path - append domain DN
        return "$OUPath,$DomainDN"
    }
}

#endregion

#region Parallel Processing Helpers

<#
.SYNOPSIS
    Gets the effective throttle limit for parallel operations.
    
.DESCRIPTION
    Returns the throttle limit from parameter, configuration, or default.
    
.PARAMETER ExplicitLimit
    Explicitly specified throttle limit (0 means use config).
    
.PARAMETER Configuration
    The ADTierGuard configuration hashtable.
    
.PARAMETER Default
    Default value if nothing else specified.
    
.OUTPUTS
    Integer throttle limit.
    
.EXAMPLE
    $throttle = Get-EffectiveThrottleLimit -ExplicitLimit 0 -Configuration $config
#>
function Get-EffectiveThrottleLimit {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter()]
        [int]$ExplicitLimit = 0,
        
        [Parameter()]
        [hashtable]$Configuration,
        
        [Parameter()]
        [int]$Default = 4
    )
    
    if ($ExplicitLimit -gt 0) {
        return $ExplicitLimit
    }
    
    if ($Configuration -and $Configuration.General.MaxParallelOperations -gt 0) {
        return $Configuration.General.MaxParallelOperations
    }
    
    return $Default
}

#endregion

#region Results Formatting

<#
.SYNOPSIS
    Creates a standardized sync operation result object.
    
.DESCRIPTION
    Factory function for creating consistent result objects across sync operations.
    
.PARAMETER Domain
    Domain DNS name.
    
.PARAMETER Success
    Whether the operation succeeded.
    
.PARAMETER Message
    Optional status message.
    
.PARAMETER AdditionalProperties
    Hashtable of additional properties to include.
    
.OUTPUTS
    Hashtable with standardized structure.
    
.EXAMPLE
    $result = New-SyncOperationResult -Domain "corp.local" -Success $true -AdditionalProperties @{ Added = 5 }
#>
function New-SyncOperationResult {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [bool]$Success,
        
        [Parameter()]
        [string]$Message = '',
        
        [Parameter()]
        [hashtable]$AdditionalProperties = @{}
    )
    
    $result = @{
        Domain    = $Domain
        Success   = $Success
        Message   = $Message
        Timestamp = [DateTime]::Now
    }
    
    foreach ($key in $AdditionalProperties.Keys) {
        $result[$key] = $AdditionalProperties[$key]
    }
    
    return $result
}

<#
.SYNOPSIS
    Formats a summary report from sync results.
    
.DESCRIPTION
    Generates a formatted summary string from an array of domain results.
    
.PARAMETER OperationType
    Type of sync operation (e.g., "Computer", "User").
    
.PARAMETER TierLevel
    The tier level processed.
    
.PARAMETER Duration
    Total operation duration.
    
.PARAMETER Results
    Array of domain result hashtables.
    
.PARAMETER Metrics
    Hashtable of metric names to sum from results.
    
.OUTPUTS
    Formatted summary string.
    
.EXAMPLE
    $summary = Format-SyncSummary -OperationType "Computer" -TierLevel 0 -Duration $elapsed -Results $results -Metrics @{ Added = 'Added'; Removed = 'Removed' }
#>
function Format-SyncSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OperationType,
        
        [Parameter(Mandatory = $true)]
        [int]$TierLevel,
        
        [Parameter(Mandatory = $true)]
        [TimeSpan]$Duration,
        
        [Parameter(Mandatory = $true)]
        [hashtable[]]$Results,
        
        [Parameter()]
        [hashtable]$Metrics = @{}
    )
    
    $successfulDomains = ($Results | Where-Object { $_.Success }).Count
    $totalDomains = $Results.Count
    
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("Tier $TierLevel $OperationType Sync Completed")
    [void]$sb.AppendLine("=" * 50)
    [void]$sb.AppendLine("Duration: $($Duration.ToString('hh\:mm\:ss\.fff'))")
    [void]$sb.AppendLine("Domains Processed: $totalDomains (Success: $successfulDomains)")
    
    foreach ($metricKey in $Metrics.Keys) {
        $propertyName = $Metrics[$metricKey]
        $total = ($Results | Measure-Object -Property $propertyName -Sum -ErrorAction SilentlyContinue).Sum
        if ($null -eq $total) { $total = 0 }
        [void]$sb.AppendLine("${metricKey}: $total")
    }
    
    return $sb.ToString()
}

#endregion

#region Export Module Members

Export-ModuleMember -Function @(
    # Initialization
    'Initialize-SyncUtilities'
    'Test-SyncUtilitiesInitialized'
    
    # Logging
    'Write-SyncLog'
    
    # Configuration
    'Get-TierSpecificConfiguration'
    'Test-TierEnabled'
    
    # Domain Enumeration
    'Get-SyncTargetDomains'
    
    # OU Resolution
    'Resolve-OUPathForDomain'
    
    # Parallel Processing
    'Get-EffectiveThrottleLimit'
    
    # Results
    'New-SyncOperationResult'
    'Format-SyncSummary'
)

#endregion
