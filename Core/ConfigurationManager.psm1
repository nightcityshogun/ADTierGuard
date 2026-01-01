<#
.SYNOPSIS
    ADTierGuard - Configuration Management Module
    
.DESCRIPTION
    Handles configuration loading, validation, and persistence for
    the tier isolation framework. Supports JSON configuration files
    with schema validation.
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.0.0
    License: GPL-3.0
#>

#region Module Configuration
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
#endregion

#region Configuration Schema

<#
.SYNOPSIS
    Returns the default configuration schema.
#>
function Get-ConfigurationSchema {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    return @{
        SchemaVersion = '2.0'
        
        General = @{
            ForestScope              = $true           # Process all domains in forest
            LogLevel                 = 'Information'   # Verbose, Information, Warning, Error
            LogPath                  = ''              # Path to log directory
            EventLogSource           = 'ADTierGuard'
            MaxParallelOperations    = [Environment]::ProcessorCount
            OperationTimeoutSeconds  = 300
        }
        
        Tier0 = @{
            Enabled                  = $true
            AdminOUs                 = @()             # Relative or full DN paths
            ServiceAccountOUs        = @()             # Service accounts (no Kerberos policy)
            ComputerOUs              = @()             # Computer objects
            ComputerGroupName        = 'Tier0-Computers'
            KerberosAuthPolicyName   = 'Tier0-AuthPolicy'
            AddToProtectedUsers      = $true
            EnforcePrivilegedGroupCleanup = $true
            ExcludedAccounts         = @()             # sAMAccountNames to exclude
        }
        
        Tier1 = @{
            Enabled                  = $false
            AdminOUs                 = @()
            ServiceAccountOUs        = @()
            ComputerOUs              = @()
            ComputerGroupName        = 'Tier1-Computers'
            KerberosAuthPolicyName   = 'Tier1-AuthPolicy'
            AddToProtectedUsers      = $false
            ExcludedAccounts         = @()
        }
        
        Domains = @{
            TargetDomains            = @()             # Empty = all domains
            ExcludedDomains          = @()
            PrimaryDomain            = ''              # For GMSA and policy storage
        }
        
        ServiceAccount = @{
            UseGMSA                  = $false
            GMSAName                 = ''
            GMSAPrincipalsAllowed    = @()
        }
        
        Scheduling = @{
            ComputerSyncIntervalMinutes = 10
            UserSyncIntervalMinutes     = 10
            EnabledTasks                = @('ComputerSync', 'UserSync')
        }
        
        Notifications = @{
            Enabled                  = $false
            SmtpServer               = ''
            SmtpPort                 = 25
            FromAddress              = ''
            ToAddresses              = @()
            OnError                  = $true
            OnPolicyApplication      = $false
            OnGroupMembershipChange  = $false
        }
    }
}
#endregion

#region Configuration Loading

<#
.SYNOPSIS
    Loads configuration from a JSON file.
#>
function Import-TierGuardConfiguration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    
    if (-not (Test-Path $Path)) {
        throw "Configuration file not found: $Path"
    }
    
    try {
        $jsonContent = Get-Content -Path $Path -Raw -Encoding UTF8
        $config = $jsonContent | ConvertFrom-Json -AsHashtable
        
        # Merge with defaults for any missing values
        $defaults = Get-ConfigurationSchema
        $merged = Merge-Configuration -Default $defaults -Override $config
        
        # Validate
        $validation = Test-TierGuardConfiguration -Configuration $merged
        if (-not $validation.IsValid) {
            throw "Configuration validation failed: $($validation.Errors -join '; ')"
        }
        
        return $merged
    }
    catch {
        Write-Error "Failed to load configuration from '$Path': $_"
        throw
    }
}

<#
.SYNOPSIS
    Saves configuration to a JSON file.
#>
function Export-TierGuardConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        
        [Parameter()]
        [switch]$Force
    )
    
    if ((Test-Path $Path) -and -not $Force) {
        throw "Configuration file already exists: $Path. Use -Force to overwrite."
    }
    
    try {
        if ($PSCmdlet.ShouldProcess($Path, "Save configuration")) {
            $json = $Configuration | ConvertTo-Json -Depth 10
            $json | Set-Content -Path $Path -Encoding UTF8 -Force
            Write-Verbose "Configuration saved to '$Path'"
        }
    }
    catch {
        Write-Error "Failed to save configuration to '$Path': $_"
        throw
    }
}

<#
.SYNOPSIS
    Creates a new configuration with default values.
#>
function New-TierGuardConfiguration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [hashtable]$Overrides = @{}
    )
    
    $defaults = Get-ConfigurationSchema
    return Merge-Configuration -Default $defaults -Override $Overrides
}

<#
.SYNOPSIS
    Merges two configuration hashtables recursively.
#>
function Merge-Configuration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Default,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Override
    )
    
    $result = @{}
    
    foreach ($key in $Default.Keys) {
        if ($Override.ContainsKey($key)) {
            if ($Default[$key] -is [hashtable] -and $Override[$key] -is [hashtable]) {
                $result[$key] = Merge-Configuration -Default $Default[$key] -Override $Override[$key]
            }
            else {
                $result[$key] = $Override[$key]
            }
        }
        else {
            $result[$key] = $Default[$key]
        }
    }
    
    # Add any keys from Override that don't exist in Default
    foreach ($key in $Override.Keys) {
        if (-not $Default.ContainsKey($key)) {
            $result[$key] = $Override[$key]
        }
    }
    
    return $result
}
#endregion

#region Configuration Validation

<#
.SYNOPSIS
    Validates a tier guard configuration.
#>
function Test-TierGuardConfiguration {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration
    )
    
    $errors = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    
    # Validate schema version
    if (-not $Configuration.ContainsKey('SchemaVersion')) {
        $warnings.Add("Configuration missing SchemaVersion, assuming 2.0")
    }
    
    # Validate Tier 0 configuration
    if ($Configuration.Tier0.Enabled) {
        if ($Configuration.Tier0.AdminOUs.Count -eq 0) {
            $errors.Add("Tier 0 is enabled but no Admin OUs are configured")
        }
        
        if ($Configuration.Tier0.ComputerOUs.Count -eq 0) {
            $errors.Add("Tier 0 is enabled but no Computer OUs are configured")
        }
        
        if ([string]::IsNullOrWhiteSpace($Configuration.Tier0.ComputerGroupName)) {
            $errors.Add("Tier 0 Computer Group name is required")
        }
        
        if ([string]::IsNullOrWhiteSpace($Configuration.Tier0.KerberosAuthPolicyName)) {
            $errors.Add("Tier 0 Kerberos Authentication Policy name is required")
        }
    }
    
    # Validate Tier 1 configuration
    if ($Configuration.Tier1.Enabled) {
        if ($Configuration.Tier1.AdminOUs.Count -eq 0) {
            $errors.Add("Tier 1 is enabled but no Admin OUs are configured")
        }
        
        if ($Configuration.Tier1.ComputerOUs.Count -eq 0) {
            $errors.Add("Tier 1 is enabled but no Computer OUs are configured")
        }
    }
    
    # Validate General settings
    $validLogLevels = @('Verbose', 'Information', 'Warning', 'Error')
    if ($Configuration.General.LogLevel -notin $validLogLevels) {
        $errors.Add("Invalid LogLevel: $($Configuration.General.LogLevel). Must be one of: $($validLogLevels -join ', ')")
    }
    
    if ($Configuration.General.MaxParallelOperations -lt 1 -or 
        $Configuration.General.MaxParallelOperations -gt 64) {
        $warnings.Add("MaxParallelOperations ($($Configuration.General.MaxParallelOperations)) is outside recommended range (1-64)")
    }
    
    # Validate GMSA configuration
    if ($Configuration.ServiceAccount.UseGMSA) {
        if ([string]::IsNullOrWhiteSpace($Configuration.ServiceAccount.GMSAName)) {
            $errors.Add("GMSA is enabled but GMSAName is not configured")
        }
    }
    
    # Validate Notifications
    if ($Configuration.Notifications.Enabled) {
        if ([string]::IsNullOrWhiteSpace($Configuration.Notifications.SmtpServer)) {
            $errors.Add("Notifications are enabled but SMTP server is not configured")
        }
        
        if ([string]::IsNullOrWhiteSpace($Configuration.Notifications.FromAddress)) {
            $errors.Add("Notifications are enabled but FromAddress is not configured")
        }
        
        if ($Configuration.Notifications.ToAddresses.Count -eq 0) {
            $errors.Add("Notifications are enabled but no ToAddresses are configured")
        }
    }
    
    return [PSCustomObject]@{
        IsValid  = ($errors.Count -eq 0)
        Errors   = $errors.ToArray()
        Warnings = $warnings.ToArray()
    }
}
#endregion

#region OU Path Resolution

<#
.SYNOPSIS
    Resolves OU paths for all target domains.
#>
function Resolve-TierOUPaths {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$OUPaths,
        
        [Parameter(Mandatory = $true)]
        [hashtable[]]$Domains
    )
    
    $resolvedPaths = @{}
    
    foreach ($domain in $Domains) {
        $domainDN = $domain.DistinguishedName
        $domainName = $domain.DnsName
        $resolvedPaths[$domainName] = [System.Collections.Generic.List[string]]::new()
        
        foreach ($ouPath in $OUPaths) {
            if ($ouPath -match 'DC=') {
                # Full DN - extract domain and check if it matches
                $pathDomain = ($ouPath -split ',' | Where-Object { $_ -like 'DC=*' }) -join ','
                if ($pathDomain -eq $domainDN) {
                    $resolvedPaths[$domainName].Add($ouPath)
                }
            }
            else {
                # Relative path - append domain DN
                $fullPath = "$ouPath,$domainDN"
                $resolvedPaths[$domainName].Add($fullPath)
            }
        }
    }
    
    return $resolvedPaths
}
#endregion

#region Event Log Configuration

<#
.SYNOPSIS
    Configures event log source for ADTierGuard.
#>
function Initialize-TierGuardEventLog {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$Source = 'ADTierGuard',
        
        [Parameter()]
        [string]$LogName = 'Application'
    )
    
    try {
        if ($PSCmdlet.ShouldProcess($Source, "Register event log source")) {
            if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
                [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
                Write-Verbose "Created event log source '$Source' in log '$LogName'"
            }
            else {
                Write-Verbose "Event log source '$Source' already exists"
            }
        }
    }
    catch {
        Write-Warning "Failed to create event log source: $_"
    }
}

<#
.SYNOPSIS
    Writes an event to the Windows Event Log.
#>
function Write-TierGuardEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$EntryType = 'Information',
        
        [Parameter(Mandatory = $true)]
        [int]$EventId,
        
        [Parameter()]
        [string]$Source = 'ADTierGuard'
    )
    
    try {
        $eventLogType = switch ($EntryType) {
            'Information' { [System.Diagnostics.EventLogEntryType]::Information }
            'Warning'     { [System.Diagnostics.EventLogEntryType]::Warning }
            'Error'       { [System.Diagnostics.EventLogEntryType]::Error }
        }
        
        [System.Diagnostics.EventLog]::WriteEntry($Source, $Message, $eventLogType, $EventId)
    }
    catch {
        Write-Warning "Failed to write event log entry: $_"
    }
}
#endregion

#region Event IDs

<#
.SYNOPSIS
    Returns the standard event ID mappings.
#>
function Get-TierGuardEventIds {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    return @{
        # Computer Management Events (1xxx)
        ComputerSyncStarted           = 1000
        ComputerSyncCompleted         = 1001
        ComputerSyncFailed            = 1002
        ComputerAddedToGroup          = 1100
        ComputerRemovedFromGroup      = 1101
        ComputerProcessingError       = 1199
        
        # User Management Events (2xxx)
        UserSyncStarted               = 2000
        UserSyncCompleted             = 2001
        UserSyncFailed                = 2002
        PolicyApplied                 = 2100
        PolicyRemoved                 = 2101
        AddedToProtectedUsers         = 2102
        RemovedFromPrivilegedGroup    = 2103
        UserProcessingError           = 2199
        
        # Configuration Events (3xxx)
        ConfigurationLoaded           = 3000
        ConfigurationError            = 3001
        ConfigurationValidationFailed = 3002
        
        # General Events (9xxx)
        ServiceStarted                = 9000
        ServiceStopped                = 9001
        UnexpectedError               = 9999
    }
}
#endregion

#region Export Module Members
Export-ModuleMember -Function @(
    # Schema
    'Get-ConfigurationSchema'
    
    # Loading/Saving
    'Import-TierGuardConfiguration'
    'Export-TierGuardConfiguration'
    'New-TierGuardConfiguration'
    'Merge-Configuration'
    
    # Validation
    'Test-TierGuardConfiguration'
    
    # Path Resolution
    'Resolve-TierOUPaths'
    
    # Event Logging
    'Initialize-TierGuardEventLog'
    'Write-TierGuardEvent'
    'Get-TierGuardEventIds'
)
#endregion
