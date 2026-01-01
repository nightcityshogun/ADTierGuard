<#
.SYNOPSIS
    ADTierGuard - Installation and Setup Script
    
.DESCRIPTION
    Interactive setup wizard for deploying ADTierGuard tier isolation.
    Creates configuration, validates environment, and sets up scheduled tasks.
    
.PARAMETER ConfigurationPath
    Path where the configuration file will be saved.
    
.PARAMETER NonInteractive
    Run in non-interactive mode using a template configuration.
    
.PARAMETER TemplateConfigPath
    Path to a template configuration file for non-interactive setup.
    
.EXAMPLE
    .\Install-TierGuard.ps1
    
.EXAMPLE
    .\Install-TierGuard.ps1 -ConfigurationPath "C:\ADTierGuard\config.json"
    
.EXAMPLE
    .\Install-TierGuard.ps1 -NonInteractive -TemplateConfigPath "C:\Templates\config.json"
    
.NOTES
    Author: Night City Shogun
    Version: 2.0.0
    License: GPL-3.0
    Requires: Enterprise Administrator permissions
    Copyright         = '(c) 2025 NCS Dojo. All rights reserved.'
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigurationPath = "$env:ProgramData\ADTierGuard\config.json",
    
    [Parameter()]
    [switch]$NonInteractive,
    
    [Parameter()]
    [string]$TemplateConfigPath,
    
    [Parameter()]
    [switch]$SkipScheduledTasks,
    
    [Parameter()]
    [switch]$SkipGroupCreation,
    
    [Parameter()]
    [switch]$Force
)

#region Script Initialization

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Script:ModulePath = $PSScriptRoot

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

#region Helper Functions

function Write-Banner {
    $banner = @"

    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     █████╗ ██████╗ ████████╗██╗███████╗██████╗                ║
    ║    ██╔══██╗██╔══██╗╚══██╔══╝██║██╔════╝██╔══██╗               ║
    ║    ███████║██║  ██║   ██║   ██║█████╗  ██████╔╝               ║
    ║    ██╔══██║██║  ██║   ██║   ██║██╔══╝  ██╔══██╗               ║
    ║    ██║  ██║██████╔╝   ██║   ██║███████╗██║  ██║               ║
    ║    ╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝               ║
    ║                    GUARD                                      ║
    ║                                                               ║
    ║         Tier Level Isolation for Active Directory             ║
    ║                     Version 2.0.0                             ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Write-Step {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Question')]
        [string]$Type = 'Info'
    )
    
    $prefix = switch ($Type) {
        'Info'     { '[*]'; $color = 'Cyan' }
        'Success'  { '[+]'; $color = 'Green' }
        'Warning'  { '[!]'; $color = 'Yellow' }
        'Error'    { '[-]'; $color = 'Red' }
        'Question' { '[?]'; $color = 'Magenta' }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Read-UserInput {
    param(
        [string]$Prompt,
        [string]$Default = '',
        [switch]$Required,
        [string[]]$ValidOptions = @()
    )
    
    $promptText = $Prompt
    if ($Default) {
        $promptText += " [$Default]"
    }
    $promptText += ": "
    
    do {
        Write-Host $promptText -NoNewline -ForegroundColor Yellow
        $input = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($input)) {
            $input = $Default
        }
        
        if ($Required -and [string]::IsNullOrWhiteSpace($input)) {
            Write-Step "This field is required." -Type Warning
            continue
        }
        
        if ($ValidOptions.Count -gt 0 -and $input -notin $ValidOptions) {
            Write-Step "Invalid option. Valid options: $($ValidOptions -join ', ')" -Type Warning
            continue
        }
        
        break
    } while ($true)
    
    return $input
}

function Read-MultipleInputs {
    param(
        [string]$Prompt,
        [string]$ItemName = 'item'
    )
    
    Write-Host "$Prompt (Enter each $ItemName on a new line, empty line to finish):" -ForegroundColor Yellow
    
    $items = [System.Collections.Generic.List[string]]::new()
    
    while ($true) {
        $input = Read-Host "  $ItemName"
        if ([string]::IsNullOrWhiteSpace($input)) {
            break
        }
        $items.Add($input)
    }
    
    return $items.ToArray()
}

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default = $true
    )
    
    $defaultText = if ($Default) { 'Y/n' } else { 'y/N' }
    Write-Host "$Prompt [$defaultText]: " -NoNewline -ForegroundColor Yellow
    $input = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $Default
    }
    
    return $input -match '^[Yy]'
}

function Test-Prerequisites {
    Write-Step "Checking prerequisites..." -Type Info
    
    $issues = [System.Collections.Generic.List[string]]::new()
    
    # Check if running as admin
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $issues.Add("Script must be run as Administrator")
    }
    
    # Check domain connectivity
    try {
        $rootDse = Get-AdsiRootDse
        Write-Step "Connected to domain: $($rootDse.DefaultNamingContext)" -Type Success
    }
    catch {
        $issues.Add("Cannot connect to Active Directory: $_")
    }
    
    # Check forest functional level (must be 2012 R2 or higher for AuthN Policies)
    try {
        $rootDse = Get-AdsiRootDse
        if ($rootDse.ForestFunctionalLevel -lt 6) {
            $issues.Add("Forest functional level must be Windows Server 2012 R2 or higher for Kerberos Authentication Policies")
        }
        else {
            Write-Step "Forest functional level is sufficient for Authentication Policies" -Type Success
        }
    }
    catch {
        $issues.Add("Cannot determine forest functional level")
    }
    
    if ($issues.Count -gt 0) {
        Write-Step "Prerequisites check failed:" -Type Error
        foreach ($issue in $issues) {
            Write-Step "  - $issue" -Type Error
        }
        return $false
    }
    
    Write-Step "All prerequisites met" -Type Success
    return $true
}

#endregion

#region Configuration Wizard

function Invoke-ConfigurationWizard {
    Write-Step "Starting configuration wizard..." -Type Info
    Write-Host ""
    
    $config = New-TierGuardConfiguration
    
    #region Domain Selection
    Write-Host "=== Domain Selection ===" -ForegroundColor Cyan
    Write-Host ""
    
    $domains = Get-AdsiForestDomains
    Write-Step "Available domains in forest:" -Type Info
    for ($i = 0; $i -lt $domains.Count; $i++) {
        Write-Host "  [$i] $($domains[$i].DnsName) ($($domains[$i].NetBIOSName))"
    }
    Write-Host "  [A] All domains"
    Write-Host ""
    
    $domainSelection = Read-UserInput -Prompt "Select domains to manage (comma-separated numbers or 'A' for all)" -Default 'A'
    
    if ($domainSelection -eq 'A' -or $domainSelection -eq 'a') {
        $config.General.ForestScope = $true
        $config.Domains.TargetDomains = @()
    }
    else {
        $config.General.ForestScope = $false
        $selectedIndices = $domainSelection -split ',' | ForEach-Object { [int]$_.Trim() }
        $config.Domains.TargetDomains = @($selectedIndices | ForEach-Object { $domains[$_].DnsName })
    }
    Write-Host ""
    #endregion
    
    #region Tier 0 Configuration
    Write-Host "=== Tier 0 Configuration ===" -ForegroundColor Cyan
    Write-Host ""
    
    $config.Tier0.Enabled = Read-YesNo -Prompt "Enable Tier 0 isolation" -Default $true
    
    if ($config.Tier0.Enabled) {
        Write-Host ""
        Write-Step "Configure Tier 0 Administrator OUs" -Type Question
        Write-Host "  Enter relative OUs (e.g., OU=Admins,OU=Tier0) or full DNs"
        $config.Tier0.AdminOUs = Read-MultipleInputs -Prompt "Tier 0 Admin OUs" -ItemName "OU path"
        
        Write-Host ""
        Write-Step "Configure Tier 0 Service Account OUs (accounts that should NOT get Kerberos policy)" -Type Question
        $config.Tier0.ServiceAccountOUs = Read-MultipleInputs -Prompt "Tier 0 Service Account OUs" -ItemName "OU path"
        
        Write-Host ""
        Write-Step "Configure Tier 0 Computer OUs" -Type Question
        $config.Tier0.ComputerOUs = Read-MultipleInputs -Prompt "Tier 0 Computer OUs" -ItemName "OU path"
        
        Write-Host ""
        $config.Tier0.ComputerGroupName = Read-UserInput -Prompt "Tier 0 Computer Group name" `
            -Default 'Tier0-Computers' -Required
        
        $config.Tier0.KerberosAuthPolicyName = Read-UserInput -Prompt "Tier 0 Kerberos Authentication Policy name" `
            -Default 'Tier0-AuthPolicy' -Required
        
        $config.Tier0.AddToProtectedUsers = Read-YesNo -Prompt "Add Tier 0 admins to Protected Users" -Default $true
        $config.Tier0.EnforcePrivilegedGroupCleanup = Read-YesNo -Prompt "Remove unauthorized users from privileged groups" -Default $true
        
        Write-Host ""
        Write-Step "Exclude any accounts from Tier 0 management (sAMAccountName)" -Type Question
        $config.Tier0.ExcludedAccounts = Read-MultipleInputs -Prompt "Excluded accounts" -ItemName "sAMAccountName"
    }
    Write-Host ""
    #endregion
    
    #region Tier 1 Configuration
    Write-Host "=== Tier 1 Configuration ===" -ForegroundColor Cyan
    Write-Host ""
    
    $config.Tier1.Enabled = Read-YesNo -Prompt "Enable Tier 1 isolation" -Default $false
    
    if ($config.Tier1.Enabled) {
        Write-Host ""
        Write-Step "Configure Tier 1 Administrator OUs" -Type Question
        $config.Tier1.AdminOUs = Read-MultipleInputs -Prompt "Tier 1 Admin OUs" -ItemName "OU path"
        
        Write-Host ""
        Write-Step "Configure Tier 1 Computer OUs" -Type Question
        $config.Tier1.ComputerOUs = Read-MultipleInputs -Prompt "Tier 1 Computer OUs" -ItemName "OU path"
        
        Write-Host ""
        $config.Tier1.ComputerGroupName = Read-UserInput -Prompt "Tier 1 Computer Group name" `
            -Default 'Tier1-Computers' -Required
        
        $config.Tier1.KerberosAuthPolicyName = Read-UserInput -Prompt "Tier 1 Kerberos Authentication Policy name" `
            -Default 'Tier1-AuthPolicy' -Required
        
        $config.Tier1.AddToProtectedUsers = Read-YesNo -Prompt "Add Tier 1 admins to Protected Users" -Default $false
    }
    Write-Host ""
    #endregion
    
    #region General Settings
    Write-Host "=== General Settings ===" -ForegroundColor Cyan
    Write-Host ""
    
    $config.General.LogPath = Read-UserInput -Prompt "Log directory path" `
        -Default "$env:ProgramData\ADTierGuard\Logs"
    
    $config.General.EventLogSource = Read-UserInput -Prompt "Event log source name" `
        -Default 'ADTierGuard'
    
    $config.General.MaxParallelOperations = [int](Read-UserInput -Prompt "Max parallel operations" `
        -Default ([Environment]::ProcessorCount).ToString())
    
    Write-Host ""
    #endregion
    
    #region Service Account
    Write-Host "=== Service Account Configuration ===" -ForegroundColor Cyan
    Write-Host ""
    
    $config.ServiceAccount.UseGMSA = Read-YesNo -Prompt "Use Group Managed Service Account (GMSA) for multi-domain" -Default $false
    
    if ($config.ServiceAccount.UseGMSA) {
        $config.ServiceAccount.GMSAName = Read-UserInput -Prompt "GMSA sAMAccountName" -Required
    }
    Write-Host ""
    #endregion
    
    #region Scheduling
    Write-Host "=== Scheduling Configuration ===" -ForegroundColor Cyan
    Write-Host ""
    
    $config.Scheduling.ComputerSyncIntervalMinutes = [int](Read-UserInput -Prompt "Computer sync interval (minutes)" -Default '10')
    $config.Scheduling.UserSyncIntervalMinutes = [int](Read-UserInput -Prompt "User sync interval (minutes)" -Default '10')
    Write-Host ""
    #endregion
    
    return $config
}

#endregion

#region Resource Creation

function New-TierComputerGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$DomainDN,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [string]$Description = 'Tier Computer Group managed by ADTierGuard'
    )
    
    # Check if group exists
    $filter = "(&(objectClass=group)(sAMAccountName=$GroupName))"
    $existing = Search-AdsiDirectory -SearchBase $DomainDN -LdapFilter $filter `
        -Properties @('distinguishedName') -Server $Server
    
    if ($existing.Count -gt 0) {
        Write-Step "Group '$GroupName' already exists" -Type Info
        return $existing[0].distinguishedName
    }
    
    # Create in Users container
    $usersContainer = "CN=Users,$DomainDN"
    $groupDN = "CN=$GroupName,$usersContainer"
    
    if ($PSCmdlet.ShouldProcess($groupDN, "Create security group")) {
        $ldapPath = if ($Server) { "LDAP://$Server/$usersContainer" } else { "LDAP://$usersContainer" }
        $container = New-AdsiConnection -LdapPath $ldapPath
        
        try {
            $newGroup = $container.Children.Add("CN=$GroupName", 'group')
            $newGroup.Properties['sAMAccountName'].Add($GroupName)
            $newGroup.Properties['groupType'].Add(-2147483646)  # Global Security Group
            $newGroup.Properties['description'].Add($Description)
            $newGroup.CommitChanges()
            
            Write-Step "Created group: $GroupName" -Type Success
            return $groupDN
        }
        finally {
            if ($container) { $container.Dispose() }
        }
    }
}

function New-KerberosAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyName,
        
        [Parameter(Mandatory = $true)]
        [string]$ComputerGroupDN,
        
        [Parameter()]
        [string]$Description = 'Tier Authentication Policy managed by ADTierGuard',
        
        [Parameter()]
        [int]$TGTLifetimeMinutes = 240
    )
    
    $rootDse = Get-AdsiRootDse
    $configNC = $rootDse.ConfigurationNamingContext
    $policiesPath = "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,$configNC"
    
    # Check if policy exists
    $existing = Get-AdsiKerberosAuthenticationPolicy -Name $PolicyName
    
    if ($existing.Count -gt 0) {
        Write-Step "Authentication Policy '$PolicyName' already exists" -Type Info
        return $existing[0].distinguishedName
    }
    
    # Build SDDL for user allowed to authenticate from
    # This restricts users to only authenticate from computers in the specified group
    $sddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == `"$PolicyName`") || (Member_of_any {SID($ComputerGroupDN)}))"
    
    $policyDN = "CN=$PolicyName,$policiesPath"
    
    if ($PSCmdlet.ShouldProcess($policyDN, "Create Kerberos Authentication Policy")) {
        $ldapPath = "LDAP://$policiesPath"
        $container = New-AdsiConnection -LdapPath $ldapPath
        
        try {
            $newPolicy = $container.Children.Add("CN=$PolicyName", 'msDS-AuthNPolicy')
            $newPolicy.Properties['msDS-AuthNPolicyEnforced'].Add($true)
            $newPolicy.Properties['description'].Add($Description)
            
            # TGT lifetime in 100-nanosecond intervals (negative for relative time)
            $tgtLifetime = -($TGTLifetimeMinutes * 60 * 10000000)
            $newPolicy.Properties['msDS-UserTGTLifetime'].Add($tgtLifetime)
            
            $newPolicy.CommitChanges()
            
            Write-Step "Created Kerberos Authentication Policy: $PolicyName" -Type Success
            return $policyDN
        }
        catch {
            Write-Step "Failed to create Authentication Policy: $_" -Type Error
            throw
        }
        finally {
            if ($container) { $container.Dispose() }
        }
    }
}

function Install-ScheduledTasks {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,
        
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )
    
    $taskFolder = '\ADTierGuard\'
    
    # Create task folder if it doesn't exist
    try {
        $scheduler = New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        $rootFolder = $scheduler.GetFolder('\')
        
        try {
            $folder = $rootFolder.GetFolder('ADTierGuard')
        }
        catch {
            if ($PSCmdlet.ShouldProcess($taskFolder, "Create scheduled task folder")) {
                $folder = $rootFolder.CreateFolder('ADTierGuard')
            }
        }
    }
    catch {
        Write-Step "Failed to access Task Scheduler: $_" -Type Error
        return
    }
    
    $configPath = $ConfigurationPath
    
    # Create tasks
    $tasks = @()
    
    if ($Config.Tier0.Enabled) {
        $tasks += @{
            Name = 'Tier0-ComputerSync'
            Description = 'ADTierGuard Tier 0 Computer Synchronization'
            Script = Join-Path $ScriptPath 'Scripts\Invoke-TierComputerSync.ps1'
            Arguments = "-ConfigurationPath `"$configPath`" -TierLevel 0"
            IntervalMinutes = $Config.Scheduling.ComputerSyncIntervalMinutes
            Enabled = $true
        }
        
        $tasks += @{
            Name = 'Tier0-UserSync'
            Description = 'ADTierGuard Tier 0 User Synchronization'
            Script = Join-Path $ScriptPath 'Scripts\Invoke-TierUserSync.ps1'
            Arguments = "-ConfigurationPath `"$configPath`" -TierLevel 0"
            IntervalMinutes = $Config.Scheduling.UserSyncIntervalMinutes
            Enabled = $false  # Disabled by default for safety
        }
    }
    
    if ($Config.Tier1.Enabled) {
        $tasks += @{
            Name = 'Tier1-ComputerSync'
            Description = 'ADTierGuard Tier 1 Computer Synchronization'
            Script = Join-Path $ScriptPath 'Scripts\Invoke-TierComputerSync.ps1'
            Arguments = "-ConfigurationPath `"$configPath`" -TierLevel 1"
            IntervalMinutes = $Config.Scheduling.ComputerSyncIntervalMinutes
            Enabled = $true
        }
        
        $tasks += @{
            Name = 'Tier1-UserSync'
            Description = 'ADTierGuard Tier 1 User Synchronization'
            Script = Join-Path $ScriptPath 'Scripts\Invoke-TierUserSync.ps1'
            Arguments = "-ConfigurationPath `"$configPath`" -TierLevel 1"
            IntervalMinutes = $Config.Scheduling.UserSyncIntervalMinutes
            Enabled = $false
        }
    }
    
    foreach ($task in $tasks) {
        if ($PSCmdlet.ShouldProcess($task.Name, "Create scheduled task")) {
            try {
                $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
                    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$($task.Script)`" $($task.Arguments)"
                
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddHours(12) `
                    -RepetitionInterval (New-TimeSpan -Minutes $task.IntervalMinutes)
                
                $principal = if ($Config.ServiceAccount.UseGMSA) {
                    New-ScheduledTaskPrincipal -UserId "$($Config.ServiceAccount.GMSAName)$" `
                        -LogonType Password -RunLevel Highest
                }
                else {
                    New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                }
                
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
                
                $registeredTask = Register-ScheduledTask -TaskName $task.Name `
                    -TaskPath $taskFolder `
                    -Description $task.Description `
                    -Action $action `
                    -Trigger $trigger `
                    -Principal $principal `
                    -Settings $settings `
                    -Force
                
                if (-not $task.Enabled) {
                    Disable-ScheduledTask -TaskName $task.Name -TaskPath $taskFolder | Out-Null
                }
                
                Write-Step "Created scheduled task: $($task.Name) ($(if ($task.Enabled) { 'Enabled' } else { 'Disabled' }))" -Type Success
            }
            catch {
                Write-Step "Failed to create task '$($task.Name)': $_" -Type Error
            }
        }
    }
}

#endregion

#region Main Execution

try {
    Write-Banner
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Step "Please resolve the prerequisite issues and run the installer again." -Type Error
        exit 1
    }
    
    Write-Host ""
    
    # Get configuration
    $config = if ($NonInteractive -and $TemplateConfigPath) {
        Write-Step "Loading template configuration from: $TemplateConfigPath" -Type Info
        Import-TierGuardConfiguration -Path $TemplateConfigPath
    }
    else {
        Invoke-ConfigurationWizard
    }
    
    # Validate configuration
    Write-Step "Validating configuration..." -Type Info
    $validation = Test-TierGuardConfiguration -Configuration $config
    
    if (-not $validation.IsValid) {
        Write-Step "Configuration validation failed:" -Type Error
        foreach ($error in $validation.Errors) {
            Write-Step "  - $error" -Type Error
        }
        exit 1
    }
    
    if ($validation.Warnings.Count -gt 0) {
        foreach ($warning in $validation.Warnings) {
            Write-Step $warning -Type Warning
        }
    }
    
    Write-Step "Configuration validated successfully" -Type Success
    Write-Host ""
    
    # Create directories
    $configDir = Split-Path -Parent $ConfigurationPath
    if (-not (Test-Path $configDir)) {
        New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        Write-Step "Created directory: $configDir" -Type Success
    }
    
    if ($config.General.LogPath -and -not (Test-Path $config.General.LogPath)) {
        New-Item -Path $config.General.LogPath -ItemType Directory -Force | Out-Null
        Write-Step "Created log directory: $($config.General.LogPath)" -Type Success
    }
    
    # Save configuration
    Write-Step "Saving configuration to: $ConfigurationPath" -Type Info
    Export-TierGuardConfiguration -Configuration $config -Path $ConfigurationPath -Force
    Write-Step "Configuration saved" -Type Success
    Write-Host ""
    
    # Initialize event log
    Write-Step "Initializing event log source..." -Type Info
    Initialize-TierGuardEventLog -Source $config.General.EventLogSource
    Write-Step "Event log source initialized" -Type Success
    Write-Host ""
    
    # Create resources
    if (-not $SkipGroupCreation) {
        Write-Host "=== Creating AD Resources ===" -ForegroundColor Cyan
        Write-Host ""
        
        $rootDse = Get-AdsiRootDse
        $domainDN = $rootDse.DefaultNamingContext
        
        if ($config.Tier0.Enabled) {
            Write-Step "Creating Tier 0 resources..." -Type Info
            
            $tier0GroupDN = New-TierComputerGroup -GroupName $config.Tier0.ComputerGroupName `
                -DomainDN $domainDN -Description 'Tier 0 Computers - Managed by ADTierGuard'
            
            # Note: Kerberos Auth Policy creation requires additional SDDL setup
            # This is a simplified version - full implementation would include proper claim setup
            Write-Step "Note: Kerberos Authentication Policy must be created/configured via GUI or additional script" -Type Warning
        }
        
        if ($config.Tier1.Enabled) {
            Write-Step "Creating Tier 1 resources..." -Type Info
            
            $tier1GroupDN = New-TierComputerGroup -GroupName $config.Tier1.ComputerGroupName `
                -DomainDN $domainDN -Description 'Tier 1 Computers - Managed by ADTierGuard'
        }
        
        Write-Host ""
    }
    
    # Create scheduled tasks
    if (-not $SkipScheduledTasks) {
        Write-Host "=== Creating Scheduled Tasks ===" -ForegroundColor Cyan
        Write-Host ""
        
        Install-ScheduledTasks -Config $config -ScriptPath $Script:ModulePath
        Write-Host ""
    }
    
    # Final summary
    Write-Host "=== Installation Complete ===" -ForegroundColor Green
    Write-Host ""
    Write-Step "ADTierGuard has been installed successfully!" -Type Success
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Create/Configure Kerberos Authentication Policies in AD"
    Write-Host "  2. Verify computer groups have been created"
    Write-Host "  3. Run Computer Sync tasks manually to populate groups"
    Write-Host "  4. Test with a pilot user before enabling User Sync tasks"
    Write-Host "  5. Enable User Sync scheduled tasks when ready"
    Write-Host ""
    Write-Host "Configuration file: $ConfigurationPath" -ForegroundColor Yellow
    Write-Host "Log directory: $($config.General.LogPath)" -ForegroundColor Yellow
    Write-Host ""
    Write-Step "Review the documentation for Kerberos Armoring setup and GPO configuration" -Type Info
}
catch {
    Write-Step "Installation failed: $_" -Type Error
    Write-Step $_.ScriptStackTrace -Type Error
    exit 1
}

#endregion
