# ADTierGuard

**Enterprise Active Directory Tier Isolation Module v2.3.0**

A comprehensive solution for Active Directory Tier 0/1 isolation using Kerberos Authentication Policies. Protects privileged accounts by restricting where they can authenticate.

## Features

- **Two Deployment Models**: Centralized (management server) or Distributed (GPO on DCs)
- **GPO-Based Deployment**: Scheduled tasks pushed to all Domain Controllers
- **GMSA Support**: Secure Group Managed Service Account for scheduled tasks
- **Pure ADSI**: No dependency on ActiveDirectory PowerShell module
- **Runspace Parallelism**: High-performance parallel processing
- **Kerberos Authentication Policies**: Restrict admin authentication to tier systems
- **Protected Users**: Automatic group membership for Tier 0 admins
- **Privileged Group Cleanup**: Remove unexpected users from admin groups
- **Kerberos Armoring**: Automatic FAST configuration via GPO

## Deployment Models

### Model 1: Distributed (GPO-Based) - Recommended

Scripts run on every Domain Controller via GPO-deployed scheduled tasks.

```
Forest Root Domain Controllers OU
└── GPO: "TierGuard Isolation"
    ├── Scheduled Task: Computer Sync (SYSTEM) - Every 10 min
    └── Scheduled Task: User Sync (GMSA) - Every 10 min
```

**Advantages:**
- No single point of failure
- Faster sync (every 10 minutes)
- Self-healing (runs on all DCs)
- GMSA for secure service account

**Installation:**
```powershell
# Run from forest root domain as Enterprise Admin
.\Install-ADTierGuard.ps1 -Scope All-Tiers -UseGMSA -DeployGPO
```

### Model 2: Centralized (Management Server)

Scripts run from a dedicated management server on a schedule.

```
Management Server
└── Scheduled Task (runs as gMSA or admin account)
    ├── Invoke-TierUserSync
    └── Invoke-TierComputerSync
```

**Advantages:**
- Single point of control
- Easier to monitor
- Works with existing task scheduling

**Installation:**
```powershell
# Run from forest root first
.\Initialize-TierGuardAuth.ps1 -CreateTier0 -CreateTier1

# Then run sync from any domain
Import-Module .\ADTierGuard.psd1
Invoke-TierUserSync -TierLevel 0
Invoke-TierComputerSync -TierLevel 0
```

## Quick Start (Distributed Model)

```powershell
# 1. Run installer from forest root DC as Enterprise Admin
.\Install-TierGuardForest.ps1

# 2. Follow interactive prompts to configure:
#    - Domains to manage
#    - Tier 0/1 OUs
#    - Computer groups
#    - GMSA name

# 3. Configure scheduled tasks in GPO (manual step)

# 4. Enable GPO link to Domain Controllers OU

# 5. Wait for computer sync to populate groups

# 6. Reboot Tier 0/1 servers

# 7. Test with a tier admin account

# 8. Enable user sync scheduled tasks
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            FOREST ROOT DOMAIN                                │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Configuration NC (Forest-Wide)                                      │   │
│  │  └─ CN=AuthN Policies                                                │   │
│  │      ├─ TierGuard-Tier0-AuthPolicy                                   │   │
│  │      └─ TierGuard-Tier1-AuthPolicy                                   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  SYSVOL (Replicated to all DCs)                                      │   │
│  │  └─ \\domain\SYSVOL\domain\scripts\TierGuard\                        │   │
│  │      ├─ Sync-TierComputers.ps1                                       │   │
│  │      ├─ Sync-TierUsers.ps1                                           │   │
│  │      ├─ TierGuard.config                                             │   │
│  │      └─ Core\*.psm1                                                  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Domain Controllers OU                                                │   │
│  │  └─ GPO: TierGuard Isolation                                         │   │
│  │      └─ Scheduled Tasks → Run on every DC                            │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## File Structure

```
ADTierGuard/
├── ADTierGuard.psd1              # Module manifest
├── ADTierGuard.psm1              # Main module loader
├── Install-TierGuardForest.ps1   # GPO-based forest deployment
├── Initialize-TierGuardAuth.ps1  # Centralized auth policy setup
├── Install-TierGuard.ps1         # Centralized installation
├── Core/
│   ├── AdsiOperations.psm1       # Pure ADSI operations
│   ├── AuthPolicyManager.psm1    # Authentication policy management
│   ├── ConfigurationManager.psm1 # JSON config handling
│   ├── ForestDeployment.psm1     # GPO/GMSA/SYSVOL deployment
│   ├── ForestTopology.psm1       # Forest discovery
│   ├── SyncUtilities.psm1        # Logging and utilities
│   └── Get-ForestInfo.ps1        # Standalone forest info
├── Engine/
│   └── RunspaceEngine.psm1       # Parallel processing
├── Scripts/
│   ├── Sync-TierComputers.ps1    # DC-based computer sync
│   ├── Sync-TierUsers.ps1        # DC-based user sync
│   ├── Invoke-TierComputerSync.ps1  # Centralized computer sync
│   └── Invoke-TierUserSync.ps1      # Centralized user sync
├── GPO/
│   └── {TierGuard-GPO-Backup}/   # GPO template for import
├── Config/
│   └── Sample-TierGuard.json     # Sample configuration
└── Docs/
    ├── Deployment-Guide.md
    ├── AuthPolicy-Configuration.md
    ├── UML-Architecture.md
    └── UML-Mermaid.md
```

## Requirements

- Windows Server 2012 R2 Forest Functional Level or higher
- PowerShell 5.1 or higher
- Enterprise Admin (for forest deployment)
- Domain Admin (for domain-only operations)

## Event Log Monitoring

Events are logged to Application log with source "TierGuard":

| Event ID | Type | Description |
|----------|------|-------------|
| 1000 | Info | Computer sync started |
| 1001 | Info | Computer sync completed |
| 1100 | Info | Computer added to group |
| 1101 | Info | Computer removed from group |
| 2000 | Info | User sync started |
| 2001 | Info | User sync completed |
| 2100 | Info | Auth policy applied to user |
| 2101 | Info | User added to Protected Users |
| 2102 | Warn | User removed from privileged group |

## License

MIT License - See LICENSE file for details.

## Credits

Based on Microsoft's Enterprise Access Model and inspired by the TierLevelIsolation project by Andreas Lucas [MSFT].

**Enterprise Active Directory Tier Isolation Module**

A pure ADSI (System.DirectoryServices) implementation for Active Directory Tier 0/1 isolation using Kerberos Authentication Policies. Zero dependency on the ActiveDirectory PowerShell module.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2012%20R2%2B-blue.svg)](https://www.microsoft.com/en-us/windows-server)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture](#architecture)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Overview

ADTierGuard implements Microsoft's Administrative Tier Model (also known as the Enhanced Security Administrative Environment - ESAE) using Kerberos Authentication Policies. This restricts where privileged credentials can be used, preventing credential theft escalation attacks.

### The Tier Model

| Tier | Description | Examples |
|------|-------------|----------|
| **Tier 0** | Forest/Domain administration | Domain Controllers, AD admins, PKI, SCCM |
| **Tier 1** | Server administration | Member servers, server admins |
| **Tier 2** | Workstation administration | Workstations, helpdesk |

### How It Works

1. **Computer Groups**: Computers are organized into tier-specific security groups
2. **Kerberos Authentication Policies**: Restrict where user credentials can be used
3. **Protected Users**: Tier 0 accounts added to Protected Users group
4. **Privileged Group Cleanup**: Unauthorized users removed from privileged groups

## Features

### Core Capabilities

- ✅ **Pure ADSI Implementation** - No ActiveDirectory PowerShell module required
- ✅ **Runspace Parallel Processing** - High-performance bulk operations
- ✅ **Computer Group Management** - Automatic synchronization of tier groups
- ✅ **Kerberos Policy Enforcement** - Apply authentication policies to users
- ✅ **Protected Users Management** - Automatic membership for Tier 0
- ✅ **Privileged Group Cleanup** - Remove unauthorized privileged access

### Enterprise Features

- 🌐 Forest-wide or single-domain operation
- 📊 Comprehensive logging (file + Windows Event Log)
- ⚙️ JSON-based configuration with validation
- 🔄 Scheduled task integration
- 📧 Email notifications (configurable)
- 🛡️ WhatIf support for safe testing
- 🔐 GMSA support for scheduled tasks

## Prerequisites

### System Requirements

| Requirement | Minimum |
|-------------|---------|
| PowerShell | 5.1 (Windows PowerShell) or 7+ (PowerShell Core) |
| Forest Functional Level | Windows Server 2012 R2 (Level 6) |
| .NET Framework | 4.5 or higher |
| Operating System | Windows Server 2012 R2+ / Windows 10+ |

### Permissions Required

- **Enterprise Admin** - For forest-wide deployment
- **Domain Admin** - For single-domain deployment
- **Schema Read** - To query Kerberos Authentication Policies

### Pre-Configuration Steps

1. **Create Kerberos Authentication Policies** (manual step)
   ```powershell
   # Example using AD PowerShell (one-time setup)
   New-ADAuthenticationPolicy -Name "TG-Tier0-AuthPolicy" `
       -UserAllowedToAuthenticateFrom "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(TG-Tier0-RestrictionGroup)}))" `
       -Enforce
   ```

2. **Enable Kerberos Armoring** via Group Policy
   - Path: `Computer Configuration\Policies\Administrative Templates\System\KDC`
   - Setting: `KDC support for claims, compound authentication and Kerberos armoring`
   - Value: `Enabled` with `Always provide claims`

## Installation

### Option 1: Interactive Installation

```powershell
# Download and extract to desired location
cd C:\ADTierGuard

# Run the installation wizard
.\Install-TierGuard.ps1
```

### Option 2: Non-Interactive Installation

```powershell
.\Install-TierGuard.ps1 -NonInteractive `
    -TemplateConfigPath ".\Config\Sample-TierGuard.json" `
    -Force
```

### Option 3: Module Import Only

```powershell
# Import the module
Import-Module .\ADTierGuard.psd1

# Verify import
Get-TierGuardStatus
```

## Quick Start

### 1. Test Environment Readiness

```powershell
Import-Module .\ADTierGuard.psd1
Test-TierEnvironment
```

### 2. Create Configuration

```powershell
# Copy and modify sample configuration
Copy-Item .\Config\Sample-TierGuard.json .\Config\TierGuard.json

# Or create new configuration
New-TierGuardConfiguration -Path .\Config\TierGuard.json
```

### 3. Validate Configuration

```powershell
$result = Initialize-TierGuard -ConfigurationPath .\Config\TierGuard.json -ValidateOnly
$result.Warnings | ForEach-Object { Write-Warning $_ }
```

### 4. Run Computer Sync (WhatIf)

```powershell
Invoke-TierComputerSync -ConfigurationPath .\Config\TierGuard.json -TierLevel 0 -WhatIf
```

### 5. Run Computer Sync (Production)

```powershell
Invoke-TierComputerSync -ConfigurationPath .\Config\TierGuard.json -TierLevel 0
```

## Configuration

### Configuration File Structure

```json
{
  "General": {
    "ForestScope": true,
    "LogLevel": "Information",
    "LogPath": "C:\\ADTierGuard\\Logs",
    "EventLogSource": "ADTierGuard",
    "MaxParallelOperations": 8,
    "OperationTimeoutSeconds": 300
  },
  "Tier0": {
    "Enabled": true,
    "AdminOUs": ["OU=Tier0-Admins,OU=Admin,DC=contoso,DC=com"],
    "ServiceAccountOUs": ["OU=Tier0-ServiceAccounts,OU=Admin,DC=contoso,DC=com"],
    "ComputerOUs": ["OU=Domain Controllers,DC=contoso,DC=com"],
    "ComputerGroupName": "TG-Tier0-RestrictionGroup",
    "KerberosAuthPolicyName": "TG-Tier0-AuthPolicy",
    "AddToProtectedUsers": true,
    "EnforcePrivilegedGroupCleanup": true,
    "ExcludedAccounts": ["krbtgt", "Administrator"]
  },
  "Tier1": {
    "Enabled": true,
    "AdminOUs": ["OU=Tier1-Admins,OU=Admin,DC=contoso,DC=com"],
    "ServiceAccountOUs": ["OU=Tier1-ServiceAccounts,OU=Admin,DC=contoso,DC=com"],
    "ComputerOUs": ["OU=Tier1-Servers,OU=Servers,DC=contoso,DC=com"],
    "ComputerGroupName": "TG-Tier1-RestrictionGroup",
    "KerberosAuthPolicyName": "TG-Tier1-AuthPolicy",
    "AddToProtectedUsers": false,
    "EnforcePrivilegedGroupCleanup": false,
    "ExcludedAccounts": []
  }
}
```

### Configuration Options

| Section | Setting | Description | Default |
|---------|---------|-------------|---------|
| General | ForestScope | Process all domains | `true` |
| General | LogLevel | Debug/Information/Warning/Error | `Information` |
| General | MaxParallelOperations | Concurrent threads | `8` |
| Tier0/1 | Enabled | Enable this tier | `true` |
| Tier0/1 | AdminOUs | OUs containing admin users | - |
| Tier0/1 | ServiceAccountOUs | OUs containing service accounts | - |
| Tier0/1 | ComputerOUs | OUs containing computers | - |
| Tier0/1 | AddToProtectedUsers | Add to Protected Users group | Tier0: `true` |
| Tier0/1 | EnforcePrivilegedGroupCleanup | Remove unauthorized privileged members | Tier0: `true` |

## Usage

### Computer Synchronization

```powershell
# Sync Tier 0 computers (adds to restriction group)
Invoke-TierComputerSync -ConfigurationPath .\Config\TierGuard.json -TierLevel 0

# Sync Tier 1 computers with custom throttle
Invoke-TierComputerSync -ConfigurationPath .\Config\TierGuard.json -TierLevel 1 -ThrottleLimit 16

# Forest-wide sync
Invoke-TierComputerSync -ConfigurationPath .\Config\TierGuard.json -TierLevel 0 -ForestScope
```

### User Synchronization

```powershell
# Apply Kerberos policies to Tier 0 users
Invoke-TierUserSync -ConfigurationPath .\Config\TierGuard.json -TierLevel 0

# Skip Protected Users addition
Invoke-TierUserSync -ConfigurationPath .\Config\TierGuard.json -TierLevel 0 -SkipProtectedUsers

# Skip privileged group cleanup
Invoke-TierUserSync -ConfigurationPath .\Config\TierGuard.json -TierLevel 0 -SkipPrivilegedGroupCleanup
```

### Query Functions

```powershell
# Get all Tier 0 computers
$computers = Get-TierComputers -ConfigurationPath .\Config\TierGuard.json -TierLevel 0

# Get all Tier 0 users
$users = Get-TierUsers -ConfigurationPath .\Config\TierGuard.json -TierLevel 0

# Include service accounts
$allUsers = Get-TierUsers -ConfigurationPath .\Config\TierGuard.json -TierLevel 0 -IncludeServiceAccounts
```

### Direct ADSI Operations

```powershell
# Get RootDSE
$rootDse = Get-AdsiRootDse

# Search for computers
$computers = Get-AdsiComputer -SearchBase "OU=Servers,DC=contoso,DC=com" -IncludeDisabled:$false

# Get group members (handles large groups)
$members = Get-AdsiGroupMember -GroupDN "CN=Domain Admins,CN=Users,DC=contoso,DC=com"

# Apply authentication policy
Set-AdsiAuthenticationPolicy -UserDN "CN=Admin,OU=Admins,DC=contoso,DC=com" -PolicyDN "CN=TG-Tier0-AuthPolicy,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,DC=contoso,DC=com"
```

## Architecture

### Module Structure

```
ADTierGuard/
├── ADTierGuard.psd1          # Module manifest
├── ADTierGuard.psm1          # Main module loader
├── Install-TierGuard.ps1     # Installation wizard
├── Core/
│   ├── AdsiOperations.psm1   # Pure ADSI functions
│   └── ConfigurationManager.psm1  # Config & logging
├── Engine/
│   └── RunspaceEngine.psm1   # Parallel processing
├── Scripts/
│   ├── Invoke-TierComputerSync.ps1
│   └── Invoke-TierUserSync.ps1
├── Config/
│   └── Sample-TierGuard.json
└── Docs/
    └── Deployment-Guide.md
```

### Processing Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Configuration  │────▶│  ADSI Operations│────▶│ Runspace Engine │
│    Manager      │     │   (Queries)     │     │  (Parallel Ops) │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                        ┌───────────────────────────────┘
                        ▼
              ┌─────────────────┐     ┌─────────────────┐
              │   Event Log     │     │    File Log     │
              │   (Windows)     │     │    (JSON/Text)  │
              └─────────────────┘     └─────────────────┘
```

### Event IDs

| Range | Category | Examples |
|-------|----------|----------|
| 1000-1999 | Computer Operations | 1000: Sync Started, 1001: Sync Completed, 1100: Added, 1101: Removed |
| 2000-2999 | User Operations | 2000: Sync Started, 2100: Policy Applied, 2102: Protected Users |
| 3000-3999 | Configuration | 3000: Config Loaded, 3001: Config Error |
| 9000-9999 | General | 9000: Service Started, 9001: Service Stopped |

## Security Considerations

### Recommended Practices

1. **Test in Lab First** - Always validate in a test environment
2. **Use WhatIf** - Preview changes before applying
3. **Start with Computer Sync** - Get groups populated before enabling policies
4. **Staged Rollout** - Apply policies to pilot users first
5. **Monitor Events** - Watch for policy violations
6. **Backup Configuration** - Keep copies of working configurations

### Protected Users Group Considerations

Adding accounts to Protected Users enforces:
- No NTLM authentication
- No DES or RC4 in Kerberos pre-authentication
- No delegation
- 4-hour TGT lifetime (non-renewable)

**Warning**: Some applications may break with Protected Users membership.

### Service Account Handling

- Service accounts in ServiceAccountOUs are **excluded** from Kerberos policies
- Service accounts are **allowed** in privileged groups
- gMSAs and MSAs are automatically detected and handled appropriately

## Troubleshooting

### Common Issues

**Issue**: "Cannot connect to domain"
```powershell
# Verify domain connectivity
$rootDse = Get-AdsiRootDse
$rootDse.defaultNamingContext
```

**Issue**: "Forest functional level too low"
```powershell
# Check forest level (needs 6+ for AuthN Policies)
$rootDse = Get-AdsiRootDse
$rootDse.forestFunctionality  # Should be >= 6
```

**Issue**: "Policy not applying"
1. Verify Kerberos Armoring GPO is applied
2. Check policy SDDL references correct group SID
3. Ensure computer has restarted after group membership change
4. Verify user's TGT has refreshed (log off/on or `klist purge`)

**Issue**: "User locked out after policy applied"
1. User may be authenticating from non-tier computer
2. Check Event Viewer for KDC errors
3. Temporarily remove policy: `Remove-AdsiAuthenticationPolicy -UserDN "..."`

### Logging

```powershell
# View recent events
Get-EventLog -LogName Application -Source "ADTierGuard" -Newest 50

# Check log files
Get-ChildItem "C:\ADTierGuard\Logs" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

### Debug Mode

```powershell
# Enable verbose output
$VerbosePreference = 'Continue'
Invoke-TierComputerSync -ConfigurationPath .\Config\TierGuard.json -TierLevel 0 -Verbose
```

## Performance

### Benchmarks

| Operation | 1,000 Objects | 10,000 Objects | 50,000 Objects |
|-----------|---------------|----------------|----------------|
| Computer Sync | ~30 sec | ~3 min | ~15 min |
| User Sync | ~45 sec | ~5 min | ~20 min |

### Tuning

```json
{
  "General": {
    "MaxParallelOperations": 16,  // Increase for faster processing
    "OperationTimeoutSeconds": 600  // Increase for slow networks
  }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Based on [Kili69/TierLevelIsolation](https://github.com/Kili69/TierLevelIsolation)
- Microsoft's [Securing Privileged Access](https://docs.microsoft.com/en-us/security/compass/privileged-access-strategy) guidance
- [Kerberos Authentication Policies](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos)

---

**ADTierGuard** - Protecting your Active Directory, one tier at a time. 🛡️
