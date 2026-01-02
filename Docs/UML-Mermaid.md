# ADTierGuard - Mermaid UML Diagrams

## 1. Component Diagram

```mermaid
flowchart TB
    subgraph Scripts["Scripts Layer"]
        Init[Initialize-TierGuardAuth.ps1<br/>Forest Root Only]
        UserSync[Invoke-TierUserSync.ps1]
        CompSync[Invoke-TierComputerSync.ps1]
    end
    
    subgraph Core["Core Layer"]
        AuthMgr[AuthPolicyManager.psm1<br/>1,179 lines]
        Forest[ForestTopology.psm1<br/>528 lines]
        Config[ConfigurationManager.psm1<br/>502 lines]
        ADSI[AdsiOperations.psm1<br/>1,046 lines]
        Sync[SyncUtilities.psm1<br/>700 lines]
        ForestInfo[Get-ForestInfo.ps1<br/>599 lines]
    end
    
    subgraph Engine["Engine Layer"]
        Runspace[RunspaceEngine.psm1<br/>661 lines]
    end
    
    subgraph AD["Active Directory"]
        ConfigNC[Configuration NC<br/>Auth Policies & Silos]
        DomainNC[Domain NC<br/>Users, Groups, Computers]
        RootDSE[RootDSE<br/>Forest Detection]
    end
    
    Init --> AuthMgr
    UserSync --> AuthMgr
    UserSync --> Forest
    UserSync --> Runspace
    CompSync --> Forest
    CompSync --> Runspace
    
    AuthMgr --> ADSI
    Forest --> ADSI
    Forest --> ForestInfo
    Config --> Sync
    
    ADSI --> ConfigNC
    ADSI --> DomainNC
    ADSI --> RootDSE
    Runspace --> ADSI
```

## 2. Class Diagram - Tier Configuration

```mermaid
classDiagram
    direction TB
    
    class TierLevel {
        <<enumeration>>
        Tier0 = 0
        Tier1 = 1
        Tier2 = 2
    }
    
    class TierGuardConfiguration {
        +string SchemaVersion
        +GeneralSettings General
        +TierConfiguration Tier0
        +TierConfiguration Tier1
        +NotificationSettings Notifications
        +Validate() ValidationResult
        +GetTierConfig(level) TierConfiguration
        +Save(path) void
        +Load(path) TierGuardConfiguration
    }
    
    class TierConfiguration {
        +bool Enabled
        +TierLevel Level
        +string[] AdminOUs
        +string[] ServiceAccountOUs
        +string[] ComputerOUs
        +string ComputerGroupName
        +string KerberosAuthPolicyName
        +bool AddToProtectedUsers
        +bool EnforcePrivilegedGroupCleanup
        +bool IncludeDomainControllers
        +string[] ExcludedAccounts
        +IsUserInTier(userDN) bool
        +GetAuthPolicyDN() string
    }
    
    class TierSecuritySettings {
        +int TGTLifetimeMinutes
        +bool RequireSmartCard
        +bool RestrictDelegation
    }
    
    TierGuardConfiguration "1" *-- "2" TierConfiguration
    TierConfiguration "1" *-- "1" TierSecuritySettings
    TierConfiguration ..> TierLevel
```

## 3. Class Diagram - Forest Topology

```mermaid
classDiagram
    direction TB
    
    class DomainType {
        <<enumeration>>
        ForestRoot
        TreeRoot
        ChildDomain
    }
    
    class ForestTopology {
        +bool Initialized
        +string ForestRootFQDN
        +string ForestRootSID
        +DomainInfo[] Domains
        +DCInfo[] DomainControllers
        +DateTime LastRefresh
        +Refresh() void
        +GetForestRoot() DomainInfo
        +GetChildDomains() DomainInfo[]
        +IsForestRoot(dns) bool
    }
    
    class DomainInfo {
        +string DnsName
        +string NetBIOSName
        +string DistinguishedName
        +string DomainSID
        +DomainType Type
        +bool IsForestRoot
        +bool IsTreeRoot
        +bool IsChildDomain
        +string ParentDomain
        +int FunctionalLevel
        +string[] DomainControllers
        +string[] OnlineDCs
        +GetPreferredDC() string
        +TestConnectivity() bool
    }
    
    class DCInfo {
        +string FQDN
        +string Domain
        +string Site
        +bool IsGlobalCatalog
        +bool IsRODC
        +bool Online
        +string[] FSMORoles
        +string Type
        +Test() bool
        +GetRootDSE() RootDSE
    }
    
    ForestTopology "1" *-- "*" DomainInfo
    ForestTopology "1" *-- "*" DCInfo
    DomainInfo ..> DomainType
```

## 4. Class Diagram - Authentication Policy

```mermaid
classDiagram
    direction TB
    
    class AuthPolicyForestContext {
        +string ForestRootDN
        +string ForestRootDns
        +string CurrentDomainDN
        +string CurrentDomainDns
        +bool IsForestRoot
        +string ConfigurationNC
        +string AuthPoliciesPath
        +string AuthSilosPath
        +bool SupportsAuthPolicies
        +CanCreatePolicies() bool
    }
    
    class AuthenticationPolicy {
        +string Name
        +string DistinguishedName
        +string Description
        +bool Enforced
        +long UserTGTLifetime
        +long ComputerTGTLifetime
        +long ServiceTGTLifetime
        +string UserAllowedToAuthFrom
        +string UserAllowedToAuthTo
        +DateTime WhenCreated
        +GetTGTLifetimeMinutes() int
    }
    
    class AuthenticationPolicySilo {
        +string Name
        +string DistinguishedName
        +string Description
        +bool Enforced
        +string[] Members
        +int MemberCount
        +string UserAuthNPolicy
        +string ComputerAuthNPolicy
        +string ServiceAuthNPolicy
        +DateTime WhenCreated
        +AddMember(dn) void
        +RemoveMember(dn) void
        +IsMember(dn) bool
    }
    
    AuthPolicyForestContext "1" --> "*" AuthenticationPolicy : contains
    AuthPolicyForestContext "1" --> "*" AuthenticationPolicySilo : contains
    AuthenticationPolicySilo "*" --> "*" AuthenticationPolicy : references
```

## 5. Class Diagram - Runspace Engine

```mermaid
classDiagram
    direction TB
    
    class RunspacePoolManager {
        -RunspacePool Pool
        -int MaxRunspaces
        -string[] Modules
        -hashtable Variables
        +NewRunspacePool() RunspacePool
        +CloseRunspacePool() void
    }
    
    class ParallelOperationEngine {
        +int ThrottleLimit
        +int TimeoutSeconds
        +bool ShowProgress
        +string ProgressActivity
        +InvokeParallelOperation() ParallelJobResult[]
        +InvokeBatchOperation() ParallelJobResult[]
    }
    
    class ParallelJobResult {
        +string JobId
        +object InputObject
        +object Output
        +ErrorRecord[] Errors
        +bool Success
        +TimeSpan Duration
        +DateTime StartTime
        +DateTime EndTime
    }
    
    class IThreadSafeCollection~T~ {
        <<interface>>
        +Add(item) void
        +TryTake(out item) bool
        +Count int
        +ToArray() T[]
    }
    
    class ConcurrentBag~T~ {
        +Add(item) void
        +TryTake(out item) bool
    }
    
    class ConcurrentDictionary~K,V~ {
        +TryAdd(key, value) bool
        +TryGetValue(key, out value) bool
    }
    
    RunspacePoolManager --> ParallelOperationEngine : provides pool
    ParallelOperationEngine --> ParallelJobResult : produces
    ParallelOperationEngine --> IThreadSafeCollection : uses
    IThreadSafeCollection <|.. ConcurrentBag
    IThreadSafeCollection <|.. ConcurrentDictionary
```

## 6. Sequence Diagram - Forest Root Detection

```mermaid
sequenceDiagram
    autonumber
    participant Script as Initialize-TierGuardAuth
    participant AuthMgr as AuthPolicyManager
    participant ADSI as AdsiOperations
    participant AD as Active Directory
    
    Script->>AuthMgr: Test-AuthPolicyPrerequisites
    AuthMgr->>ADSI: Get-AdsiRootDse
    ADSI->>AD: LDAP://RootDSE
    AD-->>ADSI: defaultNamingContext<br/>rootDomainNamingContext<br/>configurationNamingContext
    ADSI-->>AuthMgr: RootDSE object
    
    AuthMgr->>AuthMgr: Compare:<br/>defaultNC == rootDomainNC?
    
    alt IsForestRoot = TRUE
        AuthMgr-->>Script: CanProceed: true<br/>IsForestRoot: true
        Script->>AuthMgr: New-TierAuthenticationPolicy
        AuthMgr->>AD: Create in CN=AuthN Policies,<br/>CN=Configuration,...
        AD-->>AuthMgr: Policy DN
        AuthMgr-->>Script: Policy created
    else IsForestRoot = FALSE
        AuthMgr-->>Script: Warning: Not forest root
        Script->>Script: Prompt for confirmation
    end
```

## 7. Sequence Diagram - User Sync Flow

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Domain Admin
    participant Sync as Invoke-TierUserSync
    participant AuthMgr as AuthPolicyManager
    participant Runspace as RunspaceEngine
    participant AD as Active Directory
    
    Admin->>Sync: -TierLevel 0
    Sync->>Sync: Load Configuration
    
    rect rgb(255, 240, 240)
        Note over Sync,AD: Policy Validation
        Sync->>AuthMgr: Get-TierAuthenticationPolicy
        AuthMgr->>AD: Search Configuration NC
        AD-->>AuthMgr: Policy DN (or empty)
        
        alt Policy NOT Found
            AuthMgr-->>Sync: Empty result
            Sync-->>Admin: ERROR: Run Initialize-TierGuardAuth
        else Policy Found
            AuthMgr-->>Sync: Policy DN + attributes
        end
    end
    
    rect rgb(240, 255, 240)
        Note over Sync,AD: User Discovery & Sync
        Sync->>AD: Search Tier OUs for users
        AD-->>Sync: users[]
        
        Sync->>Runspace: Invoke-ParallelOperation<br/>(Apply Auth Policy)
        
        loop Parallel Workers (4x)
            Runspace->>AD: Set msDS-AssignedAuthNPolicy
            AD-->>Runspace: Success/Error
        end
        
        Runspace-->>Sync: ParallelJobResult[]
    end
    
    Sync-->>Admin: Sync Complete<br/>(users processed, errors)
```

## 8. Sequence Diagram - Runspace Parallel Execution

```mermaid
sequenceDiagram
    autonumber
    participant Caller
    participant Engine as Invoke-ParallelOperation
    participant Pool as RunspacePool
    participant PS as PowerShell[]
    participant AD as Active Directory
    
    Caller->>Engine: 100 users, ThrottleLimit=4
    Engine->>Pool: New-RunspacePool(MaxRunspaces=4)
    Pool-->>Engine: Pool ready
    
    loop For each user
        Engine->>PS: [PowerShell]::Create()
        PS->>Pool: .RunspacePool = $pool
        PS->>PS: .AddScript($scriptBlock)
        PS->>PS: .BeginInvoke() [async]
        PS-->>Engine: IAsyncResult
        Engine->>Engine: Store in $jobs[]
    end
    
    par Worker 1
        PS->>AD: Set User1 policy
    and Worker 2
        PS->>AD: Set User2 policy
    and Worker 3
        PS->>AD: Set User3 policy
    and Worker 4
        PS->>AD: Set User4 policy
    end
    
    loop Collect Results
        Engine->>PS: .EndInvoke()
        PS-->>Engine: Output + Errors
    end
    
    Engine->>Pool: Close-RunspacePool
    Engine-->>Caller: 100 results (Success: 98, Errors: 2)
```

## 9. State Diagram - User Protection States

```mermaid
stateDiagram-v2
    [*] --> Unprotected : User created
    
    Unprotected --> Discovered : User in Tier OU<br/>OR added to priv group
    
    Discovered --> PolicyApplied : Invoke-TierUserSync<br/>sets msDS-AssignedAuthNPolicy
    
    PolicyApplied --> FullyProtected : Tier 0 only:<br/>Add to Protected Users<br/>Group cleanup
    
    PolicyApplied --> Discovered : User moved<br/>out of Tier OU
    
    FullyProtected --> Stale : User removed from<br/>Tier OU or priv group
    
    Stale --> Unprotected : Next sync cycle<br/>removes protections
    
    FullyProtected --> FullyProtected : Regular sync<br/>(no changes needed)
```

## 10. State Diagram - Authentication Policy Lifecycle

```mermaid
stateDiagram-v2
    [*] --> NotCreated
    
    NotCreated --> AuditMode : Initialize-TierGuardAuth<br/>(Forest Root, Enterprise Admin)
    
    AuditMode --> Enforced : Set-TierAuthPolicy<br/>-Enforced $true
    
    Enforced --> AuditMode : Disable for emergency<br/>-Enforced $false
    
    Enforced --> Enforced : Update TGT lifetime<br/>Update SDDL
    
    AuditMode --> Enforced : Re-enable
    
    Enforced --> [*] : Remove-TierAuthPolicy<br/>(breaks assignments!)
    AuditMode --> [*] : Remove-TierAuthPolicy
```

## 11. Activity Diagram - Full Sync Workflow

```mermaid
flowchart TD
    Start([Start]) --> LoadConfig[Load Configuration<br/>TierGuard.json]
    LoadConfig --> InitLog[Initialize Logging<br/>& Event Log]
    InitLog --> TierEnabled{Tier Enabled?}
    
    TierEnabled -->|No| ExitDisabled[Exit: Tier Disabled]
    TierEnabled -->|Yes| GetTierConfig[Get Tier Config]
    
    GetTierConfig --> ValidatePolicy[Get-TierAuthenticationPolicy<br/>from Configuration NC]
    ValidatePolicy --> PolicyFound{Policy Found?}
    
    PolicyFound -->|No| PolicyError[ERROR: Run<br/>Initialize-TierGuardAuth<br/>from forest root]
    PolicyError --> ExitError([Exit Error])
    
    PolicyFound -->|Yes| PolicyOK[Log: Policy Found OK]
    PolicyOK --> DiscoverDomains[Get-SyncTargetDomains<br/>Auto-discover forest]
    
    DiscoverDomains --> ForEachDomain{For Each Domain}
    
    ForEachDomain --> CheckForestRoot{Is Forest Root?}
    CheckForestRoot -->|Yes| IncludeEnterprise[Include Enterprise Admins<br/>Schema Admins]
    CheckForestRoot -->|No| DomainOnly[Domain-only groups]
    
    IncludeEnterprise --> SearchUsers[Search Tier OUs<br/>for Users]
    DomainOnly --> SearchUsers
    
    SearchUsers --> SearchSvcAcct[Search for<br/>Service Accounts]
    SearchSvcAcct --> ParallelApply[Parallel Apply<br/>Auth Policy]
    
    ParallelApply --> Tier0Check{Tier 0?}
    Tier0Check -->|Yes| ProtectedUsers[Add to<br/>Protected Users]
    Tier0Check -->|No| NextDomain
    
    ProtectedUsers --> GroupCleanup[Cleanup Privileged<br/>Group Membership]
    GroupCleanup --> NextDomain{Next Domain?}
    
    NextDomain -->|Yes| ForEachDomain
    NextDomain -->|No| Aggregate[Aggregate Results]
    
    Aggregate --> WriteLog[Write Event Log<br/>& Summary]
    WriteLog --> End([End])
```

## 12. Activity Diagram - Forest Root Detection

```mermaid
flowchart TD
    Start([Start]) --> Connect[Connect to RootDSE<br/>LDAP://RootDSE]
    Connect --> ReadAttrs[Read Attributes:<br/>• defaultNamingContext<br/>• rootDomainNamingContext<br/>• configurationNamingContext]
    
    ReadAttrs --> Extract[Extract forest root from configNC:<br/>CN=Configuration,DC=corp,DC=com<br/>↓<br/>DC=corp,DC=com]
    
    Extract --> Compare{defaultNC ==<br/>rootDomainNC?}
    
    Compare -->|EQUAL| IsRoot[IsForestRoot: TRUE<br/><br/>Example:<br/>default: DC=corp,DC=com<br/>root: DC=corp,DC=com<br/>✓ MATCH]
    
    Compare -->|NOT EQUAL| NotRoot[IsForestRoot: FALSE<br/><br/>Example:<br/>default: DC=child,DC=corp,DC=com<br/>root: DC=corp,DC=com<br/>✗ NO MATCH]
    
    IsRoot --> CanCreate[Can create policies<br/>and silos in<br/>Configuration NC]
    
    NotRoot --> ReadOnly[Can only READ and<br/>APPLY policies<br/>not create]
    
    CanCreate --> Return[Return Context Object]
    ReadOnly --> Return
    
    Return --> End([End])
```

## 13. Deployment Diagram

```mermaid
flowchart TB
    subgraph Forest["Active Directory Forest: corp.contoso.com"]
        subgraph ForestRoot["Forest Root Domain: corp.contoso.com"]
            DC1["DC01.corp.contoso.com<br/>Domain Controller<br/><br/>Configuration NC:<br/>• AuthN Policies<br/>• AuthN Silos"]
            
            MgmtServer["Management Server<br/><br/>ADTierGuard Installation:<br/>C:\ADTierGuard\<br/><br/>Task Scheduler:<br/>• Daily Tier0 Sync<br/>• Daily Tier1 Sync"]
        end
        
        subgraph ChildDomain["Child Domain: child.corp.contoso.com"]
            DC2["DC01.child.corp.contoso.com<br/>Domain Controller<br/><br/>Domain NC only<br/>Users point to<br/>forest root policy"]
            
            OptionalSync["Optional: Local Sync<br/><br/>Can run sync for<br/>THIS domain only"]
        end
    end
    
    MgmtServer -->|LDAP/ADSI| DC1
    MgmtServer -->|LDAP/ADSI| DC2
    OptionalSync -->|LDAP/ADSI| DC2
    DC2 -.->|Policy Reference| DC1
```

## 14. Data Flow Diagram - Level 1

```mermaid
flowchart LR
    subgraph External
        Config[(TierGuard.json)]
        EventLog[(Windows<br/>Event Log)]
    end
    
    subgraph Processes
        P1[1.0<br/>Load & Validate<br/>Config]
        P2[2.0<br/>Discover<br/>Forest Topology]
        P3[3.0<br/>Sync User<br/>Protections]
    end
    
    subgraph AD["Active Directory"]
        ConfigNC[(Configuration NC<br/>Policies & Silos)]
        DomainNC[(Domain NC<br/>Users, Groups)]
    end
    
    Config -->|tier config| P1
    P1 -->|validated config| P2
    P1 -->|validated config| P3
    
    P2 -->|domains| P3
    P2 <-->|topology| DomainNC
    
    P3 <-->|policy validation| ConfigNC
    P3 <-->|user updates| DomainNC
    P3 -->|events| EventLog
```
