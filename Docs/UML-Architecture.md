# ADTierGuard - Expert Level UML Documentation

## Table of Contents
1. [System Context Diagram](#1-system-context-diagram)
2. [Component Architecture](#2-component-architecture)
3. [Class Diagrams](#3-class-diagrams)
4. [Sequence Diagrams](#4-sequence-diagrams)
5. [Activity Diagrams](#5-activity-diagrams)
6. [State Machine Diagrams](#6-state-machine-diagrams)
7. [Data Flow Diagrams](#7-data-flow-diagrams)
8. [Deployment Diagram](#8-deployment-diagram)

---

## 1. System Context Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                        SYSTEM CONTEXT                                                │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                        ┌─────────────────────┐
                                        │   Enterprise Admin  │
                                        │      «actor»        │
                                        │                     │
                                        │ • Initialize Auth   │
                                        │   Policies (once)   │
                                        └──────────┬──────────┘
                                                   │
                                                   │ Initialize-TierGuardAuth.ps1
                                                   ▼
┌──────────────────────┐                ┌─────────────────────────────────────┐                ┌──────────────────────┐
│                      │                │                                     │                │                      │
│   Domain Admin       │                │          ADTierGuard                │                │   Active Directory   │
│     «actor»          │                │           «system»                  │                │      Forest          │
│                      │                │                                     │                │    «external»        │
│ • Run scheduled      │ Invoke-Tier*   │  ┌─────────────────────────────┐   │   LDAP/ADSI    │                      │
│   sync operations    │───────────────►│  │   Enterprise Access Model   │   │◄──────────────►│ • Configuration NC   │
│ • Review reports     │                │  │      Enforcement Engine     │   │                │ • Domain NCs         │
│                      │                │  └─────────────────────────────┘   │                │ • Schema NC          │
└──────────────────────┘                │                                     │                │                      │
                                        │  Tier 0 & Tier 1 Protection         │                └──────────────────────┘
                                        │  • Auth Policies                    │                           │
┌──────────────────────┐                │  • Protected Users                  │                           │
│                      │                │  • Computer Groups                  │                           │
│  Task Scheduler      │ Scheduled      │  • Privileged Group Cleanup         │                ┌──────────┴──────────┐
│    «external»        │ Execution      │                                     │                │                     │
│                      │───────────────►│                                     │                ▼                     ▼
│ • Daily/Hourly       │                └─────────────────────────────────────┘         ┌─────────────┐     ┌─────────────┐
│   sync triggers      │                           │                                    │ Forest Root │     │   Child     │
│                      │                           │                                    │   Domain    │     │  Domains    │
└──────────────────────┘                           ▼                                    │             │     │             │
                                        ┌─────────────────────┐                         │ • Auth      │     │ • Users     │
                                        │   Windows Event     │                         │   Policies  │     │ • Computers │
                                        │       Log           │                         │ • Silos     │     │ • Groups    │
                                        │    «external»       │                         └─────────────┘     └─────────────┘
                                        └─────────────────────┘
```

---

## 2. Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   ADTIERGUARD COMPONENT DIAGRAM                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                         «module»                                                     │
│                                        ADTierGuard                                                   │
│                                                                                                      │
│  ┌───────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                      Scripts Layer                                             │  │
│  │                                                                                                │  │
│  │  ┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────┐        │  │
│  │  │ Initialize-TierGuard    │  │ Invoke-TierUserSync     │  │ Invoke-TierComputerSync │        │  │
│  │  │ Auth.ps1                │  │ .ps1                    │  │ .ps1                    │        │  │
│  │  │                         │  │                         │  │                         │        │  │
│  │  │ • Create Auth Policies  │  │ • Sync Tier 0/1 users   │  │ • Sync Tier 0/1 servers │        │  │
│  │  │ • Create Auth Silos     │  │ • Apply Auth Policy     │  │ • Update computer groups│        │  │
│  │  │ • Forest root required  │  │ • Protected Users       │  │ • Track DC membership   │        │  │
│  │  │                         │  │ • Group cleanup         │  │                         │        │  │
│  │  └────────────┬────────────┘  └────────────┬────────────┘  └────────────┬────────────┘        │  │
│  │               │                            │                            │                      │  │
│  └───────────────┼────────────────────────────┼────────────────────────────┼──────────────────────┘  │
│                  │                            │                            │                         │
│                  └────────────────────────────┼────────────────────────────┘                         │
│                                               │                                                      │
│                                               ▼                                                      │
│  ┌───────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                       Core Layer                                               │  │
│  │                                                                                                │  │
│  │  ┌───────────────────────┐  ┌───────────────────────┐  ┌───────────────────────┐              │  │
│  │  │  AuthPolicyManager    │  │   ForestTopology      │  │  ConfigurationManager │              │  │
│  │  │      .psm1            │  │       .psm1           │  │       .psm1           │              │  │
│  │  │  (1,179 lines)        │  │    (528 lines)        │  │    (502 lines)        │              │  │
│  │  │                       │  │                       │  │                       │              │  │
│  │  │ • Get/New/Set Auth    │  │ • Get-ForestTopology  │  │ • Import/Export config│              │  │
│  │  │   Policy              │  │ • Get-ForestRootDomain│  │ • Validate settings   │              │  │
│  │  │ • Get/New Auth Silo   │  │ • Test-IsForestRoot   │  │ • Merge defaults      │              │  │
│  │  │ • Add/Remove Silo     │  │ • Get-SyncTargetDomains│ │                       │              │  │
│  │  │   Members             │  │                       │  │                       │              │  │
│  │  └───────────┬───────────┘  └───────────┬───────────┘  └───────────┬───────────┘              │  │
│  │              │                          │                          │                          │  │
│  │  ┌───────────┴───────────┐  ┌───────────┴───────────┐  ┌───────────┴───────────┐              │  │
│  │  │   AdsiOperations      │  │    SyncUtilities      │  │  Get-ForestInfo       │              │  │
│  │  │       .psm1           │  │        .psm1          │  │       .ps1            │              │  │
│  │  │   (1,046 lines)       │  │     (700 lines)       │  │    (599 lines)        │              │  │
│  │  │                       │  │                       │  │                       │              │  │
│  │  │ • Pure ADSI/LDAP ops  │  │ • Logging framework   │  │ • Standalone forest   │              │  │
│  │  │ • No AD module needed │  │ • Progress tracking   │  │   discovery script    │              │  │
│  │  │ • Search, Get, Set    │  │ • Result aggregation  │  │ • DC enumeration      │              │  │
│  │  │ • Group membership    │  │ • Event log writing   │  │ • FSMO detection      │              │  │
│  │  └───────────────────────┘  └───────────────────────┘  └───────────────────────┘              │  │
│  │                                                                                                │  │
│  └────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                               │                                                      │
│                                               ▼                                                      │
│  ┌───────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                      Engine Layer                                              │  │
│  │                                                                                                │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                              RunspaceEngine.psm1 (661 lines)                            │  │  │
│  │  │                                                                                         │  │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │  │  │
│  │  │  │ New-RunspacePool│  │Invoke-Parallel  │  │ Thread-Safe     │  │ Progress        │    │  │  │
│  │  │  │                 │  │ Operation       │  │ Collections     │  │ Tracker         │    │  │  │
│  │  │  │ • Create pool   │  │                 │  │                 │  │                 │    │  │  │
│  │  │  │ • Configure     │  │ • Async jobs    │  │ • ConcurrentBag │  │ • Real-time     │    │  │  │
│  │  │  │   threads       │  │ • Result        │  │ • ConcurrentDict│  │   progress      │    │  │  │
│  │  │  │ • Load modules  │  │   aggregation   │  │ • ConcurrentQueue│ │ • ETA calc      │    │  │  │
│  │  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘    │  │  │
│  │  │                                                                                         │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                                                │  │
│  └────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                               │
                                               │ ADSI / System.DirectoryServices
                                               ▼
                    ┌─────────────────────────────────────────────────────────────┐
                    │                    Active Directory                          │
                    │                                                              │
                    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
                    │  │ RootDSE     │  │Configuration│  │ Domain NC   │          │
                    │  │             │  │     NC      │  │             │          │
                    │  │ • Forest    │  │             │  │ • Users     │          │
                    │  │   info      │  │ • AuthN     │  │ • Groups    │          │
                    │  │ • Domain    │  │   Policies  │  │ • Computers │          │
                    │  │   info      │  │ • AuthN     │  │ • OUs       │          │
                    │  │             │  │   Silos     │  │             │          │
                    │  └─────────────┘  └─────────────┘  └─────────────┘          │
                    │                                                              │
                    └─────────────────────────────────────────────────────────────┘
```

---

## 3. Class Diagrams

### 3.1 Domain Model - Tier Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    TIER MODEL DOMAIN CLASSES                                         │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────┐
│        «enumeration»                │
│          TierLevel                  │
├─────────────────────────────────────┤
│ Tier0 = 0  (Control Plane)          │
│ Tier1 = 1  (Management Plane)       │
│ Tier2 = 2  (Data Plane) [unused]    │
└─────────────────────────────────────┘
              ▲
              │ uses
              │
┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
│          «class»                    │       │           «class»                   │
│      TierConfiguration              │       │     TierOUConfiguration             │
├─────────────────────────────────────┤       ├─────────────────────────────────────┤
│ - Enabled: bool                     │ 1   * │ - AdminOUs: string[]                │
│ - TierLevel: TierLevel              │◄──────│ - ServiceAccountOUs: string[]       │
│ - KerberosAuthPolicyName: string    │       │ - ComputerOUs: string[]             │
│ - AddToProtectedUsers: bool         │       └─────────────────────────────────────┘
│ - EnforcePrivilegedGroupCleanup: bool│
│ - IncludeDomainControllers: bool    │       ┌─────────────────────────────────────┐
│ - ComputerGroupName: string         │       │           «class»                   │
│ - ExcludedAccounts: string[]        │ 1   1 │      TierSecuritySettings           │
├─────────────────────────────────────┤◄──────├─────────────────────────────────────┤
│ + IsUserInTier(userDN): bool        │       │ - TGTLifetimeMinutes: int           │
│ + IsComputerInTier(compDN): bool    │       │ - RequireSmartCard: bool            │
│ + GetAuthPolicyDN(): string         │       │ - RestrictDelegation: bool          │
└─────────────────────────────────────┘       └─────────────────────────────────────┘

┌─────────────────────────────────────┐
│          «class»                    │
│     TierGuardConfiguration          │
├─────────────────────────────────────┤
│ - SchemaVersion: string             │
│ - General: GeneralSettings          │
│ - Tier0: TierConfiguration          │
│ - Tier1: TierConfiguration          │
│ - Notifications: NotifySettings     │
├─────────────────────────────────────┤
│ + Validate(): ValidationResult      │
│ + GetTierConfig(level): TierConfig  │
│ + Save(path): void                  │
│ + Load(path): TierGuardConfiguration│
└─────────────────────────────────────┘
```

### 3.2 Forest Topology Model

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    FOREST TOPOLOGY CLASSES                                           │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
│        «enumeration»                │       │          «class»                    │
│         DomainType                  │       │      ForestTopology                 │
├─────────────────────────────────────┤       ├─────────────────────────────────────┤
│ ForestRoot                          │       │ - Initialized: bool                 │
│ TreeRoot                            │       │ - ForestRootFQDN: string            │
│ ChildDomain                         │       │ - ForestRootSID: string             │
└─────────────────────────────────────┘       │ - Domains: DomainInfo[]             │
              ▲                               │ - DomainControllers: DCInfo[]       │
              │                               │ - LastRefresh: DateTime             │
              │ uses                          ├─────────────────────────────────────┤
              │                               │ + Refresh(): void                   │
┌─────────────────────────────────────┐       │ + GetForestRoot(): DomainInfo       │
│          «class»                    │       │ + GetChildDomains(): DomainInfo[]   │
│         DomainInfo                  │ *   1 │ + IsForestRoot(dns): bool           │
├─────────────────────────────────────┤◄──────└─────────────────────────────────────┘
│ - DnsName: string                   │
│ - NetBIOSName: string               │
│ - DistinguishedName: string         │
│ - DomainSID: string                 │
│ - Type: DomainType                  │       ┌─────────────────────────────────────┐
│ - IsForestRoot: bool                │       │          «class»                    │
│ - IsTreeRoot: bool                  │       │      DomainControllerInfo           │
│ - IsChildDomain: bool               │       ├─────────────────────────────────────┤
│ - ParentDomain: string              │       │ - FQDN: string                      │
│ - FunctionalLevel: int              │       │ - Domain: string                    │
│ - DomainControllers: string[]       │ 1   * │ - Site: string                      │
│ - OnlineDCs: string[]               │◄──────│ - IsGlobalCatalog: bool             │
├─────────────────────────────────────┤       │ - IsRODC: bool                      │
│ + GetPreferredDC(): string          │       │ - Online: bool                      │
│ + TestConnectivity(): bool          │       │ - FSMORoles: string[]               │
└─────────────────────────────────────┘       │ - Type: string                      │
                                              ├─────────────────────────────────────┤
                                              │ + Test(): bool                      │
                                              │ + GetRootDSE(): RootDSE             │
                                              └─────────────────────────────────────┘
```

### 3.3 Authentication Policy Model

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              AUTHENTICATION POLICY CLASSES                                           │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────┐
│          «class»                    │
│   AuthPolicyForestContext           │
├─────────────────────────────────────┤
│ + ForestRootDN: string              │
│ + ForestRootDns: string             │       ┌─────────────────────────────────────┐
│ + CurrentDomainDN: string           │       │          «class»                    │
│ + CurrentDomainDns: string          │       │    AuthenticationPolicy             │
│ + IsForestRoot: bool                │       │   «msDS-AuthNPolicy»                │
│ + ConfigurationNC: string           │       ├─────────────────────────────────────┤
│ + AuthPoliciesPath: string          │ 1   * │ - Name: string                      │
│ + AuthSilosPath: string             │◄──────│ - DistinguishedName: string         │
│ + SupportsAuthPolicies: bool        │       │ - Description: string               │
├─────────────────────────────────────┤       │ - Enforced: bool                    │
│ + CanCreatePolicies(): bool         │       │ - UserTGTLifetime: long             │
│ + GetPolicyContainer(): string      │       │ - ComputerTGTLifetime: long         │
│ + GetSiloContainer(): string        │       │ - ServiceTGTLifetime: long          │
└─────────────────────────────────────┘       │ - UserAllowedToAuthFrom: string     │
                                              │ - UserAllowedToAuthTo: string       │
                                              │ - WhenCreated: DateTime             │
┌─────────────────────────────────────┐       ├─────────────────────────────────────┤
│          «class»                    │       │ + GetTGTLifetimeMinutes(): int      │
│    AuthenticationPolicySilo         │       │ + ToSDDL(): string                  │
│    «msDS-AuthNPolicySilo»           │       └─────────────────────────────────────┘
├─────────────────────────────────────┤                       ▲
│ - Name: string                      │                       │ references
│ - DistinguishedName: string         │                       │
│ - Description: string               │       ┌───────────────┴───────────────────────┐
│ - Enforced: bool                    │       │                                       │
│ - Members: string[]                 │───────┤  Silo references policies for:        │
│ - MemberCount: int                  │       │  • Users (msDS-UserAuthNPolicy)       │
│ - UserAuthNPolicy: string           │───────┤  • Computers (msDS-ComputerAuthNPolicy)
│ - ComputerAuthNPolicy: string       │───────┤  • Services (msDS-ServiceAuthNPolicy) │
│ - ServiceAuthNPolicy: string        │───────┤                                       │
│ - WhenCreated: DateTime             │       └───────────────────────────────────────┘
├─────────────────────────────────────┤
│ + AddMember(dn): void               │
│ + RemoveMember(dn): void            │
│ + IsMember(dn): bool                │
└─────────────────────────────────────┘
```

### 3.4 Runspace Engine Model

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   RUNSPACE ENGINE CLASSES                                            │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────┐
│          «class»                    │
│  System.Management.Automation.      │
│       Runspaces.RunspacePool        │
│          «external»                 │
├─────────────────────────────────────┤
│ - MinRunspaces: int                 │
│ - MaxRunspaces: int                 │
│ - RunspacePoolStateInfo: StateInfo  │
├─────────────────────────────────────┤
│ + Open(): void                      │
│ + Close(): void                     │
│ + Dispose(): void                   │
└─────────────────────────────────────┘
              ▲
              │ creates/manages
              │
┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
│          «class»                    │       │          «class»                    │
│      RunspacePoolManager            │       │     ParallelJobResult               │
├─────────────────────────────────────┤       ├─────────────────────────────────────┤
│ - Pool: RunspacePool                │       │ + JobId: string                     │
│ - MaxRunspaces: int                 │       │ + InputObject: object               │
│ - Modules: string[]                 │ 1   * │ + Output: object                    │
│ - Variables: hashtable              │◄──────│ + Errors: ErrorRecord[]             │
├─────────────────────────────────────┤       │ + Success: bool                     │
│ + New-RunspacePool(): RunspacePool  │       │ + Duration: TimeSpan                │
│ + Close-RunspacePool(): void        │       │ + StartTime: DateTime               │
└─────────────────────────────────────┘       │ + EndTime: DateTime                 │
              │                               └─────────────────────────────────────┘
              │ uses
              ▼
┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
│          «class»                    │       │        «interface»                  │
│     ParallelOperationEngine         │       │   IThreadSafeCollection<T>          │
├─────────────────────────────────────┤       ├─────────────────────────────────────┤
│ - ThrottleLimit: int                │       │ + Add(item): void                   │
│ - TimeoutSeconds: int               │ uses  │ + TryTake(out item): bool           │
│ - ShowProgress: bool                │──────►│ + Count: int                        │
│ - ProgressActivity: string          │       │ + ToArray(): T[]                    │
├─────────────────────────────────────┤       └─────────────────────────────────────┘
│ + Invoke-ParallelOperation():       │                       ▲
│     ParallelJobResult[]             │                       │
│ + Invoke-BatchOperation():          │       ┌───────────────┼───────────────┐
│     ParallelJobResult[]             │       │               │               │
└─────────────────────────────────────┘       ▼               ▼               ▼
                                      ┌───────────┐   ┌───────────┐   ┌───────────┐
                                      │Concurrent │   │Concurrent │   │Concurrent │
                                      │   Bag     │   │Dictionary │   │  Queue    │
                                      └───────────┘   └───────────┘   └───────────┘
```

### 3.5 ADSI Operations Model

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    ADSI OPERATIONS CLASSES                                           │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
│          «class»                    │       │          «class»                    │
│          RootDSE                    │       │      DirectorySearcher              │
├─────────────────────────────────────┤       │        «wrapper»                    │
│ + DefaultNamingContext: string      │       ├─────────────────────────────────────┤
│ + ConfigurationNamingContext: string│       │ - SearchRoot: DirectoryEntry        │
│ + SchemaNamingContext: string       │       │ - Filter: string                    │
│ + RootDomainNamingContext: string   │       │ - SearchScope: SearchScope          │
│ + DnsHostName: string               │       │ - PageSize: int                     │
│ + ForestFunctionalLevel: int        │       │ - PropertiesToLoad: string[]        │
│ + DomainFunctionalLevel: int        │       ├─────────────────────────────────────┤
├─────────────────────────────────────┤       │ + FindAll(): SearchResultCollection │
│ + Get-AdsiRootDse(): RootDSE        │       │ + FindOne(): SearchResult           │
└─────────────────────────────────────┘       └─────────────────────────────────────┘
                                                              │
                                                              │ uses
                                                              ▼
┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
│          «class»                    │       │          «class»                    │
│      AdsiUserOperations             │       │    AdsiGroupOperations              │
├─────────────────────────────────────┤       ├─────────────────────────────────────┤
│ + Get-AdsiUser(filter): hashtable[] │       │ + Get-AdsiGroupMember(): hashtable[]│
│ + Get-AdsiPrivilegedUser():         │       │ + Add-AdsiGroupMember(): bool       │
│     hashtable[]                     │       │ + Remove-AdsiGroupMember(): bool    │
│ + Set-AdsiAuthenticationPolicy():   │       │ + Get-AdsiProtectedUsersGroup():    │
│     void                            │       │     hashtable                       │
│ + Remove-AdsiAuthenticationPolicy():│       │ + Add-AdsiProtectedUser(): bool     │
│     void                            │       │ + Get-AdsiPrivilegedGroup():        │
└─────────────────────────────────────┘       │     hashtable[]                     │
                                              └─────────────────────────────────────┘

┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
│          «class»                    │       │          «class»                    │
│    AdsiComputerOperations           │       │    AdsiAuthPolicyOperations         │
├─────────────────────────────────────┤       ├─────────────────────────────────────┤
│ + Get-AdsiComputer(): hashtable[]   │       │ + Get-AdsiKerberosAuthentication    │
│ + Test-AdsiDomainController(): bool │       │     Policy(): hashtable[]           │
│ + Test-AdsiGroupManagedService      │       │ + Set-AdsiAuthenticationPolicy():   │
│     Account(): bool                 │       │     void                            │
│ + Test-AdsiManagedServiceAccount(): │       │ + Remove-AdsiAuthenticationPolicy():│
│     bool                            │       │     void                            │
└─────────────────────────────────────┘       └─────────────────────────────────────┘
```

---

## 4. Sequence Diagrams

### 4.1 Forest Root Detection and Policy Creation

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                           FOREST ROOT DETECTION & POLICY CREATION                                    │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Enterprise  │  │ Initialize-  │  │AuthPolicy    │  │    ADSI      │  │ Active       │
│   Admin     │  │ TierGuardAuth│  │ Manager      │  │  Operations  │  │ Directory    │
└──────┬──────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                │                 │                 │                 │
       │ Run script     │                 │                 │                 │
       │───────────────►│                 │                 │                 │
       │                │                 │                 │                 │
       │                │ Test-AuthPolicyPrerequisites      │                 │
       │                │────────────────►│                 │                 │
       │                │                 │                 │                 │
       │                │                 │ Get-AdsiRootDse │                 │
       │                │                 │────────────────►│                 │
       │                │                 │                 │                 │
       │                │                 │                 │ LDAP://RootDSE  │
       │                │                 │                 │────────────────►│
       │                │                 │                 │                 │
       │                │                 │                 │ defaultNamingContext       │
       │                │                 │                 │ rootDomainNamingContext    │
       │                │                 │                 │ configurationNamingContext │
       │                │                 │                 │◄────────────────│
       │                │                 │                 │                 │
       │                │                 │ RootDSE         │                 │
       │                │                 │◄────────────────│                 │
       │                │                 │                 │                 │
       │                │                 │ Compare:        │                 │
       │                │                 │ defaultNC == rootDomainNC?        │
       │                │                 │────────┐        │                 │
       │                │                 │        │        │                 │
       │                │                 │◄───────┘        │                 │
       │                │                 │                 │                 │
       │                │ { IsForestRoot: true/false,       │                 │
       │                │   ConfigNC: "CN=Config,DC=...",   │                 │
       │                │   CanProceed: true/false }        │                 │
       │                │◄────────────────│                 │                 │
       │                │                 │                 │                 │
       │                │                 │                 │                 │
       │                │  alt [IsForestRoot = false && !Force]               │
       │                │  ┌──────────────────────────────────────────────────┤
       │                │  │                                                  │
       │ "WARNING: Not  │  │                                                  │
       │  forest root"  │  │                                                  │
       │◄───────────────│  │                                                  │
       │                │  │                                                  │
       │ Confirm (y/N)  │  │                                                  │
       │───────────────►│  │                                                  │
       │                │  └──────────────────────────────────────────────────┤
       │                │                 │                 │                 │
       │                │ New-TierAuthenticationPolicy      │                 │
       │                │ (Tier 0, 4hr TGT)                 │                 │
       │                │────────────────►│                 │                 │
       │                │                 │                 │                 │
       │                │                 │ Create in CN=AuthN Policies,      │
       │                │                 │ CN=AuthN Policy Configuration,    │
       │                │                 │ CN=Services,CN=Configuration,...  │
       │                │                 │────────────────────────────────────────────►
       │                │                 │                 │                 │
       │                │                 │                 │   Policy DN     │
       │                │                 │◄────────────────────────────────────────────
       │                │                 │                 │                 │
       │                │ New-TierAuthenticationSilo        │                 │
       │                │────────────────►│                 │                 │
       │                │                 │                 │                 │
       │                │                 │ Create in CN=AuthN Silos,...      │
       │                │                 │────────────────────────────────────────────►
       │                │                 │                 │                 │
       │                │                 │                 │    Silo DN      │
       │                │                 │◄────────────────────────────────────────────
       │                │                 │                 │                 │
       │ "Tier 0 Ready" │                 │                 │                 │
       │◄───────────────│                 │                 │                 │
       │                │                 │                 │                 │
```

### 4.2 User Sync with Policy Validation

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              USER SYNC WITH POLICY VALIDATION                                        │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│Domain Admin │  │Invoke-Tier   │  │AuthPolicy    │  │  Runspace    │  │   Active     │
│             │  │UserSync      │  │Manager       │  │  Engine      │  │  Directory   │
└──────┬──────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                │                 │                 │                 │
       │ -TierLevel 0   │                 │                 │                 │
       │───────────────►│                 │                 │                 │
       │                │                 │                 │                 │
       │                │ Load Config     │                 │                 │
       │                │────────┐        │                 │                 │
       │                │        │        │                 │                 │
       │                │◄───────┘        │                 │                 │
       │                │                 │                 │                 │
       │                │ ═══════════════════════════════════════════════════│
       │                │  POLICY VALIDATION (NEW in v2.2)                   │
       │                │ ═══════════════════════════════════════════════════│
       │                │                 │                 │                 │
       │                │ Get-TierAuthenticationPolicy      │                 │
       │                │ ("TG-Tier0-RestrictedAuth")       │                 │
       │                │────────────────►│                 │                 │
       │                │                 │                 │                 │
       │                │                 │ Search Configuration NC           │
       │                │                 │ (forest-wide, any DC)             │
       │                │                 │────────────────────────────────────────────►
       │                │                 │                 │                 │
       │                │                 │     alt [Policy NOT Found]        │
       │                │                 │     ┌──────────────────────────────────────┐
       │                │                 │     │                              │      │
       │                │ ERROR: "Policy  │     │  (empty result)              │      │
       │                │ not found.      │     │◄─────────────────────────────────────│
       │                │ Run Initialize- │◄────│                              │      │
       │                │ TierGuardAuth"  │     │                              │      │
       │◄───────────────│                 │     │                              │      │
       │                │                 │     └──────────────────────────────────────┘
       │                │                 │                 │                 │
       │                │                 │     alt [Policy Found]            │
       │                │                 │     ┌──────────────────────────────────────┐
       │                │                 │     │                              │      │
       │                │                 │     │  Policy DN + attributes      │      │
       │                │ Policy validated│◄────│◄─────────────────────────────────────│
       │                │◄────────────────│     │                              │      │
       │                │                 │     └──────────────────────────────────────┘
       │                │                 │                 │                 │
       │                │ ═══════════════════════════════════════════════════│
       │                │  DOMAIN SYNC (for each domain)                     │
       │                │ ═══════════════════════════════════════════════════│
       │                │                 │                 │                 │
       │                │ Get privileged users from OUs     │                 │
       │                │────────────────────────────────────────────────────►│
       │                │                 │                 │                 │
       │                │                 │    users[]      │                 │
       │                │◄────────────────────────────────────────────────────│
       │                │                 │                 │                 │
       │                │ Invoke-ParallelOperation          │                 │
       │                │ (Apply Auth Policy)               │                 │
       │                │─────────────────────────────────►│                 │
       │                │                 │                 │                 │
       │                │                 │                 │ Parallel: Set   │
       │                │                 │                 │ msDS-Assigned   │
       │                │                 │                 │ AuthNPolicy     │
       │                │                 │                 │────────────────►│
       │                │                 │                 │                 │
       │                │                 │                 │    (x N users)  │
       │                │                 │                 │◄────────────────│
       │                │                 │                 │                 │
       │                │ ParallelJobResult[]               │                 │
       │                │◄─────────────────────────────────│                 │
       │                │                 │                 │                 │
       │ Sync Complete  │                 │                 │                 │
       │ (50 users, 2s) │                 │                 │                 │
       │◄───────────────│                 │                 │                 │
       │                │                 │                 │                 │
```

### 4.3 Runspace Parallel Execution

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              RUNSPACE PARALLEL EXECUTION DETAIL                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Caller    │  │ Invoke-      │  │RunspacePool  │  │ PowerShell   │  │   Active     │
│             │  │ Parallel     │  │              │  │ Instances    │  │  Directory   │
│             │  │ Operation    │  │              │  │  (1..N)      │  │              │
└──────┬──────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                │                 │                 │                 │
       │ 100 users,     │                 │                 │                 │
       │ ThrottleLimit=4│                 │                 │                 │
       │───────────────►│                 │                 │                 │
       │                │                 │                 │                 │
       │                │ New-RunspacePool                  │                 │
       │                │ (MaxRunspaces=4)                  │                 │
       │                │────────────────►│                 │                 │
       │                │                 │                 │                 │
       │                │                 │ Create initial  │                 │
       │                │                 │ session state   │                 │
       │                │                 │────────┐        │                 │
       │                │                 │        │        │                 │
       │                │                 │◄───────┘        │                 │
       │                │                 │                 │                 │
       │                │ Pool ready      │                 │                 │
       │                │◄────────────────│                 │                 │
       │                │                 │                 │                 │
       │                │══════════════════════════════════════════════════════
       │                │  PARALLEL EXECUTION LOOP                            │
       │                │══════════════════════════════════════════════════════
       │                │                 │                 │                 │
       │                │ foreach ($user in $users)         │                 │
       │                │────────┐        │                 │                 │
       │                │        │        │                 │                 │
       │                │        │        │                 │                 │
       │                │        │ [PowerShell]::Create()   │                 │
       │                │        │───────────────────────────────────────────►│
       │                │        │        │                 │                 │
       │                │        │        │ .RunspacePool = $pool             │
       │                │        │        │────────────────►│                 │
       │                │        │        │                 │                 │
       │                │        │        │ .AddScript($scriptBlock)          │
       │                │        │        │ .AddParameter("User", $user)      │
       │                │        │        │────────────────────────────────────────────►
       │                │        │        │                 │                 │
       │                │        │        │ .BeginInvoke()  │                 │
       │                │        │        │ (async, non-blocking)             │
       │                │        │        │────────────────►│                 │
       │                │        │        │                 │                 │
       │                │        │        │ IAsyncResult    │                 │
       │                │        │◄───────│◄────────────────│                 │
       │                │        │        │                 │                 │
       │                │        │ Store in $jobs           │                 │
       │                │◄───────┘        │                 │                 │
       │                │                 │                 │                 │
       │                │══════════════════════════════════════════════════════
       │                │  BACKGROUND: 4 CONCURRENT WORKERS                   │
       │                │══════════════════════════════════════════════════════
       │                │                 │                 │                 │
       │                │                 │                 │ Worker 1: Set   │
       │                │                 │                 │ User1 policy    │
       │                │                 │                 │────────────────►│
       │                │                 │                 │                 │
       │                │                 │                 │ Worker 2: Set   │
       │                │                 │                 │ User2 policy    │
       │                │                 │                 │────────────────►│
       │                │                 │                 │                 │
       │                │                 │                 │ Worker 3: Set   │
       │                │                 │                 │ User3 policy    │
       │                │                 │                 │────────────────►│
       │                │                 │                 │                 │
       │                │                 │                 │ Worker 4: Set   │
       │                │                 │                 │ User4 policy    │
       │                │                 │                 │────────────────►│
       │                │                 │                 │                 │
       │                │                 │ (Workers complete, get next batch)│
       │                │                 │                 │                 │
       │                │══════════════════════════════════════════════════════
       │                │  COLLECT RESULTS                                    │
       │                │══════════════════════════════════════════════════════
       │                │                 │                 │                 │
       │                │ foreach ($job in $jobs)           │                 │
       │                │────────┐        │                 │                 │
       │                │        │        │                 │                 │
       │                │        │ .EndInvoke()             │                 │
       │                │        │────────────────────────────────────────────►
       │                │        │        │                 │                 │
       │                │        │ Output + Errors          │                 │
       │                │◄───────│◄────────────────────────────────────────────
       │                │        │        │                 │                 │
       │                │◄───────┘        │                 │                 │
       │                │                 │                 │                 │
       │                │ Close-RunspacePool                │                 │
       │                │────────────────►│                 │                 │
       │                │                 │                 │                 │
       │ 100 results    │                 │                 │                 │
       │ (Success: 98,  │                 │                 │                 │
       │  Errors: 2)    │                 │                 │                 │
       │◄───────────────│                 │                 │                 │
       │                │                 │                 │                 │
```

---

## 5. Activity Diagrams

### 5.1 Full Tier Sync Workflow

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    FULL TIER SYNC WORKFLOW                                           │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                        ┌─────────┐
                                        │  Start  │
                                        └────┬────┘
                                             │
                                             ▼
                                  ┌─────────────────────┐
                                  │ Load Configuration  │
                                  │ (TierGuard.json)    │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                                  ┌─────────────────────┐
                                  │ Initialize Logging  │
                                  │ & Event Log         │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                                     ◇ Tier Enabled?
                                    ╱              ╲
                                  no                yes
                                  │                  │
                                  ▼                  ▼
                         ┌─────────────┐   ┌─────────────────────┐
                         │ Exit (0)    │   │ Get Tier Config     │
                         │ "Disabled"  │   │ (Tier0 or Tier1)    │
                         └─────────────┘   └──────────┬──────────┘
                                                      │
                                                      ▼
                              ╔══════════════════════════════════════════╗
                              ║  VALIDATE AUTH POLICY EXISTS (Forest NC) ║
                              ╚══════════════════════════════════════════╝
                                                      │
                                                      ▼
                                  ┌─────────────────────┐
                                  │ Get-TierAuthPolicy  │
                                  │ from Configuration  │
                                  │ Naming Context      │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                                      ◇ Policy Found?
                                     ╱              ╲
                                   no                yes
                                   │                  │
                                   ▼                  ▼
                          ┌─────────────────┐  ┌─────────────────────┐
                          │ ERROR:          │  │ Log: "[OK] Policy   │
                          │ "Run Initialize-│  │  found: DN=..."     │
                          │  TierGuardAuth" │  └──────────┬──────────┘
                          │ from forest root│             │
                          └────────┬────────┘             │
                                   │                      │
                                   ▼                      │
                              ┌─────────┐                 │
                              │  Exit   │                 │
                              │  (1)    │                 │
                              └─────────┘                 │
                                                          │
                                                          ▼
                              ╔══════════════════════════════════════════╗
                              ║     DISCOVER TARGET DOMAINS              ║
                              ╚══════════════════════════════════════════╝
                                                          │
                                                          ▼
                                  ┌─────────────────────┐
                                  │ Get-SyncTargetDomains│
                                  │ (auto-discover from │
                                  │  forest topology)   │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                         ┌───────────────────────────────────────────┐
                         │         FOR EACH Domain                   │
                         └───────────────────┬───────────────────────┘
                                             │
                                             ▼
                                  ┌─────────────────────┐
                                  │ Check: Is Forest    │
                                  │ Root Domain?        │
                                  └──────────┬──────────┘
                                             │
                              ┌──────────────┴──────────────┐
                             yes                            no
                              │                              │
                              ▼                              ▼
                   ┌──────────────────────┐    ┌──────────────────────┐
                   │ Include Enterprise   │    │ Domain-only groups   │
                   │ Admins, Schema Admins│    │ (Domain Admins, etc) │
                   └──────────┬───────────┘    └──────────┬───────────┘
                              │                           │
                              └─────────────┬─────────────┘
                                            │
                                            ▼
                              ╔══════════════════════════════════════════╗
                              ║        DISCOVER PRIVILEGED USERS         ║
                              ╚══════════════════════════════════════════╝
                                            │
                                            ▼
                                  ┌─────────────────────┐
                                  │ Search Tier OUs for │
                                  │ Admin Users         │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                                  ┌─────────────────────┐
                                  │ Search Tier OUs for │
                                  │ Service Accounts    │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                              ╔══════════════════════════════════════════╗
                              ║      APPLY PROTECTIONS (PARALLEL)        ║
                              ╚══════════════════════════════════════════╝
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
         ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
         │ Apply Auth Policy   │  │ Add to Protected    │  │ Cleanup Privileged  │
         │ (Invoke-Parallel    │  │ Users Group         │  │ Group Membership    │
         │  Operation)         │  │ (Tier 0 only)       │  │ (Tier 0 only)       │
         │                     │  │                     │  │                     │
         │ msDS-Assigned       │  │ CN=Protected Users, │  │ Remove non-Tier0    │
         │ AuthNPolicy = DN    │  │ CN=Users,...        │  │ from Domain Admins  │
         └──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘
                    │                        │                        │
                    └────────────────────────┼────────────────────────┘
                                             │
                                             ▼
                         └───────────────────────────────────────────┘
                                      (NEXT Domain)
                                             │
                                             ▼
                              ╔══════════════════════════════════════════╗
                              ║         AGGREGATE RESULTS                ║
                              ╚══════════════════════════════════════════╝
                                             │
                                             ▼
                                  ┌─────────────────────┐
                                  │ Calculate Totals    │
                                  │ • Users processed   │
                                  │ • Policies applied  │
                                  │ • Protected added   │
                                  │ • Errors            │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                                  ┌─────────────────────┐
                                  │ Write Event Log     │
                                  │ Write Summary       │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                                        ┌─────────┐
                                        │   End   │
                                        └─────────┘
```

### 5.2 Forest Root Detection Logic

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 FOREST ROOT DETECTION ALGORITHM                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                        ┌─────────┐
                                        │  Start  │
                                        └────┬────┘
                                             │
                                             ▼
                                  ┌─────────────────────┐
                                  │ Connect to RootDSE  │
                                  │ LDAP://RootDSE      │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                         ┌─────────────────────────────────────┐
                         │ Read Key Attributes:                │
                         │                                     │
                         │ • defaultNamingContext              │
                         │   (current domain DN)               │
                         │                                     │
                         │ • rootDomainNamingContext           │
                         │   (forest root DN)                  │
                         │                                     │
                         │ • configurationNamingContext        │
                         │   (where policies live)             │
                         └───────────────────┬─────────────────┘
                                             │
                                             ▼
                                  ┌─────────────────────┐
                                  │ Extract forest root │
                                  │ from configNC:      │
                                  │                     │
                                  │ "CN=Configuration,  │
                                  │  DC=corp,DC=com"    │
                                  │        ↓            │
                                  │ "DC=corp,DC=com"    │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                                  ┌─────────────────────┐
                                  │ Compare:            │
                                  │                     │
                                  │ defaultNC ==        │
                                  │ rootDomainNC ?      │
                                  └──────────┬──────────┘
                                             │
                              ┌──────────────┴──────────────┐
                            EQUAL                        NOT EQUAL
                              │                              │
                              ▼                              ▼
                   ┌──────────────────────┐    ┌──────────────────────┐
                   │                      │    │                      │
                   │  IsForestRoot: TRUE  │    │  IsForestRoot: FALSE │
                   │                      │    │                      │
                   │  Example:            │    │  Example:            │
                   │  default: DC=corp,   │    │  default: DC=child,  │
                   │          DC=com      │    │          DC=corp,    │
                   │  root:    DC=corp,   │    │          DC=com      │
                   │          DC=com      │    │  root:    DC=corp,   │
                   │                      │    │          DC=com      │
                   │  ✓ MATCH            │    │                      │
                   │                      │    │  ✗ NO MATCH         │
                   └──────────┬───────────┘    └──────────┬───────────┘
                              │                           │
                              ▼                           ▼
                   ┌──────────────────────┐    ┌──────────────────────┐
                   │ Can create policies  │    │ Can only READ and    │
                   │ and silos in         │    │ APPLY policies       │
                   │ Configuration NC     │    │ (not create)         │
                   └──────────────────────┘    └──────────────────────┘
                              │                           │
                              └─────────────┬─────────────┘
                                            │
                                            ▼
                                  ┌─────────────────────┐
                                  │ Return:             │
                                  │ {                   │
                                  │   IsForestRoot,     │
                                  │   ForestRootDns,    │
                                  │   CurrentDomainDns, │
                                  │   ConfigurationNC,  │
                                  │   PolicyContainerDN │
                                  │ }                   │
                                  └──────────┬──────────┘
                                             │
                                             ▼
                                        ┌─────────┐
                                        │   End   │
                                        └─────────┘
```

---

## 6. State Machine Diagrams

### 6.1 User Tier Protection States

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               USER TIER PROTECTION STATE MACHINE                                     │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘


                                  ┌─────────────────┐
                                  │                 │
                                  │   [Initial]     │
                                  │ Unprotected     │
                                  │                 │
                                  └────────┬────────┘
                                           │
                                           │ User created in Tier OU
                                           │ OR
                                           │ Added to privileged group
                                           ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                      │
│                                                                                                      │
│    ┌─────────────────┐                                    ┌─────────────────┐                       │
│    │                 │         Invoke-TierUserSync        │                 │                       │
│    │   Discovered    │───────────────────────────────────►│  Policy Applied │                       │
│    │   (In Tier OU)  │                                    │                 │                       │
│    │                 │◄───────────────────────────────────│ msDS-Assigned   │                       │
│    └────────┬────────┘        User moved out of OU        │ AuthNPolicy set │                       │
│             │                                             │                 │                       │
│             │                                             └────────┬────────┘                       │
│             │                                                      │                                │
│             │ Tier 0 only                                          │ Tier 0 only                    │
│             ▼                                                      ▼                                │
│    ┌─────────────────┐                                    ┌─────────────────┐                       │
│    │                 │         Invoke-TierUserSync        │                 │                       │
│    │  Policy Applied │───────────────────────────────────►│  Fully Protected│                       │
│    │  + Protected    │                                    │                 │                       │
│    │  Users Pending  │                                    │ • Auth Policy   │                       │
│    │                 │                                    │ • Protected User│                       │
│    └─────────────────┘                                    │ • Group Cleaned │                       │
│                                                           │                 │                       │
│                                                           └────────┬────────┘                       │
│                                                                    │                                │
│                                                                    │ User removed from Tier OU      │
│                                                                    │ OR                             │
│                                                                    │ Removed from priv group        │
│                                                                    ▼                                │
│                                                           ┌─────────────────┐                       │
│                                                           │                 │                       │
│                                                           │   Stale         │                       │
│                                                           │   (Needs        │                       │
│                                                           │   Cleanup)      │                       │
│                                                           │                 │                       │
│                                                           └────────┬────────┘                       │
│                                                                    │                                │
│                                                                    │ Next sync cycle                │
│                                                                    │ removes protections            │
│                                                                    ▼                                │
│                                                           ┌─────────────────┐                       │
│                                                           │                 │                       │
│                                                           │  Unprotected    │                       │
│                                                           │  (Back to       │                       │
│                                                           │   normal user)  │                       │
│                                                           │                 │                       │
│                                                           └─────────────────┘                       │
│                                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Authentication Policy Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                            AUTHENTICATION POLICY LIFECYCLE                                           │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘


                         ┌─────────────────┐
                         │                 │
                         │   [Initial]     │
                         │   Not Created   │
                         │                 │
                         └────────┬────────┘
                                  │
                                  │ Initialize-TierGuardAuth
                                  │ (Forest Root, Enterprise Admin)
                                  ▼
                         ┌─────────────────┐
                         │                 │
                         │    Created      │
                         │   (Audit Mode)  │
                         │                 │
                         │ Enforced: FALSE │
                         │                 │
                         └────────┬────────┘
                                  │
                                  │ Review audit logs
                                  │ Set-TierAuthPolicy -Enforced $true
                                  ▼
                         ┌─────────────────┐
                         │                 │
                         │    Active       │◄─────────────────────────────────┐
                         │   (Enforced)    │                                  │
                         │                 │                                  │
                         │ Enforced: TRUE  │                                  │
                         │ Blocking auth   │                                  │
                         │ failures        │                                  │
                         │                 │                                  │
                         └────────┬────────┘                                  │
                                  │                                           │
                    ┌─────────────┼─────────────┐                             │
                    │             │             │                             │
                    ▼             ▼             ▼                             │
           ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                    │
           │ Update TGT  │ │ Update SDDL │ │ Disable for │                    │
           │ lifetime    │ │ (allowed    │ │ emergency   │                    │
           │             │ │  from/to)   │ │             │                    │
           └──────┬──────┘ └──────┬──────┘ └──────┬──────┘                    │
                  │               │               │                           │
                  │               │               │ Enforced: FALSE           │
                  │               │               ▼                           │
                  │               │        ┌─────────────┐                    │
                  │               │        │   Disabled  │                    │
                  │               │        │ (Audit Mode)│───────────────────►│
                  │               │        │             │  Re-enable          
                  │               │        └─────────────┘                    
                  │               │                                           
                  └───────────────┴──────────────────────────────────────────►│
                           Policy updated                                     │
                                                                              │
                                                                              │
                         ┌─────────────────┐                                  │
                         │                 │                                  │
                         │   [Deleted]     │                                  │
                         │                 │                                  │
                         └─────────────────┘                                  │
                                  ▲                                           │
                                  │                                           │
                                  │ Remove-TierAuthenticationPolicy           │
                                  │ (breaks all assignments!)                 │
                                  │                                           │
                                  └───────────────────────────────────────────┘
```

---

## 7. Data Flow Diagrams

### 7.1 Level 0 - Context DFD

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      LEVEL 0 - CONTEXT DFD                                           │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘


                          ┌─────────────────────┐
                          │                     │
                          │   Administrators    │
                          │                     │
                          └──────────┬──────────┘
                                     │
                                     │ Commands
                                     │ Configuration
                                     │ Parameters
                                     ▼
    ┌─────────────────┐    ┌─────────────────────────────────────────┐    ┌─────────────────┐
    │                 │    │                                         │    │                 │
    │ Task Scheduler  │───►│              ADTierGuard                │◄───│ TierGuard.json  │
    │                 │    │                                         │    │                 │
    │ Scheduled       │    │    ┌─────────────────────────────┐     │    │ Configuration   │
    │ Triggers        │    │    │                             │     │    │                 │
    └─────────────────┘    │    │   Tier Model Enforcement    │     │    └─────────────────┘
                           │    │                             │     │
                           │    │   • Discover users          │     │
                           │    │   • Apply policies          │     │
                           │    │   • Manage groups           │     │
                           │    │   • Forest-wide sync        │     │
                           │    │                             │     │
                           │    └─────────────────────────────┘     │
                           │                                         │
                           └────────────────────┬────────────────────┘
                                                │
                           ┌────────────────────┼────────────────────┐
                           │                    │                    │
                           ▼                    ▼                    ▼
              ┌─────────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
              │                     │ │                 │ │                     │
              │  Configuration NC   │ │  Domain NCs     │ │  Windows Event Log  │
              │                     │ │  (per domain)   │ │                     │
              │  • Auth Policies    │ │                 │ │  • Sync events      │
              │  • Auth Silos       │ │  • User objects │ │  • Errors           │
              │  (forest-wide)      │ │  • Groups       │ │  • Audit trail      │
              │                     │ │  • Computers    │ │                     │
              └─────────────────────┘ └─────────────────┘ └─────────────────────┘
```

### 7.2 Level 1 - Major Processes

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      LEVEL 1 - PROCESS DFD                                           │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘


┌───────────────────┐                                                    ┌───────────────────┐
│  Configuration    │                                                    │ Forest Topology   │
│     Store         │                                                    │     Cache         │
│     [D1]          │                                                    │      [D2]         │
└─────────┬─────────┘                                                    └─────────┬─────────┘
          │                                                                        │
          │ tier config                                               domain list  │
          │                                                                        │
          ▼                                                                        ▼
    ┌───────────────────┐     domains      ┌───────────────────┐     users    ┌───────────────────┐
    │                   │◄────────────────│                    │◄────────────│                    │
    │   1.0             │                  │   2.0              │              │   3.0              │
    │   Load &          │                  │   Discover         │              │   Sync User        │
    │   Validate        │                  │   Forest           │              │   Protections      │
    │   Config          │                  │   Topology         │              │                    │
    │                   │                  │                    │              │ • Auth Policy      │
    └───────────────────┘                  │ • Get domains      │              │ • Protected Users  │
          │                                │ • Find forest root │              │ • Group cleanup    │
          │                                │ • Get DCs          │              │                    │
          │ validated config               └───────────────────┘              └────────┬───────────┘
          │                                         │                                  │
          │                                         │ topology                         │ user updates
          │                                         ▼                                  │
          │                                ┌───────────────────┐                       │
          │                                │ Auth Policy       │                       │
          └───────────────────────────────►│ Validation        │                       │
                                           │    [D3]           │                       │
                                           │                   │                       │
                                           │ Policy exists?    │                       │
                                           │ DN resolution     │                       │
                                           └───────────────────┘                       │
                                                    │                                  │
                                                    │ policy DN                        │
                                                    ▼                                  ▼
                                         ┌──────────────────────────────────────────────────────┐
                                         │                                                      │
                                         │                  Active Directory                    │
                                         │                                                      │
                                         │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
                                         │  │Configuration│  │  Domain 1   │  │  Domain 2   │  │
                                         │  │     NC      │  │    NC       │  │    NC       │  │
                                         │  │             │  │             │  │             │  │
                                         │  │ Policies    │  │ Users       │  │ Users       │  │
                                         │  │ Silos       │  │ Groups      │  │ Groups      │  │
                                         │  └─────────────┘  └─────────────┘  └─────────────┘  │
                                         │                                                      │
                                         └──────────────────────────────────────────────────────┘
```

### 7.3 Level 2 - User Sync Detail

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                LEVEL 2 - USER SYNC PROCESS DETAIL                                    │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘


                                  ┌─────────────────────────────────────────────────────────┐
                                  │                    3.0 SYNC USER PROTECTIONS            │
                                  └─────────────────────────────────────────────────────────┘

┌───────────────────┐                                                     ┌───────────────────┐
│ Tier Config       │   OU paths                                          │ Policy DN         │
│ [D1]              │─────────────────┐                                   │ [D3]              │
└───────────────────┘                 │                                   └─────────┬─────────┘
                                      │                                             │
                                      ▼                                             │
                            ┌───────────────────┐                                   │
                            │                   │                                   │
                            │   3.1             │                                   │
                            │   Search Tier     │                                   │
                            │   OUs for Users   │                                   │
                            │                   │                                   │
                            └─────────┬─────────┘                                   │
                                      │                                             │
                                      │ admin users[]                               │
                                      │ service accounts[]                          │
                                      ▼                                             │
┌───────────────────┐       ┌───────────────────┐                                   │
│ Privileged        │ group │                   │                                   │
│ Groups Config     │ names │   3.2             │                                   │
│ [D4]              │──────►│   Enumerate       │                                   │
└───────────────────┘       │   Privileged      │                                   │
                            │   Group Members   │                                   │
                            │                   │                                   │
                            └─────────┬─────────┘                                   │
                                      │                                             │
                                      │ privileged users[]                          │
                                      ▼                                             │
                            ┌───────────────────┐                                   │
                            │                   │◄──────────────────────────────────┘
                            │   3.3             │   policy DN
                            │   Filter Users    │
                            │   Needing Policy  │
                            │                   │
                            │ Check: msDS-      │
                            │ AssignedAuthN     │
                            │ Policy == null?   │
                            │                   │
                            └─────────┬─────────┘
                                      │
                                      │ users needing policy[]
                                      ▼
                            ┌───────────────────┐       ┌───────────────────┐
                            │                   │       │                   │
                            │   3.4             │       │   Runspace Pool   │
                            │   Parallel Apply  │◄─────►│   [D5]            │
                            │   Auth Policy     │       │                   │
                            │                   │       │   4 workers       │
                            │ Invoke-Parallel   │       │   concurrent      │
                            │ Operation         │       │                   │
                            └─────────┬─────────┘       └───────────────────┘
                                      │
                                      │ results[]
                                      ▼
                            ┌───────────────────┐       ┌───────────────────┐
                            │                   │       │                   │
                            │   3.5             │──────►│ Protected Users   │
                            │   Add to          │       │ Group (Domain)    │
                            │   Protected Users │       │ [D6]              │
                            │   (Tier 0 only)   │       │                   │
                            │                   │       └───────────────────┘
                            └─────────┬─────────┘
                                      │
                                      │ final results
                                      ▼
                            ┌───────────────────┐
                            │                   │
                            │   Sync Results    │
                            │   [D7]            │
                            │                   │
                            │ • Users processed │
                            │ • Policies set    │
                            │ • Errors          │
                            │                   │
                            └───────────────────┘
```

---

## 8. Deployment Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      DEPLOYMENT DIAGRAM                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    Active Directory Forest                                           │
│                                     corp.contoso.com                                                 │
│                                                                                                      │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              FOREST ROOT DOMAIN                                                 │ │
│  │                            corp.contoso.com                                                     │ │
│  │                                                                                                 │ │
│  │  ┌─────────────────────────────────────────────┐  ┌─────────────────────────────────────────┐  │ │
│  │  │          «server»                           │  │          «server»                       │  │ │
│  │  │        DC01.corp.contoso.com                │  │      YOURSERVER.corp.contoso.com          │  │ │
│  │  │        (Domain Controller)                  │  │      (Management Server)                │  │ │
│  │  │                                             │  │                                         │  │ │
│  │  │  ┌───────────────────────────────────────┐  │  │  ┌───────────────────────────────────┐  │  │ │
│  │  │  │ Active Directory Domain Services      │  │  │  │ ADTierGuard Installation          │  │  │ │
│  │  │  │                                       │  │  │  │                                   │  │  │ │
│  │  │  │ • Configuration NC (Forest-wide)      │  │  │  │ C:\ADTierGuard\                   │  │  │ │
│  │  │  │   └─ CN=AuthN Policies               │  │  │  │ ├─ ADTierGuard.psd1               │  │  │ │
│  │  │  │   └─ CN=AuthN Silos                  │  │  │  │ ├─ Config\TierGuard.json          │  │  │ │
│  │  │  │                                       │  │  │  │ ├─ Core\*.psm1                   │  │  │ │
│  │  │  │ • Domain NC                           │  │  │  │ └─ Scripts\*.ps1                 │  │  │ │
│  │  │  │   └─ Users, Groups, Computers        │  │  │  │                                   │  │  │ │
│  │  │  │                                       │  │  │  │ Runs: Invoke-TierUserSync        │  │  │ │
│  │  │  └───────────────────────────────────────┘  │  │  │       Invoke-TierComputerSync    │  │  │ │
│  │  │                                             │  │  └───────────────────────────────────┘  │  │ │
│  │  │                                             │  │                                         │  │ │
│  │  │  Hosts:                                     │  │  ┌───────────────────────────────────┐  │  │ │
│  │  │  • TierGuard-Tier0-AuthPolicy              │  │  │ Task Scheduler                    │  │  │ │
│  │  │  • TierGuard-Tier1-AuthPolicy              │  │  │                                   │  │  │ │
│  │  │  • TierGuard-Tier0-Silo                    │  │  │ • ADTierGuard-Tier0-UserSync      │  │  │ │
│  │  │  • TierGuard-Tier1-Silo                    │  │  │   (Daily 2:00 AM)                 │  │  │ │
│  │  │                                             │  │  │                                   │  │  │ │
│  │  └─────────────────────────────────────────────┘  │  │ • ADTierGuard-Tier0-ComputerSync  │  │  │ │
│  │                      │                            │  │   (Daily 3:00 AM)                 │  │  │ │
│  │                      │ LDAP/ADSI                  │  │                                   │  │  │ │
│  │                      │                            │  │ Runs as: YOURSERVICE$                │  │  │ │
│  │                      │                            │  │ (gMSA with Domain Admin)          │  │  │ │
│  │                      └────────────────────────────┤  └───────────────────────────────────┘  │  │ │
│  │                                                   │                                         │  │ │
│  └───────────────────────────────────────────────────┴─────────────────────────────────────────┘ │
│                                                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              CHILD DOMAIN                                                    │  │
│  │                        child.corp.contoso.com                                               │  │
│  │                                                                                              │  │
│  │  ┌─────────────────────────────────────────┐      ┌─────────────────────────────────────┐   │  │
│  │  │          «server»                       │      │        «execution»                  │   │  │
│  │  │    DC01.child.corp.contoso.com          │      │    Optional: Local Sync Server     │   │  │
│  │  │                                         │      │                                     │   │  │
│  │  │  • Domain NC only (no Config access)    │◄─────│  Can run Invoke-TierUserSync       │   │  │
│  │  │  • Receives policy assignments         │      │  for THIS domain only              │   │  │
│  │  │  • Users point to forest root policy   │      │                                     │   │  │
│  │  │                                         │      │  Policy DN still points to:        │   │  │
│  │  │  User object:                           │      │  CN=TierGuard-Tier0-AuthPolicy,    │   │  │
│  │  │  msDS-AssignedAuthNPolicy =            │      │  CN=AuthN Policies,...,            │   │  │
│  │  │    CN=TierGuard-Tier0-AuthPolicy,      │      │  CN=Configuration,                 │   │  │
│  │  │    CN=AuthN Policies,                   │      │  DC=corp,DC=contoso,DC=com         │   │  │
│  │  │    CN=AuthN Policy Configuration,       │      │                                     │   │  │
│  │  │    CN=Services,                         │      │  (Forest root, NOT child domain)   │   │  │
│  │  │    CN=Configuration,                    │      │                                     │   │  │
│  │  │    DC=corp,DC=contoso,DC=com           │      │                                     │   │  │
│  │  │                                         │      │                                     │   │  │
│  │  └─────────────────────────────────────────┘      └─────────────────────────────────────┘   │  │
│  │                                                                                              │  │
│  └──────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘


                    ┌───────────────────────────────────────────────────────────┐
                    │                  LEGEND                                   │
                    ├───────────────────────────────────────────────────────────┤
                    │                                                           │
                    │  ══════════════════════════════════                       │
                    │  FOREST ROOT RESPONSIBILITIES:                            │
                    │  • Create Authentication Policies                         │
                    │  • Create Authentication Silos                            │
                    │  • Enterprise Admin permissions required                  │
                    │  • Run: Initialize-TierGuardAuth.ps1                      │
                    │  ══════════════════════════════════                       │
                    │                                                           │
                    │  ══════════════════════════════════                       │
                    │  ANY DOMAIN RESPONSIBILITIES:                             │
                    │  • Run user/computer sync                                 │
                    │  • Apply policies to local users                          │
                    │  • Manage local Protected Users group                     │
                    │  • Domain Admin permissions sufficient                    │
                    │  • Run: Invoke-TierUserSync.ps1                           │
                    │  ══════════════════════════════════                       │
                    │                                                           │
                    └───────────────────────────────────────────────────────────┘
```

---

## Appendix: AD Attributes Reference

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              ACTIVE DIRECTORY ATTRIBUTES USED                                        │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Object Type           │ Attribute                        │ Purpose                                  │
├───────────────────────┼──────────────────────────────────┼──────────────────────────────────────────┤
│ RootDSE               │ defaultNamingContext             │ Current domain DN                        │
│                       │ rootDomainNamingContext          │ Forest root domain DN                    │
│                       │ configurationNamingContext       │ Configuration NC DN                      │
│                       │ domainFunctionality              │ Domain functional level                  │
│                       │ forestFunctionality              │ Forest functional level                  │
├───────────────────────┼──────────────────────────────────┼──────────────────────────────────────────┤
│ User                  │ distinguishedName                │ User's DN                                │
│                       │ sAMAccountName                   │ Logon name                               │
│                       │ userPrincipalName                │ UPN                                      │
│                       │ memberOf                         │ Group memberships                        │
│                       │ msDS-AssignedAuthNPolicy         │ Assigned authentication policy           │
│                       │ msDS-AssignedAuthNPolicySilo     │ Assigned authentication silo             │
├───────────────────────┼──────────────────────────────────┼──────────────────────────────────────────┤
│ Group                 │ member                           │ Group members                            │
│                       │ groupType                        │ Security/Distribution, Scope             │
├───────────────────────┼──────────────────────────────────┼──────────────────────────────────────────┤
│ msDS-AuthNPolicy      │ cn                               │ Policy name                              │
│                       │ msDS-AuthNPolicyEnforced         │ Enforced (true/false)                    │
│                       │ msDS-UserTGTLifetime             │ User TGT lifetime (100ns intervals)      │
│                       │ msDS-ComputerTGTLifetime         │ Computer TGT lifetime                    │
│                       │ msDS-UserAllowedToAuthenticateFrom│ SDDL - where users can auth from       │
│                       │ msDS-UserAllowedToAuthenticateTo │ SDDL - what users can auth to           │
├───────────────────────┼──────────────────────────────────┼──────────────────────────────────────────┤
│ msDS-AuthNPolicySilo  │ cn                               │ Silo name                                │
│                       │ msDS-AuthNPolicySiloEnforced     │ Enforced (true/false)                    │
│                       │ msDS-AuthNPolicySiloMembers      │ Silo members (DNs)                       │
│                       │ msDS-UserAuthNPolicy             │ User policy for silo members             │
│                       │ msDS-ComputerAuthNPolicy         │ Computer policy for silo members         │
│                       │ msDS-ServiceAuthNPolicy          │ Service policy for silo members          │
└───────────────────────┴──────────────────────────────────┴──────────────────────────────────────────┘
```

---

**Document Version:** 2.2.0  
**Last Updated:** 2025-01-01  
**Author:** ADTierGuard Architecture Team
**Total Module Lines:** 8,583
