using System;
using System.Collections.Generic;

namespace SecKey.Core.Models
{
    /// <summary>
    /// Represents Active Directory domain information discovered during analysis.
    /// </summary>
    public class AdDomainInfo
    {
        public string DomainDn { get; set; } = string.Empty;
        public string DomainNetbiosName { get; set; } = string.Empty;
        public string DomainFqdn { get; set; } = string.Empty;
        public string ForestDn { get; set; } = string.Empty;
        public string ForestNetbiosName { get; set; } = string.Empty;
        public string ForestFqdn { get; set; } = string.Empty;
        public string DomainSid { get; set; } = string.Empty;
        public string ForestSid { get; set; } = string.Empty;
        public string DomainFunctionalLevel { get; set; } = string.Empty;
        public string ForestFunctionalLevel { get; set; } = string.Empty;
        public string PdcEmulator { get; set; } = string.Empty;
        public string ChosenDc { get; set; } = string.Empty;
        public string SysvolReplicationInfo { get; set; } = string.Empty;
        public bool IsAdRecycleBinEnabled { get; set; }
        public bool IsDomainJoined { get; set; }
        public bool IsRunningOnDc { get; set; }
        public string Hostname { get; set; } = string.Empty;
        public Dictionary<string, string> FsmoRoles { get; set; } = new();
        public List<string> DomainControllers { get; set; } = new();
        public DateTime DiscoveryTime { get; set; } = DateTime.Now;
    }

    /// <summary>
    /// Represents a member of a privileged AD group.
    /// </summary>
    public class AdPrivilegedMember
    {
        public string SamAccountName { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string ObjectClass { get; set; } = string.Empty;
        public string GroupName { get; set; } = string.Empty;
        public DateTime? PasswordLastSet { get; set; }
        public DateTime? LastLogon { get; set; }
        public bool PasswordNeverExpires { get; set; }
        public bool TrustedForDelegation { get; set; }
        public bool HasSpn { get; set; }
        public bool IsEnabled { get; set; }
        public bool IsNested { get; set; }
        public string NestedPath { get; set; } = string.Empty;
        public List<string> RiskyUacFlags { get; set; } = new();
    }

    /// <summary>
    /// Represents a risky ACL entry found on an AD object.
    /// </summary>
    public class AdRiskyAcl
    {
        public string ObjectDn { get; set; } = string.Empty;
        public string ObjectClass { get; set; } = string.Empty;
        public string IdentityReference { get; set; } = string.Empty;
        public string ActiveDirectoryRights { get; set; } = string.Empty;
        public string AccessControlType { get; set; } = string.Empty;
        public string ObjectType { get; set; } = string.Empty;
        public string ObjectTypeName { get; set; } = string.Empty;
        public string InheritedObjectType { get; set; } = string.Empty;
        public bool IsInherited { get; set; }
        public string Severity { get; set; } = "Medium";
        public string Description { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents a risky GPO configuration.
    /// </summary>
    public class AdRiskyGpo
    {
        public string GpoName { get; set; } = string.Empty;
        public string GpoGuid { get; set; } = string.Empty;
        public DateTime CreatedTime { get; set; }
        public DateTime ModifiedTime { get; set; }
        public List<string> RiskySettings { get; set; } = new();
        public bool HasScheduledTasks { get; set; }
        public bool HasRegistryMods { get; set; }
        public bool HasFileOperations { get; set; }
        public bool HasSoftwareInstallation { get; set; }
        public bool HasLocalUserMods { get; set; }
        public bool HasEnvironmentMods { get; set; }
        public string Severity { get; set; } = "Medium";
        
        /// <summary>
        /// Detailed risk reasons for this GPO.
        /// </summary>
        public List<GpoRiskDetail> RiskDetails { get; set; } = new();
        
        /// <summary>
        /// OU/site paths where this GPO is linked, with enabled status.
        /// </summary>
        public Dictionary<string, bool> LinkLocations { get; set; } = new();
        
        /// <summary>
        /// Indicates if this GPO is considered risky overall.
        /// </summary>
        public bool IsRisky => HasScheduledTasks || HasRegistryMods || HasFileOperations || 
                               HasSoftwareInstallation || HasLocalUserMods || HasEnvironmentMods;
    }

    /// <summary>
    /// Represents detailed information about a specific risk in a GPO.
    /// </summary>
    public class GpoRiskDetail
    {
        public string RiskType { get; set; } = string.Empty;  // scheduledtask, filedeploy, registry, etc.
        public string Name { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;

        public GpoRiskDetail() { }

        public GpoRiskDetail(string riskType, string name, string details)
        {
            RiskType = riskType;
            Name = name;
            Details = details;
        }

        public override string ToString() => $"{RiskType}: {Name} - {Details}";
    }

    /// <summary>
    /// Represents a risky file found in SYSVOL.
    /// </summary>
    public class SysvolRiskyFile
    {
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string Extension { get; set; } = string.Empty;
        public DateTime CreationTime { get; set; }
        public DateTime LastWriteTime { get; set; }
        public long FileSize { get; set; }
        public string Sha256Hash { get; set; } = string.Empty;
        public string Severity { get; set; } = "Medium";
    }

    /// <summary>
    /// Represents an account with Kerberos delegation configured.
    /// </summary>
    public class AdKerberosDelegation
    {
        public string SamAccountName { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string ObjectClass { get; set; } = string.Empty;
        public string DelegationType { get; set; } = string.Empty; // Unconstrained, Constrained, Resource-Based
        public List<string> AllowedToDelegateTo { get; set; } = new();
        public List<string> AllowedToActOnBehalfOf { get; set; } = new();
        public bool IsSensitive { get; set; }
        public string Severity { get; set; } = "High";
        public string Description { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents an account with AdminCount anomaly.
    /// </summary>
    public class AdAdminCountAnomaly
    {
        public string SamAccountName { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string ObjectClass { get; set; } = string.Empty;
        public int AdminCount { get; set; }
        public bool IsCurrentlyPrivileged { get; set; }
        public string Issue { get; set; } = string.Empty;
    }

    /// <summary>
    /// Overall AD Security Analysis result.
    /// </summary>
    public class AdSecurityAnalysisResult
    {
        public AdDomainInfo DomainInfo { get; set; } = new();
        public List<AdPrivilegedMember> PrivilegedMembers { get; set; } = new();
        public List<AdRiskyAcl> RiskyAcls { get; set; } = new();
        public List<AdRiskyGpo> RiskyGpos { get; set; } = new();
        public List<SysvolRiskyFile> SysvolRiskyFiles { get; set; } = new();
        public List<AdKerberosDelegation> KerberosDelegations { get; set; } = new();
        public List<AdAdminCountAnomaly> AdminCountAnomalies { get; set; } = new();
        
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
        
        public int TotalFindings => 
            PrivilegedMembers.Count + 
            RiskyAcls.Count + 
            RiskyGpos.Count + 
            SysvolRiskyFiles.Count + 
            KerberosDelegations.Count + 
            AdminCountAnomalies.Count;

        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }

        public List<string> Errors { get; set; } = new();
        public bool IsComplete { get; set; }
    }

    /// <summary>
    /// Analysis options for AD Security scans.
    /// </summary>
    public class AdSecurityAnalysisOptions
    {
        public bool AnalyzePrivilegedGroups { get; set; } = true;
        public bool AnalyzeRiskyAcls { get; set; } = true;
        public bool AnalyzeGpos { get; set; } = true;
        public bool AnalyzeSysvol { get; set; } = true;
        public bool AnalyzeKerberosDelegation { get; set; } = true;
        public bool AnalyzeAdminCount { get; set; } = true;
        public bool IncludeForestMode { get; set; } = false;
        public bool FilterSafeIdentities { get; set; } = true;
        public int GpoDaysThreshold { get; set; } = 30;
        public string? TargetDomain { get; set; }
        public string? TargetDc { get; set; }
    }

    /// <summary>
    /// Well-known privileged group definitions.
    /// Based on Microsoft Appendix B: Active Directory privileged accounts and groups reference guide
    /// https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory
    /// </summary>
    public static class WellKnownPrivilegedGroups
    {
        /// <summary>
        /// Highest privilege AD groups - Tier 0 equivalents
        /// </summary>
        public static readonly string[] Tier0Groups = new[]
        {
            "Enterprise Admins",
            "Domain Admins",
            "Schema Admins",
            "Administrators"
        };

        /// <summary>
        /// High-privilege domain-level groups that can compromise AD
        /// </summary>
        public static readonly string[] DomainGroups = new[]
        {
            // Tier 0 - Highest privilege
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            
            // DC/Server Operators - can take over domain controllers
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators",
            
            // DNS/GPO - can compromise domain
            "Group Policy Creator Owners",
            "DNSAdmins",
            "DnsAdmins",
            
            // Cryptographic/Certificate access
            "Cryptographic Operators",
            "Cert Publishers",
            
            // Remote access groups
            "Remote Desktop Users",
            "Remote Management Users",
            "Hyper-V Administrators",
            
            // Replication and DC groups
            "Domain Controllers",
            "Read-only Domain Controllers",
            "Cloneable Domain Controllers",
            "Enterprise Read-only Domain Controllers",
            
            // Trust builders
            "Incoming Forest Trust Builders",
            
            // RODC password replication
            "Allowed RODC Password Replication Group",
            "Denied RODC Password Replication Group",
            
            // Service-specific admin groups
            "DHCP Administrators",
            "RAS and IAS Servers",
            "Terminal Server License Servers",
            
            // RDS management
            "RDS Endpoint Servers",
            "RDS Management Servers",
            "RDS Remote Access Servers",
            
            // Event Log access  
            "Event Log Readers",
            
            // Pre-2000 compatibility - often over-permissioned
            "Pre-Windows 2000 Compatible Access"
        };

        /// <summary>
        /// Groups that should NEVER have external members (protected groups)
        /// </summary>
        public static readonly string[] ProtectedGroups = new[]
        {
            "Enterprise Admins",
            "Domain Admins",
            "Schema Admins",
            "Administrators",
            "Domain Controllers",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators",
            "Replicator"
        };

        public static readonly Dictionary<string, string> WellKnownSids = new()
        {
            // Built-in container groups
            { "S-1-5-32-544", "Administrators" },
            { "S-1-5-32-545", "Users" },
            { "S-1-5-32-546", "Guests" },
            { "S-1-5-32-548", "Account Operators" },
            { "S-1-5-32-549", "Server Operators" },
            { "S-1-5-32-550", "Print Operators" },
            { "S-1-5-32-551", "Backup Operators" },
            { "S-1-5-32-552", "Replicator" },
            { "S-1-5-32-555", "Remote Desktop Users" },
            { "S-1-5-32-556", "Network Configuration Operators" },
            { "S-1-5-32-557", "Incoming Forest Trust Builders" },
            { "S-1-5-32-558", "Performance Monitor Users" },
            { "S-1-5-32-559", "Performance Log Users" },
            { "S-1-5-32-560", "Windows Authorization Access Group" },
            { "S-1-5-32-561", "Terminal Server License Servers" },
            { "S-1-5-32-562", "Distributed COM Users" },
            { "S-1-5-32-568", "IIS_IUSRS" },
            { "S-1-5-32-569", "Cryptographic Operators" },
            { "S-1-5-32-573", "Event Log Readers" },
            { "S-1-5-32-574", "Certificate Service DCOM Access" },
            { "S-1-5-32-575", "RDS Remote Access Servers" },
            { "S-1-5-32-576", "RDS Endpoint Servers" },
            { "S-1-5-32-577", "RDS Management Servers" },
            { "S-1-5-32-578", "Hyper-V Administrators" },
            { "S-1-5-32-579", "Access Control Assistance Operators" },
            { "S-1-5-32-580", "Remote Management Users" },
            
            // Domain relative IDs (append to domain SID)
            { "-500", "Administrator" },
            { "-501", "Guest" },
            { "-502", "KRBTGT" },
            { "-512", "Domain Admins" },
            { "-513", "Domain Users" },
            { "-514", "Domain Guests" },
            { "-515", "Domain Computers" },
            { "-516", "Domain Controllers" },
            { "-517", "Cert Publishers" },
            { "-518", "Schema Admins" },
            { "-519", "Enterprise Admins" },
            { "-520", "Group Policy Creator Owners" },
            { "-521", "Read-only Domain Controllers" },
            { "-522", "Cloneable Domain Controllers" },
            { "-525", "Protected Users" },
            { "-526", "Key Admins" },
            { "-527", "Enterprise Key Admins" },
            { "-553", "RAS and IAS Servers" },
            { "-571", "Allowed RODC Password Replication Group" },
            { "-572", "Denied RODC Password Replication Group" }
        };
    }

    /// <summary>
    /// Risky AD rights that should trigger alerts.
    /// </summary>
    public static class RiskyAdRights
    {
        public static readonly string[] DangerousRights = new[]
        {
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "AllExtendedRights",
            "WriteProperty"
        };

        public static readonly string[] DangerousExtendedRights = new[]
        {
            "DS-Replication-Get-Changes-All",
            "DS-Replication-Get-Changes",
            "User-Force-Change-Password",
            "Member",
            "GP-Link",
            "Allowed-To-Authenticate"
        };

        public static readonly string[] RiskyUacFlags = new[]
        {
            "DONT_REQ_PREAUTH",
            "ENCRYPTED_TEXT_PWD_ALLOWED",
            "PASSWD_NOTREQD",
            "USE_DES_KEY_ONLY",
            "TRUSTED_TO_AUTH_FOR_DELEGATION",
            "TRUSTED_FOR_DELEGATION",
            "DONT_EXPIRE_PASSWORD"
        };
    }

    /// <summary>
    /// Identities that are normally safe to have risky permissions.
    /// </summary>
    public static class SafeIdentities
    {
        public static readonly string[] SystemIdentities = new[]
        {
            "NT AUTHORITY\\SELF",
            "NT AUTHORITY\\SYSTEM",
            "Everyone",
            "Enterprise Read-only Domain Controllers",
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Domain Controllers",
            "NT AUTHORITY\\Enterprise Domain Controllers",
            "BUILTIN\\Administrators"
        };
    }

    #region GPO and OU Models

    /// <summary>
    /// Represents a Group Policy Object for creation or analysis.
    /// </summary>
    public class AdGroupPolicy
    {
        public string Name { get; set; } = string.Empty;
        public string GpoGuid { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public DateTime CreatedTime { get; set; }
        public DateTime ModifiedTime { get; set; }
        public List<string> LinkedOUs { get; set; } = new();
        public string Description { get; set; } = string.Empty;
        public GpoSettings Settings { get; set; } = new();
    }

    /// <summary>
    /// GPO Settings container.
    /// </summary>
    public class GpoSettings
    {
        public bool ComputerEnabled { get; set; } = true;
        public bool UserEnabled { get; set; } = true;
        public List<string> SecuritySettings { get; set; } = new();
        public List<string> RegistrySettings { get; set; } = new();
        public List<string> ScriptSettings { get; set; } = new();
    }

    /// <summary>
    /// Represents an Organizational Unit.
    /// </summary>
    public class AdOrganizationalUnit
    {
        public string Name { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string ParentDn { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsProtectedFromDeletion { get; set; }
        public DateTime CreatedTime { get; set; }
        public int ChildCount { get; set; }
        public List<string> LinkedGpos { get; set; } = new();
    }

    /// <summary>
    /// Template for creating tiered admin model OUs (BILL model).
    /// </summary>
    public class BillOuTemplate
    {
        public string BaseName { get; set; } = "Admin";
        public string Tier0Name { get; set; } = "Tier0";
        public string Tier1Name { get; set; } = "Tier1";
        public string Tier2Name { get; set; } = "Tier2";
        public bool CreatePawOus { get; set; } = true;
        public bool CreateServiceAccountOus { get; set; } = true;
        public bool CreateGroupsOus { get; set; } = true;
    }

    /// <summary>
    /// Options for deploying baseline GPOs.
    /// </summary>
    public class GpoDeploymentOptions
    {
        // Legacy/Quick Deploy GPOs
        public bool DeployPasswordPolicy { get; set; } = true;
        public bool DeployAuditPolicy { get; set; } = true;
        public bool DeploySecurityBaseline { get; set; } = true;
        public bool DeployPawPolicy { get; set; } = true;
        public string TieredOuBaseName { get; set; } = "Admin";

        // === PLATYPUS/BILL Tiered GPOs ===

        // Tier 0 GPOs (Domain Controllers / Tier 0 Servers)
        public bool DeployT0BaselineAudit { get; set; } = false;
        public bool DeployT0DisallowDsrm { get; set; } = false;
        public bool DeployT0DomainBlock { get; set; } = false;
        public bool DeployT0DomainControllers { get; set; } = false;
        public bool DeployT0EsxAdmins { get; set; } = false;
        public bool DeployT0UserRights { get; set; } = false;
        public bool DeployT0RestrictedGroups { get; set; } = false;

        // Tier 1 GPOs (Tier 1 Servers)
        public bool DeployT1LocalAdmin { get; set; } = false;
        public bool DeployT1UserRights { get; set; } = false;
        public bool DeployT1RestrictedGroups { get; set; } = false;

        // Tier 2 GPOs (Tier 2 Devices / Workstations)
        public bool DeployT2LocalAdmin { get; set; } = false;
        public bool DeployT2UserRights { get; set; } = false;
        public bool DeployT2RestrictedGroups { get; set; } = false;

        // Cross-Tier GPOs (Top Level / All Tiers)
        public bool DeployDisableSmb1 { get; set; } = false;
        public bool DeployDisableWDigest { get; set; } = false;
        public bool DeployResetMachinePassword { get; set; } = false;

        // Security Groups for Tiered Model
        public bool CreateTierGroups { get; set; } = true;

        // Linking option
        public bool LinkGposToOus { get; set; } = false;

        // === NEW: Fine-Grained Password Policy Options ===
        public bool DeployFineGrainedPasswordPolicy { get; set; } = false;
        public int FgppMaxPasswordAge { get; set; } = 90;
        public int FgppMinPasswordLength { get; set; } = 25;
        public int FgppPasswordHistoryCount { get; set; } = 12;
        public bool FgppComplexityEnabled { get; set; } = true;

        // === NEW: Domain Join Delegation Options ===
        public bool SetDomainJoinDelegation { get; set; } = false;
        public string DomainJoinDelegateGroup { get; set; } = "BILL Domain Join";

        // === NEW: OU Creation Options ===
        public bool CreateFullOuStructure { get; set; } = false;
        public bool BlockInheritanceOnStagingOus { get; set; } = false;
        public string IdOuName { get; set; } = "SITH";

        // === NEW: WMI Filter Options ===
        public bool CreateWmiFilters { get; set; } = false;

        // === NEW: GPO ACL Options ===
        public bool SetGpoAcls { get; set; } = false;
    }

    /// <summary>
    /// Represents a WMI Filter for GPO targeting.
    /// </summary>
    public class WmiFilter
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Namespace { get; set; } = @"root\CIMv2";
        public string Query { get; set; } = string.Empty;
        public DateTime Created { get; set; }
        public string Author { get; set; } = string.Empty;
    }

    /// <summary>
    /// Result of Fine-Grained Password Policy creation.
    /// </summary>
    public class FineGrainedPasswordPolicyResult
    {
        public bool Success { get; set; }
        public string PolicyName { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public List<string> SubjectsApplied { get; set; } = new();
        public Exception? Error { get; set; }
    }

    /// <summary>
    /// Extended GPO groups dictionary for multi-forest scenarios.
    /// Maps to the Get-BillGpoGroups function from PLATYPUS.
    /// </summary>
    public class TieredModelGroupSids
    {
        // Tier 0 Groups
        public string? Tier0Operators { get; set; }
        public string? Tier0ServiceAccounts { get; set; }
        public string? Tier0Computers { get; set; }

        // Tier 1 Groups
        public string? Tier1Operators { get; set; }
        public string? Tier1ServiceAccounts { get; set; }
        public string? Tier1ServerLocalAdmins { get; set; }

        // Tier 2 Groups
        public string? Tier2Operators { get; set; }
        public string? Tier2ServiceAccounts { get; set; }
        public string? Tier2WorkstationLocalAdmins { get; set; }

        // Domain Groups
        public string? DomainAdmins { get; set; }
        public string? EnterpriseAdmins { get; set; }
        public string? SchemaAdmins { get; set; }
        public string? DomainControllers { get; set; }
        public string? DomainAdministratorAccount { get; set; }
        public string? DomainGuestAccount { get; set; }
        public string? DomainGuests { get; set; }
        public string? DomainUsers { get; set; }
        public string? DomainAuthUsers { get; set; }
        public string? DomainAccountOperators { get; set; }
        public string? DomainBackupOperators { get; set; }
        public string? DomainPrintOperators { get; set; }
        public string? DomainServerOperators { get; set; }

        // Enterprise/Forest Groups
        public string? EnterpriseReadOnlyDCs { get; set; }
        public string? ReadOnlyDomainControllers { get; set; }
        public string? ExchangeServers { get; set; }

        // DVRL Group (Deny Logon All Tiers)
        public string? DenyLogonAllTiers { get; set; }

        // Special Groups
        public string? EsxAdmins { get; set; }
        public string? BillDomainJoin { get; set; }

        // Root Domain Groups (for child domain scenarios)
        public string? RootDomainAdmins { get; set; }
        public string? RootTier0Operators { get; set; }
        public string? RootTier0ServiceAccounts { get; set; }
        public string? RootTier1Operators { get; set; }
        public string? RootTier2Operators { get; set; }

        // Well-known SIDs
        public string LocalAdministrators { get; } = "*S-1-5-32-544";
        public string LocalUsers { get; } = "*S-1-5-32-545";
        public string LocalGuests { get; } = "*S-1-5-32-546";
        public string PerformanceLogUsers { get; } = "*S-1-5-32-559";
        public string LocalAccountAndAdmins { get; } = "*S-1-5-114";
        public string NtAllServices { get; } = "*S-1-5-80-0";
        public string NtAuthSystem { get; } = "*S-1-5-18";
        public string NtLocalService { get; } = "*S-1-5-19";
        public string NtNetworkService { get; } = "*S-1-5-20";
        public string NtService { get; } = "*S-1-5-6";
        public string EnterpriseDomainControllers { get; } = "*S-1-5-9";
        public string AuthenticatedUsers { get; } = "*S-1-5-11";

        // Domain-specific SIDs (set during discovery)
        public string DomainSid { get; set; } = string.Empty;
        public string ForestSid { get; set; } = string.Empty;

        // Multi-forest flag
        public bool IsSingleForestSingleDomain { get; set; } = true;

        /// <summary>
        /// Generates a well-known domain SID based on domain SID and RID.
        /// </summary>
        public string GetDomainSid(int rid) => $"*{DomainSid}-{rid}";

        /// <summary>
        /// Generates a well-known forest SID based on forest SID and RID.
        /// </summary>
        public string GetForestSid(int rid) => $"*{ForestSid}-{rid}";
    }

    /// <summary>
    /// Result of GPO/OU creation operations.
    /// </summary>
    public class AdObjectCreationResult
    {
        public bool Success { get; set; }
        public string ObjectType { get; set; } = string.Empty;
        public string ObjectName { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public Exception? Error { get; set; }
    }

    /// <summary>
    /// Result of GPO-specific deployment operations.
    /// </summary>
    public class AdGpoResult
    {
        public bool Success { get; set; }
        public string GpoName { get; set; } = string.Empty;
        public string? GpoGuid { get; set; }
        public string? GpoDn { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    #endregion

    #region Entra ID (Azure AD) Models

    /// <summary>
    /// Represents an Entra ID (formerly Azure AD) tenant.
    /// </summary>
    public class EntraIdTenant
    {
        public string TenantId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string DefaultDomain { get; set; } = string.Empty;
        public List<string> VerifiedDomains { get; set; } = new();
        public DateTime DiscoveryTime { get; set; } = DateTime.Now;
    }

    /// <summary>
    /// Represents a privileged role assignment in Entra ID.
    /// </summary>
    public class EntraIdPrivilegedRole
    {
        public string RoleId { get; set; } = string.Empty;
        public string RoleDisplayName { get; set; } = string.Empty;
        public string RoleTemplateId { get; set; } = string.Empty;
        public bool IsBuiltIn { get; set; }
        public List<EntraIdRoleMember> Members { get; set; } = new();
    }

    /// <summary>
    /// Represents a member of an Entra ID privileged role.
    /// </summary>
    public class EntraIdRoleMember
    {
        public string ObjectId { get; set; } = string.Empty;
        public string ObjectType { get; set; } = string.Empty; // User, ServicePrincipal, Group
        public string DisplayName { get; set; } = string.Empty;
        public string UserPrincipalName { get; set; } = string.Empty;
        public string RoleName { get; set; } = string.Empty;
        public bool IsEligible { get; set; } // PIM eligible vs permanent
        public DateTime? AssignmentStart { get; set; }
        public DateTime? AssignmentEnd { get; set; }
        public string AssignmentType { get; set; } = "Permanent"; // Permanent, Eligible, Active
    }

    /// <summary>
    /// Represents a PIM violation where a privileged role has permanent assignment instead of eligible.
    /// </summary>
    public class EntraIdPimViolation
    {
        /// <summary>Role template ID (GUID).</summary>
        public string RoleId { get; set; } = string.Empty;

        /// <summary>Display name of the role.</summary>
        public string RoleName { get; set; } = string.Empty;

        /// <summary>Description of the role.</summary>
        public string RoleDescription { get; set; } = string.Empty;

        /// <summary>Object ID of the principal with permanent assignment.</summary>
        public string PrincipalId { get; set; } = string.Empty;

        /// <summary>Type of principal: User, ServicePrincipal, Group.</summary>
        public string PrincipalType { get; set; } = string.Empty;

        /// <summary>Display name of the principal.</summary>
        public string PrincipalDisplayName { get; set; } = string.Empty;

        /// <summary>UPN of the principal (for users).</summary>
        public string PrincipalUpn { get; set; } = string.Empty;

        /// <summary>Type of assignment: Permanent, Eligible, Active.</summary>
        public string AssignmentType { get; set; } = "Permanent";

        /// <summary>Severity of the violation: Critical, Warning, Info.</summary>
        public string ViolationType { get; set; } = "Warning";

        /// <summary>Recommended remediation action.</summary>
        public string Recommendation { get; set; } = string.Empty;

        /// <summary>When the permanent assignment started.</summary>
        public DateTime? AssignmentStart { get; set; }

        /// <summary>Whether this role should NEVER have permanent assignments per security best practice.</summary>
        public bool ShouldNeverBePermanent { get; set; }
    }

    /// <summary>
    /// Represents a risky application in Entra ID.
    /// </summary>
    public class EntraIdRiskyApp
    {
        public string AppId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string ObjectId { get; set; } = string.Empty;
        public List<EntraIdAppPermissionInfo> Permissions { get; set; } = new();
        public List<string> Owners { get; set; } = new();
        public DateTime? CreatedDateTime { get; set; }
        public string Severity { get; set; } = "Medium";
        public string RiskReason { get; set; } = string.Empty;
        
        // Helper properties for UI binding
        public int RiskyPermissionCount => Permissions.Count(p => p.IsHighRisk);
        public List<EntraIdAppPermissionInfo> RiskyPermissions => Permissions.Where(p => p.IsHighRisk).ToList();
    }

    /// <summary>
    /// Represents an API permission for an Entra ID app.
    /// </summary>
    public class EntraIdAppPermissionInfo
    {
        public string PermissionId { get; set; } = string.Empty;
        public string PermissionName { get; set; } = string.Empty;
        public string PermissionDescription { get; set; } = string.Empty;
        public string ResourceAppId { get; set; } = string.Empty;
        public string ResourceDisplayName { get; set; } = string.Empty;
        public string PermissionType { get; set; } = string.Empty; // Delegated, Application
        public bool IsHighRisk { get; set; }
        public string ConsentType { get; set; } = string.Empty; // Admin, User
    }

    /// <summary>
    /// Represents a Conditional Access Policy in Entra ID.
    /// </summary>
    public class EntraIdConditionalAccessPolicy
    {
        public string Id { get; set; } = string.Empty;
        public string PolicyId => Id; // Alias for UI binding
        public string DisplayName { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty; // Enabled, Disabled, EnabledForReportingButNotEnforced
        public DateTime? CreatedDateTime { get; set; }
        public DateTime? ModifiedDateTime { get; set; }
        public List<string> IncludedUsers { get; set; } = new();
        public List<string> ExcludedUsers { get; set; } = new();
        public List<string> IncludedApplications { get; set; } = new();
        public List<string> GrantControls { get; set; } = new();
        public string SessionControls { get; set; } = string.Empty;
        
        // Helper properties for UI
        public bool IncludesAllUsers => IncludedUsers.Contains("All") || IncludedUsers.Contains("all");
        public bool IncludesAllApps => IncludedApplications.Contains("All") || IncludedApplications.Contains("all");
        public string GrantControlsSummary => GrantControls.Count > 0 ? string.Join(", ", GrantControls) : "None";
    }

    /// <summary>
    /// Entra ID Security Analysis Result.
    /// </summary>
    public class EntraIdSecurityResult
    {
        public EntraIdTenant? Tenant { get; set; }
        public List<EntraIdPrivilegedRole> PrivilegedRoles { get; set; } = new();
        public List<EntraIdRiskyApp> RiskyApps { get; set; } = new();
        public List<EntraIdConditionalAccessPolicy> ConditionalAccessPolicies { get; set; } = new();
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
        public List<string> Errors { get; set; } = new();
        public bool IsComplete { get; set; }
        
        public int TotalPrivilegedUsers => PrivilegedRoles.SelectMany(r => r.Members).Count();
        public int HighRiskAppCount => RiskyApps.Count(a => a.Severity == "High" || a.Severity == "Critical");
    }

    /// <summary>
    /// Known risky Entra ID API permissions.
    /// </summary>
    public static class RiskyEntraIdPermissions
    {
        public static readonly Dictionary<string, string> HighRiskPermissions = new()
        {
            { "810c84a8-4a9e-49e6-bf7d-12d183f40d01", "Mail.Read" },
            { "e2a3a72e-5f79-4c64-b1b1-878b674786c9", "Mail.ReadWrite" },
            { "b633e1c5-b582-4048-a93e-9f11b44c7e96", "Mail.Send" },
            { "d56682ec-c09e-4743-aaf4-1a3aac4caa21", "Contacts.ReadWrite" },
            { "01d4889c-1287-42c6-ac1f-5d1e02578ef6", "Files.Read.All" },
            { "75359482-378d-4052-8f01-80520e7db3cd", "Files.ReadWrite.All" },
            { "7ab1d382-f21e-4acd-a863-ba3e13f7da61", "Directory.Read.All" },
            { "19dbc75e-c2e2-444c-a770-ec69d8559fc7", "Directory.ReadWrite.All" },
            { "62a82d76-70ea-41e2-9197-370581804d09", "Group.ReadWrite.All" },
            { "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8", "RoleManagement.ReadWrite.Directory" },
            { "06b708a9-e830-4db3-a914-8e69da51d44f", "AppRoleAssignment.ReadWrite.All" },
            { "741f803b-c850-494e-b5df-cde7c675a1ca", "User.ReadWrite.All" }
        };

        public static readonly string[] CriticalPermissions = new[]
        {
            "Directory.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
            "AppRoleAssignment.ReadWrite.All",
            "Application.ReadWrite.All",
            "Mail.ReadWrite",
            "Mail.Send"
        };

        private static readonly Dictionary<string, string> PermissionDescriptions = new()
        {
            { "Mail.Read", "Read user mailbox - can access all emails" },
            { "Mail.ReadWrite", "Read and modify user mailbox - full mailbox access" },
            { "Mail.Send", "Send mail as any user - can impersonate users" },
            { "Contacts.ReadWrite", "Full access to user contacts" },
            { "Files.Read.All", "Read all files in SharePoint/OneDrive" },
            { "Files.ReadWrite.All", "Read and write all files in SharePoint/OneDrive" },
            { "Directory.Read.All", "Read all directory data including users, groups, applications" },
            { "Directory.ReadWrite.All", "Read and write all directory data - can modify tenant config" },
            { "Group.ReadWrite.All", "Create and manage all groups including security groups" },
            { "RoleManagement.ReadWrite.Directory", "Manage role assignments - can grant Global Admin" },
            { "AppRoleAssignment.ReadWrite.All", "Manage app role assignments - can grant permissions" },
            { "User.ReadWrite.All", "Create and modify all users - can reset passwords" }
        };

        public static string GetPermissionDescription(string permissionName)
        {
            return PermissionDescriptions.TryGetValue(permissionName, out var desc) ? desc : $"Risky permission: {permissionName}";
        }
    }

    #endregion

    #region Analysis Database Models

    /// <summary>
    /// Represents a stored analysis run for historical tracking.
    /// </summary>
    public class StoredAnalysisRun
    {
        public long Id { get; set; }
        public string AnalysisType { get; set; } = string.Empty; // AD, EntraID, Combined
        public DateTime RunTime { get; set; }
        public string TargetDomain { get; set; } = string.Empty;
        public string TargetTenantId { get; set; } = string.Empty;
        public int TotalFindings { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public double DurationSeconds { get; set; }
        public bool IsComplete { get; set; }
        public string ResultJson { get; set; } = string.Empty;
    }

    #endregion

    #region Tenant Takeback / IR Models (PLATYPUS)

    /// <summary>
    /// Options for tenant takeback operation.
    /// </summary>
    public class TenantTakebackOptions
    {
        public string TenantId { get; set; } = string.Empty;
        public List<string> ExemptedUserUpns { get; set; } = new();
        public bool ResetPasswords { get; set; } = true;
        public bool RevokeSessions { get; set; } = true;
        public bool RemoveFromRoles { get; set; } = false;
        public bool SavePasswordsToResult { get; set; } = false;
        public bool WhatIf { get; set; } = true;
    }

    /// <summary>
    /// Result of tenant takeback operation.
    /// </summary>
    public class TenantTakebackResult
    {
        public string TenantId { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
        public bool Success { get; set; }
        public List<UserTakebackResult> ProcessedUsers { get; set; } = new();
        public List<string> SkippedUsers { get; set; } = new();
        public List<string> Errors { get; set; } = new();
        
        public int TotalProcessed => ProcessedUsers.Count;
        public int PasswordsReset => ProcessedUsers.Count(u => u.PasswordReset);
        public int SessionsRevoked => ProcessedUsers.Count(u => u.SessionsRevoked);
        public int RolesRemoved => ProcessedUsers.Count(u => u.RolesRemoved);
    }

    /// <summary>
    /// Result for a single user in takeback operation.
    /// </summary>
    public class UserTakebackResult
    {
        public string UserPrincipalName { get; set; } = string.Empty;
        public string ObjectId { get; set; } = string.Empty;
        public bool PasswordReset { get; set; }
        public bool SessionsRevoked { get; set; }
        public bool RolesRemoved { get; set; }
        public bool WhatIfOnly { get; set; }
        public string NewPassword { get; set; } = string.Empty;
        public string? Error { get; set; }
    }

    /// <summary>
    /// Result of mass password reset operation.
    /// </summary>
    public class MassPasswordResetResult
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
        public bool Success { get; set; }
        public int ResetCount { get; set; }
        public int SkippedCount { get; set; }
        public int FailedCount { get; set; }
        public Dictionary<string, string> ResetPasswords { get; set; } = new();
        public List<string> Errors { get; set; } = new();
    }

    /// <summary>
    /// Result of an AD remediation operation.
    /// </summary>
    public class AdRemediationResult
    {
        public string ObjectDn { get; set; } = string.Empty;
        public string ObjectName { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    #endregion

    #region Entra ID Privileged Roles Reference

    /// <summary>
    /// Entra ID privileged roles - based on Microsoft documentation
    /// https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
    /// Roles marked with "Privileged label icon" in Microsoft documentation
    /// </summary>
    public static class EntraIdPrivilegedRoles
    {
        /// <summary>
        /// Highest-privilege roles that can take over the entire tenant
        /// These should have ZERO permanent assignments except break-glass accounts
        /// </summary>
        public static readonly Dictionary<string, string> Tier0Roles = new()
        {
            { "62e90394-69f5-4237-9190-012177145e10", "Global Administrator" },
            { "e8611ab8-c189-46e8-94e1-60213ab1f814", "Privileged Role Administrator" },
            { "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "Privileged Authentication Administrator" }
        };

        /// <summary>
        /// All privileged roles as defined by Microsoft (marked with Privileged label)
        /// Key = Role Template ID, Value = Role Display Name
        /// </summary>
        public static readonly Dictionary<string, string> AllPrivilegedRoles = new()
        {
            // Tier 0 - Tenant control
            { "62e90394-69f5-4237-9190-012177145e10", "Global Administrator" },
            { "e8611ab8-c189-46e8-94e1-60213ab1f814", "Privileged Role Administrator" },
            { "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "Privileged Authentication Administrator" },
            
            // Global Reader - can see everything
            { "f2ef992c-3afb-46b9-b7cf-a126ee74c451", "Global Reader" },
            
            // Identity/Auth management
            { "c4e39bd9-1100-46d3-8c65-fb160da0071f", "Authentication Administrator" },
            { "25a516ed-2fa0-40ea-a2d0-12923a21473a", "Authentication Extensibility Administrator" },
            { "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", "Hybrid Identity Administrator" },
            { "59d46f88-662b-457b-bceb-5c3809e5908f", "Lifecycle Workflows Administrator" },
            
            // Application/Service Principal management
            { "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "Application Administrator" },
            { "cf1c38e5-3621-4004-a7cb-879624dced7c", "Application Developer" },
            { "158c047a-c907-4556-b7ef-446551a6b5f7", "Cloud Application Administrator" },
            
            // Directory and domain management
            { "9360feb5-f418-4baa-8175-e2a00bac4301", "Directory Writers" },
            { "8329153b-31d0-4727-b945-745eb3bc5f31", "Domain Name Administrator" },
            
            // User management
            { "fe930be7-5e62-47db-91af-98c3a49a38b1", "User Administrator" },
            { "729827e3-9c14-49f7-bb1b-9608f156bbb8", "Helpdesk Administrator" },
            { "966707d0-3269-4727-9be2-8c3a10f19b9d", "Password Administrator" },
            
            // Conditional Access
            { "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "Conditional Access Administrator" },
            
            // Security
            { "194ae4cb-b126-40b2-bd5b-6091b380977d", "Security Administrator" },
            { "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f", "Security Operator" },
            { "5d6b6bb7-de71-4623-b4af-96380a352509", "Security Reader" },
            
            // Intune/Device management
            { "3a2c62db-5318-420d-8d74-23affee5d9d5", "Intune Administrator" },
            { "7698a772-787b-4ac8-901f-60d6b08affd2", "Cloud Device Administrator" },
            
            // External identity
            { "be2f45a1-457d-42af-a067-6ec1fa63bc45", "External Identity Provider Administrator" },
            
            // B2C specific
            { "aaf43236-0c0d-4d5f-883a-6955382ac081", "B2C IEF Keyset Administrator" },
            
            // Partner support (deprecated but still privileged)
            { "4ba39ca4-527c-499a-b93d-d9b492c50246", "Partner Tier1 Support" },
            { "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8", "Partner Tier2 Support" },
            
            // Attribute provisioning
            { "ecb2c6bf-0ab6-418e-bd87-7986f8d63bbe", "Attribute Provisioning Administrator" },
            { "422218e4-db15-4ef9-bbe0-8afb41546d79", "Attribute Provisioning Reader" },
            
            // Agent ID (new)
            { "db506228-d27e-4b7d-95e5-295956d6615f", "Agent ID Administrator" }
        };

        /// <summary>
        /// Roles that should NEVER have permanent assignments in a secure tenant
        /// Any permanent assignment here is a PIM policy violation
        /// </summary>
        public static readonly string[] NeverPermanent = new[]
        {
            "Global Administrator",
            "Privileged Role Administrator",
            "Privileged Authentication Administrator",
            "Security Administrator",
            "Conditional Access Administrator",
            "Application Administrator",
            "Cloud Application Administrator",
            "User Administrator",
            "Intune Administrator",
            "Exchange Administrator",
            "SharePoint Administrator",
            "Hybrid Identity Administrator"
        };

        /// <summary>
        /// Check if a role name is privileged
        /// </summary>
        public static bool IsPrivilegedRole(string? roleName)
        {
            if (string.IsNullOrEmpty(roleName))
                return false;

            return AllPrivilegedRoles.Values.Any(r => 
                roleName.Equals(r, StringComparison.OrdinalIgnoreCase) ||
                roleName.Contains(r, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Check if a role ID is privileged
        /// </summary>
        public static bool IsPrivilegedRoleId(string? roleId)
        {
            if (string.IsNullOrEmpty(roleId))
                return false;

            return AllPrivilegedRoles.ContainsKey(roleId);
        }

        /// <summary>
        /// Check if a role should never have permanent assignments
        /// </summary>
        public static bool ShouldNeverBePermanent(string? roleName)
        {
            if (string.IsNullOrEmpty(roleName))
                return false;

            return NeverPermanent.Any(r => 
                roleName.Equals(r, StringComparison.OrdinalIgnoreCase));
        }
    }

    #endregion

    #region Attack Path Detection Models

    /// <summary>
    /// Represents a security finding from attack path detection.
    /// </summary>
    public class SecurityFinding
    {
        public string Category { get; set; } = string.Empty;
        public string Severity { get; set; } = "Medium";
        public string ObjectName { get; set; } = string.Empty;
        public string ObjectDn { get; set; } = string.Empty;
        public string ObjectType { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
    }

    /// <summary>
    /// Results from a complete attack path detection scan.
    /// </summary>
    public class AttackPathScanResult
    {
        public List<SecurityFinding> UnconstrainedDelegation { get; set; } = new();
        public List<SecurityFinding> ConstrainedDelegation { get; set; } = new();
        public List<SecurityFinding> Rbcd { get; set; } = new();
        public List<SecurityFinding> AsRepRoastable { get; set; } = new();
        public List<SecurityFinding> Kerberoastable { get; set; } = new();
        public List<SecurityFinding> DcSyncPrincipals { get; set; } = new();
        public List<SecurityFinding> SidHistory { get; set; } = new();
        public List<SecurityFinding> OrphanedAdminCount { get; set; } = new();
        public int TotalFindings { get; set; }
        public int CriticalFindings { get; set; }
        
        /// <summary>
        /// Gets all findings flattened into a single list.
        /// </summary>
        public List<SecurityFinding> AllFindings => 
            UnconstrainedDelegation.Concat(ConstrainedDelegation)
            .Concat(Rbcd).Concat(AsRepRoastable).Concat(Kerberoastable)
            .Concat(DcSyncPrincipals).Concat(SidHistory).Concat(OrphanedAdminCount).ToList();
    }

    #endregion

    #region LAPS Audit Models

    /// <summary>
    /// Results from LAPS deployment audit.
    /// </summary>
    public class LapsAuditResult
    {
        public bool LapsSchemaExtended { get; set; }
        public bool WindowsLapsSchemaExtended { get; set; }
        public int TotalComputers { get; set; }
        public int ComputersWithLaps { get; set; }
        public double CoveragePercent { get; set; }
        public List<ComputerLapsStatus> ComputersWithoutLaps { get; set; } = new();
    }

    /// <summary>
    /// LAPS status for a specific computer.
    /// </summary>
    public class ComputerLapsStatus
    {
        public string ComputerName { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string OperatingSystem { get; set; } = string.Empty;
        public bool HasLaps { get; set; }
        public DateTime? LapsPasswordExpiration { get; set; }
    }

    #endregion

    #region Stale Accounts Models

    /// <summary>
    /// Results from stale accounts scan.
    /// </summary>
    public class StaleAccountsResult
    {
        public int InactiveDaysThreshold { get; set; }
        public List<StaleAccountInfo> StaleUsers { get; set; } = new();
        public List<StaleAccountInfo> StaleComputers { get; set; } = new();
    }

    /// <summary>
    /// Information about a stale account.
    /// </summary>
    public class StaleAccountInfo
    {
        public string SamAccountName { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public DateTime LastLogon { get; set; }
        public DateTime PasswordLastSet { get; set; }
        public string OperatingSystem { get; set; } = string.Empty;
        public bool IsPrivileged { get; set; }
        public int DaysSinceLastLogon { get; set; }
    }

    #endregion

    #region PIM Assignment Models

    /// <summary>
    /// Represents an active or eligible PIM role assignment.
    /// </summary>
    public class EntraIdPimAssignment
    {
        public string AssignmentId { get; set; } = string.Empty;
        public string RoleId { get; set; } = string.Empty;
        public string RoleName { get; set; } = string.Empty;
        public string PrincipalId { get; set; } = string.Empty;
        public string PrincipalDisplayName { get; set; } = string.Empty;
        public string PrincipalUpn { get; set; } = string.Empty;
        public string PrincipalType { get; set; } = string.Empty; // User, Group, ServicePrincipal
        /// <summary>Eligible, Active, or Permanent.</summary>
        public string AssignmentType { get; set; } = string.Empty;
        public DateTime? StartDateTime { get; set; }
        public DateTime? EndDateTime { get; set; }
        public string Justification { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty; // Provisioned, PendingApproval, etc.
    }

    /// <summary>
    /// Result of creating an app registration.
    /// </summary>
    public class AppRegistrationResult
    {
        public bool Success { get; set; }
        public string AppId { get; set; } = string.Empty;
        public string ObjectId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public bool AlreadyExisted { get; set; }
    }

    #endregion
}
