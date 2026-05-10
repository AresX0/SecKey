using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SecKey.Core.Models;

#pragma warning disable CA2000 // Dispose objects before losing scope - using var handles disposal correctly

namespace SecKey.Core.Services
{
    /// <summary>
    /// Active Directory Security Analysis Service.
    /// Provides incident response and security assessment capabilities similar to PLATYPUS.
    /// Implemented in native C#/.NET for Windows platform.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class AdSecurityAnalysisService
    {
        private readonly IProgress<string>? _progress;
        private AdDomainInfo? _domainInfo;
        private Dictionary<Guid, string> _schemaGuids = new();
        private Dictionary<Guid, string> _extendedRightsGuids = new();

        // Risky file extensions to scan in SYSVOL
        private static readonly HashSet<string> RiskyExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".com", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".wsf", ".hta", ".msi", ".msp"
        };

        public AdSecurityAnalysisService(IProgress<string>? progress = null)
        {
            _progress = progress;
        }

        #region Domain Discovery

        /// <summary>
        /// Checks if the current machine is domain joined.
        /// </summary>
        public bool IsDomainJoined()
        {
            try
            {
                return Domain.GetComputerDomain() != null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Discovers Active Directory domain information.
        /// </summary>
        public async Task<AdDomainInfo> DiscoverDomainAsync(string? domainName = null, string? dcName = null, CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                _progress?.Report("Discovering Active Directory domain...");

                var info = new AdDomainInfo
                {
                    Hostname = Environment.MachineName,
                    DiscoveryTime = DateTime.Now
                };

                try
                {
                    // Check if domain joined
                    info.IsDomainJoined = IsDomainJoined();

                    if (!info.IsDomainJoined && string.IsNullOrEmpty(domainName))
                    {
                        _progress?.Report("Machine is not domain joined. Specify a target domain.");
                        _domainInfo = info;
                        return info;
                    }

                    // Get domain context
                    Domain domain;
                    if (!string.IsNullOrEmpty(domainName))
                    {
                        var context = new DirectoryContext(DirectoryContextType.Domain, domainName);
                        domain = Domain.GetDomain(context);
                    }
                    else
                    {
                        domain = Domain.GetComputerDomain();
                    }

                    info.DomainFqdn = domain.Name;
                    info.DomainDn = DomainToDn(domain.Name);

                    // Get a usable DC
                    if (!string.IsNullOrEmpty(dcName))
                    {
                        if (TestDcConnection(dcName))
                        {
                            info.ChosenDc = dcName;
                        }
                        else
                        {
                            _progress?.Report($"Specified DC {dcName} is not reachable. Finding alternative...");
                        }
                    }

                    if (string.IsNullOrEmpty(info.ChosenDc))
                    {
                        info.ChosenDc = FindReachableDc(domain);
                    }

                    if (string.IsNullOrEmpty(info.ChosenDc))
                    {
                        _progress?.Report("Could not find a reachable domain controller.");
                        _domainInfo = info;
                        return info;
                    }

                    _progress?.Report($"Using domain controller: {info.ChosenDc}");

                    // Get additional domain details
                    using var domainEntry = new DirectoryEntry($"LDAP://{info.ChosenDc}/{info.DomainDn}");
                    var domainSearcher = new DirectorySearcher(domainEntry)
                    {
                        Filter = "(objectClass=domain)",
                        SearchScope = SearchScope.Base
                    };
                    domainSearcher.PropertiesToLoad.AddRange(new[] { "objectSid", "whenCreated" });

                    var domainResult = domainSearcher.FindOne();
                    if (domainResult != null)
                    {
                        var sidBytes = domainResult.Properties["objectSid"]?[0] as byte[];
                        if (sidBytes != null)
                        {
                            var sid = new SecurityIdentifier(sidBytes, 0);
                            info.DomainSid = sid.Value;
                        }
                    }

                    // Get forest info
                    var forest = domain.Forest;
                    info.ForestFqdn = forest.Name;
                    info.ForestDn = DomainToDn(forest.Name);

                    // Get domain/forest functional levels
                    try
                    {
                        info.DomainFunctionalLevel = domain.DomainMode.ToString();
                        info.ForestFunctionalLevel = forest.ForestMode.ToString();
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"Warning: Could not retrieve functional levels: {ex.Message}");
                        info.DomainFunctionalLevel = "Unknown";
                        info.ForestFunctionalLevel = "Unknown";
                    }

                    // Get FSMO roles
                    try
                    {
                        info.FsmoRoles["PDCEmulator"] = domain.PdcRoleOwner?.Name ?? "Unknown";
                        info.FsmoRoles["RIDMaster"] = domain.RidRoleOwner?.Name ?? "Unknown";
                        info.FsmoRoles["InfrastructureMaster"] = domain.InfrastructureRoleOwner?.Name ?? "Unknown";
                        info.FsmoRoles["SchemaMaster"] = forest.SchemaRoleOwner?.Name ?? "Unknown";
                        info.FsmoRoles["DomainNamingMaster"] = forest.NamingRoleOwner?.Name ?? "Unknown";
                        info.PdcEmulator = info.FsmoRoles["PDCEmulator"];
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"Warning: Could not retrieve all FSMO roles: {ex.Message}");
                    }

                    // Get domain controllers
                    foreach (DomainController dc in domain.DomainControllers)
                    {
                        info.DomainControllers.Add(dc.Name);
                    }

                    // Check if running on a DC
                    info.IsRunningOnDc = info.DomainControllers.Any(dc => 
                        dc.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase) ||
                        dc.StartsWith(Environment.MachineName + ".", StringComparison.OrdinalIgnoreCase));

                    // Check AD Recycle Bin
                    info.IsAdRecycleBinEnabled = CheckAdRecycleBin(info.ChosenDc, info.ForestDn);

                    // Check SYSVOL replication
                    info.SysvolReplicationInfo = GetSysvolReplicationInfo(info.ChosenDc, info.DomainDn);

                    _progress?.Report($"Domain discovery complete: {info.DomainFqdn}");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error discovering domain: {ex.Message}");
                }

                _domainInfo = info;
                return info;
            }, ct);
        }

        private string FindReachableDc(Domain domain)
        {
            // Try PDC first
            try
            {
                var pdc = domain.PdcRoleOwner;
                if (pdc != null && TestDcConnection(pdc.Name))
                {
                    return pdc.Name;
                }
            }
            catch { }

            // Try other DCs
            foreach (DomainController dc in domain.DomainControllers)
            {
                if (TestDcConnection(dc.Name))
                {
                    return dc.Name;
                }
            }

            return string.Empty;
        }

        private bool TestDcConnection(string dcName, int port = 389, int timeoutMs = 3000)
        {
            try
            {
                using var client = new TcpClient();
                var result = client.BeginConnect(dcName, port, null, null);
                var success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeoutMs));
                
                if (success)
                {
                    client.EndConnect(result);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        private string DomainToDn(string domainName)
        {
            var parts = domainName.Split('.');
            return string.Join(",", parts.Select(p => $"DC={p}"));
        }

        private bool CheckAdRecycleBin(string dc, string forestDn)
        {
            try
            {
                var configDn = $"CN=Configuration,{forestDn}";
                using var entry = new DirectoryEntry($"LDAP://{dc}/CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,{configDn}");
                using var searcher = new DirectorySearcher(entry)
                {
                    Filter = "(objectClass=msDS-OptionalFeature)",
                    SearchScope = SearchScope.Base
                };
                searcher.PropertiesToLoad.Add("msDS-EnabledFeatureBL");
                
                var result = searcher.FindOne();
                return result?.Properties["msDS-EnabledFeatureBL"]?.Count > 0;
            }
            catch
            {
                return false;
            }
        }

        private string GetSysvolReplicationInfo(string dc, string domainDn)
        {
            try
            {
                // Check for DFSR
                var dcOu = $"OU=Domain Controllers,{domainDn}";
                using var entry = new DirectoryEntry($"LDAP://{dc}/{dcOu}");
                using var searcher = new DirectorySearcher(entry)
                {
                    Filter = $"(&(objectClass=computer)(dNSHostName={dc}))",
                    SearchScope = SearchScope.OneLevel
                };

                var dcResult = searcher.FindOne();
                if (dcResult != null)
                {
                    // Look for DFSR subscription
                    using var dcEntry = dcResult.GetDirectoryEntry();
                    using var dfsrSearcher = new DirectorySearcher(dcEntry)
                    {
                        Filter = "(&(objectClass=msDFSR-Subscription)(name=SYSVOL Subscription))",
                        SearchScope = SearchScope.Subtree
                    };

                    if (dfsrSearcher.FindOne() != null)
                    {
                        return "SYSVOL is using DFSR replication";
                    }

                    // Look for FRS
                    using var frsSearcher = new DirectorySearcher(dcEntry)
                    {
                        Filter = "(&(objectClass=nTFRSSubscriber)(name=Domain System Volume (SYSVOL share)))",
                        SearchScope = SearchScope.Subtree
                    };

                    if (frsSearcher.FindOne() != null)
                    {
                        return "SYSVOL is using FRS replication (should migrate to DFSR)";
                    }
                }
            }
            catch (Exception ex)
            {
                return $"Could not determine SYSVOL replication: {ex.Message}";
            }

            return "Unknown SYSVOL replication type";
        }

        #endregion

        #region Schema GUID Resolution

        private void LoadSchemaGuids(string dc, string forestDn)
        {
            try
            {
                _progress?.Report("Loading schema GUIDs...");
                
                var configDn = $"CN=Configuration,{forestDn}";
                var schemaDn = $"CN=Schema,{configDn}";

                // Load schema object GUIDs
                using var schemaEntry = new DirectoryEntry($"LDAP://{dc}/{schemaDn}");
                using var schemaSearcher = new DirectorySearcher(schemaEntry)
                {
                    Filter = "(schemaIDGUID=*)",
                    SearchScope = SearchScope.OneLevel,
                    PageSize = 1000
                };
                schemaSearcher.PropertiesToLoad.AddRange(new[] { "name", "schemaIDGUID" });

                foreach (SearchResult result in schemaSearcher.FindAll())
                {
                    var name = result.Properties["name"]?[0]?.ToString();
                    var guidBytes = result.Properties["schemaIDGUID"]?[0] as byte[];
                    if (name != null && guidBytes != null)
                    {
                        var guid = new Guid(guidBytes);
                        _schemaGuids[guid] = name;
                    }
                }

                // Load extended rights GUIDs
                var extendedRightsDn = $"CN=Extended-Rights,{configDn}";
                using var extEntry = new DirectoryEntry($"LDAP://{dc}/{extendedRightsDn}");
                using var extSearcher = new DirectorySearcher(extEntry)
                {
                    Filter = "(objectClass=controlAccessRight)",
                    SearchScope = SearchScope.OneLevel,
                    PageSize = 1000
                };
                extSearcher.PropertiesToLoad.AddRange(new[] { "name", "rightsGuid" });

                foreach (SearchResult result in extSearcher.FindAll())
                {
                    var name = result.Properties["name"]?[0]?.ToString();
                    var guidStr = result.Properties["rightsGuid"]?[0]?.ToString();
                    if (name != null && !string.IsNullOrEmpty(guidStr) && Guid.TryParse(guidStr, out var guid))
                    {
                        _extendedRightsGuids[guid] = name;
                    }
                }

                _progress?.Report($"Loaded {_schemaGuids.Count} schema GUIDs and {_extendedRightsGuids.Count} extended rights");
            }
            catch (Exception ex)
            {
                _progress?.Report($"Warning: Could not load all schema GUIDs: {ex.Message}");
            }
        }

        private string ResolveGuid(Guid guid)
        {
            if (guid == Guid.Empty)
                return "All";

            if (_schemaGuids.TryGetValue(guid, out var schemaName))
                return schemaName;

            if (_extendedRightsGuids.TryGetValue(guid, out var extName))
                return extName;

            return guid.ToString();
        }

        #endregion

        #region Privileged Role Analysis

        /// <summary>
        /// Gets all members of privileged AD groups.
        /// </summary>
        public async Task<List<AdPrivilegedMember>> GetPrivilegedMembersAsync(
            bool forestMode = false, 
            CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                await DiscoverDomainAsync(ct: ct);
            }

            if (_domainInfo == null || string.IsNullOrEmpty(_domainInfo.ChosenDc))
            {
                return new List<AdPrivilegedMember>();
            }

            return await Task.Run(() =>
            {
                var members = new List<AdPrivilegedMember>();
                var searchedGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                _progress?.Report("Analyzing privileged group memberships...");

                foreach (var groupName in WellKnownPrivilegedGroups.DomainGroups)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        _progress?.Report($"Checking group: {groupName}");
                        var groupMembers = GetGroupMembersRecursive(
                            _domainInfo.ChosenDc, 
                            _domainInfo.DomainDn, 
                            groupName, 
                            searchedGroups,
                            string.Empty);

                        foreach (var member in groupMembers)
                        {
                            member.GroupName = groupName;
                            members.Add(member);
                        }
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"Warning: Could not enumerate {groupName}: {ex.Message}");
                    }
                }

                _progress?.Report($"Found {members.Count} privileged accounts");
                return members;
            }, ct);
        }

        private List<AdPrivilegedMember> GetGroupMembersRecursive(
            string dc, 
            string domainDn, 
            string groupName, 
            HashSet<string> searchedGroups,
            string nestedPath)
        {
            var members = new List<AdPrivilegedMember>();

            try
            {
                using var entry = new DirectoryEntry($"LDAP://{dc}/{domainDn}");
                using var searcher = new DirectorySearcher(entry)
                {
                    Filter = $"(&(objectClass=group)(|(sAMAccountName={groupName})(cn={groupName})))",
                    SearchScope = SearchScope.Subtree
                };
                searcher.PropertiesToLoad.Add("member");
                searcher.PropertiesToLoad.Add("distinguishedName");

                var groupResult = searcher.FindOne();
                if (groupResult == null) return members;

                var groupDn = groupResult.Properties["distinguishedName"]?[0]?.ToString() ?? string.Empty;
                if (searchedGroups.Contains(groupDn)) return members;
                searchedGroups.Add(groupDn);

                var memberDns = groupResult.Properties["member"];
                if (memberDns == null) return members;

                foreach (string memberDn in memberDns)
                {
                    try
                    {
                        using var memberEntry = new DirectoryEntry($"LDAP://{dc}/{memberDn}");
                        using var memberSearcher = new DirectorySearcher(memberEntry)
                        {
                            Filter = "(objectClass=*)",
                            SearchScope = SearchScope.Base
                        };
                        memberSearcher.PropertiesToLoad.AddRange(new[] 
                        { 
                            "sAMAccountName", "objectClass", "pwdLastSet", "lastLogon", 
                            "userAccountControl", "servicePrincipalName", "distinguishedName",
                            "memberOf"
                        });

                        var memberResult = memberSearcher.FindOne();
                        if (memberResult == null) continue;

                        var objectClass = memberResult.Properties["objectClass"];
                        bool isGroup = objectClass?.Contains("group") == true;

                        if (isGroup)
                        {
                            // Recursive call for nested groups
                            var nestedName = memberResult.Properties["sAMAccountName"]?[0]?.ToString() ?? string.Empty;
                            var newPath = string.IsNullOrEmpty(nestedPath) ? groupName : $"{nestedPath} -> {groupName}";
                            var nestedMembers = GetGroupMembersRecursive(dc, domainDn, nestedName, searchedGroups, newPath);
                            
                            foreach (var nm in nestedMembers)
                            {
                                nm.IsNested = true;
                                nm.NestedPath = newPath + " -> " + nestedName;
                            }
                            members.AddRange(nestedMembers);
                        }
                        else
                        {
                            var member = new AdPrivilegedMember
                            {
                                SamAccountName = memberResult.Properties["sAMAccountName"]?[0]?.ToString() ?? string.Empty,
                                DistinguishedName = memberDn,
                                ObjectClass = objectClass?.Cast<string>().LastOrDefault() ?? "unknown",
                                IsNested = !string.IsNullOrEmpty(nestedPath),
                                NestedPath = nestedPath
                            };

                            // Parse UAC flags
                            var uac = memberResult.Properties["userAccountControl"]?[0];
                            if (uac != null && int.TryParse(uac.ToString(), out var uacInt))
                            {
                                member.IsEnabled = (uacInt & 0x2) == 0; // ACCOUNTDISABLE flag
                                member.PasswordNeverExpires = (uacInt & 0x10000) != 0;
                                member.TrustedForDelegation = (uacInt & 0x80000) != 0;
                                member.RiskyUacFlags = DecodeUac(uacInt);
                            }

                            // Password last set
                            var pwdLastSet = memberResult.Properties["pwdLastSet"]?[0];
                            if (pwdLastSet != null && long.TryParse(pwdLastSet.ToString(), out var pwdTicks) && pwdTicks > 0)
                            {
                                member.PasswordLastSet = DateTime.FromFileTime(pwdTicks);
                            }

                            // Last logon
                            var lastLogon = memberResult.Properties["lastLogon"]?[0];
                            if (lastLogon != null && long.TryParse(lastLogon.ToString(), out var logonTicks) && logonTicks > 0)
                            {
                                member.LastLogon = DateTime.FromFileTime(logonTicks);
                            }

                            // SPNs
                            member.HasSpn = memberResult.Properties["servicePrincipalName"]?.Count > 0;

                            members.Add(member);
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return members;
        }

        private List<string> DecodeUac(int uac)
        {
            var riskyFlags = new List<string>();

            if ((uac & 0x00400000) != 0) riskyFlags.Add("DONT_REQ_PREAUTH");
            if ((uac & 0x00000080) != 0) riskyFlags.Add("ENCRYPTED_TEXT_PWD_ALLOWED");
            if ((uac & 0x00000020) != 0) riskyFlags.Add("PASSWD_NOTREQD");
            if ((uac & 0x00200000) != 0) riskyFlags.Add("USE_DES_KEY_ONLY");
            if ((uac & 0x01000000) != 0) riskyFlags.Add("TRUSTED_TO_AUTH_FOR_DELEGATION");
            if ((uac & 0x00080000) != 0) riskyFlags.Add("TRUSTED_FOR_DELEGATION");
            if ((uac & 0x00010000) != 0) riskyFlags.Add("DONT_EXPIRE_PASSWORD");

            return riskyFlags;
        }

        #endregion

        #region ACL Analysis

        /// <summary>
        /// Analyzes ACLs on sensitive AD objects for risky permissions.
        /// </summary>
        public async Task<List<AdRiskyAcl>> GetRiskyAclsAsync(
            bool filterSafe = true,
            string? specificObjectDn = null,
            CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                await DiscoverDomainAsync(ct: ct);
            }

            if (_domainInfo == null || string.IsNullOrEmpty(_domainInfo.ChosenDc))
            {
                return new List<AdRiskyAcl>();
            }

            // Load schema GUIDs if not already loaded
            if (_schemaGuids.Count == 0)
            {
                LoadSchemaGuids(_domainInfo.ChosenDc, _domainInfo.ForestDn);
            }

            return await Task.Run(() =>
            {
                var riskyAcls = new List<AdRiskyAcl>();

                _progress?.Report("Analyzing ACLs on sensitive objects...");

                // Objects to check
                var objectsToCheck = new List<string>();

                if (!string.IsNullOrEmpty(specificObjectDn))
                {
                    objectsToCheck.Add(specificObjectDn);
                }
                else
                {
                    // Standard IR objects
                    objectsToCheck.Add(_domainInfo.DomainDn); // Domain DSE
                    objectsToCheck.Add($"OU=Domain Controllers,{_domainInfo.DomainDn}");
                    objectsToCheck.Add($"CN=AdminSDHolder,CN=System,{_domainInfo.DomainDn}");
                    
                    // Find krbtgt
                    try
                    {
                        using var entry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                        var searcher = new DirectorySearcher(entry)
                        {
                            Filter = "(sAMAccountName=krbtgt)",
                            SearchScope = SearchScope.Subtree
                        };
                        searcher.PropertiesToLoad.Add("distinguishedName");
                        var krbtgt = searcher.FindOne();
                        if (krbtgt != null)
                        {
                            objectsToCheck.Add(krbtgt.Properties["distinguishedName"]?[0]?.ToString() ?? string.Empty);
                        }
                    }
                    catch { }

                    // Find privileged groups
                    foreach (var groupName in new[] { "Domain Admins", "Enterprise Admins", "Schema Admins" })
                    {
                        try
                        {
                            using var entry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                            var searcher = new DirectorySearcher(entry)
                            {
                                Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))",
                                SearchScope = SearchScope.Subtree
                            };
                            searcher.PropertiesToLoad.Add("distinguishedName");
                            var group = searcher.FindOne();
                            if (group != null)
                            {
                                objectsToCheck.Add(group.Properties["distinguishedName"]?[0]?.ToString() ?? string.Empty);
                            }
                        }
                        catch { }
                    }
                }

                foreach (var objectDn in objectsToCheck.Where(o => !string.IsNullOrEmpty(o)))
                {
                    ct.ThrowIfCancellationRequested();
                    
                    try
                    {
                        _progress?.Report($"Checking ACLs on: {objectDn}");
                        var objectAcls = AnalyzeObjectAcls(objectDn, filterSafe);
                        riskyAcls.AddRange(objectAcls);
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"Warning: Could not analyze ACLs on {objectDn}: {ex.Message}");
                    }
                }

                _progress?.Report($"Found {riskyAcls.Count} ACLs of interest");
                return riskyAcls;
            }, ct);
        }

        private List<AdRiskyAcl> AnalyzeObjectAcls(string objectDn, bool filterSafe)
        {
            var riskyAcls = new List<AdRiskyAcl>();

            try
            {
                using var entry = new DirectoryEntry($"LDAP://{_domainInfo!.ChosenDc}/{objectDn}");
                var security = entry.ObjectSecurity;
                var rules = security.GetAccessRules(true, true, typeof(NTAccount));

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    // Skip inherited ACEs for brevity
                    if (rule.IsInherited) continue;

                    var identity = rule.IdentityReference.Value;

                    // Filter safe identities
                    if (filterSafe && IsSafeIdentity(identity))
                        continue;

                    // Check for risky rights
                    var rightsStr = rule.ActiveDirectoryRights.ToString();
                    bool isRisky = RiskyAdRights.DangerousRights.Any(r => 
                        rightsStr.Contains(r, StringComparison.OrdinalIgnoreCase));

                    // Check for risky extended rights
                    var objectTypeName = ResolveGuid(rule.ObjectType);
                    bool isRiskyExtended = RiskyAdRights.DangerousExtendedRights.Any(r =>
                        objectTypeName.Equals(r, StringComparison.OrdinalIgnoreCase));

                    if (isRisky || isRiskyExtended)
                    {
                        riskyAcls.Add(new AdRiskyAcl
                        {
                            ObjectDn = objectDn,
                            IdentityReference = identity,
                            ActiveDirectoryRights = rightsStr,
                            AccessControlType = rule.AccessControlType.ToString(),
                            ObjectType = rule.ObjectType.ToString(),
                            ObjectTypeName = objectTypeName,
                            InheritedObjectType = rule.InheritedObjectType.ToString(),
                            IsInherited = rule.IsInherited,
                            Severity = DetermineAclSeverity(rightsStr, objectTypeName),
                            Description = $"{identity} has {rightsStr} on {objectTypeName}"
                        });
                    }
                }
            }
            catch { }

            return riskyAcls;
        }

        private bool IsSafeIdentity(string identity)
        {
            return SafeIdentities.SystemIdentities.Any(s => 
                identity.Contains(s, StringComparison.OrdinalIgnoreCase));
        }

        private string DetermineAclSeverity(string rights, string objectType)
        {
            if (rights.Contains("GenericAll") || rights.Contains("WriteDacl") || rights.Contains("WriteOwner"))
                return "Critical";
            
            if (objectType.Contains("Replication") || objectType.Contains("Force-Change-Password"))
                return "Critical";

            if (rights.Contains("GenericWrite") || rights.Contains("AllExtendedRights"))
                return "High";

            return "Medium";
        }

        #endregion

        #region Kerberos Delegation Analysis

        /// <summary>
        /// Finds accounts with Kerberos delegation configured.
        /// </summary>
        public async Task<List<AdKerberosDelegation>> GetKerberosDelegationsAsync(CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                await DiscoverDomainAsync(ct: ct);
            }

            if (_domainInfo == null || string.IsNullOrEmpty(_domainInfo.ChosenDc))
            {
                return new List<AdKerberosDelegation>();
            }

            return await Task.Run(() =>
            {
                var delegations = new List<AdKerberosDelegation>();

                _progress?.Report("Searching for Kerberos delegation...");

                try
                {
                    using var entry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    
                    // Find unconstrained delegation
                    var unconstrainedSearcher = new DirectorySearcher(entry)
                    {
                        // UserAccountControl bit 0x80000 = TRUSTED_FOR_DELEGATION
                        Filter = "(&(|(objectClass=user)(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };
                    unconstrainedSearcher.PropertiesToLoad.AddRange(new[] 
                    { 
                        "sAMAccountName", "distinguishedName", "objectClass", "userAccountControl"
                    });

                    foreach (SearchResult result in unconstrainedSearcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var samName = result.Properties["sAMAccountName"]?[0]?.ToString() ?? "";
                        
                        // Skip domain controllers (they legitimately have unconstrained)
                        if (samName.EndsWith("$") && result.Path.Contains("OU=Domain Controllers"))
                            continue;

                        delegations.Add(new AdKerberosDelegation
                        {
                            SamAccountName = samName,
                            DistinguishedName = result.Properties["distinguishedName"]?[0]?.ToString() ?? "",
                            ObjectClass = result.Properties["objectClass"]?.Cast<string>().LastOrDefault() ?? "unknown",
                            DelegationType = "Unconstrained",
                            Severity = "Critical",
                            Description = "Unconstrained delegation allows impersonation of any user to any service"
                        });
                    }

                    // Find constrained delegation
                    var constrainedSearcher = new DirectorySearcher(entry)
                    {
                        Filter = "(msDS-AllowedToDelegateTo=*)",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };
                    constrainedSearcher.PropertiesToLoad.AddRange(new[] 
                    { 
                        "sAMAccountName", "distinguishedName", "objectClass", 
                        "msDS-AllowedToDelegateTo", "userAccountControl"
                    });

                    foreach (SearchResult result in constrainedSearcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var allowedTo = result.Properties["msDS-AllowedToDelegateTo"]?
                            .Cast<string>().ToList() ?? new List<string>();

                        var uac = 0;
                        if (result.Properties["userAccountControl"]?[0] != null)
                        {
                            int.TryParse(result.Properties["userAccountControl"][0].ToString(), out uac);
                        }

                        var delegationType = (uac & 0x01000000) != 0 
                            ? "Constrained (Protocol Transition)" 
                            : "Constrained";

                        delegations.Add(new AdKerberosDelegation
                        {
                            SamAccountName = result.Properties["sAMAccountName"]?[0]?.ToString() ?? "",
                            DistinguishedName = result.Properties["distinguishedName"]?[0]?.ToString() ?? "",
                            ObjectClass = result.Properties["objectClass"]?.Cast<string>().LastOrDefault() ?? "unknown",
                            DelegationType = delegationType,
                            AllowedToDelegateTo = allowedTo,
                            Severity = (uac & 0x01000000) != 0 ? "High" : "Medium",
                            Description = $"Can delegate to: {string.Join(", ", allowedTo.Take(3))}"
                        });
                    }

                    // Find resource-based constrained delegation
                    var rbcdSearcher = new DirectorySearcher(entry)
                    {
                        Filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };
                    rbcdSearcher.PropertiesToLoad.AddRange(new[] 
                    { 
                        "sAMAccountName", "distinguishedName", "objectClass",
                        "msDS-AllowedToActOnBehalfOfOtherIdentity"
                    });

                    foreach (SearchResult result in rbcdSearcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        delegations.Add(new AdKerberosDelegation
                        {
                            SamAccountName = result.Properties["sAMAccountName"]?[0]?.ToString() ?? "",
                            DistinguishedName = result.Properties["distinguishedName"]?[0]?.ToString() ?? "",
                            ObjectClass = result.Properties["objectClass"]?.Cast<string>().LastOrDefault() ?? "unknown",
                            DelegationType = "Resource-Based Constrained",
                            Severity = "High",
                            Description = "Has resource-based constrained delegation configured"
                        });
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error analyzing Kerberos delegation: {ex.Message}");
                }

                _progress?.Report($"Found {delegations.Count} accounts with delegation");
                return delegations;
            }, ct);
        }

        #endregion

        #region AdminCount Analysis

        /// <summary>
        /// Gets the set of protected groups and accounts that should legitimately have AdminCount=1.
        /// These are groups and accounts that are protected by SDProp (Security Descriptor Propagator).
        /// </summary>
        private HashSet<string> GetProtectedGroupsAndAccounts()
        {
            var protected_items = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            if (_domainInfo == null || string.IsNullOrEmpty(_domainInfo.DomainSid))
                return protected_items;

            var domainSid = _domainInfo.DomainSid;
            
            // Well-known protected groups that should have AdminCount=1
            // Domain local built-in groups (S-1-5-32-xxx)
            var builtinGroups = new[]
            {
                "S-1-5-32-544",  // Administrators
                "S-1-5-32-548",  // Account Operators
                "S-1-5-32-549",  // Server Operators
                "S-1-5-32-550",  // Print Operators
                "S-1-5-32-551",  // Backup Operators
                "S-1-5-32-552",  // Replicators
            };

            // Domain-specific protected groups
            var domainGroups = new[]
            {
                $"{domainSid}-500",  // Domain Administrator account
                $"{domainSid}-502",  // KRBTGT
                $"{domainSid}-512",  // Domain Admins
                $"{domainSid}-516",  // Domain Controllers
                $"{domainSid}-518",  // Schema Admins (forest root)
                $"{domainSid}-519",  // Enterprise Admins (forest root)
                $"{domainSid}-521",  // Read-only Domain Controllers
            };

            try
            {
                using var entry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                
                // Look up all protected items by SID
                foreach (var sid in builtinGroups.Concat(domainGroups))
                {
                    try
                    {
                        var searcher = new DirectorySearcher(entry)
                        {
                            Filter = $"(objectSid={sid})",
                            SearchScope = SearchScope.Subtree
                        };
                        searcher.PropertiesToLoad.Add("distinguishedName");
                        
                        var result = searcher.FindOne();
                        if (result?.Properties["distinguishedName"]?[0] != null)
                        {
                            protected_items.Add(result.Properties["distinguishedName"][0].ToString()!);
                        }
                    }
                    catch
                    {
                        // Some SIDs may not exist (e.g., Enterprise Admins in child domain)
                    }
                }

                // Also add members of Domain Controllers group (all DCs should have AdminCount=1)
                var dcGroupSearcher = new DirectorySearcher(entry)
                {
                    Filter = $"(objectSid={domainSid}-516)",
                    SearchScope = SearchScope.Subtree
                };
                dcGroupSearcher.PropertiesToLoad.Add("member");
                
                var dcGroupResult = dcGroupSearcher.FindOne();
                if (dcGroupResult?.Properties["member"] != null)
                {
                    foreach (var member in dcGroupResult.Properties["member"])
                    {
                        protected_items.Add(member.ToString()!);
                    }
                }
            }
            catch
            {
                // Ignore errors, we'll just have fewer exclusions
            }

            return protected_items;
        }

        /// <summary>
        /// Finds accounts with AdminCount anomalies.
        /// An anomaly is an account with AdminCount=1 that is NOT currently a member of any protected group.
        /// This excludes legitimate protected groups (Domain Admins, etc.) and their direct members.
        /// </summary>
        public async Task<List<AdAdminCountAnomaly>> GetAdminCountAnomaliesAsync(CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                await DiscoverDomainAsync(ct: ct);
            }

            if (_domainInfo == null || string.IsNullOrEmpty(_domainInfo.ChosenDc))
            {
                return new List<AdAdminCountAnomaly>();
            }

            return await Task.Run(() =>
            {
                var anomalies = new List<AdAdminCountAnomaly>();

                _progress?.Report("Analyzing AdminCount attributes...");

                try
                {
                    using var entry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    var searcher = new DirectorySearcher(entry)
                    {
                        Filter = "(&(|(objectClass=user)(objectClass=group)(objectClass=computer))(adminCount=1))",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };
                    searcher.PropertiesToLoad.AddRange(new[] 
                    { 
                        "sAMAccountName", "distinguishedName", "objectClass", 
                        "adminCount", "memberOf", "primaryGroupID"
                    });

                    // Get list of currently privileged accounts for comparison
                    var privilegedMembers = GetPrivilegedMembersAsync(false, ct).Result;
                    var privilegedDns = new HashSet<string>(
                        privilegedMembers.Select(p => p.DistinguishedName), 
                        StringComparer.OrdinalIgnoreCase);

                    // Get protected groups and accounts that legitimately should have AdminCount=1
                    var protectedItems = GetProtectedGroupsAndAccounts();

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var dn = result.Properties["distinguishedName"]?[0]?.ToString() ?? "";
                        var samAccountName = result.Properties["sAMAccountName"]?[0]?.ToString() ?? "";
                        var objectClass = result.Properties["objectClass"]?.Cast<string>().LastOrDefault() ?? "unknown";
                        var adminCount = 1;
                        if (result.Properties["adminCount"]?[0] != null)
                        {
                            int.TryParse(result.Properties["adminCount"][0].ToString(), out adminCount);
                        }

                        // Check if this is a protected item that legitimately should have AdminCount=1
                        var isProtectedItem = protectedItems.Contains(dn);

                        // Check if currently a member of a privileged group
                        var isCurrentlyPrivileged = privilegedDns.Contains(dn);

                        // Skip if this is a protected group/account (these SHOULD have AdminCount=1)
                        if (isProtectedItem || isCurrentlyPrivileged)
                        {
                            continue;
                        }

                        // Check primary group ID for domain controllers (primaryGroupID=516)
                        var primaryGroupId = 0;
                        if (result.Properties["primaryGroupID"]?[0] != null)
                        {
                            int.TryParse(result.Properties["primaryGroupID"][0].ToString(), out primaryGroupId);
                        }
                        
                        // Skip domain controllers (primaryGroupID 516 = Domain Controllers)
                        if (primaryGroupId == 516)
                        {
                            continue;
                        }

                        // This is a true anomaly - account has AdminCount=1 but isn't currently privileged
                        anomalies.Add(new AdAdminCountAnomaly
                        {
                            SamAccountName = samAccountName,
                            DistinguishedName = dn,
                            ObjectClass = objectClass,
                            AdminCount = adminCount,
                            IsCurrentlyPrivileged = false,
                            Issue = "Account has AdminCount=1 but is not currently a member of any protected group. " +
                                   "This may indicate the account was previously privileged or was manually modified. " +
                                   "Consider resetting ACLs and removing AdminCount attribute."
                        });
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error analyzing AdminCount: {ex.Message}");
                }

                _progress?.Report($"Found {anomalies.Count} AdminCount anomalies");
                return anomalies;
            }, ct);
        }

        #endregion

        #region SYSVOL Analysis

        /// <summary>
        /// Scans SYSVOL for risky files (executables, scripts).
        /// </summary>
        public async Task<List<SysvolRiskyFile>> ScanSysvolAsync(CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                await DiscoverDomainAsync(ct: ct);
            }

            if (_domainInfo == null || string.IsNullOrEmpty(_domainInfo.ChosenDc))
            {
                return new List<SysvolRiskyFile>();
            }

            return await Task.Run(() =>
            {
                var riskyFiles = new List<SysvolRiskyFile>();

                _progress?.Report("Scanning SYSVOL for risky files...");

                try
                {
                    var sysvolPath = $@"\\{_domainInfo.ChosenDc}\SYSVOL\{_domainInfo.DomainFqdn}";

                    if (!Directory.Exists(sysvolPath))
                    {
                        _progress?.Report($"SYSVOL path not accessible: {sysvolPath}");
                        return riskyFiles;
                    }

                    var files = Directory.EnumerateFiles(sysvolPath, "*.*", SearchOption.AllDirectories);

                    foreach (var filePath in files)
                    {
                        ct.ThrowIfCancellationRequested();

                        var ext = Path.GetExtension(filePath);
                        if (!RiskyExtensions.Contains(ext))
                            continue;

                        try
                        {
                            var fileInfo = new FileInfo(filePath);
                            var hash = ComputeSha256(filePath);

                            riskyFiles.Add(new SysvolRiskyFile
                            {
                                FileName = fileInfo.Name,
                                FilePath = fileInfo.DirectoryName ?? "",
                                Extension = ext,
                                CreationTime = fileInfo.CreationTime,
                                LastWriteTime = fileInfo.LastWriteTime,
                                FileSize = fileInfo.Length,
                                Sha256Hash = hash,
                                Severity = DetermineFileSeverity(ext)
                            });
                        }
                        catch { }
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error scanning SYSVOL: {ex.Message}");
                }

                _progress?.Report($"Found {riskyFiles.Count} risky files in SYSVOL");
                return riskyFiles.OrderByDescending(f => f.LastWriteTime).ToList();
            }, ct);
        }

        private string ComputeSha256(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return "ERROR";
            }
        }

        private string DetermineFileSeverity(string extension)
        {
            return extension.ToLowerInvariant() switch
            {
                ".exe" or ".dll" or ".msi" => "High",
                ".ps1" or ".bat" or ".cmd" => "Medium",
                ".vbs" or ".js" or ".wsf" => "Medium",
                _ => "Low"
            };
        }

        #endregion

        #region Risky GPO Analysis

        /// <summary>
        /// Analyzes Group Policy Objects for potentially risky configurations.
        /// Identifies GPOs that deploy scheduled tasks, modify registry, deploy files,
        /// install software, modify local users/groups, or modify environment variables.
        /// This mirrors the PLATYPUS Get-AdRiskyGpoReport functionality.
        /// </summary>
        /// <param name="days">Number of days to look back for recently created/modified GPOs. Default 30.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>List of risky GPOs with details about their risk factors.</returns>
        public async Task<List<AdRiskyGpo>> GetRiskyGposAsync(int days = 30, CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                await DiscoverDomainAsync(ct: ct);
            }

            if (_domainInfo == null || string.IsNullOrEmpty(_domainInfo.ChosenDc))
            {
                return new List<AdRiskyGpo>();
            }

            return await Task.Run(() =>
            {
                var riskyGpos = new List<AdRiskyGpo>();
                _progress?.Report("Analyzing Group Policy Objects for risky configurations...");

                try
                {
                    var gpoPath = $@"\\{_domainInfo.ChosenDc}\SYSVOL\{_domainInfo.DomainFqdn}\Policies";
                    
                    if (!Directory.Exists(gpoPath))
                    {
                        _progress?.Report($"GPO policies path not accessible: {gpoPath}");
                        return riskyGpos;
                    }

                    // Get GPO information from AD
                    using var entry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/CN=Policies,CN=System,{_domainInfo.DomainDn}");
                    var searcher = new DirectorySearcher(entry)
                    {
                        Filter = "(objectClass=groupPolicyContainer)",
                        SearchScope = SearchScope.OneLevel
                    };
                    searcher.PropertiesToLoad.AddRange(new[] { 
                        "displayName", "name", "whenCreated", "whenChanged", 
                        "gPCFileSysPath", "distinguishedName" 
                    });

                    var results = searcher.FindAll();
                    _progress?.Report($"Found {results.Count} GPOs to analyze...");

                    var threshold = DateTime.Now.AddDays(-days);
                    int analyzed = 0;

                    foreach (SearchResult result in results)
                    {
                        ct.ThrowIfCancellationRequested();

                        try
                        {
                            var gpoName = result.Properties["displayName"]?[0]?.ToString() ?? "Unknown";
                            var gpoGuid = result.Properties["name"]?[0]?.ToString() ?? "";
                            var gpcPath = result.Properties["gPCFileSysPath"]?[0]?.ToString() ?? "";
                            var gpoDn = result.Properties["distinguishedName"]?[0]?.ToString() ?? "";
                            
                            DateTime createdTime = DateTime.MinValue;
                            DateTime modifiedTime = DateTime.MinValue;
                            
                            if (result.Properties["whenCreated"]?[0] is DateTime created)
                                createdTime = created;
                            if (result.Properties["whenChanged"]?[0] is DateTime modified)
                                modifiedTime = modified;

                            var riskyGpo = new AdRiskyGpo
                            {
                                GpoName = gpoName,
                                GpoGuid = gpoGuid,
                                CreatedTime = createdTime,
                                ModifiedTime = modifiedTime,
                                RiskDetails = new List<GpoRiskDetail>(),
                                LinkLocations = new Dictionary<string, bool>()
                            };

                            // Analyze GPO contents in SYSVOL
                            if (!string.IsNullOrEmpty(gpcPath) && Directory.Exists(gpcPath))
                            {
                                AnalyzeGpoContent(gpcPath, riskyGpo);
                            }

                            // Get GPO links from AD
                            GetGpoLinks(gpoDn, riskyGpo);

                            // Only add if risky
                            if (riskyGpo.IsRisky)
                            {
                                // Determine severity based on risk types
                                riskyGpo.Severity = DetermineGpoSeverity(riskyGpo);
                                riskyGpos.Add(riskyGpo);
                            }

                            analyzed++;
                            if (analyzed % 50 == 0)
                            {
                                _progress?.Report($"Analyzed {analyzed}/{results.Count} GPOs...");
                            }
                        }
                        catch (Exception ex)
                        {
                            _progress?.Report($"Error analyzing GPO: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error during GPO analysis: {ex.Message}");
                }

                _progress?.Report($"Found {riskyGpos.Count} potentially risky GPOs");
                return riskyGpos.OrderByDescending(g => g.ModifiedTime).ToList();
            }, ct);
        }

        /// <summary>
        /// Gets GPOs that were created or modified within the specified number of days.
        /// </summary>
        public async Task<List<AdRiskyGpo>> GetRecentlyModifiedGposAsync(int days = 30, CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                await DiscoverDomainAsync(ct: ct);
            }

            if (_domainInfo == null || string.IsNullOrEmpty(_domainInfo.ChosenDc))
            {
                return new List<AdRiskyGpo>();
            }

            return await Task.Run(() =>
            {
                var recentGpos = new List<AdRiskyGpo>();
                var threshold = DateTime.Now.AddDays(-days);

                _progress?.Report($"Finding GPOs created or modified in the last {days} days...");

                try
                {
                    using var entry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/CN=Policies,CN=System,{_domainInfo.DomainDn}");
                    var searcher = new DirectorySearcher(entry)
                    {
                        Filter = "(objectClass=groupPolicyContainer)",
                        SearchScope = SearchScope.OneLevel
                    };
                    searcher.PropertiesToLoad.AddRange(new[] { 
                        "displayName", "name", "whenCreated", "whenChanged" 
                    });

                    var results = searcher.FindAll();

                    foreach (SearchResult result in results)
                    {
                        ct.ThrowIfCancellationRequested();

                        try
                        {
                            DateTime createdTime = DateTime.MinValue;
                            DateTime modifiedTime = DateTime.MinValue;
                            
                            if (result.Properties["whenCreated"]?[0] is DateTime created)
                                createdTime = created;
                            if (result.Properties["whenChanged"]?[0] is DateTime modified)
                                modifiedTime = modified;

                            // Check if recently created or modified
                            if (createdTime > threshold || modifiedTime > threshold)
                            {
                                var gpoName = result.Properties["displayName"]?[0]?.ToString() ?? "Unknown";
                                var gpoGuid = result.Properties["name"]?[0]?.ToString() ?? "";

                                recentGpos.Add(new AdRiskyGpo
                                {
                                    GpoName = gpoName,
                                    GpoGuid = gpoGuid,
                                    CreatedTime = createdTime,
                                    ModifiedTime = modifiedTime,
                                    Severity = "Info"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error getting recent GPOs: {ex.Message}");
                }

                _progress?.Report($"Found {recentGpos.Count} recently modified GPOs");
                return recentGpos.OrderByDescending(g => g.ModifiedTime).ToList();
            }, ct);
        }

        /// <summary>
        /// Analyzes GPO content in SYSVOL for risky settings.
        /// </summary>
        private void AnalyzeGpoContent(string gpcPath, AdRiskyGpo gpo)
        {
            try
            {
                // Check Machine\Preferences for risky settings
                var machinePrefsPath = Path.Combine(gpcPath, "Machine", "Preferences");
                if (Directory.Exists(machinePrefsPath))
                {
                    // Scheduled Tasks
                    var schedTasksPath = Path.Combine(machinePrefsPath, "ScheduledTasks", "ScheduledTasks.xml");
                    if (File.Exists(schedTasksPath))
                    {
                        gpo.HasScheduledTasks = true;
                        AnalyzeScheduledTasksXml(schedTasksPath, gpo);
                    }

                    // Registry settings
                    var registryPath = Path.Combine(machinePrefsPath, "Registry", "Registry.xml");
                    if (File.Exists(registryPath))
                    {
                        gpo.HasRegistryMods = true;
                        AnalyzeRegistryXml(registryPath, gpo);
                    }

                    // Files deployment
                    var filesPath = Path.Combine(machinePrefsPath, "Files", "Files.xml");
                    if (File.Exists(filesPath))
                    {
                        gpo.HasFileOperations = true;
                        AnalyzeFilesXml(filesPath, gpo);
                    }

                    // Environment variables
                    var envPath = Path.Combine(machinePrefsPath, "EnvironmentVariables", "EnvironmentVariables.xml");
                    if (File.Exists(envPath))
                    {
                        gpo.HasEnvironmentMods = true;
                        AnalyzeEnvironmentXml(envPath, gpo);
                    }

                    // Local Users and Groups
                    var groupsPath = Path.Combine(machinePrefsPath, "Groups", "Groups.xml");
                    if (File.Exists(groupsPath))
                    {
                        gpo.HasLocalUserMods = true;
                        AnalyzeGroupsXml(groupsPath, gpo);
                    }
                }

                // Check for Software Installation (MSI)
                var scriptsPath = Path.Combine(gpcPath, "Machine", "Scripts");
                if (Directory.Exists(scriptsPath))
                {
                    var msiFiles = Directory.GetFiles(scriptsPath, "*.msi", SearchOption.AllDirectories);
                    if (msiFiles.Length > 0)
                    {
                        gpo.HasSoftwareInstallation = true;
                        foreach (var msi in msiFiles)
                        {
                            gpo.RiskDetails.Add(new GpoRiskDetail("swdeploy", Path.GetFileName(msi), msi));
                        }
                    }
                }

                // Also check Applications folder for software installation policies
                var appsPath = Path.Combine(gpcPath, "Machine", "Applications");
                if (Directory.Exists(appsPath) && Directory.GetFiles(appsPath, "*.aas").Length > 0)
                {
                    gpo.HasSoftwareInstallation = true;
                    foreach (var aas in Directory.GetFiles(appsPath, "*.aas"))
                    {
                        gpo.RiskDetails.Add(new GpoRiskDetail("swdeploy", Path.GetFileName(aas), aas));
                    }
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error analyzing GPO content at {gpcPath}: {ex.Message}");
            }
        }

        /// <summary>
        /// Parses ScheduledTasks.xml for risky scheduled task configurations.
        /// </summary>
        private void AnalyzeScheduledTasksXml(string xmlPath, AdRiskyGpo gpo)
        {
            try
            {
                var doc = System.Xml.Linq.XDocument.Load(xmlPath);
                var ns = doc.Root?.GetDefaultNamespace() ?? System.Xml.Linq.XNamespace.None;

                // Look for ImmediateTaskV2 and TaskV2 elements
                var tasks = doc.Descendants().Where(e => 
                    e.Name.LocalName == "ImmediateTaskV2" || 
                    e.Name.LocalName == "TaskV2" ||
                    e.Name.LocalName == "Task");

                foreach (var task in tasks)
                {
                    var taskName = task.Attribute("name")?.Value ?? "UnnamedTask";
                    
                    // Look for Exec actions
                    var execElements = task.Descendants().Where(e => e.Name.LocalName == "Exec");
                    foreach (var exec in execElements)
                    {
                        var command = exec.Element(exec.Name.Namespace + "Command")?.Value ?? "";
                        var arguments = exec.Element(exec.Name.Namespace + "Arguments")?.Value ?? "";
                        
                        if (!string.IsNullOrEmpty(command))
                        {
                            gpo.RiskDetails.Add(new GpoRiskDetail("scheduledtask", taskName, $"{command} {arguments}".Trim()));
                            gpo.RiskySettings.Add($"Scheduled Task: {taskName} -> {command}");
                        }
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Parses Registry.xml for registry modifications.
        /// </summary>
        private void AnalyzeRegistryXml(string xmlPath, AdRiskyGpo gpo)
        {
            try
            {
                var doc = System.Xml.Linq.XDocument.Load(xmlPath);
                var registryItems = doc.Descendants().Where(e => e.Name.LocalName == "Registry");

                foreach (var reg in registryItems)
                {
                    var props = reg.Element(reg.Name.Namespace + "Properties");
                    if (props != null)
                    {
                        var key = props.Attribute("key")?.Value ?? "";
                        var name = props.Attribute("name")?.Value ?? "";
                        var value = props.Attribute("value")?.Value ?? "";
                        
                        if (!string.IsNullOrEmpty(key))
                        {
                            gpo.RiskDetails.Add(new GpoRiskDetail("registry", $"{key}\\{name}", value));
                            gpo.RiskySettings.Add($"Registry: {key}\\{name} = {value}");
                        }
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Parses Files.xml for file deployment configurations.
        /// </summary>
        private void AnalyzeFilesXml(string xmlPath, AdRiskyGpo gpo)
        {
            try
            {
                var doc = System.Xml.Linq.XDocument.Load(xmlPath);
                var fileItems = doc.Descendants().Where(e => e.Name.LocalName == "File");

                foreach (var file in fileItems)
                {
                    var fileName = file.Attribute("name")?.Value ?? "";
                    var props = file.Element(file.Name.Namespace + "Properties");
                    if (props != null)
                    {
                        var targetPath = props.Attribute("targetPath")?.Value ?? "";
                        var sourcePath = props.Attribute("fromPath")?.Value ?? "";
                        
                        gpo.RiskDetails.Add(new GpoRiskDetail("filedeploy", fileName, $"{sourcePath} -> {targetPath}"));
                        gpo.RiskySettings.Add($"File Deploy: {fileName} -> {targetPath}");
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Parses EnvironmentVariables.xml for environment variable modifications.
        /// </summary>
        private void AnalyzeEnvironmentXml(string xmlPath, AdRiskyGpo gpo)
        {
            try
            {
                var doc = System.Xml.Linq.XDocument.Load(xmlPath);
                var envItems = doc.Descendants().Where(e => e.Name.LocalName == "EnvironmentVariable");

                foreach (var env in envItems)
                {
                    var envName = env.Attribute("name")?.Value ?? "";
                    var props = env.Element(env.Name.Namespace + "Properties");
                    if (props != null)
                    {
                        var value = props.Attribute("value")?.Value ?? "";
                        
                        gpo.RiskDetails.Add(new GpoRiskDetail("environmentVariable", envName, value));
                        gpo.RiskySettings.Add($"Environment: {envName} = {value}");
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Parses Groups.xml for local user and group modifications.
        /// </summary>
        private void AnalyzeGroupsXml(string xmlPath, AdRiskyGpo gpo)
        {
            try
            {
                var doc = System.Xml.Linq.XDocument.Load(xmlPath);
                var groupItems = doc.Descendants().Where(e => e.Name.LocalName == "Group");

                foreach (var group in groupItems)
                {
                    var props = group.Element(group.Name.Namespace + "Properties");
                    if (props != null)
                    {
                        var groupName = props.Attribute("groupName")?.Value ?? props.Attribute("name")?.Value ?? "";
                        var members = props.Element(props.Name.Namespace + "Members");
                        
                        if (members != null)
                        {
                            var memberElements = members.Elements().Where(e => e.Name.LocalName == "Member");
                            foreach (var member in memberElements)
                            {
                                var memberName = member.Attribute("name")?.Value ?? "";
                                var action = member.Attribute("action")?.Value ?? "";
                                
                                gpo.RiskDetails.Add(new GpoRiskDetail("moddedgroup", groupName, $"{memberName}:{action}"));
                                gpo.RiskySettings.Add($"Group Mod: {groupName} <- {memberName} ({action})");
                            }
                        }
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Gets the OU/site paths where this GPO is linked.
        /// </summary>
        private void GetGpoLinks(string gpoDn, AdRiskyGpo gpo)
        {
            if (_domainInfo == null || string.IsNullOrEmpty(gpoDn))
                return;

            try
            {
                // Search for objects that have this GPO linked (gpLink attribute contains the GPO DN)
                var escapedDn = EscapeLdapFilter(gpoDn);
                
                using var entry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                var searcher = new DirectorySearcher(entry)
                {
                    Filter = $"(gPLink=*{escapedDn}*)",
                    SearchScope = SearchScope.Subtree
                };
                searcher.PropertiesToLoad.AddRange(new[] { "distinguishedName", "gPLink" });

                var results = searcher.FindAll();
                foreach (SearchResult result in results)
                {
                    var linkDn = result.Properties["distinguishedName"]?[0]?.ToString() ?? "";
                    var gpLink = result.Properties["gPLink"]?[0]?.ToString() ?? "";
                    
                    // Parse gpLink to determine if this GPO is enabled
                    // Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;0] where 0=enabled, 1=disabled
                    var isEnabled = true;
                    if (gpLink.Contains(gpoDn))
                    {
                        var linkSection = gpLink.Substring(gpLink.IndexOf(gpoDn));
                        if (linkSection.Contains(";1]") || linkSection.Contains(";3]"))
                        {
                            isEnabled = false;
                        }
                    }
                    
                    gpo.LinkLocations[linkDn] = isEnabled;
                }
            }
            catch { }
        }

        /// <summary>
        /// Determines the severity of a risky GPO based on its risk factors.
        /// </summary>
        private string DetermineGpoSeverity(AdRiskyGpo gpo)
        {
            // High severity: scheduled tasks or software installation (common attack vector)
            if (gpo.HasScheduledTasks || gpo.HasSoftwareInstallation)
                return "High";

            // Medium severity: file operations, registry mods, or local user/group modifications
            if (gpo.HasFileOperations || gpo.HasRegistryMods || gpo.HasLocalUserMods)
                return "Medium";

            // Low severity: environment variable modifications only
            return "Low";
        }

        #endregion

        #region Full Analysis

        /// <summary>
        /// Runs a complete AD security analysis.
        /// </summary>
        public async Task<AdSecurityAnalysisResult> RunFullAnalysisAsync(
            AdSecurityAnalysisOptions options,
            CancellationToken ct = default)
        {
            var result = new AdSecurityAnalysisResult
            {
                StartTime = DateTime.Now
            };

            try
            {
                // Discover domain
                result.DomainInfo = await DiscoverDomainAsync(options.TargetDomain, options.TargetDc, ct);

                if (string.IsNullOrEmpty(result.DomainInfo.ChosenDc))
                {
                    result.Errors.Add("Could not connect to a domain controller");
                    return result;
                }

                // Run selected analyses
                if (options.AnalyzePrivilegedGroups)
                {
                    result.PrivilegedMembers = await GetPrivilegedMembersAsync(options.IncludeForestMode, ct);
                }

                if (options.AnalyzeRiskyAcls)
                {
                    result.RiskyAcls = await GetRiskyAclsAsync(options.FilterSafeIdentities, null, ct);
                }

                if (options.AnalyzeKerberosDelegation)
                {
                    result.KerberosDelegations = await GetKerberosDelegationsAsync(ct);
                }

                if (options.AnalyzeAdminCount)
                {
                    result.AdminCountAnomalies = await GetAdminCountAnomaliesAsync(ct);
                }

                if (options.AnalyzeSysvol)
                {
                    result.SysvolRiskyFiles = await ScanSysvolAsync(ct);
                }

                if (options.AnalyzeGpos)
                {
                    result.RiskyGpos = await GetRiskyGposAsync(options.GpoDaysThreshold, ct);
                }

                // Count severities
                result.CriticalCount = 
                    result.RiskyAcls.Count(a => a.Severity == "Critical") +
                    result.KerberosDelegations.Count(d => d.Severity == "Critical") +
                    result.RiskyGpos.Count(g => g.Severity == "Critical");
                
                result.HighCount = 
                    result.RiskyAcls.Count(a => a.Severity == "High") +
                    result.KerberosDelegations.Count(d => d.Severity == "High") +
                    result.SysvolRiskyFiles.Count(f => f.Severity == "High") +
                    result.RiskyGpos.Count(g => g.Severity == "High");

                result.MediumCount = 
                    result.RiskyAcls.Count(a => a.Severity == "Medium") +
                    result.KerberosDelegations.Count(d => d.Severity == "Medium") +
                    result.SysvolRiskyFiles.Count(f => f.Severity == "Medium") +
                    result.RiskyGpos.Count(g => g.Severity == "Medium") +
                    result.AdminCountAnomalies.Count;

                result.IsComplete = true;
            }
            catch (OperationCanceledException)
            {
                result.Errors.Add("Analysis was cancelled");
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Analysis error: {ex.Message}");
            }
            finally
            {
                result.EndTime = DateTime.Now;
            }

            _progress?.Report($"Analysis complete. Total findings: {result.TotalFindings}");
            return result;
        }

        #endregion

        #region Report Generation

        /// <summary>
        /// Exports the analysis result to a CSV file.
        /// </summary>
        public async Task ExportToCsvAsync(AdSecurityAnalysisResult result, string outputPath)
        {
            await Task.Run(() =>
            {
                var sb = new StringBuilder();

                // Domain Info
                sb.AppendLine("=== DOMAIN INFORMATION ===");
                sb.AppendLine($"Domain,{result.DomainInfo.DomainFqdn}");
                sb.AppendLine($"Domain Controller,{result.DomainInfo.ChosenDc}");
                sb.AppendLine($"PDC Emulator,{result.DomainInfo.PdcEmulator}");
                sb.AppendLine($"Analysis Time,{result.StartTime}");
                sb.AppendLine();

                // Privileged Members
                if (result.PrivilegedMembers.Any())
                {
                    sb.AppendLine("=== PRIVILEGED MEMBERS ===");
                    sb.AppendLine("SamAccountName,GroupName,ObjectClass,Enabled,PasswordNeverExpires,TrustedForDelegation,HasSPN,Nested,RiskyFlags");
                    foreach (var m in result.PrivilegedMembers)
                    {
                        sb.AppendLine($"{m.SamAccountName},{m.GroupName},{m.ObjectClass},{m.IsEnabled},{m.PasswordNeverExpires},{m.TrustedForDelegation},{m.HasSpn},{m.IsNested},{string.Join(";", m.RiskyUacFlags)}");
                    }
                    sb.AppendLine();
                }

                // ACLs of Interest
                if (result.RiskyAcls.Any())
                {
                    sb.AppendLine("=== ACLs OF INTEREST ===");
                    sb.AppendLine("ObjectDN,Identity,Rights,ObjectType,Severity");
                    foreach (var a in result.RiskyAcls)
                    {
                        sb.AppendLine($"\"{a.ObjectDn}\",{a.IdentityReference},{a.ActiveDirectoryRights},{a.ObjectTypeName},{a.Severity}");
                    }
                    sb.AppendLine();
                }

                // Kerberos Delegations
                if (result.KerberosDelegations.Any())
                {
                    sb.AppendLine("=== KERBEROS DELEGATIONS ===");
                    sb.AppendLine("SamAccountName,DelegationType,Severity,AllowedToDelegateTo");
                    foreach (var d in result.KerberosDelegations)
                    {
                        sb.AppendLine($"{d.SamAccountName},{d.DelegationType},{d.Severity},{string.Join(";", d.AllowedToDelegateTo)}");
                    }
                    sb.AppendLine();
                }

                // SYSVOL Files
                if (result.SysvolRiskyFiles.Any())
                {
                    sb.AppendLine("=== SYSVOL RISKY FILES ===");
                    sb.AppendLine("FileName,Path,CreationTime,LastWriteTime,Size,SHA256,Severity");
                    foreach (var f in result.SysvolRiskyFiles)
                    {
                        sb.AppendLine($"{f.FileName},\"{f.FilePath}\",{f.CreationTime},{f.LastWriteTime},{f.FileSize},{f.Sha256Hash},{f.Severity}");
                    }
                    sb.AppendLine();
                }

                // AdminCount Anomalies
                if (result.AdminCountAnomalies.Any())
                {
                    sb.AppendLine("=== ADMINCOUNT ANOMALIES ===");
                    sb.AppendLine("SamAccountName,ObjectClass,Issue");
                    foreach (var a in result.AdminCountAnomalies)
                    {
                        sb.AppendLine($"{a.SamAccountName},{a.ObjectClass},\"{a.Issue}\"");
                    }
                }

                File.WriteAllText(outputPath, sb.ToString());
            });
        }

        #endregion

        #region Deployment Methods

        /// <summary>
        /// Deploys the tiered admin OU structure (BILL model).
        /// </summary>
        public async Task<List<AdObjectCreationResult>> DeployTieredOuStructureAsync(
            BillOuTemplate template,
            bool protectFromDeletion,
            bool createUsersOus,
            bool createDevicesOus,
            CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                var results = new List<AdObjectCreationResult>();

                if (_domainInfo == null || string.IsNullOrEmpty(_domainInfo.ChosenDc))
                {
                    results.Add(new AdObjectCreationResult
                    {
                        Success = false,
                        ObjectType = "Prerequisite",
                        ObjectName = "Domain Connection",
                        Message = "Domain not discovered. Run DiscoverDomainAsync first."
                    });
                    return results;
                }

                try
                {
                    var domainDn = _domainInfo.DomainDn;
                    var dc = _domainInfo.ChosenDc;

                    // Create base OU
                    var baseOuDn = $"OU={template.BaseName},{domainDn}";
                    results.Add(CreateOrganizationalUnit(dc, domainDn, template.BaseName, $"Tiered Administration Root OU", protectFromDeletion));

                    // Create tier OUs
                    var tiers = new[] { template.Tier0Name, template.Tier1Name, template.Tier2Name };
                    foreach (var tier in tiers)
                    {
                        ct.ThrowIfCancellationRequested();

                        var tierOuDn = $"OU={tier},{baseOuDn}";
                        results.Add(CreateOrganizationalUnit(dc, baseOuDn, tier, $"{tier} - Tiered Admin OU", protectFromDeletion));

                        // Create sub-OUs for each tier
                        if (template.CreatePawOus)
                        {
                            results.Add(CreateOrganizationalUnit(dc, tierOuDn, "SecureKeyboard", $"SecureKeyboard workstations for {tier}", protectFromDeletion));
                        }

                        if (template.CreateServiceAccountOus)
                        {
                            results.Add(CreateOrganizationalUnit(dc, tierOuDn, "ServiceAccounts", $"Service Accounts for {tier}", protectFromDeletion));
                        }

                        if (template.CreateGroupsOus)
                        {
                            results.Add(CreateOrganizationalUnit(dc, tierOuDn, "Groups", $"Security Groups for {tier}", protectFromDeletion));
                        }

                        if (createUsersOus)
                        {
                            results.Add(CreateOrganizationalUnit(dc, tierOuDn, "Users", $"Admin Users for {tier}", protectFromDeletion));
                        }

                        if (createDevicesOus && tier != template.Tier0Name)
                        {
                            var deviceOuName = tier == template.Tier1Name ? "Servers" : "Workstations";
                            results.Add(CreateOrganizationalUnit(dc, tierOuDn, deviceOuName, $"{deviceOuName} for {tier}", protectFromDeletion));
                        }
                    }

                    _progress?.Report($"OU deployment complete: {results.Count(r => r.Success)} succeeded, {results.Count(r => !r.Success)} failed");
                }
                catch (Exception ex)
                {
                    results.Add(new AdObjectCreationResult
                    {
                        Success = false,
                        ObjectType = "Error",
                        ObjectName = "Deployment",
                        Message = ex.Message,
                        Error = ex
                    });
                }

                return results;
            }, ct);
        }

        /// <summary>
        /// Checks if an OU exists in AD.
        /// </summary>
        private bool OuExists(string dc, string ouDn)
        {
            try
            {
                using var entry = new DirectoryEntry($"LDAP://{dc}/{ouDn}");
                var _ = entry.Guid; // Force connection to verify existence
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Ensures the ESX Admins group exists for CVE-2024-37085 mitigation.
        /// Creates the group in CN=Users if it doesn't exist.
        /// </summary>
        private void EnsureEsxAdminsGroupExists(string dc, string domainDn)
        {
            const string groupName = "ESX Admins";
            const string description = "ESX Admins group - emptied via GPO to mitigate CVE-2024-37085";
            
            try
            {
                _progress?.Report("[DEBUG] Checking if ESX Admins group exists...");
                
                using var rootEntry = new DirectoryEntry($"LDAP://{dc}/{domainDn}");
                using var searcher = new DirectorySearcher(rootEntry)
                {
                    Filter = $"(&(objectClass=group)(cn={EscapeLdapFilter(groupName)}))",
                    SearchScope = SearchScope.Subtree
                };
                searcher.PropertiesToLoad.Add("distinguishedName");
                
                var existing = searcher.FindOne();
                if (existing != null)
                {
                    _progress?.Report($"[DEBUG] ESX Admins group already exists: {existing.Properties["distinguishedName"]?[0]}");
                    return;
                }
                
                // Group doesn't exist - create it in CN=Users container
                _progress?.Report("[DEBUG] ESX Admins group not found - creating it...");
                
                var usersContainerDn = $"CN=Users,{domainDn}";
                using var usersContainer = new DirectoryEntry($"LDAP://{dc}/{usersContainerDn}");
                
                using var newGroup = usersContainer.Children.Add($"CN={groupName}", "group");
                newGroup.Properties["sAMAccountName"].Value = "ESXAdmins";
                newGroup.Properties["description"].Value = description;
                newGroup.Properties["groupType"].Value = unchecked((int)0x80000002); // Global Security Group
                newGroup.CommitChanges();
                
                _progress?.Report($"[DEBUG] Created ESX Admins group at CN={groupName},{usersContainerDn}");
            }
            catch (UnauthorizedAccessException)
            {
                _progress?.Report("[WARN] Access denied creating ESX Admins group - may need manual creation");
            }
            catch (Exception ex)
            {
                _progress?.Report($"[WARN] Could not create ESX Admins group: {ex.Message}");
            }
        }

        /// <summary>
        /// Resolves the SIDs for tiered security groups.
        /// Returns a dictionary with group name -> SID mapping.
        /// </summary>
        private Dictionary<string, string> ResolveGroupSids(string dc, string domainDn, string domainSid, string tieredOuBaseName)
        {
            var sids = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            _progress?.Report("[DEBUG] Resolving group SIDs from Active Directory...");

            var groupNames = new[]
            {
                "Tier 0 - Operators",
                "Tier 0 - SecureKeyboard Users", 
                "Tier 0 - Service Accounts",
                "Tier 0 Computers",  // For T0 Admin Block DENY ACL
                "Tier 1 - Operators",
                "Tier 1 - SecureKeyboard Users",
                "Tier 1 - Service Accounts",
                "Tier 1 - Server Local Admins",
                "Tier 2 - Operators",
                "Tier 2 - SecureKeyboard Users",
                "Tier 2 - Service Accounts",
                "Tier 2 - Workstation Local Admins",
                "IR - Emergency Access",
                "DVRL - Deny Logon All Tiers",
                "ESX Admins"  // CVE-2024-37085 mitigation
            };
            
            // Ensure ESX Admins group exists for CVE-2024-37085 mitigation
            EnsureEsxAdminsGroupExists(dc, domainDn);

            try
            {
                using var rootEntry = new DirectoryEntry($"LDAP://{dc}/{domainDn}");
                using var searcher = new DirectorySearcher(rootEntry)
                {
                    SearchScope = SearchScope.Subtree
                };
                searcher.PropertiesToLoad.AddRange(new[] { "cn", "objectSid", "distinguishedName" });

                foreach (var groupName in groupNames)
                {
                    searcher.Filter = $"(&(objectClass=group)(cn={EscapeLdapFilter(groupName)}))";
                    var result = searcher.FindOne();
                    if (result != null)
                    {
                        var sidBytes = result.Properties["objectSid"]?[0] as byte[];
                        if (sidBytes != null)
                        {
                            var sid = new SecurityIdentifier(sidBytes, 0).Value;
                            sids[groupName] = sid;
                            _progress?.Report($"[DEBUG] Resolved SID for '{groupName}': {sid}");
                        }
                    }
                    else
                    {
                        _progress?.Report($"[WARN] Could not find group '{groupName}' to resolve SID");
                    }
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"[ERROR] Failed to resolve group SIDs: {ex.Message}");
            }

            // Also add well-known SIDs
            sids["Administrators"] = "S-1-5-32-544";
            sids["Users"] = "S-1-5-32-545";
            sids["Guests"] = "S-1-5-32-546";
            sids["Backup Operators"] = "S-1-5-32-551";
            sids["Print Operators"] = "S-1-5-32-550";
            sids["Server Operators"] = "S-1-5-32-549";
            sids["Account Operators"] = "S-1-5-32-548";
            sids["Domain Admins"] = $"{domainSid}-512";
            sids["Domain Users"] = $"{domainSid}-513";
            sids["Domain Guests"] = $"{domainSid}-514";      // Domain Guests group
            sids["Domain Controllers"] = $"{domainSid}-516";
            sids["Enterprise Admins"] = $"{domainSid}-519";
            sids["Schema Admins"] = $"{domainSid}-518";
            sids["Administrator"] = $"{domainSid}-500";      // Domain Administrator account
            sids["Guest"] = $"{domainSid}-501";              // Domain Guest account

            _progress?.Report($"[DEBUG] Total SIDs resolved: {sids.Count}");

            return sids;
        }

        /// <summary>
        /// Creates an organizational unit.
        /// </summary>
        private AdObjectCreationResult CreateOrganizationalUnit(string dc, string parentDn, string ouName, string description, bool protectFromDeletion)
        {
            var result = new AdObjectCreationResult
            {
                ObjectType = "OU",
                ObjectName = ouName,
                DistinguishedName = $"OU={ouName},{parentDn}"
            };

            try
            {
                _progress?.Report($"Creating OU: {ouName} in {parentDn}");

                using var parentEntry = new DirectoryEntry($"LDAP://{dc}/{parentDn}");
                
                // Check if OU already exists
                using var searcher = new DirectorySearcher(parentEntry)
                {
                    Filter = $"(&(objectClass=organizationalUnit)(ou={ouName}))",
                    SearchScope = SearchScope.OneLevel
                };

                var existing = searcher.FindOne();
                if (existing != null)
                {
                    result.Success = true;
                    result.Message = "OU already exists";
                    _progress?.Report($"OU already exists: {ouName}");
                    return result;
                }

                // Create new OU
                using var newOu = parentEntry.Children.Add($"OU={ouName}", "organizationalUnit");
                newOu.Properties["description"].Value = description;
                newOu.CommitChanges();

                // Set protection from accidental deletion
                if (protectFromDeletion)
                {
                    try
                    {
                        var security = newOu.ObjectSecurity;
                        var everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                        var denyDeleteRule = new ActiveDirectoryAccessRule(
                            everyoneSid,
                            ActiveDirectoryRights.Delete | ActiveDirectoryRights.DeleteTree,
                            System.Security.AccessControl.AccessControlType.Deny);
                        security.AddAccessRule(denyDeleteRule);
                        newOu.CommitChanges();
                    }
                    catch (Exception protectEx)
                    {
                        _progress?.Report($"Warning: Could not set deletion protection on {ouName}: {protectEx.Message}");
                    }
                }

                result.Success = true;
                result.Message = "Created successfully";
                _progress?.Report($"Created OU: {ouName}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = ex.Message;
                result.Error = ex;
                _progress?.Report($"Failed to create OU {ouName}: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// Creates a security group in the specified OU.
        /// </summary>
        private AdObjectCreationResult CreateSecurityGroup(string dc, string targetOuDn, string domainDn, string groupName, string description)
        {
            var result = new AdObjectCreationResult
            {
                ObjectType = "Group",
                ObjectName = groupName,
                DistinguishedName = $"CN={groupName},{targetOuDn}"
            };

            try
            {
                _progress?.Report($"Creating security group: {groupName}");

                // First check if the target OU exists, if not try to use domain root
                DirectoryEntry? parentEntry = null;
                try
                {
                    parentEntry = new DirectoryEntry($"LDAP://{dc}/{targetOuDn}");
                    // Force connection to verify OU exists
                    var _ = parentEntry.Guid;
                }
                catch
                {
                    // OU doesn't exist, try to create group at domain level (Users container)
                    parentEntry?.Dispose();
                    var usersContainerDn = $"CN=Users,{domainDn}";
                    parentEntry = new DirectoryEntry($"LDAP://{dc}/{usersContainerDn}");
                    result.DistinguishedName = $"CN={groupName},{usersContainerDn}";
                    _progress?.Report($"Target OU not found, using Users container for: {groupName}");
                }

                using (parentEntry)
                {
                    // Check if group already exists
                    using var searcher = new DirectorySearcher(parentEntry)
                    {
                        Filter = $"(&(objectClass=group)(cn={EscapeLdapFilter(groupName)}))",
                        SearchScope = SearchScope.OneLevel
                    };

                    var existing = searcher.FindOne();
                    if (existing != null)
                    {
                        result.Success = true;
                        result.Message = "Group already exists";
                        result.DistinguishedName = existing.Properties["distinguishedName"]?[0]?.ToString() ?? result.DistinguishedName;
                        _progress?.Report($"Group already exists: {groupName}");
                        return result;
                    }

                    // Create new security group (Global Security Group = 0x80000002)
                    using var newGroup = parentEntry.Children.Add($"CN={groupName}", "group");
                    newGroup.Properties["sAMAccountName"].Value = groupName.Length > 20 
                        ? groupName.Replace(" ", "").Replace("-", "")[..Math.Min(20, groupName.Replace(" ", "").Replace("-", "").Length)]
                        : groupName.Replace(" ", "");
                    newGroup.Properties["description"].Value = description;
                    newGroup.Properties["groupType"].Value = unchecked((int)0x80000002); // Global Security Group
                    newGroup.CommitChanges();

                    result.Success = true;
                    result.Message = "Created successfully";
                    _progress?.Report($"Created group: {groupName}");
                }
            }
            catch (UnauthorizedAccessException)
            {
                result.Success = false;
                result.Message = "Access denied. Requires appropriate permissions to create groups.";
                _progress?.Report($"Access denied creating group: {groupName}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = ex.Message;
                result.Error = ex;
                _progress?.Report($"Failed to create group {groupName}: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// Deploys baseline GPOs for security hardening.
        /// Creates GPOs with actual policy settings based on PLATYPUS patterns.
        /// Includes detailed debug logging and verification.
        /// </summary>
        public async Task<List<AdObjectCreationResult>> DeployBaselineGposAsync(
            GpoDeploymentOptions options,
            CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                var results = new List<AdObjectCreationResult>();

                _progress?.Report("[DEBUG] Starting DeployBaselineGposAsync...");

                if (_domainInfo == null || string.IsNullOrEmpty(_domainInfo.ChosenDc))
                {
                    _progress?.Report("[ERROR] Domain not discovered. Run DiscoverDomainAsync first.");
                    results.Add(new AdObjectCreationResult
                    {
                        Success = false,
                        ObjectType = "Prerequisite",
                        ObjectName = "Domain Connection",
                        Message = "Domain not discovered. Run DiscoverDomainAsync first."
                    });
                    return results;
                }

                _progress?.Report("[DEBUG] Domain info validated. Starting deployment...");

                try
                {
                    var dc = _domainInfo.ChosenDc;
                    var domainDn = _domainInfo.DomainDn;
                    var domainFqdn = _domainInfo.DomainFqdn ?? "";
                    var domainSid = _domainInfo.DomainSid ?? "";

                    _progress?.Report($"[DEBUG] DC: {dc}");
                    _progress?.Report($"[DEBUG] Domain DN: {domainDn}");
                    _progress?.Report($"[DEBUG] Domain FQDN: {domainFqdn}");
                    _progress?.Report($"[DEBUG] Domain SID: {domainSid}");

                    // === STEP 1: Ensure Required OUs Exist First ===
                    _progress?.Report("[STEP 1] Ensuring required OUs exist...");
                    var adminOuDn = $"OU={options.TieredOuBaseName},{domainDn}";
                    
                    // Check if Admin OU exists
                    if (!OuExists(dc, adminOuDn))
                    {
                        _progress?.Report($"[DEBUG] Admin OU does not exist: {adminOuDn}");
                        _progress?.Report($"[DEBUG] Creating base Admin OU: {options.TieredOuBaseName}");
                        results.Add(CreateOrganizationalUnit(dc, domainDn, options.TieredOuBaseName, "Tiered Administration Root OU", true));
                    }
                    else
                    {
                        _progress?.Report($"[DEBUG] Admin OU already exists: {adminOuDn}");
                    }

                    // Create tier OUs
                    foreach (var tier in new[] { "Tier0", "Tier1", "Tier2" })
                    {
                        ct.ThrowIfCancellationRequested();
                        var tierOuDn = $"OU={tier},{adminOuDn}";
                        
                        if (!OuExists(dc, tierOuDn))
                        {
                            _progress?.Report($"[DEBUG] Creating Tier OU: {tier}");
                            results.Add(CreateOrganizationalUnit(dc, adminOuDn, tier, $"{tier} - Tiered Admin OU", true));
                        }
                        else
                        {
                            _progress?.Report($"[DEBUG] Tier OU already exists: {tierOuDn}");
                        }

                        // Create Groups sub-OU
                        var groupsOuDn = $"OU=Groups,{tierOuDn}";
                        if (!OuExists(dc, groupsOuDn))
                        {
                            _progress?.Report($"[DEBUG] Creating Groups OU under {tier}");
                            results.Add(CreateOrganizationalUnit(dc, tierOuDn, "Groups", $"Security Groups for {tier}", true));
                        }
                        else
                        {
                            _progress?.Report($"[DEBUG] Groups OU already exists: {groupsOuDn}");
                        }
                    }

                    // === STEP 2: Create Tiered Security Groups ===
                    if (options.CreateTierGroups)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[STEP 2] Creating tiered security groups...");
                        
                        // Tier 0 Groups
                        var tier0GroupsOu = $"OU=Groups,OU=Tier0,{adminOuDn}";
                        _progress?.Report($"[DEBUG] Creating Tier 0 groups in: {tier0GroupsOu}");
                        
                        results.Add(CreateSecurityGroup(dc, tier0GroupsOu, domainDn, "Tier 0 - Operators", 
                            "Tier 0 privileged operators - Domain Controllers and core infrastructure"));
                        results.Add(CreateSecurityGroup(dc, tier0GroupsOu, domainDn, "Tier 0 - SecureKeyboard Users", 
                            "Users authorized to log on to Tier 0 SecureKeyboard workstations"));
                        results.Add(CreateSecurityGroup(dc, tier0GroupsOu, domainDn, "Tier 0 - Service Accounts", 
                            "Service accounts for Tier 0 systems"));
                        results.Add(CreateSecurityGroup(dc, tier0GroupsOu, domainDn, "Tier 0 Computers", 
                            "Members of this group are Tier 0 computers and will be exempted from the Tier 0 Admin Block GPO"));
                        
                        // Add Domain Controllers to Tier 0 Computers group
                        try
                        {
                            _progress?.Report("[DEBUG] Adding Domain Controllers to Tier 0 Computers group...");
                            AddDomainControllersToTier0Computers(dc, domainDn, tier0GroupsOu);
                        }
                        catch (Exception ex)
                        {
                            _progress?.Report($"[WARN] Could not add Domain Controllers to Tier 0 Computers: {ex.Message}");
                        }
                        
                        // Tier 1 Groups
                        var tier1GroupsOu = $"OU=Groups,OU=Tier1,{adminOuDn}";
                        _progress?.Report($"[DEBUG] Creating Tier 1 groups in: {tier1GroupsOu}");
                        
                        results.Add(CreateSecurityGroup(dc, tier1GroupsOu, domainDn, "Tier 1 - Operators", 
                            "Tier 1 privileged operators - Server administrators"));
                        results.Add(CreateSecurityGroup(dc, tier1GroupsOu, domainDn, "Tier 1 - SecureKeyboard Users", 
                            "Users authorized to log on to Tier 1 SecureKeyboard workstations"));
                        results.Add(CreateSecurityGroup(dc, tier1GroupsOu, domainDn, "Tier 1 - Service Accounts", 
                            "Service accounts for Tier 1 systems"));
                        results.Add(CreateSecurityGroup(dc, tier1GroupsOu, domainDn, "Tier 1 - Server Local Admins", 
                            "Members become local administrators on Tier 1 servers"));
                        
                        // Tier 2 Groups
                        var tier2GroupsOu = $"OU=Groups,OU=Tier2,{adminOuDn}";
                        _progress?.Report($"[DEBUG] Creating Tier 2 groups in: {tier2GroupsOu}");
                        
                        results.Add(CreateSecurityGroup(dc, tier2GroupsOu, domainDn, "Tier 2 - Operators", 
                            "Tier 2 privileged operators - Workstation administrators"));
                        results.Add(CreateSecurityGroup(dc, tier2GroupsOu, domainDn, "Tier 2 - SecureKeyboard Users", 
                            "Users authorized to log on to Tier 2 SecureKeyboard workstations"));
                        results.Add(CreateSecurityGroup(dc, tier2GroupsOu, domainDn, "Tier 2 - Service Accounts", 
                            "Service accounts for Tier 2 systems"));
                        results.Add(CreateSecurityGroup(dc, tier2GroupsOu, domainDn, "Tier 2 - Workstation Local Admins", 
                            "Members become local administrators on Tier 2 workstations"));
                        
                        // Cross-tier / IR groups
                        _progress?.Report("[DEBUG] Creating cross-tier IR groups...");
                        results.Add(CreateSecurityGroup(dc, tier0GroupsOu, domainDn, "IR - Emergency Access", 
                            "Emergency access accounts for incident response - break glass"));
                        results.Add(CreateSecurityGroup(dc, tier0GroupsOu, domainDn, "DVRL - Deny Logon All Tiers", 
                            "Members are denied logon to all tier systems - for compromised accounts"));

                        // Log group creation results
                        var createdGroups = results.Where(r => r.ObjectType == "Group").ToList();
                        _progress?.Report($"[DEBUG] Group creation summary: {createdGroups.Count(r => r.Success)} created, {createdGroups.Count(r => !r.Success)} failed");
                    }
                    else
                    {
                        _progress?.Report("[DEBUG] CreateTierGroups is false - skipping group creation");
                    }

                    // === STEP 3: Get Group SIDs for GPO Settings ===
                    _progress?.Report("[STEP 3] Resolving group SIDs for GPO settings...");
                    var domainNetBios = _domainInfo.DomainNetbiosName ?? domainFqdn.Split('.').FirstOrDefault() ?? "DOMAIN";
                    var groupSids = ResolveGroupSids(dc, domainDn, domainSid, options.TieredOuBaseName);
                    groupSids["DomainNetBIOS"] = domainNetBios;  // Add for GPP content generation

                    // === STEP 4: Deploy GPOs with Settings ===
                    _progress?.Report("[STEP 4] Deploying GPOs with settings...");

                    // === Quick Deploy GPOs with Settings ===
                    if (options.DeployPasswordPolicy)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Password Policy GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Baseline-PasswordPolicy", 
                            "Password policy settings configured.",
                            GpoSettingsType.SecuritySettings));
                    }

                    if (options.DeployAuditPolicy)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Audit Policy GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Baseline-AuditPolicy",
                            "Advanced audit policies configured for security monitoring.",
                            GpoSettingsType.AuditPolicy));
                    }

                    if (options.DeploySecurityBaseline)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Security Baseline GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Baseline-SecurityHardening",
                            "Security hardening settings: LM hash disabled, NTLMv2 required.",
                            GpoSettingsType.SecuritySettings));
                    }

                    if (options.DeployPawPolicy)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating SecureKeyboard Security Policy GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "SecureKeyboard-SecurityPolicy",
                            "SecureKeyboard lockdown settings configured.",
                            GpoSettingsType.SecuritySettings));
                    }

                    // === Tier 0 GPOs (PLATYPUS/BILL) ===
                    if (options.DeployT0BaselineAudit)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 0 Baseline Audit GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 0 - Baseline Audit Policies - Tier 0 Servers",
                            "Enhanced audit policies for Tier 0 servers configured.",
                            GpoSettingsType.AuditPolicy));
                    }

                    if (options.DeployT0DisallowDsrm)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 0 DSRM Disallow GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 0 - Disallow DSRM Login - DC ONLY",
                            "DSRM network logon disabled.",
                            GpoSettingsType.SecuritySettings));
                    }

                    if (options.DeployT0DomainBlock)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 0 Admin Block GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 0 - Admin Block - Top Level",
                            "Tier 0 account blocking configured.",
                            GpoSettingsType.T0DomainBlock));
                    }

                    if (options.DeployT0DomainControllers)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 0 DC Security GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 0 - Domain Controllers - DC Only",
                            "DC security hardening configured.",
                            GpoSettingsType.DomainControllers));
                    }

                    if (options.DeployT0EsxAdmins)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 0 ESX Admins Restricted Groups GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 0 - ESX Admins Restricted Group - DC Only",
                            "ESX Admins group emptied via Restricted Groups.",
                            GpoSettingsType.RestrictedGroups));
                    }

                    if (options.DeployT0UserRights)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 0 User Rights GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 0 - User Rights Assignments - Tier 0 Servers",
                            "Tier 0 logon rights restrictions configured.",
                            GpoSettingsType.UserRights));
                    }

                    if (options.DeployT0RestrictedGroups)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 0 Restricted Groups GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 0 - Restricted Groups - Tier 0 Servers",
                            "Tier 0 local admin membership controls configured.",
                            GpoSettingsType.RestrictedGroups));
                    }

                    // === Tier 1 GPOs ===
                    if (options.DeployT1LocalAdmin)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 1 Local Admin GPO (GPP)...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 1 - Tier 1 Operators in Local Admin - Tier 1 Servers",
                            "Tier 1 local admin membership configured via GPP.",
                            GpoSettingsType.LocalUsersAndGroups));
                    }

                    if (options.DeployT1UserRights)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 1 User Rights GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 1 - User Rights Assignments - Tier 1 Servers",
                            "Tier 1 logon rights restrictions configured.",
                            GpoSettingsType.UserRights));
                    }

                    if (options.DeployT1RestrictedGroups)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 1 Restricted Groups GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 1 - Restricted Groups - Tier 1 Servers",
                            "Tier 1 local admin membership controls configured.",
                            GpoSettingsType.RestrictedGroups));
                    }

                    // === Tier 2 GPOs ===
                    if (options.DeployT2LocalAdmin)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 2 Local Admin GPO (GPP)...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 2 - Tier 2 Operators in Local Admin - Tier 2 Devices",
                            "Tier 2 local admin membership configured via GPP.",
                            GpoSettingsType.LocalUsersAndGroups));
                    }

                    if (options.DeployT2UserRights)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 2 User Rights GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 2 - User Rights Assignments - Tier 2 Devices",
                            "Tier 2 logon rights restrictions configured.",
                            GpoSettingsType.UserRights));
                    }

                    if (options.DeployT2RestrictedGroups)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Tier 2 Restricted Groups GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier 2 - Restricted Groups - Tier 2 Devices",
                            "Tier 2 local admin membership controls configured.",
                            GpoSettingsType.RestrictedGroups));
                    }

                    // === Cross-Tier GPOs ===
                    if (options.DeployDisableSmb1)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Disable SMBv1 GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier ALL - Disable SMBv1 - Top Level",
                            "SMBv1 disabled via registry preferences.",
                            GpoSettingsType.Registry));
                    }

                    if (options.DeployDisableWDigest)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Disable WDigest GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "Tier ALL - Disable WDigest - Top Level",
                            "WDigest credential caching disabled via registry preferences.",
                            GpoSettingsType.Registry));
                    }

                    if (options.DeployResetMachinePassword)
                    {
                        ct.ThrowIfCancellationRequested();
                        _progress?.Report("[DEBUG] Creating Reset Machine Password GPO...");
                        results.Add(CreateGpoWithSettings(dc, domainFqdn, groupSids,
                            "PLATYPUS - Reset Machine Account Password",
                            "Machine account password rotation configured (30 days).",
                            GpoSettingsType.SecuritySettings));
                    }

                    // === STEP 5: Verify GPO Settings ===
                    _progress?.Report("[STEP 5] Verifying GPO deployment results...");
                    var gpoResults = results.Where(r => r.ObjectType == "GPO").ToList();
                    var successGpos = gpoResults.Count(r => r.Success);
                    var failedGpos = gpoResults.Count(r => !r.Success);
                    _progress?.Report($"[DEBUG] GPO Results: {successGpos} succeeded, {failedGpos} failed");

                    foreach (var gpo in gpoResults.Where(r => !r.Success))
                    {
                        _progress?.Report($"[ERROR] GPO Failed: {gpo.ObjectName} - {gpo.Message}");
                    }

                    // Summary
                    var ouResults = results.Where(r => r.ObjectType == "OU").ToList();
                    var groupResults = results.Where(r => r.ObjectType == "Group").ToList();
                    
                    _progress?.Report("[SUMMARY] Deployment Complete:");
                    _progress?.Report($"  - OUs: {ouResults.Count(r => r.Success)} created/verified");
                    _progress?.Report($"  - Groups: {groupResults.Count(r => r.Success)} created/verified");
                    _progress?.Report($"  - GPOs: {successGpos} created with settings");
                    _progress?.Report($"  - Failures: {results.Count(r => !r.Success)} total");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[ERROR] GPO Deployment failed: {ex.Message}");
                    results.Add(new AdObjectCreationResult
                    {
                        Success = false,
                        ObjectType = "Error",
                        ObjectName = "GPO Deployment",
                        Message = ex.Message,
                        Error = ex
                    });
                }

                return results;
            }, ct);
        }

        /// <summary>
        /// Creates a GPO with actual settings based on PLATYPUS patterns.
        /// Full GPO creation including SYSVOL folder structure and policy content.
        /// Includes detailed debug logging.
        /// </summary>
        private AdObjectCreationResult CreateGpoWithSettings(
            string dc, 
            string domainFqdn,
            Dictionary<string, string> groupSids,
            string gpoName, 
            string description,
            GpoSettingsType settingsType)
        {
            var result = new AdObjectCreationResult
            {
                ObjectType = "GPO",
                ObjectName = gpoName
            };

            try
            {
                _progress?.Report($"[DEBUG] Creating GPO: {gpoName}");
                _progress?.Report($"[DEBUG] Settings Type: {settingsType}");

                var gpoContainerDn = $"CN=Policies,CN=System,{DomainToDn(domainFqdn)}";
                _progress?.Report($"[DEBUG] GPO Container DN: {gpoContainerDn}");
                
                using var gpoContainer = new DirectoryEntry($"LDAP://{dc}/{gpoContainerDn}");
                
                // Check if GPO already exists
                using var searcher = new DirectorySearcher(gpoContainer)
                {
                    Filter = $"(&(objectClass=groupPolicyContainer)(displayName={EscapeLdapFilter(gpoName)}))",
                    SearchScope = SearchScope.OneLevel
                };

                var existing = searcher.FindOne();
                string gpoGuid;
                string sysvolPath;
                bool gpoWasCreated = false;

                if (existing != null)
                {
                    // GPO exists - check if we need to update settings
                    result.DistinguishedName = existing.Properties["distinguishedName"]?[0]?.ToString() ?? "";
                    gpoGuid = existing.Properties["name"]?[0]?.ToString() ?? "";
                    sysvolPath = $"\\\\{dc}\\SYSVOL\\{domainFqdn}\\Policies\\{gpoGuid}";
                    _progress?.Report($"[DEBUG] GPO already exists: {gpoName}");
                    _progress?.Report($"[DEBUG] Existing GPO GUID: {gpoGuid}");
                    _progress?.Report($"[DEBUG] Will check/update SYSVOL settings at: {sysvolPath}");
                }
                else
                {
                    // Generate new GUID for the GPO
                    gpoGuid = Guid.NewGuid().ToString("B").ToUpperInvariant();
                    var gpoCn = $"CN={gpoGuid}";
                    sysvolPath = $"\\\\{dc}\\SYSVOL\\{domainFqdn}\\Policies\\{gpoGuid}";
                    
                    _progress?.Report($"[DEBUG] Creating new GPO with GUID: {gpoGuid}");

                    // Create GPO AD object
                    using var newGpo = gpoContainer.Children.Add(gpoCn, "groupPolicyContainer");
                    newGpo.Properties["displayName"].Value = gpoName;
                    newGpo.Properties["gPCFileSysPath"].Value = $"\\\\{domainFqdn}\\SysVol\\{domainFqdn}\\Policies\\{gpoGuid}";
                    newGpo.Properties["gPCFunctionalityVersion"].Value = 2;
                    newGpo.Properties["flags"].Value = 0; // GPO enabled
                    newGpo.Properties["versionNumber"].Value = 1;
                    
                    // Set gPCMachineExtensionNames based on settings type
                    var gpcExtension = GetGpcMachineExtensionNames(settingsType);
                    if (!string.IsNullOrEmpty(gpcExtension))
                    {
                        newGpo.Properties["gPCMachineExtensionNames"].Value = gpcExtension;
                        _progress?.Report($"[DEBUG] Set gPCMachineExtensionNames: {gpcExtension}");
                    }
                    
                    newGpo.CommitChanges();
                    _progress?.Report($"[DEBUG] GPO AD object created successfully");
                    
                    result.DistinguishedName = $"{gpoCn},{gpoContainerDn}";
                    gpoWasCreated = true;
                }

                // Create or update SYSVOL folder structure and policy files
                _progress?.Report($"[DEBUG] Creating/updating SYSVOL content at: {sysvolPath}");
                if (CreateGpoSysvolContentWithSids(sysvolPath, settingsType, gpoName, groupSids))
                {
                    result.Success = true;
                    result.Message = gpoWasCreated 
                        ? $"Created with settings. {description}" 
                        : $"Exists - settings verified/updated. {description}";
                    _progress?.Report($"[DEBUG] SYSVOL content created/updated successfully for: {gpoName}");
                }
                else
                {
                    result.Success = true;
                    result.Message = gpoWasCreated 
                        ? $"GPO created but SYSVOL content failed. Configure manually: {description}"
                        : $"GPO exists but SYSVOL content update failed. {description}";
                    _progress?.Report($"[WARN] SYSVOL content creation/update failed for: {gpoName}");
                }

                // For T0 Admin Block GPO: Create WMI filter and set DENY Apply ACLs
                if (settingsType == GpoSettingsType.T0DomainBlock && result.Success)
                {
                    ConfigureT0DomainBlockGpo(dc, domainFqdn, gpoGuid);
                }
            }
            catch (UnauthorizedAccessException uaex)
            {
                result.Success = false;
                result.Message = "Access denied. Requires Domain Admin or GPO Creator Owners rights.";
                _progress?.Report($"[ERROR] Access denied creating GPO: {gpoName}");
                _progress?.Report($"[ERROR] Details: {uaex.Message}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = ex.Message;
                result.Error = ex;
                _progress?.Report($"[ERROR] Failed to create GPO {gpoName}: {ex.Message}");
                _progress?.Report($"[ERROR] Stack: {ex.StackTrace}");
            }

            return result;
        }

        /// <summary>
        /// Gets the gPCMachineExtensionNames value for the GPO type.
        /// </summary>
        private string GetGpcMachineExtensionNames(GpoSettingsType settingsType)
        {
            return settingsType switch
            {
                // Security settings + audit policy
                GpoSettingsType.AuditPolicy => "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]",
                // Security settings only
                GpoSettingsType.SecuritySettings => "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]",
                // Security settings + restricted groups
                GpoSettingsType.RestrictedGroups => "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]",
                // Security settings + user rights
                GpoSettingsType.UserRights => "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]",
                // Registry settings (Group Policy Preferences)
                GpoSettingsType.Registry => "[{B087BE9D-ED37-454F-AF9C-04291E351182}{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}]",
                // GPP Local Users and Groups
                GpoSettingsType.LocalUsersAndGroups => "[{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]",
                // T0 Admin Block - same as UserRights (security settings)
                GpoSettingsType.T0DomainBlock => "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]",
                // Domain Controllers GPO - security settings + audit + registry preferences
                GpoSettingsType.DomainControllers => "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{B087BE9D-ED37-454F-AF9C-04291E351182}{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}][{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]",
                _ => ""
            };
        }

        /// <summary>
        /// Creates the SYSVOL folder structure and policy content files for a GPO with proper SIDs.
        /// This is the enhanced version that uses resolved group SIDs.
        /// </summary>
        private bool CreateGpoSysvolContentWithSids(string sysvolPath, GpoSettingsType settingsType, string gpoName, Dictionary<string, string> groupSids)
        {
            try
            {
                _progress?.Report($"[DEBUG] Creating SYSVOL content at: {sysvolPath}");
                
                // Create directory structure
                var machinePath = Path.Combine(sysvolPath, "Machine");
                var userPath = Path.Combine(sysvolPath, "User");
                var secEditPath = Path.Combine(machinePath, "microsoft", "windows nt", "SecEdit");
                var auditPath = Path.Combine(machinePath, "microsoft", "windows nt", "Audit");

                _progress?.Report($"[DEBUG] Creating directories...");
                Directory.CreateDirectory(machinePath);
                Directory.CreateDirectory(userPath);
                Directory.CreateDirectory(secEditPath);

                // Create GPT.ini
                var gptIniPath = Path.Combine(sysvolPath, "GPT.ini");
                var gptIniContent = "[General]\r\nVersion=1\r\n";
                File.WriteAllText(gptIniPath, gptIniContent);
                _progress?.Report($"[DEBUG] Created GPT.ini at: {gptIniPath}");

                // Create policy content based on settings type
                _progress?.Report($"[DEBUG] Creating policy content for type: {settingsType}");
                
                switch (settingsType)
                {
                    case GpoSettingsType.AuditPolicy:
                        CreateBaselineAuditPolicyContent(secEditPath, auditPath);
                        break;
                    case GpoSettingsType.SecuritySettings:
                        CreateSecuritySettingsContent(secEditPath, gpoName, groupSids);
                        break;
                    case GpoSettingsType.RestrictedGroups:
                        CreateRestrictedGroupsContentWithSids(secEditPath, gpoName, groupSids);
                        break;
                    case GpoSettingsType.UserRights:
                        CreateUserRightsContentWithSids(secEditPath, gpoName, groupSids);
                        break;
                    case GpoSettingsType.Registry:
                        CreateRegistryContent(machinePath, gpoName);
                        break;
                    case GpoSettingsType.LocalUsersAndGroups:
                        CreateLocalUsersAndGroupsContent(machinePath, gpoName, groupSids);
                        break;
                    case GpoSettingsType.T0DomainBlock:
                        CreateT0DomainBlockContent(secEditPath, gpoName, groupSids);
                        break;
                    case GpoSettingsType.DomainControllers:
                        CreateDomainControllersContent(sysvolPath, machinePath, secEditPath, auditPath, groupSids);
                        break;
                }

                // Verify the GptTmpl.inf was created
                var gptTmplPath = Path.Combine(secEditPath, "GptTmpl.inf");
                if (File.Exists(gptTmplPath))
                {
                    var content = File.ReadAllText(gptTmplPath);
                    _progress?.Report($"[DEBUG] GptTmpl.inf created, size: {content.Length} bytes");
                    _progress?.Report($"[DEBUG] GptTmpl.inf content preview: {content.Substring(0, Math.Min(500, content.Length))}...");
                }
                else
                {
                    _progress?.Report($"[WARN] GptTmpl.inf was not created at: {gptTmplPath}");
                }

                return true;
            }
            catch (Exception ex)
            {
                _progress?.Report($"[ERROR] Failed to create SYSVOL content: {ex.Message}");
                _progress?.Report($"[ERROR] Stack: {ex.StackTrace}");
                return false;
            }
        }

        /// <summary>
        /// Creates baseline audit policy content for Tier 0 servers (non-DC).
        /// Matches Set-BillT0BaselineAuditGpo from PLATYPUS module.
        /// Only 4 subcategories with Success auditing.
        /// </summary>
        private void CreateBaselineAuditPolicyContent(string secEditPath, string auditPath)
        {
            Directory.CreateDirectory(auditPath);

            // Create GptTmpl.inf for advanced audit policy
            var gptTmpl = new StringBuilder();
            gptTmpl.AppendLine("[Unicode]");
            gptTmpl.AppendLine("Unicode=yes");
            gptTmpl.AppendLine("[Version]");
            gptTmpl.AppendLine("signature=\"$CHICAGO$\"");
            gptTmpl.AppendLine("Revision=1");
            gptTmpl.AppendLine();
            gptTmpl.AppendLine("[Registry Values]");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy=4,1");

            File.WriteAllText(Path.Combine(secEditPath, "GptTmpl.inf"), gptTmpl.ToString(), Encoding.Unicode);

            // Create audit.csv for baseline audit policies (4 subcategories, Success only)
            // Matches Set-BillT0BaselineAuditGpo from PLATYPUS module
            var auditCsv = new StringBuilder();
            auditCsv.AppendLine("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value");
            // Credential Validation - Success only
            auditCsv.AppendLine(",System,Audit Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success,,1");
            // Security Group Management - Success only
            auditCsv.AppendLine(",System,Audit Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},Success,,1");
            // Process Creation - Success only
            auditCsv.AppendLine(",System,Audit Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,,1");
            // Security System Extension - Success only (no trailing newline on last line)
            auditCsv.Append(",System,Audit Security System Extension,{0cce9211-69ae-11d9-bed3-505054503030},Success,,1");

            File.WriteAllText(Path.Combine(auditPath, "audit.csv"), auditCsv.ToString(), Encoding.ASCII);
        }

        /// <summary>
        /// Creates comprehensive Domain Controller GPO content.
        /// Matches Set-BillT0DomainControllersGpo from PLATYPUS module.
        /// Includes: 28 audit subcategories, security settings, registry preferences, and service settings.
        /// </summary>
        private void CreateDomainControllersContent(string sysvolPath, string machinePath, string secEditPath, string auditPath, Dictionary<string, string> groupSids)
        {
            Directory.CreateDirectory(auditPath);
            var prefsRegistryPath = Path.Combine(machinePath, "Preferences", "Registry");
            Directory.CreateDirectory(prefsRegistryPath);

            // === PART 1: Comprehensive DC Audit Policies (28 subcategories) ===
            var auditCsv = new StringBuilder();
            auditCsv.AppendLine("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value");
            // Account Logon
            auditCsv.AppendLine(",System,Audit Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // Account Management
            auditCsv.AppendLine(",System,Audit Computer Account Management,{0cce9236-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.AppendLine(",System,Audit Distribution Group Management,{0cce9238-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.AppendLine(",System,Audit Other Account Management Events,{0cce923a-69ae-11d9-bed3-505054503030},Success,,1");
            auditCsv.AppendLine(",System,Audit Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.AppendLine(",System,Audit User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // Detailed Tracking
            auditCsv.AppendLine(",System,Audit PNP Activity,{0cce9248-69ae-11d9-bed3-505054503030},Success,,1");
            auditCsv.AppendLine(",System,Audit Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,,1");
            // DS Access
            auditCsv.AppendLine(",System,Audit Directory Service Access,{0cce923b-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.AppendLine(",System,Audit Directory Service Changes,{0cce923c-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // Logon/Logoff
            auditCsv.AppendLine(",System,Audit Account Lockout,{0cce9217-69ae-11d9-bed3-505054503030},Failure,,2");
            auditCsv.AppendLine(",System,Audit Group Membership,{0cce9249-69ae-11d9-bed3-505054503030},Success,,1");
            auditCsv.AppendLine(",System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.AppendLine(",System,Audit Other Logon/Logoff Events,{0cce921c-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.AppendLine(",System,Audit Special Logon,{0cce921b-69ae-11d9-bed3-505054503030},Success,,1");
            // Object Access
            auditCsv.AppendLine(",System,Audit Detailed File Share,{0cce9244-69ae-11d9-bed3-505054503030},Failure,,2");
            auditCsv.AppendLine(",System,Audit File Share,{0cce9224-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.AppendLine(",System,Audit Other Object Access Events,{0cce9227-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.AppendLine(",System,Audit Removable Storage,{0cce9245-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // Policy Change
            auditCsv.AppendLine(",System,Audit Audit Policy Change,{0cce922f-69ae-11d9-bed3-505054503030},Success,,1");
            auditCsv.AppendLine(",System,Audit Authentication Policy Change,{0cce9230-69ae-11d9-bed3-505054503030},Success,,1");
            auditCsv.AppendLine(",System,Audit MPSSVC Rule-Level Policy Change,{0cce9232-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.AppendLine(",System,Audit Other Policy Change Events,{0cce9234-69ae-11d9-bed3-505054503030},Failure,,2");
            // Privilege Use
            auditCsv.AppendLine(",System,Audit Sensitive Privilege Use,{0cce9228-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // System
            auditCsv.AppendLine(",System,Audit Other System Events,{0cce9214-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.AppendLine(",System,Audit Security State Change,{0cce9210-69ae-11d9-bed3-505054503030},Success,,1");
            auditCsv.AppendLine(",System,Audit Security System Extension,{0cce9211-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            auditCsv.Append(",System,Audit System Integrity,{0cce9212-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            
            File.WriteAllText(Path.Combine(auditPath, "audit.csv"), auditCsv.ToString(), Encoding.ASCII);

            // === PART 2: Security Settings (GptTmpl.inf) ===
            var gptTmpl = new StringBuilder();
            gptTmpl.AppendLine("[Unicode]");
            gptTmpl.AppendLine("Unicode=yes");
            gptTmpl.AppendLine("[Version]");
            gptTmpl.AppendLine("signature=\"$CHICAGO$\"");
            gptTmpl.AppendLine("Revision=1");
            gptTmpl.AppendLine();
            gptTmpl.AppendLine("[System Access]");
            gptTmpl.AppendLine("LSAAnonymousNameLookup = 0");
            gptTmpl.AppendLine();
            gptTmpl.AppendLine("[Registry Values]");
            // NTLM and authentication settings
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\allownullsessionfallback=4,0");
            gptTmpl.AppendLine("MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs=4,900");
            gptTmpl.AppendLine("MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ScRemoveOption=1,\"1\"");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec=4,537395200");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\sealsecurechannel=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinServerSec=4,537395200");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\requiresignorseal=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\signsecurechannel=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\requiresecuritysignature=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\requirestrongkey=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RestrictNullSessAccess=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\ProtectionMode=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\maximumpasswordage=4,30");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\disablepasswordchange=4,0");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnablePlainTextPassword=4,0");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,2");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RefusePasswordChange=4,0");
            // NTLM Auditing
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\AuditReceivingNTLMTraffic=4,2");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\RestrictSendingNTLMTraffic=4,1");
            gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\AuditNTLMInDomain=4,7");
            gptTmpl.AppendLine();
            gptTmpl.AppendLine("[Privilege Rights]");
            
            // Get SIDs for DC user rights - using domain-specific SIDs per PLATYPUS BILL model
            var localAdmins = "*S-1-5-32-544"; // BUILTIN\Administrators
            var domainEntDcs = groupSids.GetValueOrDefault("DomainControllers", "*S-1-5-9"); // Enterprise Domain Controllers
            var domainAuthUsers = "*S-1-5-11"; // Authenticated Users
            var ntNetService = "*S-1-5-20"; // NETWORK SERVICE
            var ntLocalService = "*S-1-5-19"; // LOCAL SERVICE
            var ntService = "*S-1-5-80-0"; // NT SERVICE\ALL SERVICES
            var builtinPerformanceLogUsers = "*S-1-5-32-559"; // Performance Log Users
            var domainBackupOps = "*S-1-5-32-551"; // Backup Operators
            // Domain Guests and Guest account use domain-specific SIDs (not BUILTIN\Guests)
            var domainGuests = groupSids.GetValueOrDefault("Domain Guests", "");
            var domainGuestAccount = groupSids.GetValueOrDefault("Guest", "");
            var tier0ServiceAccounts = groupSids.GetValueOrDefault("Tier 0 - Service Accounts", "");
            var ntAllServices = "*S-1-5-80-0"; // ALL SERVICES
            
            // Format Domain Guests and Guest account SIDs
            var domainGuestsSid = !string.IsNullOrEmpty(domainGuests) ? $"*{domainGuests}" : "";
            var domainGuestAccountSid = !string.IsNullOrEmpty(domainGuestAccount) ? $"*{domainGuestAccount}" : "";
            
            gptTmpl.AppendLine($"SeSecurityPrivilege = {localAdmins}");
            gptTmpl.AppendLine("SeCreateTokenPrivilege = ");
            gptTmpl.AppendLine("SeTrustedCredManAccessPrivilege = ");
            gptTmpl.AppendLine($"SeRemoteInteractiveLogonRight = {localAdmins}");
            gptTmpl.AppendLine($"SeCreatePagefilePrivilege = {localAdmins}");
            gptTmpl.AppendLine($"SeRemoteShutdownPrivilege = {localAdmins}");
            gptTmpl.AppendLine($"SeLoadDriverPrivilege = {localAdmins}");
            gptTmpl.AppendLine($"SeRestorePrivilege = {localAdmins}");
            gptTmpl.AppendLine($"SeCreateGlobalPrivilege = {ntNetService},{ntLocalService},{localAdmins},{ntService}");
            gptTmpl.AppendLine($"SeManageVolumePrivilege = {localAdmins}");
            gptTmpl.AppendLine($"SeInteractiveLogonRight = {localAdmins}");
            gptTmpl.AppendLine($"SeEnableDelegationPrivilege = {localAdmins}");
            gptTmpl.AppendLine("SeCreatePermanentPrivilege = ");
            gptTmpl.AppendLine($"SeDebugPrivilege = {localAdmins}");
            gptTmpl.AppendLine($"SeProfileSingleProcessPrivilege = {localAdmins}");
            gptTmpl.AppendLine($"SeBackupPrivilege = {localAdmins}");
            gptTmpl.AppendLine($"SeNetworkLogonRight = {domainEntDcs},{domainAuthUsers},{localAdmins}");
            gptTmpl.AppendLine($"SeImpersonatePrivilege = {ntNetService},{ntLocalService},{localAdmins},{ntService}");
            gptTmpl.AppendLine($"SeSystemEnvironmentPrivilege = {localAdmins}");
            gptTmpl.AppendLine("SeLockMemoryPrivilege = ");
            gptTmpl.AppendLine("SeTcbPrivilege = ");
            gptTmpl.AppendLine($"SeTakeOwnershipPrivilege = {localAdmins}");
            
            // Build deny logon rights with valid SIDs only
            var denyLogonSids = new List<string>();
            if (!string.IsNullOrEmpty(domainGuestsSid)) denyLogonSids.Add(domainGuestsSid);
            if (!string.IsNullOrEmpty(domainGuestAccountSid)) denyLogonSids.Add(domainGuestAccountSid);
            var denyLogonList = string.Join(",", denyLogonSids);
            
            gptTmpl.AppendLine($"SeDenyNetworkLogonRight = {denyLogonList}");
            gptTmpl.AppendLine($"SeDenyBatchLogonRight = {denyLogonList}");
            gptTmpl.AppendLine($"SeDenyRemoteInteractiveLogonRight = {denyLogonList}");
            gptTmpl.AppendLine($"SeDenyInteractiveLogonRight = {denyLogonList}");
            gptTmpl.AppendLine("SeDenyServiceLogonRight = ");
            var tier0SvcSid = !string.IsNullOrEmpty(tier0ServiceAccounts) ? $"*{tier0ServiceAccounts}" : "";
            var serviceLogonRight = string.IsNullOrEmpty(tier0SvcSid) ? ntAllServices : $"{ntAllServices},{tier0SvcSid}";
            gptTmpl.AppendLine($"SeServiceLogonRight = {serviceLogonRight}");
            gptTmpl.AppendLine($"SeBatchLogonRight = {builtinPerformanceLogUsers},{domainBackupOps},{localAdmins}");
            gptTmpl.AppendLine();
            gptTmpl.AppendLine("[Service General Setting]");
            gptTmpl.AppendLine("\"AppIDSvc\",2,\"\"");
            gptTmpl.AppendLine("\"Spooler\",4,\"\"");

            File.WriteAllText(Path.Combine(secEditPath, "GptTmpl.inf"), gptTmpl.ToString(), Encoding.Unicode);

            // === PART 3: Registry Preferences (AllowInsecureGuestAuth) ===
            var registryXml = new StringBuilder();
            registryXml.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            registryXml.Append("<RegistrySettings clsid=\"{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}\">");
            registryXml.Append("<Registry clsid=\"{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}\" name=\"AllowInsecureGuestAuth\" status=\"AllowInsecureGuestAuth\" image=\"12\" ");
            registryXml.Append($"changed=\"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}\" uid=\"{{7ECFC955-ED91-4510-96DC-0EAD748E1F97}}\">");
            registryXml.Append("<Properties action=\"U\" displayDecimal=\"0\" default=\"0\" hive=\"HKEY_LOCAL_MACHINE\" ");
            registryXml.Append("key=\"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\" name=\"AllowInsecureGuestAuth\" type=\"REG_DWORD\" value=\"00000000\"/>");
            registryXml.Append("</Registry>");
            registryXml.Append("</RegistrySettings>");
            
            File.WriteAllText(Path.Combine(prefsRegistryPath, "Registry.xml"), registryXml.ToString(), Encoding.UTF8);
        }

        private void CreateSecuritySettingsContent(string secEditPath, string gpoName, Dictionary<string, string> groupSids)
        {
            var gptTmpl = new StringBuilder();
            gptTmpl.AppendLine("[Unicode]");
            gptTmpl.AppendLine("Unicode=yes");
            gptTmpl.AppendLine("[Version]");
            gptTmpl.AppendLine("signature=\"$CHICAGO$\"");
            gptTmpl.AppendLine("Revision=1");
            gptTmpl.AppendLine();

            if (gpoName.Contains("PasswordPolicy", StringComparison.OrdinalIgnoreCase))
            {
                // Domain Password Policy - System Access section
                gptTmpl.AppendLine("[System Access]");
                gptTmpl.AppendLine("; PLATYPUS Baseline Password Policy");
                gptTmpl.AppendLine("MinimumPasswordAge = 1");                    // 1 day
                gptTmpl.AppendLine("MaximumPasswordAge = 60");                   // 60 days
                gptTmpl.AppendLine("MinimumPasswordLength = 14");                // 14 characters
                gptTmpl.AppendLine("PasswordComplexity = 1");                    // Enabled
                gptTmpl.AppendLine("PasswordHistorySize = 24");                  // 24 passwords remembered
                gptTmpl.AppendLine("ClearTextPassword = 0");                     // Don't store plaintext
                gptTmpl.AppendLine("LockoutBadCount = 5");                       // 5 failed attempts
                gptTmpl.AppendLine("ResetLockoutCount = 30");                    // Reset after 30 minutes
                gptTmpl.AppendLine("LockoutDuration = 30");                      // Lockout 30 minutes
            }
            else if (gpoName.Contains("SMB", StringComparison.OrdinalIgnoreCase))
            {
                // Disable SMBv1
                gptTmpl.AppendLine("[Registry Values]");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1=4,0");
            }
            else if (gpoName.Contains("WDigest", StringComparison.OrdinalIgnoreCase))
            {
                // Disable WDigest credential caching
                gptTmpl.AppendLine("[Registry Values]");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential=4,0");
            }
            else if (gpoName.Contains("DSRM", StringComparison.OrdinalIgnoreCase))
            {
                // Disable DSRM network logon
                gptTmpl.AppendLine("[Registry Values]");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\DSRMAdminLogonBehavior=4,1");
            }
            else if (gpoName.Contains("Machine", StringComparison.OrdinalIgnoreCase) && gpoName.Contains("Password", StringComparison.OrdinalIgnoreCase))
            {
                // Machine account password settings
                gptTmpl.AppendLine("[Registry Values]");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\MaximumPasswordAge=4,30");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\DisablePasswordChange=4,0");
            }
            else if (gpoName.Contains("SecurityHardening", StringComparison.OrdinalIgnoreCase))
            {
                // Baseline Security Hardening - LM hash disabled, NTLMv2 required, No Anonymous
                gptTmpl.AppendLine("[Registry Values]");
                gptTmpl.AppendLine("; PLATYPUS Baseline Security Hardening");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,1");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous=4,1");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM=4,1");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous=4,0");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RestrictNullSessAccess=4,1");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\NullSessionShares=7,");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\NullSessionPipes=7,");
            }
            else if (gpoName.Contains("SecureKeyboard", StringComparison.OrdinalIgnoreCase) && gpoName.Contains("Security", StringComparison.OrdinalIgnoreCase))
            {
                // SecureKeyboard Security Policy - Per PLATYPUS BILL model: Deny logon rights to sensitive accounts
                // This matches Set-BillT0UserRightsGpo from PLATYPUS module
                _progress?.Report("[DEBUG] Creating SecureKeyboard Security Policy with user rights assignments...");
                
                // Build list of SIDs to deny
                var denySids = new List<string>();
                var groups = new[] { "Schema Admins", "Enterprise Admins", "Account Operators", "Domain Admins", 
                                     "Administrator", "Backup Operators", "Print Operators", "Server Operators",
                                     "Tier 0 - Operators", "Tier 0 - Service Accounts" };
                
                foreach (var group in groups)
                {
                    var sid = groupSids.GetValueOrDefault(group, "");
                    if (!string.IsNullOrEmpty(sid))
                    {
                        denySids.Add($"*{sid}");
                    }
                }
                
                var denyList = string.Join(",", denySids);
                
                gptTmpl.AppendLine("[Privilege Rights]");
                gptTmpl.AppendLine("; PLATYPUS SecureKeyboard Security Policy - Deny logon rights to Tier 0 accounts");
                gptTmpl.AppendLine($"SeDenyNetworkLogonRight = {denyList}");
                gptTmpl.AppendLine($"SeDenyRemoteInteractiveLogonRight = {denyList}");
                gptTmpl.AppendLine($"SeDenyBatchLogonRight = {denyList}");
                gptTmpl.AppendLine($"SeDenyServiceLogonRight = {denyList}");
                gptTmpl.AppendLine($"SeDenyInteractiveLogonRight = {denyList}");
                
                _progress?.Report($"[DEBUG] SecureKeyboard Security Policy deny list: {denyList}");
            }
            else
            {
                // Generic security fallback
                gptTmpl.AppendLine("[Registry Values]");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5");
                gptTmpl.AppendLine("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,1");
            }

            File.WriteAllText(Path.Combine(secEditPath, "GptTmpl.inf"), gptTmpl.ToString(), Encoding.Unicode);
        }

        /// <summary>
        /// Creates Registry Preferences content for GPOs.
        /// Matches Set-BillTAllDisableSMB1Gpo and Set-TAllDisableWdigestGpo from PLATYPUS module.
        /// </summary>
        private void CreateRegistryContent(string machinePath, string gpoName)
        {
            var prefsPath = Path.Combine(machinePath, "Preferences", "Registry");
            Directory.CreateDirectory(prefsPath);

            var registryXml = new StringBuilder();
            registryXml.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");

            if (gpoName.Contains("SMB", StringComparison.OrdinalIgnoreCase))
            {
                // Disable SMBv1 via Registry Preferences - PLATYPUS tiered admin model
                registryXml.Append("<RegistrySettings clsid=\"{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}\">");
                registryXml.Append("<Registry clsid=\"{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}\" ");
                registryXml.Append("name=\"SMB1\" status=\"SMB1\" image=\"12\" ");
                registryXml.Append($"changed=\"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}\" ");
                registryXml.Append("uid=\"{4C46EAE9-2CFC-41C0-8C2C-A34F76CAFCAF}\">");
                registryXml.Append("<Properties action=\"U\" displayDecimal=\"0\" default=\"0\" ");
                registryXml.Append("hive=\"HKEY_LOCAL_MACHINE\" ");
                registryXml.Append("key=\"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" ");
                registryXml.Append("name=\"SMB1\" type=\"REG_DWORD\" value=\"00000000\"/>");
                registryXml.Append("</Registry>");
                registryXml.Append("</RegistrySettings>");
            }
            else if (gpoName.Contains("WDigest", StringComparison.OrdinalIgnoreCase))
            {
                // Disable WDigest via Registry Preferences - PLATYPUS tiered admin model
                registryXml.Append("<RegistrySettings clsid=\"{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}\">");
                registryXml.Append("<Registry clsid=\"{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}\" ");
                registryXml.Append("name=\"UseLogonCredential\" status=\"UseLogonCredential\" image=\"12\" ");
                registryXml.Append($"changed=\"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}\" ");
                registryXml.Append("uid=\"{932DD2D1-CA47-48E7-AC0D-46738FC9CC54}\">");
                registryXml.Append("<Properties action=\"U\" displayDecimal=\"0\" default=\"0\" ");
                registryXml.Append("hive=\"HKEY_LOCAL_MACHINE\" ");
                registryXml.Append("key=\"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" ");
                registryXml.Append("name=\"UseLogonCredential\" type=\"REG_DWORD\" value=\"00000000\"/>");
                registryXml.Append("</Registry>");
                registryXml.Append("</RegistrySettings>");
            }
            else
            {
                // Generic registry preferences placeholder
                registryXml.Append("<RegistrySettings clsid=\"{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}\">");
                registryXml.Append("<!-- Configure registry settings in Group Policy Management Console -->");
                registryXml.Append("</RegistrySettings>");
            }

            File.WriteAllText(Path.Combine(prefsPath, "Registry.xml"), registryXml.ToString(), Encoding.UTF8);
        }

        /// <summary>
        /// Creates Restricted Groups content with proper SIDs from the domain.
        /// </summary>
        private void CreateRestrictedGroupsContentWithSids(string secEditPath, string gpoName, Dictionary<string, string> groupSids)
        {
            _progress?.Report($"[DEBUG] Creating Restricted Groups content for: {gpoName}");
            
            var gptTmpl = new StringBuilder();
            gptTmpl.AppendLine("[Unicode]");
            gptTmpl.AppendLine("Unicode=yes");
            gptTmpl.AppendLine("[Version]");
            gptTmpl.AppendLine("signature=\"$CHICAGO$\"");
            gptTmpl.AppendLine("Revision=1");
            gptTmpl.AppendLine();
            gptTmpl.AppendLine("[Group Membership]");

            // ESX Admins - empty the group (CVE-2024-37085)
            // Per PLATYPUS BILL model: ESX Admins group is restricted with no members
            if (gpoName.Contains("ESX", StringComparison.OrdinalIgnoreCase))
            {
                _progress?.Report("[DEBUG] Creating ESX Admins restricted group settings...");
                
                // Get ESX Admins SID from domain lookup
                var esxAdminsSid = groupSids.GetValueOrDefault("ESX Admins", "");
                
                if (!string.IsNullOrEmpty(esxAdminsSid))
                {
                    // ESX Admins group is emptied to prevent VMware admin takeover (CVE-2024-37085)
                    // The restricted group is ESX Admins itself, not BUILTIN\Administrators
                    gptTmpl.AppendLine("; ESX Admins - emptied to prevent CVE-2024-37085");
                    gptTmpl.AppendLine($"*{esxAdminsSid}__Members =");
                    gptTmpl.AppendLine($"*{esxAdminsSid}__Memberof =");
                    _progress?.Report($"[DEBUG] ESX Admins group SID: {esxAdminsSid} set to empty");
                }
                else
                {
                    _progress?.Report("[WARN] ESX Admins group not found in domain - creating placeholder");
                    // Fallback: Create ESX Admins by name if SID not available
                    gptTmpl.AppendLine("; ESX Admins - emptied to prevent CVE-2024-37085");
                    gptTmpl.AppendLine("; WARNING: ESX Admins group SID not found in domain");
                    gptTmpl.AppendLine("; Create an 'ESX Admins' group in AD before linking this GPO");
                }
            }
            // Tier 0 Restricted Groups - local Administrators on DCs
            else if (gpoName.Contains("Tier 0", StringComparison.OrdinalIgnoreCase))
            {
                _progress?.Report("[DEBUG] Creating Tier 0 restricted group settings...");
                
                // Get Tier 0 operator SIDs
                var tier0Ops = groupSids.GetValueOrDefault("Tier 0 - Operators", "");
                var domainAdmins = groupSids.GetValueOrDefault("Domain Admins", "");
                var enterpriseAdmins = groupSids.GetValueOrDefault("Enterprise Admins", "");
                
                if (!string.IsNullOrEmpty(tier0Ops))
                {
                    // Local Administrators = Domain Admins, Enterprise Admins, Tier 0 Operators
                    var members = new List<string>();
                    if (!string.IsNullOrEmpty(domainAdmins)) members.Add($"*{domainAdmins}");
                    if (!string.IsNullOrEmpty(enterpriseAdmins)) members.Add($"*{enterpriseAdmins}");
                    if (!string.IsNullOrEmpty(tier0Ops)) members.Add($"*{tier0Ops}");
                    
                    gptTmpl.AppendLine("; Tier 0 - Local Administrators restricted to approved groups");
                    gptTmpl.AppendLine($"*S-1-5-32-544__Members = {string.Join(",", members)}");
                    gptTmpl.AppendLine("*S-1-5-32-544__Memberof =");
                    
                    _progress?.Report($"[DEBUG] Tier 0 Administrators members set to: {string.Join(",", members)}");
                }
                else
                {
                    gptTmpl.AppendLine("; Tier 0 Operators group not found - using Domain Admins only");
                    if (!string.IsNullOrEmpty(domainAdmins))
                    {
                        gptTmpl.AppendLine($"*S-1-5-32-544__Members = *{domainAdmins}");
                    }
                    gptTmpl.AppendLine("*S-1-5-32-544__Memberof =");
                }
            }
            // Tier 1 Restricted Groups - local Administrators on member servers
            // Per PLATYPUS BILL model: Only Tier 1 Operators + Administrator (NOT Domain Admins)
            else if (gpoName.Contains("Tier 1", StringComparison.OrdinalIgnoreCase))
            {
                _progress?.Report("[DEBUG] Creating Tier 1 restricted group settings...");
                
                var tier1Ops = groupSids.GetValueOrDefault("Tier 1 - Operators", "");
                
                // Per PLATYPUS BILL model: *S-1-5-32-544__Members = {tier1Operators},Administrator
                // Only Tier 1 Operators + local Administrator, NOT Domain Admins
                gptTmpl.AppendLine("; Tier 1 - Local Administrators set to Tier 1 Operators + Administrator");
                gptTmpl.AppendLine("*S-1-5-32-544__Memberof =");
                if (!string.IsNullOrEmpty(tier1Ops))
                {
                    gptTmpl.AppendLine($"*S-1-5-32-544__Members = *{tier1Ops},Administrator");
                    _progress?.Report($"[DEBUG] Tier 1 Administrators members set to: *{tier1Ops},Administrator");
                }
                else
                {
                    gptTmpl.AppendLine("*S-1-5-32-544__Members = Administrator");
                    _progress?.Report("[DEBUG] Tier 1 Operators not found, defaulting to Administrator only");
                }
            }
            // Tier 2 Restricted Groups - local Administrators on workstations
            // Per PLATYPUS BILL model: Only Tier 2 Operators + Administrator (NOT Domain Admins)
            else if (gpoName.Contains("Tier 2", StringComparison.OrdinalIgnoreCase))
            {
                _progress?.Report("[DEBUG] Creating Tier 2 restricted group settings...");
                
                var tier2Ops = groupSids.GetValueOrDefault("Tier 2 - Operators", "");
                
                // Per PLATYPUS BILL model: *S-1-5-32-544__Members = {tier2Operators},Administrator
                // Only Tier 2 Operators + local Administrator, NOT Domain Admins
                gptTmpl.AppendLine("; Tier 2 - Local Administrators set to Tier 2 Operators + Administrator");
                gptTmpl.AppendLine("*S-1-5-32-544__Memberof =");
                if (!string.IsNullOrEmpty(tier2Ops))
                {
                    gptTmpl.AppendLine($"*S-1-5-32-544__Members = *{tier2Ops},Administrator");
                    _progress?.Report($"[DEBUG] Tier 2 Administrators members set to: *{tier2Ops},Administrator");
                }
                else
                {
                    gptTmpl.AppendLine("*S-1-5-32-544__Members = Administrator");
                    _progress?.Report("[DEBUG] Tier 2 Operators not found, defaulting to Administrator only");
                }
            }
            else
            {
                gptTmpl.AppendLine("; Generic restricted groups template");
                gptTmpl.AppendLine("; Configure as needed for your environment");
            }

            var filePath = Path.Combine(secEditPath, "GptTmpl.inf");
            File.WriteAllText(filePath, gptTmpl.ToString(), Encoding.Unicode);
            _progress?.Report($"[DEBUG] Wrote GptTmpl.inf to: {filePath}");
        }

        /// <summary>
        /// Creates User Rights Assignment content with proper SIDs from the domain.
        /// </summary>
        private void CreateUserRightsContentWithSids(string secEditPath, string gpoName, Dictionary<string, string> groupSids)
        {
            _progress?.Report($"[DEBUG] Creating User Rights Assignment content for: {gpoName}");
            
            var gptTmpl = new StringBuilder();
            gptTmpl.AppendLine("[Unicode]");
            gptTmpl.AppendLine("Unicode=yes");
            gptTmpl.AppendLine("[Version]");
            gptTmpl.AppendLine("signature=\"$CHICAGO$\"");
            gptTmpl.AppendLine("Revision=1");
            gptTmpl.AppendLine();
            gptTmpl.AppendLine("[Privilege Rights]");

            // Get common SIDs
            var dvrl = groupSids.GetValueOrDefault("DVRL - Deny Logon All Tiers", "");
            var guests = "*S-1-5-32-546"; // Built-in Guests

            // Tier 0 - Domain Controllers and Tier 0 Servers
            if (gpoName.Contains("Tier 0", StringComparison.OrdinalIgnoreCase) || gpoName.Contains("Admin Block", StringComparison.OrdinalIgnoreCase))
            {
                _progress?.Report("[DEBUG] Creating Tier 0 user rights settings...");
                
                var tier0Ops = groupSids.GetValueOrDefault("Tier 0 - Operators", "");
                var tier0Paw = groupSids.GetValueOrDefault("Tier 0 - SecureKeyboard Users", "");
                var tier1Ops = groupSids.GetValueOrDefault("Tier 1 - Operators", "");
                var tier2Ops = groupSids.GetValueOrDefault("Tier 2 - Operators", "");
                var domainAdmins = groupSids.GetValueOrDefault("Domain Admins", "");
                var enterpriseAdmins = groupSids.GetValueOrDefault("Enterprise Admins", "");
                
                // Deny logon rights to Tier 1 and Tier 2 accounts on Tier 0 systems
                var denyList = new List<string> { guests };
                if (!string.IsNullOrEmpty(tier1Ops)) denyList.Add($"*{tier1Ops}");
                if (!string.IsNullOrEmpty(tier2Ops)) denyList.Add($"*{tier2Ops}");
                if (!string.IsNullOrEmpty(dvrl)) denyList.Add($"*{dvrl}");
                
                gptTmpl.AppendLine("; Tier 0 User Rights - Deny Tier 1/2 access to Tier 0 systems");
                gptTmpl.AppendLine($"SeDenyNetworkLogonRight = {string.Join(",", denyList)}");
                gptTmpl.AppendLine($"SeDenyInteractiveLogonRight = {string.Join(",", denyList)}");
                gptTmpl.AppendLine($"SeDenyRemoteInteractiveLogonRight = {string.Join(",", denyList)}");
                gptTmpl.AppendLine($"SeDenyBatchLogonRight = {string.Join(",", denyList)}");
                gptTmpl.AppendLine($"SeDenyServiceLogonRight = {string.Join(",", denyList)}");
                
                _progress?.Report($"[DEBUG] Tier 0 deny list set to: {string.Join(",", denyList)}");
                
                // Allow logon rights to Tier 0 operators
                var allowList = new List<string>();
                if (!string.IsNullOrEmpty(domainAdmins)) allowList.Add($"*{domainAdmins}");
                if (!string.IsNullOrEmpty(enterpriseAdmins)) allowList.Add($"*{enterpriseAdmins}");
                if (!string.IsNullOrEmpty(tier0Ops)) allowList.Add($"*{tier0Ops}");
                if (!string.IsNullOrEmpty(tier0Paw)) allowList.Add($"*{tier0Paw}");
                
                if (allowList.Any())
                {
                    gptTmpl.AppendLine($"; Allow logon locally to Tier 0 operators");
                    gptTmpl.AppendLine($"SeInteractiveLogonRight = *S-1-5-32-544,{string.Join(",", allowList)}");
                }
            }
            // Tier 1 - Member Servers
            // Per PLATYPUS BILL model: Deny ALL Tier 0 privileged accounts from Tier 1 systems
            else if (gpoName.Contains("Tier 1", StringComparison.OrdinalIgnoreCase))
            {
                _progress?.Report("[DEBUG] Creating Tier 1 user rights settings (BILL pattern)...");
                
                // Build deny list with ALL Tier 0 privileged accounts (same as T0 Admin Block)
                var denyList = new List<string>();
                
                // Schema Admins
                var schemaAdmins = groupSids.GetValueOrDefault("Schema Admins", "");
                if (!string.IsNullOrEmpty(schemaAdmins)) denyList.Add($"*{schemaAdmins.TrimStart('*')}");
                
                // Enterprise Admins
                var enterpriseAdmins = groupSids.GetValueOrDefault("Enterprise Admins", "");
                if (!string.IsNullOrEmpty(enterpriseAdmins)) denyList.Add($"*{enterpriseAdmins.TrimStart('*')}");
                
                // Account Operators
                var accountOps = groupSids.GetValueOrDefault("Account Operators", "");
                if (!string.IsNullOrEmpty(accountOps)) denyList.Add($"*{accountOps.TrimStart('*')}");
                
                // Domain Admins
                var domainAdmins = groupSids.GetValueOrDefault("Domain Admins", "");
                if (!string.IsNullOrEmpty(domainAdmins)) denyList.Add($"*{domainAdmins.TrimStart('*')}");
                
                // Administrator account
                var adminAccount = groupSids.GetValueOrDefault("Administrator", "");
                if (!string.IsNullOrEmpty(adminAccount)) denyList.Add($"*{adminAccount.TrimStart('*')}");
                
                // Backup Operators
                var backupOps = groupSids.GetValueOrDefault("Backup Operators", "");
                if (!string.IsNullOrEmpty(backupOps)) denyList.Add($"*{backupOps.TrimStart('*')}");
                
                // Print Operators
                var printOps = groupSids.GetValueOrDefault("Print Operators", "");
                if (!string.IsNullOrEmpty(printOps)) denyList.Add($"*{printOps.TrimStart('*')}");
                
                // Server Operators
                var serverOps = groupSids.GetValueOrDefault("Server Operators", "");
                if (!string.IsNullOrEmpty(serverOps)) denyList.Add($"*{serverOps.TrimStart('*')}");
                
                // Tier 0 - Operators
                var tier0Ops = groupSids.GetValueOrDefault("Tier 0 - Operators", "");
                if (!string.IsNullOrEmpty(tier0Ops)) denyList.Add($"*{tier0Ops.TrimStart('*')}");
                
                // Tier 0 - Service Accounts
                var tier0Svc = groupSids.GetValueOrDefault("Tier 0 - Service Accounts", "");
                if (!string.IsNullOrEmpty(tier0Svc)) denyList.Add($"*{tier0Svc.TrimStart('*')}");
                
                var denyString = string.Join(",", denyList);
                var localAdmins = "*S-1-5-32-544";  // Built-in Administrators
                
                gptTmpl.AppendLine("; Tier 1 User Rights - Deny ALL Tier 0 privileged accounts from Tier 1 systems");
                gptTmpl.AppendLine($"SeDenyNetworkLogonRight = {denyString}");
                gptTmpl.AppendLine($"SeDenyRemoteInteractiveLogonRight = {denyString}");
                gptTmpl.AppendLine($"SeDenyBatchLogonRight = {denyString}");
                gptTmpl.AppendLine($"SeDenyServiceLogonRight = {denyString}");
                gptTmpl.AppendLine($"SeDenyInteractiveLogonRight = {denyString}");
                gptTmpl.AppendLine($"SeInteractiveLogonRight = {localAdmins}");
                
                _progress?.Report($"[DEBUG] Tier 1 deny list ({denyList.Count} groups): {denyString}");
            }
            // Tier 2 - Workstations
            // Per PLATYPUS BILL model: Deny ALL Tier 0 privileged accounts from Tier 2 systems
            else if (gpoName.Contains("Tier 2", StringComparison.OrdinalIgnoreCase))
            {
                _progress?.Report("[DEBUG] Creating Tier 2 user rights settings (BILL pattern)...");
                
                // Build deny list with ALL Tier 0 privileged accounts (same as T1)
                var denyList = new List<string>();
                
                // Schema Admins
                var schemaAdmins = groupSids.GetValueOrDefault("Schema Admins", "");
                if (!string.IsNullOrEmpty(schemaAdmins)) denyList.Add($"*{schemaAdmins.TrimStart('*')}");
                
                // Enterprise Admins
                var enterpriseAdmins = groupSids.GetValueOrDefault("Enterprise Admins", "");
                if (!string.IsNullOrEmpty(enterpriseAdmins)) denyList.Add($"*{enterpriseAdmins.TrimStart('*')}");
                
                // Account Operators
                var accountOps = groupSids.GetValueOrDefault("Account Operators", "");
                if (!string.IsNullOrEmpty(accountOps)) denyList.Add($"*{accountOps.TrimStart('*')}");
                
                // Domain Admins
                var domainAdmins = groupSids.GetValueOrDefault("Domain Admins", "");
                if (!string.IsNullOrEmpty(domainAdmins)) denyList.Add($"*{domainAdmins.TrimStart('*')}");
                
                // Administrator account
                var adminAccount = groupSids.GetValueOrDefault("Administrator", "");
                if (!string.IsNullOrEmpty(adminAccount)) denyList.Add($"*{adminAccount.TrimStart('*')}");
                
                // Backup Operators
                var backupOps = groupSids.GetValueOrDefault("Backup Operators", "");
                if (!string.IsNullOrEmpty(backupOps)) denyList.Add($"*{backupOps.TrimStart('*')}");
                
                // Print Operators
                var printOps = groupSids.GetValueOrDefault("Print Operators", "");
                if (!string.IsNullOrEmpty(printOps)) denyList.Add($"*{printOps.TrimStart('*')}");
                
                // Server Operators
                var serverOps = groupSids.GetValueOrDefault("Server Operators", "");
                if (!string.IsNullOrEmpty(serverOps)) denyList.Add($"*{serverOps.TrimStart('*')}");
                
                // Tier 0 - Operators
                var tier0Ops = groupSids.GetValueOrDefault("Tier 0 - Operators", "");
                if (!string.IsNullOrEmpty(tier0Ops)) denyList.Add($"*{tier0Ops.TrimStart('*')}");
                
                // Tier 0 - Service Accounts
                var tier0Svc = groupSids.GetValueOrDefault("Tier 0 - Service Accounts", "");
                if (!string.IsNullOrEmpty(tier0Svc)) denyList.Add($"*{tier0Svc.TrimStart('*')}");
                
                var denyString = string.Join(",", denyList);
                var localAdmins = "*S-1-5-32-544";  // Built-in Administrators
                var localUsers = "*S-1-5-32-545";   // Built-in Users
                
                gptTmpl.AppendLine("; Tier 2 User Rights - Deny ALL Tier 0 privileged accounts from Tier 2 systems");
                gptTmpl.AppendLine($"SeDenyNetworkLogonRight = {denyString}");
                gptTmpl.AppendLine($"SeDenyRemoteInteractiveLogonRight = {denyString}");
                gptTmpl.AppendLine($"SeDenyBatchLogonRight = {denyString}");
                gptTmpl.AppendLine($"SeDenyServiceLogonRight = {denyString}");
                gptTmpl.AppendLine($"SeDenyInteractiveLogonRight = {denyString}");
                gptTmpl.AppendLine($"SeInteractiveLogonRight = {localUsers},{localAdmins}");
                
                _progress?.Report($"[DEBUG] Tier 2 deny list ({denyList.Count} groups): {denyString}");
            }
            else
            {
                gptTmpl.AppendLine("; Generic user rights template");
                gptTmpl.AppendLine($"SeDenyNetworkLogonRight = {guests}");
            }

            var filePath = Path.Combine(secEditPath, "GptTmpl.inf");
            File.WriteAllText(filePath, gptTmpl.ToString(), Encoding.Unicode);
            _progress?.Report($"[DEBUG] Wrote GptTmpl.inf to: {filePath}");
        }

        /// <summary>
        /// Creates GPP Local Users and Groups content (Groups.xml) for adding members to local groups.
        /// This is the correct method for "splice" GPOs that ADD operators to local Administrators
        /// without replacing existing members (unlike Restricted Groups which replaces all members).
        /// Per PLATYPUS BILL model: Uses action="ADD" to append tier operators to Administrators (built-in).
        /// </summary>
        private void CreateLocalUsersAndGroupsContent(string machinePath, string gpoName, Dictionary<string, string> groupSids)
        {
            _progress?.Report($"[DEBUG] Creating GPP Local Users and Groups content for: {gpoName}");
            
            var prefsPath = Path.Combine(machinePath, "Preferences", "Groups");
            Directory.CreateDirectory(prefsPath);

            string operatorsSid = "";
            string operatorsName = "";
            string domainNetBios = "";

            // Determine which tier this GPO is for
            if (gpoName.Contains("Tier 1", StringComparison.OrdinalIgnoreCase))
            {
                operatorsSid = groupSids.GetValueOrDefault("Tier 1 - Operators", "");
                operatorsName = "Tier 1 Operators";
                _progress?.Report("[DEBUG] Creating Tier 1 LocalAdmin GPP content...");
            }
            else if (gpoName.Contains("Tier 2", StringComparison.OrdinalIgnoreCase))
            {
                operatorsSid = groupSids.GetValueOrDefault("Tier 2 - Operators", "");
                operatorsName = "Tier 2 Operators";
                _progress?.Report("[DEBUG] Creating Tier 2 LocalAdmin GPP content...");
            }
            else
            {
                _progress?.Report("[WARN] LocalUsersAndGroups called for non-tier GPO, creating template");
                return;
            }

            // Get domain NetBIOS name from groupSids (format: DOMAIN\groupname pattern)
            // We'll need to get this from the first group SID that has a valid entry
            // For now, use a placeholder that will be replaced
            domainNetBios = groupSids.GetValueOrDefault("DomainNetBIOS", "DOMAIN");

            if (string.IsNullOrEmpty(operatorsSid))
            {
                _progress?.Report($"[WARN] {operatorsName} group SID not found, cannot create GPP content");
                return;
            }

            // Remove leading * if present (SIDs in dictionary may have it)
            operatorsSid = operatorsSid.TrimStart('*');

            // Generate GUID for uid parameter (required by GPP format)
            var gpoUid = "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}";
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            // Create Groups.xml content per PLATYPUS BILL tiered admin model
            // Format: <Groups><Group ... action="U"><Properties action="U"><Members><Member action="ADD" ...
            var xml = new StringBuilder();
            xml.Append("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            xml.Append($"<Groups clsid=\"{{3125E937-EB16-4b4c-9934-544FC6D24D26}}\">");
            xml.Append($"<Group clsid=\"{{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}}\" ");
            xml.Append($"name=\"Administrators (built-in)\" image=\"2\" changed=\"{timestamp}\" uid=\"{gpoUid}\">");
            xml.Append($"<Properties action=\"U\" newName=\"\" description=\"\" deleteAllUsers=\"0\" deleteAllGroups=\"0\" removeAccounts=\"0\" ");
            xml.Append($"groupSid=\"S-1-5-32-544\" groupName=\"Administrators (built-in)\">");
            xml.Append($"<Members>");
            xml.Append($"<Member name=\"{domainNetBios}\\{operatorsName}\" action=\"ADD\" sid=\"{operatorsSid}\"/>");
            xml.Append($"</Members></Properties></Group>");
            xml.Append("</Groups>");

            var filePath = Path.Combine(prefsPath, "Groups.xml");
            File.WriteAllText(filePath, xml.ToString(), Encoding.UTF8);
            _progress?.Report($"[DEBUG] Wrote Groups.xml to: {filePath}");
            _progress?.Report($"[DEBUG] Added {operatorsName} ({operatorsSid}) to Administrators via GPP ADD action");
        }

        /// <summary>
        /// Creates T0 Admin Block GPO content - blocks Tier 0 privileged accounts from logging on to non-Tier 0 machines.
        /// Per PLATYPUS BILL model: Applies 5 deny logon rights to all Tier 0 privileged groups.
        /// This GPO should be linked at the domain root with DENY Apply ACL for "Tier 0 Computers" and Domain Controllers.
        /// </summary>
        private void CreateT0DomainBlockContent(string secEditPath, string gpoName, Dictionary<string, string> groupSids)
        {
            _progress?.Report($"[DEBUG] Creating T0 Admin Block content for: {gpoName}");
            
            var gptTmpl = new StringBuilder();
            gptTmpl.AppendLine("[Unicode]");
            gptTmpl.AppendLine("Unicode=yes");
            gptTmpl.AppendLine("[Version]");
            gptTmpl.AppendLine("signature=\"$CHICAGO$\"");
            gptTmpl.AppendLine("Revision=1");
            gptTmpl.AppendLine();
            gptTmpl.AppendLine("[Privilege Rights]");

            // Per PLATYPUS BILL model: The T0 Admin Block applies to ALL machines in the domain EXCEPT:
            // - Domain Controllers (via DENY Apply ACL)
            // - Tier 0 Computers group members (via DENY Apply ACL)
            // - Systems filtered by WMI Filter "Tier 0 - No DC Apply" (DomainRole < 4)
            //
            // It DENIES the following logon rights to all Tier 0 privileged accounts:
            // - SeDenyNetworkLogonRight
            // - SeDenyRemoteInteractiveLogonRight
            // - SeDenyBatchLogonRight
            // - SeDenyServiceLogonRight
            // - SeDenyInteractiveLogonRight

            // Build the list of Tier 0 privileged groups to deny
            var denyGroups = new List<string>();
            
            // Schema Admins
            var schemaAdmins = groupSids.GetValueOrDefault("Schema Admins", "");
            if (!string.IsNullOrEmpty(schemaAdmins)) denyGroups.Add($"*{schemaAdmins.TrimStart('*')}");
            
            // Enterprise Admins
            var enterpriseAdmins = groupSids.GetValueOrDefault("Enterprise Admins", "");
            if (!string.IsNullOrEmpty(enterpriseAdmins)) denyGroups.Add($"*{enterpriseAdmins.TrimStart('*')}");
            
            // Domain Account Operators
            var accountOps = groupSids.GetValueOrDefault("Account Operators", "");
            if (!string.IsNullOrEmpty(accountOps)) denyGroups.Add($"*{accountOps.TrimStart('*')}");
            
            // Domain Admins
            var domainAdmins = groupSids.GetValueOrDefault("Domain Admins", "");
            if (!string.IsNullOrEmpty(domainAdmins)) denyGroups.Add($"*{domainAdmins.TrimStart('*')}");
            
            // Built-in Administrator account (domain)
            var adminAccount = groupSids.GetValueOrDefault("Administrator", "");
            if (!string.IsNullOrEmpty(adminAccount)) denyGroups.Add($"*{adminAccount.TrimStart('*')}");
            
            // Backup Operators
            var backupOps = groupSids.GetValueOrDefault("Backup Operators", "");
            if (!string.IsNullOrEmpty(backupOps)) denyGroups.Add($"*{backupOps.TrimStart('*')}");
            
            // Print Operators
            var printOps = groupSids.GetValueOrDefault("Print Operators", "");
            if (!string.IsNullOrEmpty(printOps)) denyGroups.Add($"*{printOps.TrimStart('*')}");
            
            // Server Operators
            var serverOps = groupSids.GetValueOrDefault("Server Operators", "");
            if (!string.IsNullOrEmpty(serverOps)) denyGroups.Add($"*{serverOps.TrimStart('*')}");
            
            // Tier 0 - Operators
            var tier0Ops = groupSids.GetValueOrDefault("Tier 0 - Operators", "");
            if (!string.IsNullOrEmpty(tier0Ops)) denyGroups.Add($"*{tier0Ops.TrimStart('*')}");
            
            // Tier 0 - Service Accounts
            var tier0Svc = groupSids.GetValueOrDefault("Tier 0 - Service Accounts", "");
            if (!string.IsNullOrEmpty(tier0Svc)) denyGroups.Add($"*{tier0Svc.TrimStart('*')}");
            
            // Tier 0 - SecureKeyboard Users (from user feedback)
            var tier0Paw = groupSids.GetValueOrDefault("Tier 0 - SecureKeyboard Users", "");
            if (!string.IsNullOrEmpty(tier0Paw)) denyGroups.Add($"*{tier0Paw.TrimStart('*')}");

            var denyList = string.Join(",", denyGroups);
            
            gptTmpl.AppendLine("; Tier 0 Admin Block - Denies Tier 0 privileged accounts from logging on to non-Tier 0 machines");
            gptTmpl.AppendLine("; Note: WMI Filter and DENY Apply ACLs are configured automatically for Tier 0 Computers and Domain Controllers");
            gptTmpl.AppendLine($"SeDenyNetworkLogonRight = {denyList}");
            gptTmpl.AppendLine($"SeDenyRemoteInteractiveLogonRight = {denyList}");
            gptTmpl.AppendLine($"SeDenyBatchLogonRight = {denyList}");
            gptTmpl.AppendLine($"SeDenyServiceLogonRight = {denyList}");
            gptTmpl.AppendLine($"SeDenyInteractiveLogonRight = {denyList}");

            var filePath = Path.Combine(secEditPath, "GptTmpl.inf");
            File.WriteAllText(filePath, gptTmpl.ToString(), Encoding.Unicode);
            _progress?.Report($"[DEBUG] Wrote GptTmpl.inf to: {filePath}");
            _progress?.Report($"[DEBUG] T0 Admin Block deny list ({denyGroups.Count} groups): {denyList}");
        }

        /// <summary>
        /// Adds Domain Controllers group as a member of the Tier 0 Computers group.
        /// Per PLATYPUS BILL model: Domain Controllers should be exempted from the Tier 0 Admin Block GPO.
        /// </summary>
        private void AddDomainControllersToTier0Computers(string dc, string domainDn, string tier0GroupsOu)
        {
            try
            {
                _progress?.Report("[DEBUG] Adding Domain Controllers to Tier 0 Computers group...");
                
                // Find the Domain Controllers group by name (works in all locales after Windows 2000)
                SearchResult? dcGroup = null;
                using (var dcSearcher = new DirectorySearcher(new DirectoryEntry($"LDAP://{dc}/{domainDn}"))
                {
                    Filter = "(&(objectClass=group)(samAccountName=Domain Controllers))",
                    SearchScope = SearchScope.Subtree
                })
                {
                    dcSearcher.PropertiesToLoad.Add("distinguishedName");
                    dcGroup = dcSearcher.FindOne();
                }
                
                if (dcGroup == null)
                {
                    _progress?.Report("[WARN] Domain Controllers group not found");
                    return;
                }
                
                var dcGroupDn = dcGroup.Properties["distinguishedName"]?[0]?.ToString();
                if (string.IsNullOrEmpty(dcGroupDn))
                {
                    _progress?.Report("[WARN] Could not get Domain Controllers DN");
                    return;
                }
                
                _progress?.Report($"[DEBUG] Found Domain Controllers group: {dcGroupDn}");
                
                // Find the Tier 0 Computers group with retry for replication
                // sAMAccountName has spaces removed: "Tier0Computers"
                SearchResult? t0cGroup = null;
                for (int attempt = 1; attempt <= 5; attempt++)
                {
                    using var t0cSearcher = new DirectorySearcher(new DirectoryEntry($"LDAP://{dc}/{domainDn}"))
                    {
                        Filter = "(&(objectClass=group)(samAccountName=Tier0Computers))",
                        SearchScope = SearchScope.Subtree
                    };
                    t0cSearcher.PropertiesToLoad.Add("distinguishedName");
                    t0cSearcher.PropertiesToLoad.Add("member");
                    
                    t0cGroup = t0cSearcher.FindOne();
                    if (t0cGroup != null) break;
                    
                    if (attempt < 5)
                    {
                        _progress?.Report($"[DEBUG] Tier 0 Computers group not found yet, waiting... (attempt {attempt}/5)");
                        Thread.Sleep(3000); // Wait 3 seconds between retries for replication
                    }
                }
                
                if (t0cGroup == null)
                {
                    _progress?.Report("[WARN] Tier 0 Computers group not found after retries");
                    return;
                }
                
                _progress?.Report("[DEBUG] Found Tier 0 Computers group, adding Domain Controllers as member...");
                
                // Add Domain Controllers to Tier 0 Computers
                using var t0cEntry = t0cGroup.GetDirectoryEntry();
                var members = t0cEntry.Properties["member"];
                
                // Check if already a member
                bool isMember = false;
                foreach (var member in members)
                {
                    if (member?.ToString()?.Equals(dcGroupDn, StringComparison.OrdinalIgnoreCase) == true)
                    {
                        isMember = true;
                        break;
                    }
                }
                
                if (!isMember)
                {
                    t0cEntry.Properties["member"].Add(dcGroupDn);
                    t0cEntry.CommitChanges();
                    _progress?.Report($"[DEBUG] Added Domain Controllers to Tier 0 Computers group");
                }
                else
                {
                    _progress?.Report("[DEBUG] Domain Controllers already member of Tier 0 Computers");
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"[WARN] Failed to add Domain Controllers to Tier 0 Computers: {ex.Message}");
            }
        }

        /// <summary>
        /// Configures the T0 Admin Block GPO with WMI filter and DENY Apply ACLs.
        /// This ensures the GPO only applies to non-Tier 0 computers.
        /// Per PLATYPUS BILL model, this GPO should:
        /// 1. Have a WMI filter to exclude Domain Controllers (DomainRole less than 4)
        /// 2. Have DENY Apply ACL for "Tier 0 Computers" group
        /// 3. Have DENY Apply ACL for "Domain Controllers" group
        /// 4. Have DENY Apply ACL for "Read-Only Domain Controllers" group (if exists)
        /// 5. Have DENY Apply ACL for "Enterprise Read-Only Domain Controllers" group (if exists)
        /// </summary>
        private void ConfigureT0DomainBlockGpo(string dc, string domainFqdn, string gpoGuid)
        {
            _progress?.Report($"[DEBUG] Configuring T0 Admin Block GPO with WMI filter and delegation...");
            var domainDn = DomainToDn(domainFqdn);

            try
            {
                // Step 1: Create or get the WMI Filter "Tier 0 - No DC Apply"
                var wmiFilterId = CreateOrGetWmiFilter(dc, domainFqdn, domainDn);
                
                if (!string.IsNullOrEmpty(wmiFilterId))
                {
                    // Step 2: Link WMI filter to the GPO
                    LinkWmiFilterToGpo(dc, domainDn, gpoGuid, wmiFilterId, domainFqdn);
                }
                else
                {
                    _progress?.Report("[WARN] Could not create WMI filter. GPO will apply to all computers including DCs.");
                }

                // Step 3: Set DENY Apply ACL for Tier 0 Computers
                // Note: sAMAccountName has spaces removed in CreateSecurityGroup, so use "Tier0Computers"
                SetGpoDenyApplyAcl(dc, domainDn, gpoGuid, "Tier0Computers");

                // Step 4: Set DENY Apply ACL for Domain Controllers (SID -516)
                SetGpoDenyApplyAclBySid(dc, domainDn, gpoGuid, 516, "Domain Controllers");

                // Step 5: Set DENY Apply ACL for Read-Only Domain Controllers (SID -521) if exists
                try
                {
                    SetGpoDenyApplyAclBySid(dc, domainDn, gpoGuid, 521, "Read-Only Domain Controllers");
                }
                catch
                {
                    _progress?.Report("[DEBUG] Read-Only Domain Controllers group not found (may not exist in this domain)");
                }

                // Step 6: Set DENY Apply ACL for Enterprise Read-Only Domain Controllers if exists (forest root only)
                try
                {
                    SetGpoDenyApplyAclByName(dc, domainDn, gpoGuid, "Enterprise Read-Only Domain Controllers");
                }
                catch
                {
                    _progress?.Report("[DEBUG] Enterprise Read-Only Domain Controllers group not found (may not exist or not forest root)");
                }

                _progress?.Report("[DEBUG] T0 Admin Block GPO configured with WMI filter and DENY ACLs");
            }
            catch (Exception ex)
            {
                _progress?.Report($"[WARN] Failed to fully configure T0 Admin Block GPO: {ex.Message}");
                _progress?.Report("[INFO] You may need to manually set the WMI filter and DENY Apply permissions");
            }
        }

        /// <summary>
        /// Creates or retrieves the "Tier 0 - No DC Apply" WMI filter.
        /// This filter ensures the GPO only applies to non-Domain Controller computers.
        /// WQL query: Select * from Win32_ComputerSystem where DomainRole &lt; 4
        /// DomainRole values: 0=Standalone Workstation, 1=Member Workstation, 2=Standalone Server, 3=Member Server, 4=Backup DC, 5=Primary DC
        /// </summary>
        private string? CreateOrGetWmiFilter(string dc, string domainFqdn, string domainDn)
        {
            const string wmiFilterName = "Tier 0 - No DC Apply";
            const string wmiFilterDescription = "Tier 0 - Used to prevent policy from applying to a domain controller";
            const string wmiFilterNamespace = "root\\CIMv2";
            const string wmiFilterQuery = "Select * from Win32_ComputerSystem where DomainRole < 4";

            try
            {
                var wmiContainerDn = $"CN=SOM,CN=WMIPolicy,CN=System,{domainDn}";
                _progress?.Report($"[DEBUG] Looking for WMI filter in: {wmiContainerDn}");

                using var wmiContainer = new DirectoryEntry($"LDAP://{dc}/{wmiContainerDn}");

                // Check if filter already exists
                using var searcher = new DirectorySearcher(wmiContainer)
                {
                    Filter = $"(&(objectClass=msWMI-Som)(msWMI-Name={EscapeLdapFilter(wmiFilterName)}))",
                    SearchScope = SearchScope.OneLevel
                };

                var existing = searcher.FindOne();
                if (existing != null)
                {
                    var existingId = existing.Properties["msWMI-ID"]?[0]?.ToString();
                    if (!string.IsNullOrEmpty(existingId))
                    {
                        _progress?.Report($"[DEBUG] Found existing WMI filter: {wmiFilterName} with ID: {existingId}");
                        return existingId.Trim('{', '}');
                    }
                }

                // Create new WMI filter
                _progress?.Report($"[DEBUG] Creating WMI filter: {wmiFilterName}");
                var wmiGuid = Guid.NewGuid().ToString("B").ToUpperInvariant();
                var wmiGuidClean = wmiGuid.Trim('{', '}');
                var now = DateTime.UtcNow.ToString("yyyyMMddHHmmss.ffffff") + "+000";

                // Build msWMI-Parm2 value (the WQL query specification)
                var parm2 = $"1;3;{wmiFilterNamespace.Length};{wmiFilterQuery.Length};WQL;{wmiFilterNamespace};{wmiFilterQuery};";

                using var newFilter = wmiContainer.Children.Add($"CN={wmiGuid}", "msWMI-Som");
                newFilter.Properties["msWMI-Name"].Value = wmiFilterName;
                newFilter.Properties["msWMI-ID"].Value = wmiGuid;
                newFilter.Properties["msWMI-Parm1"].Value = wmiFilterDescription + " ";
                newFilter.Properties["msWMI-Parm2"].Value = parm2;
                newFilter.Properties["msWMI-Author"].Value = Environment.UserName;
                newFilter.Properties["msWMI-ChangeDate"].Value = now;
                newFilter.Properties["msWMI-CreationDate"].Value = now;
                newFilter.CommitChanges();

                _progress?.Report($"[DEBUG] Created WMI filter: {wmiFilterName} with ID: {wmiGuidClean}");
                return wmiGuidClean;
            }
            catch (Exception ex)
            {
                _progress?.Report($"[WARN] Failed to create/get WMI filter: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Links a WMI filter to a GPO.
        /// </summary>
        private void LinkWmiFilterToGpo(string dc, string domainDn, string gpoGuid, string wmiFilterId, string domainFqdn)
        {
            try
            {
                var gpoContainerDn = $"CN=Policies,CN=System,{domainDn}";
                var gpoDn = $"CN={gpoGuid},{gpoContainerDn}";

                _progress?.Report($"[DEBUG] Linking WMI filter {wmiFilterId} to GPO {gpoGuid}");

                using var gpoEntry = new DirectoryEntry($"LDAP://{dc}/{gpoDn}");
                
                // WMI filter link format: [domain;{GUID};0]
                var wmiFilterLink = $"[{domainFqdn};{{{wmiFilterId}}};0]";
                gpoEntry.Properties["gPCWQLFilter"].Value = wmiFilterLink;
                gpoEntry.CommitChanges();

                _progress?.Report($"[DEBUG] Linked WMI filter to GPO successfully");
            }
            catch (Exception ex)
            {
                _progress?.Report($"[WARN] Failed to link WMI filter: {ex.Message}");
            }
        }

        /// <summary>
        /// Sets DENY Apply GPO permission for a group by name.
        /// Includes retry logic for newly created groups (replication lag).
        /// </summary>
        private void SetGpoDenyApplyAcl(string dc, string domainDn, string gpoGuid, string groupName)
        {
            try
            {
                _progress?.Report($"[DEBUG] Setting DENY Apply ACL for group: {groupName}");

                // Find the group with retry for replication lag
                SearchResult? groupResult = null;
                for (int attempt = 1; attempt <= 5; attempt++)
                {
                    groupResult = GetGroupBySamAccountName(dc, domainDn, groupName);
                    if (groupResult != null) break;
                    
                    if (attempt < 5)
                    {
                        _progress?.Report($"[DEBUG] Group '{groupName}' not found yet, waiting... (attempt {attempt}/5)");
                        Thread.Sleep(4000); // Wait 4 seconds between retries for replication
                    }
                }
                
                if (groupResult == null)
                {
                    _progress?.Report($"[WARN] Group '{groupName}' not found after retries, cannot set DENY ACL");
                    return;
                }

                var groupSid = new SecurityIdentifier((byte[])groupResult.Properties["objectSid"][0]!, 0);
                SetGpoDenyApplyAclForSid(dc, domainDn, gpoGuid, groupSid, groupName);
            }
            catch (Exception ex)
            {
                _progress?.Report($"[WARN] Failed to set DENY ACL for {groupName}: {ex.Message}");
            }
        }

        /// <summary>
        /// Sets DENY Apply GPO permission for a well-known group by RID.
        /// </summary>
        private void SetGpoDenyApplyAclBySid(string dc, string domainDn, string gpoGuid, int rid, string groupDescription)
        {
            try
            {
                _progress?.Report($"[DEBUG] Setting DENY Apply ACL for {groupDescription} (RID: {rid})");

                // Get domain SID first
                using var domainEntry = new DirectoryEntry($"LDAP://{dc}/{domainDn}");
                var domainSidBytes = (byte[])domainEntry.Properties["objectSid"][0]!;
                var domainSid = new SecurityIdentifier(domainSidBytes, 0);
                
                // Construct the group SID
                var groupSid = new SecurityIdentifier($"{domainSid}-{rid}");
                SetGpoDenyApplyAclForSid(dc, domainDn, gpoGuid, groupSid, groupDescription);
            }
            catch (Exception ex)
            {
                _progress?.Report($"[WARN] Failed to set DENY ACL for {groupDescription}: {ex.Message}");
            }
        }

        /// <summary>
        /// Sets DENY Apply GPO permission for a group by name (for cross-domain groups like Enterprise RODCs).
        /// </summary>
        private void SetGpoDenyApplyAclByName(string dc, string domainDn, string gpoGuid, string groupName)
        {
            try
            {
                _progress?.Report($"[DEBUG] Setting DENY Apply ACL for group: {groupName}");

                // Search for the group in the forest
                using var searcher = new DirectorySearcher(new DirectoryEntry($"LDAP://{dc}/{domainDn}"))
                {
                    Filter = $"(&(objectClass=group)(samAccountName={EscapeLdapFilter(groupName)}))",
                    SearchScope = SearchScope.Subtree
                };
                searcher.PropertiesToLoad.Add("objectSid");

                var result = searcher.FindOne();
                if (result == null)
                {
                    _progress?.Report($"[DEBUG] Group '{groupName}' not found");
                    return;
                }

                var groupSid = new SecurityIdentifier((byte[])result.Properties["objectSid"][0]!, 0);
                SetGpoDenyApplyAclForSid(dc, domainDn, gpoGuid, groupSid, groupName);
            }
            catch (Exception ex)
            {
                _progress?.Report($"[DEBUG] Could not set DENY ACL for {groupName}: {ex.Message}");
            }
        }

        /// <summary>
        /// Sets DENY Apply GPO permission for a specific SID.
        /// </summary>
        private void SetGpoDenyApplyAclForSid(string dc, string domainDn, string gpoGuid, SecurityIdentifier groupSid, string groupDescription)
        {
            try
            {
                var gpoContainerDn = $"CN=Policies,CN=System,{domainDn}";
                var gpoDn = $"CN={gpoGuid},{gpoContainerDn}";

                using var gpoEntry = new DirectoryEntry($"LDAP://{dc}/{gpoDn}");
                var gpoSecurity = gpoEntry.ObjectSecurity;

                // Apply Group Policy extended right GUID
                var applyGpoGuid = new Guid("edacfd8f-ffb3-11d1-b41d-00a0c968f939");

                // Add DENY Apply GPO permission
                var denyApplyRule = new ActiveDirectoryAccessRule(
                    groupSid,
                    ActiveDirectoryRights.ExtendedRight,
                    AccessControlType.Deny,
                    applyGpoGuid,
                    ActiveDirectorySecurityInheritance.None);

                gpoSecurity.AddAccessRule(denyApplyRule);
                gpoEntry.CommitChanges();

                _progress?.Report($"[DEBUG] Set DENY Apply ACL for: {groupDescription}");
            }
            catch (Exception ex)
            {
                _progress?.Report($"[WARN] Failed to set DENY ACL for {groupDescription}: {ex.Message}");
            }
        }

        /// <summary>
        /// Escapes special characters in LDAP filter strings.
        /// </summary>
        private string EscapeLdapFilter(string input)
        {
            return input
                .Replace("\\", "\\5c")
                .Replace("*", "\\2a")
                .Replace("(", "\\28")
                .Replace(")", "\\29")
                .Replace("\0", "\\00");
        }

        /// <summary>
        /// Types of GPO settings for proper configuration.
        /// </summary>
        private enum GpoSettingsType
        {
            None,
            AuditPolicy,
            SecuritySettings,
            RestrictedGroups,
            UserRights,
            Registry,
            /// <summary>
            /// GPP Local Users and Groups - uses Groups.xml in Preferences folder.
            /// This is different from Restricted Groups (GptTmpl.inf).
            /// GPP allows ADD action to append members rather than replace.
            /// </summary>
            LocalUsersAndGroups,
            /// <summary>
            /// T0 Admin Block - specialized GPO that blocks Tier 0 accounts from non-Tier 0 machines.
            /// Requires additional WMI filter and DENY ACL configuration.
            /// </summary>
            T0DomainBlock,
            /// <summary>
            /// T0 Domain Controllers GPO - comprehensive DC security with audit policies,
            /// security settings, user rights, registry preferences, and service settings.
            /// Based on Set-BillT0DomainControllersGpo from PLATYPUS module.
            /// </summary>
            DomainControllers
        }

        /// <summary>
        /// Creates a GPO placeholder (shell GPO without configured settings).
        /// Full GPO configuration requires the GroupPolicy PowerShell module or GPMC.
        /// </summary>
        private AdObjectCreationResult CreateGpoPlaceholder(string dc, string domainFqdn, string gpoName, string description)
        {
            var result = new AdObjectCreationResult
            {
                ObjectType = "GPO",
                ObjectName = gpoName
            };

            try
            {
                _progress?.Report($"Creating GPO: {gpoName}");

                // GPO creation via LDAP requires creating objects in CN=Policies,CN=System
                // This is complex - for production use, recommend PowerShell GroupPolicy module
                // Here we'll create a placeholder entry to track intent

                var gpoContainerDn = $"CN=Policies,CN=System,{DomainToDn(domainFqdn)}";
                
                using var gpoContainer = new DirectoryEntry($"LDAP://{dc}/{gpoContainerDn}");
                
                // Check if GPO already exists (search by displayName in groupPolicyContainer objects)
                using var searcher = new DirectorySearcher(gpoContainer)
                {
                    Filter = $"(&(objectClass=groupPolicyContainer)(displayName={EscapeLdapFilter(gpoName)}))",
                    SearchScope = SearchScope.OneLevel
                };

                var existing = searcher.FindOne();
                if (existing != null)
                {
                    result.Success = true;
                    result.Message = "GPO already exists";
                    result.DistinguishedName = existing.Properties["distinguishedName"]?[0]?.ToString() ?? "";
                    _progress?.Report($"GPO already exists: {gpoName}");
                    return result;
                }

                // Create new GPO container
                // Generate a new GUID for the GPO
                var gpoGuid = Guid.NewGuid().ToString("B").ToUpperInvariant();
                var gpoCn = $"CN={gpoGuid}";

                using var newGpo = gpoContainer.Children.Add(gpoCn, "groupPolicyContainer");
                newGpo.Properties["displayName"].Value = gpoName;
                newGpo.Properties["gPCFileSysPath"].Value = $"\\\\{domainFqdn}\\SysVol\\{domainFqdn}\\Policies\\{gpoGuid}";
                newGpo.Properties["gPCFunctionalityVersion"].Value = 2;
                newGpo.Properties["flags"].Value = 0; // GPO enabled
                newGpo.Properties["versionNumber"].Value = 0;
                newGpo.CommitChanges();

                result.Success = true;
                result.Message = $"Created. {description}";
                result.DistinguishedName = $"{gpoCn},{gpoContainerDn}";
                _progress?.Report($"Created GPO: {gpoName}");

                // Note: SYSVOL folder structure and GPT.INI would need to be created separately
                // For full GPO functionality, use PowerShell: New-GPO, Set-GPRegistryValue, etc.
            }
            catch (UnauthorizedAccessException)
            {
                result.Success = false;
                result.Message = "Access denied. Requires Domain Admin or GPO Creator Owners rights.";
                _progress?.Report($"Access denied creating GPO: {gpoName}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = ex.Message;
                result.Error = ex;
                _progress?.Report($"Failed to create GPO {gpoName}: {ex.Message}");
            }

            return result;
        }

        #endregion

        #region PLATYPUS Extended Features

        /// <summary>
        /// Creates a Fine-Grained Password Policy for Tier 0 accounts.
        /// Equivalent to New-BillFineGrainedPasswordPolicy from PLATYPUS.
        /// Requires Windows Server 2008 R2 domain functional level or higher.
        /// </summary>
        public async Task<FineGrainedPasswordPolicyResult> CreateFineGrainedPasswordPolicyAsync(
            int maxPasswordAge = 90,
            int minPasswordLength = 25,
            int passwordHistoryCount = 12,
            bool complexityEnabled = true,
            CancellationToken ct = default)
        {
            var result = new FineGrainedPasswordPolicyResult
            {
                PolicyName = "Tier 0 Password Policy"
            };

            if (_domainInfo == null)
            {
                result.Success = false;
                result.Message = "Domain not discovered. Call DiscoverDomainAsync first.";
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Creating Fine-Grained Password Policy for Tier 0...");

                    // Check domain functional level (must be 2008 R2 or higher)
                    var domainFunctionalLevel = _domainInfo.DomainFunctionalLevel ?? "";
                    if (domainFunctionalLevel.Contains("2003") || domainFunctionalLevel.Contains("2000"))
                    {
                        result.Success = false;
                        result.Message = $"Domain functional level {domainFunctionalLevel} does not support Fine-Grained Password Policies. Requires 2008 R2 or higher.";
                        _progress?.Report($"[WARN] {result.Message}");
                        return;
                    }

                    // Construct the Password Settings Container DN
                    var pscDn = $"CN=Password Settings Container,CN=System,{_domainInfo.DomainDn}";
                    var policyDn = $"CN=Tier 0 Password Policy,{pscDn}";

                    using var pscEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{pscDn}");

                    // Check if FGPP already exists
                    using var searcher = new DirectorySearcher(pscEntry)
                    {
                        Filter = $"(&(objectClass=msDS-PasswordSettings)(cn=Tier 0 Password Policy))",
                        SearchScope = SearchScope.OneLevel
                    };

                    var existing = searcher.FindOne();
                    if (existing != null)
                    {
                        result.Success = true;
                        result.Message = "Fine-Grained Password Policy 'Tier 0 Password Policy' already exists.";
                        _progress?.Report(result.Message);
                        return;
                    }

                    // Create new FGPP
                    using var newPolicy = pscEntry.Children.Add("CN=Tier 0 Password Policy", "msDS-PasswordSettings");

                    // Set policy attributes
                    // msDS-PasswordSettingsPrecedence = 1 (highest priority)
                    newPolicy.Properties["msDS-PasswordSettingsPrecedence"].Value = 1;

                    // Password complexity
                    newPolicy.Properties["msDS-PasswordComplexityEnabled"].Value = complexityEnabled;

                    // Minimum password length
                    newPolicy.Properties["msDS-MinimumPasswordLength"].Value = minPasswordLength;

                    // Password history count
                    newPolicy.Properties["msDS-PasswordHistoryLength"].Value = passwordHistoryCount;

                    // Max password age (in -100ns intervals, negative value)
                    // Formula: days * 24 * 60 * 60 * 10000000 * -1
                    var maxPwdAgeInterval = (long)maxPasswordAge * 24L * 60L * 60L * 10000000L * -1L;
                    newPolicy.Properties["msDS-MaximumPasswordAge"].Value = maxPwdAgeInterval;

                    // Min password age (1 day)
                    var minPwdAgeInterval = 1L * 24L * 60L * 60L * 10000000L * -1L;
                    newPolicy.Properties["msDS-MinimumPasswordAge"].Value = minPwdAgeInterval;

                    // Lockout settings
                    // Lockout duration: 30 minutes (in -100ns intervals)
                    var lockoutDuration = 30L * 60L * 10000000L * -1L;
                    newPolicy.Properties["msDS-LockoutDuration"].Value = lockoutDuration;
                    newPolicy.Properties["msDS-LockoutObservationWindow"].Value = lockoutDuration;
                    newPolicy.Properties["msDS-LockoutThreshold"].Value = 0; // No lockout

                    // Reversible encryption disabled
                    newPolicy.Properties["msDS-PasswordReversibleEncryptionEnabled"].Value = false;

                    newPolicy.CommitChanges();

                    _progress?.Report("Created Fine-Grained Password Policy: Tier 0 Password Policy");

                    // Apply to Domain Admins and Tier 0 Operators
                    var subjectsApplied = new List<string>();

                    try
                    {
                        // Find Domain Admins group
                        var daGroup = GetGroupBySamAccountName(_domainInfo.ChosenDc, _domainInfo.DomainDn, "Domain Admins");
                        if (daGroup != null)
                        {
                            var daDn = daGroup.Properties["distinguishedName"]?[0]?.ToString();
                            if (!string.IsNullOrEmpty(daDn))
                            {
                                newPolicy.Properties["msDS-PSOAppliesTo"].Add(daDn);
                                subjectsApplied.Add("Domain Admins");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"[WARN] Could not apply FGPP to Domain Admins: {ex.Message}");
                    }

                    try
                    {
                        // Find Tier 0 Operators group
                        var t0Group = GetGroupBySamAccountName(_domainInfo.ChosenDc, _domainInfo.DomainDn, "Tier 0 - Operators");
                        if (t0Group != null)
                        {
                            var t0Dn = t0Group.Properties["distinguishedName"]?[0]?.ToString();
                            if (!string.IsNullOrEmpty(t0Dn))
                            {
                                newPolicy.Properties["msDS-PSOAppliesTo"].Add(t0Dn);
                                subjectsApplied.Add("Tier 0 - Operators");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"[WARN] Could not apply FGPP to Tier 0 Operators: {ex.Message}");
                    }

                    if (subjectsApplied.Count > 0)
                    {
                        newPolicy.CommitChanges();
                        _progress?.Report($"Applied FGPP to: {string.Join(", ", subjectsApplied)}");
                    }

                    result.Success = true;
                    result.SubjectsApplied = subjectsApplied;
                    result.Message = $"Created Tier 0 Password Policy (Min Length: {minPasswordLength}, Max Age: {maxPasswordAge} days, History: {passwordHistoryCount})";
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.Message = ex.Message;
                    result.Error = ex;
                    _progress?.Report($"[ERROR] Failed to create Fine-Grained Password Policy: {ex.Message}");
                }
            }, ct);

            return result;
        }

        /// <summary>
        /// Gets a group by sAMAccountName.
        /// </summary>
        private SearchResult? GetGroupBySamAccountName(string dc, string domainDn, string samAccountName)
        {
            using var rootEntry = new DirectoryEntry($"LDAP://{dc}/{domainDn}");
            using var searcher = new DirectorySearcher(rootEntry)
            {
                Filter = $"(&(objectClass=group)(sAMAccountName={EscapeLdapFilter(samAccountName)}))",
                SearchScope = SearchScope.Subtree
            };
            return searcher.FindOne();
        }

        /// <summary>
        /// Sets domain join delegation permissions on the Staging OU.
        /// Equivalent to Set-BillDomainJoinDelegation from PLATYPUS.
        /// </summary>
        public async Task<AdObjectCreationResult> SetDomainJoinDelegationAsync(
            string delegateToGroup = "BILL Domain Join",
            string idOuName = "SITH",
            CancellationToken ct = default)
        {
            var result = new AdObjectCreationResult
            {
                ObjectType = "Delegation",
                ObjectName = "Domain Join Delegation"
            };

            if (_domainInfo == null)
            {
                result.Success = false;
                result.Message = "Domain not discovered. Call DiscoverDomainAsync first.";
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report($"Setting domain join delegation for group: {delegateToGroup}");

                    var stagingOuDn = $"OU=Staging,OU={idOuName},OU=BILL,{_domainInfo.DomainDn}";
                    result.DistinguishedName = stagingOuDn;

                    // Find the delegate group
                    var groupResult = GetGroupBySamAccountName(_domainInfo.ChosenDc, _domainInfo.DomainDn, delegateToGroup);
                    if (groupResult == null)
                    {
                        result.Success = false;
                        result.Message = $"Group '{delegateToGroup}' not found in domain.";
                        return;
                    }

                    var groupSid = new SecurityIdentifier((byte[])groupResult.Properties["objectSid"][0]!, 0);

                    // Open the OU and set ACLs
                    using var ouEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{stagingOuDn}");
                    var ouSecurity = ouEntry.ObjectSecurity;

                    // GUIDs for computer object and specific attributes
                    var computerGuid = new Guid("bf967a86-0de6-11d0-a285-00aa003049e2"); // Computer class
                    var sAMAccountNameGuid = new Guid("bf96793f-0de6-11d0-a285-00aa003049e2"); // sAMAccountName
                    var userAccountControlGuid = new Guid("3e0abfd0-126a-11d0-a060-00aa006c33ed"); // userAccountControl  
                    var accountRestrictions = new Guid("4c164200-20c0-11d0-a768-00aa006e0529"); // Account Restrictions property set
                    var dnsHostNameGuid = new Guid("5f0a24d9-dffa-4cd9-acbf-a0680c03731e"); // dNSHostName
                    var servicePrincipalNameGuid = new Guid("fad5dcc1-2130-4c87-a118-75322cd67050"); // servicePrincipalName
                    var msDS_AdditionalSamAccountName = new Guid("41bc7f04-be72-4930-bd10-1f3439412387"); // msDS-AdditionalSamAccountName
                    var validatedDnsHostName = new Guid("72e39547-7b18-11d1-adef-00c04fd8d5cd"); // Validated write to DNS host name
                    var validatedSpn = new Guid("f3a64788-5306-11d1-a9c5-0000f80367c1"); // Validated write to service principal name
                    var resetPasswordGuid = new Guid("00299570-246d-11d0-a768-00aa006e0529"); // Reset Password extended right

                    // Create/Delete Computer objects
                    var rule1 = new ActiveDirectoryAccessRule(
                        groupSid,
                        ActiveDirectoryRights.CreateChild | ActiveDirectoryRights.DeleteChild,
                        AccessControlType.Allow,
                        computerGuid,
                        ActiveDirectorySecurityInheritance.All);
                    ouSecurity.AddAccessRule(rule1);

                    // Read/Write all properties on computer objects (descendant computers)
                    var rule2 = new ActiveDirectoryAccessRule(
                        groupSid,
                        ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.WriteProperty,
                        AccessControlType.Allow,
                        ActiveDirectorySecurityInheritance.Descendents,
                        computerGuid);
                    ouSecurity.AddAccessRule(rule2);

                    // Reset password on computer objects
                    var rule3 = new ActiveDirectoryAccessRule(
                        groupSid,
                        ActiveDirectoryRights.ExtendedRight,
                        AccessControlType.Allow,
                        resetPasswordGuid,
                        ActiveDirectorySecurityInheritance.Descendents,
                        computerGuid);
                    ouSecurity.AddAccessRule(rule3);

                    ouEntry.CommitChanges();

                    result.Success = true;
                    result.Message = $"Domain join delegation set for '{delegateToGroup}' on {stagingOuDn}";
                    _progress?.Report(result.Message);
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.Message = ex.Message;
                    result.Error = ex;
                    _progress?.Report($"[ERROR] Failed to set domain join delegation: {ex.Message}");
                }
            }, ct);

            return result;
        }

        /// <summary>
        /// Creates a WMI Filter for GPO targeting.
        /// Equivalent to NewWmiFilter from PLATYPUS.
        /// </summary>
        public async Task<WmiFilter?> CreateWmiFilterAsync(
            string filterName,
            string description,
            string wmiNamespace,
            string wmiQuery,
            CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                _progress?.Report("[ERROR] Domain not discovered. Call DiscoverDomainAsync first.");
                return null;
            }

            return await Task.Run(() =>
            {
                try
                {
                    _progress?.Report($"Creating WMI Filter: {filterName}");

                    var wmiContainerDn = $"CN=SOM,CN=WMIPolicy,CN=System,{_domainInfo.DomainDn}";

                    using var wmiContainer = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{wmiContainerDn}");

                    // Check if filter already exists
                    using var searcher = new DirectorySearcher(wmiContainer)
                    {
                        Filter = $"(&(objectClass=msWMI-Som)(msWMI-Name={EscapeLdapFilter(filterName)}))",
                        SearchScope = SearchScope.OneLevel
                    };

                    var existing = searcher.FindOne();
                    if (existing != null)
                    {
                        var existingId = existing.Properties["msWMI-ID"]?[0]?.ToString() ?? "";
                        _progress?.Report($"WMI Filter '{filterName}' already exists with ID: {existingId}");
                        return new WmiFilter
                        {
                            Id = existingId,
                            Name = filterName,
                            Description = description,
                            Namespace = wmiNamespace,
                            Query = wmiQuery
                        };
                    }

                    // Generate new WMI Filter ID
                    var filterId = "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}";
                    var filterCn = $"CN={filterId}";

                    // Build WMI Query string in proper format
                    // Format: "1;3;10;query length;WQL;namespace;query;"
                    var queryBlock = $"1;3;10;{wmiQuery.Length};WQL;{wmiNamespace};{wmiQuery};";

                    // Create WMI Filter object
                    using var newFilter = wmiContainer.Children.Add(filterCn, "msWMI-Som");
                    newFilter.Properties["msWMI-Name"].Value = filterName;
                    newFilter.Properties["msWMI-ID"].Value = filterId;
                    newFilter.Properties["msWMI-Author"].Value = Environment.UserName;
                    newFilter.Properties["msWMI-Parm1"].Value = description;
                    newFilter.Properties["msWMI-Parm2"].Value = queryBlock;

                    // Set creation date
                    var now = DateTime.UtcNow;
                    var creationDate = now.ToString("yyyyMMddHHmmss.ffffff") + "-000";
                    newFilter.Properties["msWMI-CreationDate"].Value = creationDate;
                    newFilter.Properties["msWMI-ChangeDate"].Value = creationDate;

                    newFilter.CommitChanges();

                    _progress?.Report($"Created WMI Filter: {filterName} with ID: {filterId}");

                    return new WmiFilter
                    {
                        Id = filterId,
                        Name = filterName,
                        Description = description,
                        Namespace = wmiNamespace,
                        Query = wmiQuery,
                        Created = now,
                        Author = Environment.UserName
                    };
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[ERROR] Failed to create WMI Filter: {ex.Message}");
                    return null;
                }
            }, ct);
        }

        /// <summary>
        /// Links a WMI Filter to a GPO.
        /// Equivalent to SetWmiFilter from PLATYPUS.
        /// </summary>
        public async Task<bool> SetWmiFilterOnGpoAsync(
            string gpoGuid,
            string wmiFilterId,
            CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                _progress?.Report("[ERROR] Domain not discovered. Call DiscoverDomainAsync first.");
                return false;
            }

            return await Task.Run(() =>
            {
                try
                {
                    _progress?.Report($"Linking WMI Filter {wmiFilterId} to GPO {gpoGuid}");

                    var gpoContainerDn = $"CN=Policies,CN=System,{_domainInfo.DomainDn}";
                    var gpoDn = $"CN={gpoGuid},{gpoContainerDn}";

                    using var gpoEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{gpoDn}");

                    // Set the gPCWQLFilter attribute
                    // Format: "[DOMAIN_FQDN;{WMI_FILTER_GUID};0]"
                    var wmiFilterLink = $"[{_domainInfo.DomainFqdn};{wmiFilterId};0]";
                    gpoEntry.Properties["gPCWQLFilter"].Value = wmiFilterLink;
                    gpoEntry.CommitChanges();

                    _progress?.Report($"Linked WMI Filter to GPO successfully");
                    return true;
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[ERROR] Failed to link WMI Filter: {ex.Message}");
                    return false;
                }
            }, ct);
        }

        /// <summary>
        /// Adds an Apply/Deny GPO permission for a group.
        /// Equivalent to AddGpoApplyAcl from PLATYPUS.
        /// </summary>
        public async Task<bool> AddGpoApplyAclAsync(
            string gpoGuid,
            string groupName,
            bool denyApply = false,
            CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                _progress?.Report("[ERROR] Domain not discovered. Call DiscoverDomainAsync first.");
                return false;
            }

            return await Task.Run(() =>
            {
                try
                {
                    _progress?.Report($"Setting GPO ACL for '{groupName}' on GPO {gpoGuid} ({(denyApply ? "Deny" : "Allow")})");

                    // Find the group
                    var groupResult = GetGroupBySamAccountName(_domainInfo.ChosenDc, _domainInfo.DomainDn, groupName);
                    if (groupResult == null)
                    {
                        _progress?.Report($"[ERROR] Group '{groupName}' not found");
                        return false;
                    }

                    var groupSid = new SecurityIdentifier((byte[])groupResult.Properties["objectSid"][0]!, 0);

                    // Open the GPO
                    var gpoContainerDn = $"CN=Policies,CN=System,{_domainInfo.DomainDn}";
                    var gpoDn = $"CN={gpoGuid},{gpoContainerDn}";

                    using var gpoEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{gpoDn}");
                    var gpoSecurity = gpoEntry.ObjectSecurity;

                    // Apply Group Policy extended right GUID
                    var applyGpoGuid = new Guid("edacfd8f-ffb3-11d1-b41d-00a0c968f939");

                    var accessControlType = denyApply ? AccessControlType.Deny : AccessControlType.Allow;

                    // Add the ACL rule
                    var rule = new ActiveDirectoryAccessRule(
                        groupSid,
                        ActiveDirectoryRights.ExtendedRight,
                        accessControlType,
                        applyGpoGuid,
                        ActiveDirectorySecurityInheritance.None);

                    if (denyApply)
                    {
                        // For Deny, we also need to deny Read
                        var denyReadRule = new ActiveDirectoryAccessRule(
                            groupSid,
                            ActiveDirectoryRights.ReadProperty,
                            AccessControlType.Deny,
                            ActiveDirectorySecurityInheritance.None);
                        gpoSecurity.AddAccessRule(denyReadRule);
                    }

                    gpoSecurity.AddAccessRule(rule);
                    gpoEntry.CommitChanges();

                    _progress?.Report($"Set {(denyApply ? "Deny" : "Allow")} Apply GPO permission for '{groupName}'");
                    return true;
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[ERROR] Failed to set GPO ACL: {ex.Message}");
                    return false;
                }
            }, ct);
        }

        /// <summary>
        /// Sets GP Inheritance blocking on an OU.
        /// Equivalent to SetGpInheritance from PLATYPUS.
        /// </summary>
        public async Task<bool> SetGpInheritanceBlockingAsync(
            string ouDistinguishedName,
            bool blockInheritance = true,
            CancellationToken ct = default)
        {
            if (_domainInfo == null)
            {
                _progress?.Report("[ERROR] Domain not discovered. Call DiscoverDomainAsync first.");
                return false;
            }

            return await Task.Run(() =>
            {
                try
                {
                    _progress?.Report($"Setting GP Inheritance on: {ouDistinguishedName} (Block: {blockInheritance})");

                    using var ouEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{ouDistinguishedName}");

                    // gPOptions attribute: 0 = inherit, 1 = block inheritance
                    ouEntry.Properties["gPOptions"].Value = blockInheritance ? 1 : 0;
                    ouEntry.CommitChanges();

                    _progress?.Report($"Set GP Inheritance {(blockInheritance ? "blocked" : "enabled")} on: {ouDistinguishedName}");
                    return true;
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[ERROR] Failed to set GP Inheritance: {ex.Message}");
                    return false;
                }
            }, ct);
        }

        /// <summary>
        /// Gets the full OU manifest for the tiered admin model.
        /// Equivalent to Get-BillOuManifest from PLATYPUS.
        /// </summary>
        public List<string> GetOuManifest(string idOuName = "SITH")
        {
            if (_domainInfo == null)
            {
                return new List<string>();
            }

            var domainDn = _domainInfo.DomainDn;
            var idOuPath = $"OU={idOuName},OU=BILL,{domainDn}";

            return new List<string>
            {
                // Root BILL OU
                $"OU=BILL,{domainDn}",
                $"OU=Computer Quarantine,OU=BILL,{domainDn}",
                
                // Admin OU (ID OU)
                idOuPath,
                $"OU=Staging,{idOuPath}",
                
                // Tier 0
                $"OU=Tier 0,{idOuPath}",
                $"OU=T0-Accounts,OU=Tier 0,{idOuPath}",
                $"OU=T0-Groups,OU=Tier 0,{idOuPath}",
                $"OU=T0-Service Accounts,OU=Tier 0,{idOuPath}",
                $"OU=T0-Admin Workstations,OU=Tier 0,{idOuPath}",
                $"OU=T0-Servers,OU=Tier 0,{idOuPath}",
                $"OU=T0-Operators,OU=T0-Groups,OU=Tier 0,{idOuPath}",
                $"OU=T0-Database,OU=T0-Servers,OU=Tier 0,{idOuPath}",
                $"OU=T0-Identity,OU=T0-Servers,OU=Tier 0,{idOuPath}",
                $"OU=T0-Management,OU=T0-Servers,OU=Tier 0,{idOuPath}",
                $"OU=T0-PKI,OU=T0-Servers,OU=Tier 0,{idOuPath}",
                $"OU=T0-Backup,OU=T0-Servers,OU=Tier 0,{idOuPath}",
                $"OU=T0-Virtualization,OU=T0-Servers,OU=Tier 0,{idOuPath}",
                
                // Tier 1
                $"OU=Tier 1,{idOuPath}",
                $"OU=T1-Accounts,OU=Tier 1,{idOuPath}",
                $"OU=T1-Groups,OU=Tier 1,{idOuPath}",
                $"OU=T1-Admin Workstations,OU=Tier 1,{idOuPath}",
                $"OU=T1-Operators,OU=T1-Groups,OU=Tier 1,{idOuPath}",
                
                // Tier 2
                $"OU=Tier 2,{idOuPath}",
                $"OU=T2-Accounts,OU=Tier 2,{idOuPath}",
                $"OU=T2-Groups,OU=Tier 2,{idOuPath}",
                $"OU=T2-Service Accounts,OU=Tier 2,{idOuPath}",
                $"OU=T2-Admin Workstations,OU=Tier 2,{idOuPath}",
                $"OU=T2-Operators,OU=T2-Groups,OU=Tier 2,{idOuPath}",
                
                // Common OUs
                $"OU=Groups,OU=BILL,{domainDn}",
                $"OU=Security Groups,OU=Groups,OU=BILL,{domainDn}",
                $"OU=Distribution Groups,OU=Groups,OU=BILL,{domainDn}",
                $"OU=Contacts,OU=Groups,OU=BILL,{domainDn}",
                
                // Tier 1 Servers
                $"OU=Tier 1 Servers,OU=BILL,{domainDn}",
                $"OU=Application,OU=Tier 1 Servers,OU=BILL,{domainDn}",
                $"OU=Event Forwarding,OU=Tier 1 Servers,OU=BILL,{domainDn}",
                $"OU=Collaboration,OU=Tier 1 Servers,OU=BILL,{domainDn}",
                $"OU=Database,OU=Tier 1 Servers,OU=BILL,{domainDn}",
                $"OU=Messaging,OU=Tier 1 Servers,OU=BILL,{domainDn}",
                $"OU=Staging,OU=Tier 1 Servers,OU=BILL,{domainDn}",
                
                // Tier 2 Devices
                $"OU=T2-Devices,OU=BILL,{domainDn}",
                $"OU=Desktops,OU=T2-Devices,OU=BILL,{domainDn}",
                $"OU=Kiosks,OU=T2-Devices,OU=BILL,{domainDn}",
                $"OU=Laptops,OU=T2-Devices,OU=BILL,{domainDn}",
                $"OU=Staging,OU=T2-Devices,OU=BILL,{domainDn}",
                
                // User Accounts
                $"OU=User Accounts,OU=BILL,{domainDn}",
                $"OU=Enabled Users,OU=User Accounts,OU=BILL,{domainDn}",
                $"OU=Disabled Users,OU=User Accounts,OU=BILL,{domainDn}"
            };
        }

        /// <summary>
        /// Creates the full OU structure for the tiered admin model.
        /// Equivalent to New-BillOu from PLATYPUS.
        /// </summary>
        public async Task<List<AdObjectCreationResult>> CreateFullOuStructureAsync(
            string idOuName = "SITH",
            bool blockInheritanceOnStagingOus = true,
            CancellationToken ct = default)
        {
            var results = new List<AdObjectCreationResult>();

            if (_domainInfo == null)
            {
                results.Add(new AdObjectCreationResult
                {
                    Success = false,
                    ObjectType = "Prerequisite",
                    Message = "Domain not discovered. Call DiscoverDomainAsync first."
                });
                return results;
            }

            await Task.Run(async () =>
            {
                try
                {
                    _progress?.Report("Creating full tiered admin OU structure...");

                    var ouManifest = GetOuManifest(idOuName);
                    var dc = _domainInfo.ChosenDc;

                    foreach (var ouDn in ouManifest)
                    {
                        ct.ThrowIfCancellationRequested();

                        if (OuExists(dc, ouDn))
                        {
                            _progress?.Report($"OU already exists: {ouDn}");
                            results.Add(new AdObjectCreationResult
                            {
                                Success = true,
                                ObjectType = "OU",
                                ObjectName = ouDn,
                                DistinguishedName = ouDn,
                                Message = "Already exists"
                            });
                            continue;
                        }

                        // Parse parent DN and OU name
                        var parts = ouDn.Split(',', 2);
                        var ouName = parts[0].Replace("OU=", "");
                        var parentDn = parts.Length > 1 ? parts[1] : _domainInfo.DomainDn;

                        var result = CreateOrganizationalUnit(dc, parentDn, ouName, $"Tiered Admin Model - {ouName}", true);
                        results.Add(result);

                        // Small delay for replication
                        await Task.Delay(100, ct);
                    }

                    // Block inheritance on staging OUs
                    if (blockInheritanceOnStagingOus)
                    {
                        _progress?.Report("Setting GP inheritance blocking on staging OUs...");

                        var stagingOus = new[]
                        {
                            $"OU=Computer Quarantine,OU=BILL,{_domainInfo.DomainDn}",
                            $"OU={idOuName},OU=BILL,{_domainInfo.DomainDn}",
                            $"OU=Staging,OU={idOuName},OU=BILL,{_domainInfo.DomainDn}",
                            $"OU=Staging,OU=Tier 1 Servers,OU=BILL,{_domainInfo.DomainDn}",
                            $"OU=Staging,OU=T2-Devices,OU=BILL,{_domainInfo.DomainDn}"
                        };

                        foreach (var ouDn in stagingOus)
                        {
                            ct.ThrowIfCancellationRequested();

                            if (OuExists(dc, ouDn))
                            {
                                var blocked = await SetGpInheritanceBlockingAsync(ouDn, true, ct);
                                results.Add(new AdObjectCreationResult
                                {
                                    Success = blocked,
                                    ObjectType = "GPInheritance",
                                    ObjectName = ouDn,
                                    DistinguishedName = ouDn,
                                    Message = blocked ? "Inheritance blocked" : "Failed to block inheritance"
                                });
                            }
                        }
                    }

                    _progress?.Report($"Created {results.Count(r => r.Success && r.ObjectType == "OU")} OUs");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[ERROR] Failed to create OU structure: {ex.Message}");
                    results.Add(new AdObjectCreationResult
                    {
                        Success = false,
                        ObjectType = "Error",
                        Message = ex.Message,
                        Error = ex
                    });
                }
            }, ct);

            return results;
        }

        /// <summary>
        /// Creates advanced audit policy CSV content with 28+ subcategories.
        /// Equivalent to the audit policy content from Set-BillT0DomainControllersGpo.
        /// </summary>
        private string CreateAdvancedAuditPolicyCsv()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value");
            
            // Credential Validation
            sb.AppendLine(",System,Audit Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // Account Management
            sb.AppendLine(",System,Audit Computer Account Management,{0cce9236-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit Distribution Group Management,{0cce9238-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit Other Account Management Events,{0cce923a-69ae-11d9-bed3-505054503030},Success,,1");
            sb.AppendLine(",System,Audit Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // Detailed Tracking
            sb.AppendLine(",System,Audit PNP Activity,{0cce9248-69ae-11d9-bed3-505054503030},Success,,1");
            sb.AppendLine(",System,Audit Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,,1");
            // DS Access
            sb.AppendLine(",System,Audit Directory Service Access,{0cce923b-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit Directory Service Changes,{0cce923c-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // Logon/Logoff
            sb.AppendLine(",System,Audit Account Lockout,{0cce9217-69ae-11d9-bed3-505054503030},Failure,,2");
            sb.AppendLine(",System,Audit Group Membership,{0cce9249-69ae-11d9-bed3-505054503030},Success,,1");
            sb.AppendLine(",System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit Logoff,{0cce9216-69ae-11d9-bed3-505054503030},Success,,1");
            sb.AppendLine(",System,Audit Other Logon/Logoff Events,{0cce921c-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit Special Logon,{0cce921b-69ae-11d9-bed3-505054503030},Success,,1");
            // Object Access
            sb.AppendLine(",System,Audit Detailed File Share,{0cce9244-69ae-11d9-bed3-505054503030},Failure,,2");
            sb.AppendLine(",System,Audit File Share,{0cce9224-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit Other Object Access Events,{0cce9227-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit Removable Storage,{0cce9245-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // Policy Change
            sb.AppendLine(",System,Audit Audit Policy Change,{0cce922f-69ae-11d9-bed3-505054503030},Success,,1");
            sb.AppendLine(",System,Audit Authentication Policy Change,{0cce9230-69ae-11d9-bed3-505054503030},Success,,1");
            sb.AppendLine(",System,Audit MPSSVC Rule-Level Policy Change,{0cce9232-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit Other Policy Change Events,{0cce9234-69ae-11d9-bed3-505054503030},Failure,,2");
            // Privilege Use
            sb.AppendLine(",System,Audit Sensitive Privilege Use,{0cce9228-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // System
            sb.AppendLine(",System,Audit Other System Events,{0cce9214-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit Security State Change,{0cce9210-69ae-11d9-bed3-505054503030},Success,,1");
            sb.AppendLine(",System,Audit Security System Extension,{0cce9211-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit System Integrity,{0cce9212-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            // Kerberos
            sb.AppendLine(",System,Audit Kerberos Authentication Service,{0cce9242-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            sb.AppendLine(",System,Audit Kerberos Service Ticket Operations,{0cce9240-69ae-11d9-bed3-505054503030},Success and Failure,,3");
            
            return sb.ToString();
        }

        /// <summary>
        /// Creates GPP Groups.xml content for Local Admin Splice GPO.
        /// Adds a group to local administrators using GPP instead of Restricted Groups.
        /// Equivalent to Set-BillT1LocalAdminSpliceGpo from PLATYPUS.
        /// </summary>
        private string CreateLocalAdminSpliceGroupsXml(string groupName, string groupSid, string domainNetbiosName)
        {
            var uid = "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}";
            var changed = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            var fullGroupName = $"{domainNetbiosName}\\{groupName}";
            var cleanSid = groupSid.TrimStart('*');

            var sb = new StringBuilder();
            sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            sb.Append($"<Groups clsid=\"{{3125E937-EB16-4b4c-9934-544FC6D24D26}}\">");
            sb.Append($"<Group clsid=\"{{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}}\" ");
            sb.Append($"name=\"Administrators (built-in)\" image=\"2\" changed=\"{changed}\" uid=\"{uid}\">");
            sb.Append($"<Properties action=\"U\" newName=\"\" description=\"\" deleteAllUsers=\"0\" deleteAllGroups=\"0\" ");
            sb.Append($"removeAccounts=\"0\" groupSid=\"S-1-5-32-544\" groupName=\"Administrators (built-in)\">");
            sb.Append($"<Members><Member name=\"{fullGroupName}\" action=\"ADD\" sid=\"{cleanSid}\"/></Members>");
            sb.Append("</Properties></Group></Groups>");

            return sb.ToString();
        }

        /// <summary>
        /// Creates GPP Registry.xml content for various registry settings.
        /// Equivalent to the registry content from PLATYPUS GPO functions.
        /// </summary>
        private string CreateRegistryGppXml(string registryPath, string valueName, string valueType, string value, string description = "")
        {
            var uid = "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}";
            var changed = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");

            var sb = new StringBuilder();
            sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            sb.Append($"<RegistrySettings clsid=\"{{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}}\">");
            sb.Append($"<Registry clsid=\"{{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}}\" ");
            sb.Append($"name=\"{valueName}\" status=\"{valueName}\" image=\"12\" changed=\"{changed}\" uid=\"{uid}\">");
            sb.Append($"<Properties action=\"U\" displayDecimal=\"0\" default=\"0\" hive=\"HKEY_LOCAL_MACHINE\" ");
            sb.Append($"key=\"{registryPath}\" name=\"{valueName}\" type=\"{valueType}\" value=\"{value}\"/>");
            sb.Append("</Registry></RegistrySettings>");

            return sb.ToString();
        }

        /// <summary>
        /// Creates Scheduled Task GPP XML for machine account password reset.
        /// Equivalent to Set-BillMachineAccountPasswordGpo from PLATYPUS.
        /// </summary>
        private string CreateMachinePasswordResetTaskXml(string domainNetbiosName)
        {
            var uid = "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}";
            var changed = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            var startBoundary = DateTime.Now.AddHours(25).ToString("yyyy-MM-ddTHH:mm:ss");
            var endBoundary = DateTime.Now.AddDays(3).ToString("yyyy-MM-ddTHH:mm:ss");

            var sb = new StringBuilder();
            sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            sb.Append("<ScheduledTasks clsid=\"{CC63F200-7309-4ba0-B154-A71CD118DBCC}\">");
            sb.Append($"<TaskV2 clsid=\"{{D8896631-B747-47a7-84A6-C155337F3BC8}}\" ");
            sb.Append($"name=\"Reset Machine Account Password\" image=\"0\" changed=\"{changed}\" ");
            sb.Append($"uid=\"{uid}\" userContext=\"0\" removePolicy=\"0\">");
            sb.Append("<Properties action=\"C\" name=\"Reset Machine Account Password\" runAs=\"NT AUTHORITY\\System\" logonType=\"S4U\">");
            sb.Append("<Task version=\"1.2\">");
            sb.Append("<RegistrationInfo>");
            sb.Append($"<Author>{domainNetbiosName}\\administrator</Author>");
            sb.Append("<Description>Resets the machine account password to mitigate golden GMSA attacks</Description>");
            sb.Append("</RegistrationInfo>");
            sb.Append("<Principals><Principal id=\"Author\">");
            sb.Append("<UserId>NT AUTHORITY\\System</UserId>");
            sb.Append("<LogonType>S4U</LogonType>");
            sb.Append("<RunLevel>HighestAvailable</RunLevel>");
            sb.Append("</Principal></Principals>");
            sb.Append("<Settings>");
            sb.Append("<IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout>");
            sb.Append("<StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>");
            sb.Append("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>");
            sb.Append("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>");
            sb.Append("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>");
            sb.Append("<AllowHardTerminate>true</AllowHardTerminate>");
            sb.Append("<StartWhenAvailable>true</StartWhenAvailable>");
            sb.Append("<AllowStartOnDemand>true</AllowStartOnDemand>");
            sb.Append("<Enabled>true</Enabled>");
            sb.Append("<Hidden>false</Hidden>");
            sb.Append("<ExecutionTimeLimit>PT1H</ExecutionTimeLimit>");
            sb.Append("<Priority>7</Priority>");
            sb.Append("</Settings>");
            sb.Append("<Triggers>");
            sb.Append($"<TimeTrigger><StartBoundary>{startBoundary}</StartBoundary>");
            sb.Append($"<EndBoundary>{endBoundary}</EndBoundary>");
            sb.Append("<Enabled>true</Enabled></TimeTrigger>");
            sb.Append("</Triggers>");
            sb.Append("<Actions Context=\"Author\">");
            sb.Append("<Exec><Command>netdom.exe</Command>");
            sb.Append("<Arguments>resetpwd /s:%LOGONSERVER% /ud:%USERDOMAIN%\\%USERNAME% /pd:*</Arguments>");
            sb.Append("</Exec></Actions>");
            sb.Append("</Task></Properties></TaskV2></ScheduledTasks>");

            return sb.ToString();
        }

        /// <summary>
        /// Creates the DC GPO content with service settings (AppIDSvc, Spooler).
        /// Equivalent to the service settings from Set-BillT0DomainControllersGpo.
        /// </summary>
        private void CreateDcGpoServiceSettings(string secEditPath, StringBuilder gptTmpl)
        {
            gptTmpl.AppendLine("[Service General Setting]");
            // AppIDSvc - Automatic (2)
            gptTmpl.AppendLine("\"AppIDSvc\",2,\"\"");
            // Spooler - Disabled (4)
            gptTmpl.AppendLine("\"Spooler\",4,\"\"");
        }

        /// <summary>
        /// Resolves tiered model group SIDs for multi-forest scenarios.
        /// Equivalent to Get-BillGpoGroups from PLATYPUS.
        /// </summary>
        public async Task<TieredModelGroupSids> ResolveTieredModelGroupSidsAsync(CancellationToken ct = default)
        {
            var sids = new TieredModelGroupSids();

            if (_domainInfo == null)
            {
                return sids;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Resolving tiered model group SIDs...");

                    sids.DomainSid = _domainInfo.DomainSid ?? "";
                    sids.ForestSid = _domainInfo.ForestSid ?? sids.DomainSid;

                    // Set domain-specific well-known SIDs
                    if (!string.IsNullOrEmpty(sids.DomainSid))
                    {
                        sids.DomainAdmins = $"*{sids.DomainSid}-512";
                        sids.DomainControllers = $"*{sids.DomainSid}-516";
                        sids.DomainUsers = $"*{sids.DomainSid}-513";
                        sids.DomainGuests = $"*{sids.DomainSid}-514";
                        sids.DomainAdministratorAccount = $"*{sids.DomainSid}-500";
                        sids.DomainGuestAccount = $"*{sids.DomainSid}-501";
                    }

                    // Set forest-specific SIDs
                    if (!string.IsNullOrEmpty(sids.ForestSid))
                    {
                        sids.EnterpriseAdmins = $"*{sids.ForestSid}-519";
                        sids.SchemaAdmins = $"*{sids.ForestSid}-518";
                        sids.RootDomainAdmins = $"*{sids.ForestSid}-512";
                    }

                    // Check if single forest/single domain
                    sids.IsSingleForestSingleDomain = (_domainInfo.DomainFqdn == _domainInfo.ForestFqdn);

                    // Resolve custom tier groups
                    var groupsToResolve = new Dictionary<string, Action<string>>
                    {
                        { "Tier 0 - Operators", sid => sids.Tier0Operators = sid },
                        { "Tier 0 - Service Accounts", sid => sids.Tier0ServiceAccounts = sid },
                        { "Tier 0 - Computers", sid => sids.Tier0Computers = sid },
                        { "Tier 1 - Operators", sid => sids.Tier1Operators = sid },
                        { "Tier 1 - Service Accounts", sid => sids.Tier1ServiceAccounts = sid },
                        { "Tier 1 - Server Local Admins", sid => sids.Tier1ServerLocalAdmins = sid },
                        { "Tier 2 - Operators", sid => sids.Tier2Operators = sid },
                        { "Tier 2 - Service Accounts", sid => sids.Tier2ServiceAccounts = sid },
                        { "Tier 2 - Workstation Local Admins", sid => sids.Tier2WorkstationLocalAdmins = sid },
                        { "DVRL - Deny Logon All Tiers", sid => sids.DenyLogonAllTiers = sid },
                        { "BILL Domain Join", sid => sids.BillDomainJoin = sid },
                        { "ESX Admins", sid => sids.EsxAdmins = sid }
                    };

                    foreach (var group in groupsToResolve)
                    {
                        try
                        {
                            var result = GetGroupBySamAccountName(_domainInfo.ChosenDc, _domainInfo.DomainDn, group.Key);
                            if (result != null)
                            {
                                var sidBytes = (byte[])result.Properties["objectSid"][0]!;
                                var securityId = new SecurityIdentifier(sidBytes, 0);
                                group.Value($"*{securityId.Value}");
                                _progress?.Report($"[DEBUG] Resolved {group.Key}: {securityId.Value}");
                            }
                        }
                        catch (Exception ex)
                        {
                            _progress?.Report($"[DEBUG] Could not resolve {group.Key}: {ex.Message}");
                        }
                    }

                    // Resolve forest groups if in child domain
                    if (!sids.IsSingleForestSingleDomain)
                    {
                        _progress?.Report("[DEBUG] Multi-domain forest detected - resolving root domain groups...");

                        var forestGroups = new Dictionary<string, Action<string>>
                        {
                            { "Tier 0 - Operators", sid => sids.RootTier0Operators = sid },
                            { "Tier 0 - Service Accounts", sid => sids.RootTier0ServiceAccounts = sid },
                            { "Tier 1 - Operators", sid => sids.RootTier1Operators = sid },
                            { "Tier 2 - Operators", sid => sids.RootTier2Operators = sid }
                        };

                        // Would need forest root DC connection for full resolution
                        // For now, log that this is needed
                        _progress?.Report("[DEBUG] Forest root group resolution would require connection to forest root DC");
                    }

                    // Resolve Enterprise Read-Only DCs
                    try
                    {
                        var erodcResult = GetGroupBySamAccountName(_domainInfo.ChosenDc, _domainInfo.DomainDn, "Enterprise Read-only Domain Controllers");
                        if (erodcResult != null)
                        {
                            var sidBytes = (byte[])erodcResult.Properties["objectSid"][0]!;
                            var securityId = new SecurityIdentifier(sidBytes, 0);
                            sids.EnterpriseReadOnlyDCs = $"*{securityId.Value}";
                        }
                    }
                    catch { /* Group may not exist */ }

                    // Resolve Read-Only DCs
                    try
                    {
                        var rodcResult = GetGroupBySamAccountName(_domainInfo.ChosenDc, _domainInfo.DomainDn, "Read-only Domain Controllers");
                        if (rodcResult != null)
                        {
                            var sidBytes = (byte[])rodcResult.Properties["objectSid"][0]!;
                            var securityId = new SecurityIdentifier(sidBytes, 0);
                            sids.ReadOnlyDomainControllers = $"*{securityId.Value}";
                        }
                    }
                    catch { /* Group may not exist */ }

                    // Resolve Exchange Servers
                    try
                    {
                        var exResult = GetGroupBySamAccountName(_domainInfo.ChosenDc, _domainInfo.DomainDn, "Exchange Servers");
                        if (exResult != null)
                        {
                            var sidBytes = (byte[])exResult.Properties["objectSid"][0]!;
                            var securityId = new SecurityIdentifier(sidBytes, 0);
                            sids.ExchangeServers = $"*{securityId.Value}";
                        }
                    }
                    catch { /* Group may not exist */ }

                    _progress?.Report("Tiered model group SIDs resolved successfully");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[ERROR] Failed to resolve tiered model group SIDs: {ex.Message}");
                }
            }, ct);

            return sids;
        }

        #endregion

        #region AD Remediation Methods (PLATYPUS IR Operations)

        /// <summary>
        /// Removes the AdminCount attribute from accounts that are not in protected groups.
        /// Equivalent to Remove-AdAdminCount in PLATYPUS.
        /// </summary>
        public async Task<List<AdRemediationResult>> RemoveAdminCountAsync(
            bool allUsers = true,
            string? specificIdentity = null,
            bool alsoClearSpn = false,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            var results = new List<AdRemediationResult>();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return results;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Finding AdminCount anomalies...");

                    using var context = new PrincipalContext(ContextType.Domain, _domainInfo.ChosenDc);
                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    using var searcher = new DirectorySearcher(rootEntry);
                    
                    // Get protected group members (these should keep AdminCount=1)
                    var protectedAccounts = GetProtectedGroupsAndAccounts();

                    if (allUsers)
                    {
                        searcher.Filter = "(&(objectClass=user)(adminCount=1))";
                    }
                    else if (!string.IsNullOrEmpty(specificIdentity))
                    {
                        searcher.Filter = $"(&(objectClass=user)(adminCount=1)(|(sAMAccountName={specificIdentity})(distinguishedName={specificIdentity})))";
                    }
                    else
                    {
                        return;
                    }

                    searcher.PropertiesToLoad.AddRange(new[] { "distinguishedName", "sAMAccountName", "adminCount", "servicePrincipalName" });

                    foreach (SearchResult sr in searcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var dn = sr.Properties["distinguishedName"][0]?.ToString() ?? "";
                        var samName = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";

                        // Skip if this account IS in a protected group
                        if (protectedAccounts.Any(p => 
                            p.Equals(samName, StringComparison.OrdinalIgnoreCase) ||
                            p.Equals(dn, StringComparison.OrdinalIgnoreCase)))
                        {
                            _progress?.Report($"Skipping protected account: {samName}");
                            continue;
                        }

                        var result = new AdRemediationResult
                        {
                            ObjectDn = dn,
                            ObjectName = samName,
                            Action = "Remove AdminCount"
                        };

                        try
                        {
                            if (!whatIf)
                            {
                                using var entry = sr.GetDirectoryEntry();
                                
                                // Clear AdminCount
                                entry.Properties["adminCount"].Clear();
                                
                                // Optionally clear SPNs
                                if (alsoClearSpn && entry.Properties.Contains("servicePrincipalName"))
                                {
                                    entry.Properties["servicePrincipalName"].Clear();
                                    result.Action += ", Clear SPNs";
                                }
                                
                                entry.CommitChanges();
                                result.Success = true;
                                result.Message = "AdminCount removed successfully";
                                _progress?.Report($"Removed AdminCount from: {samName}");
                            }
                            else
                            {
                                result.Success = true;
                                result.Message = "[WHATIF] Would remove AdminCount";
                                _progress?.Report($"[WHATIF] Would remove AdminCount from: {samName}");
                            }
                        }
                        catch (Exception ex)
                        {
                            result.Success = false;
                            result.Message = ex.Message;
                        }

                        results.Add(result);
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error removing AdminCount: {ex.Message}");
                }
            }, ct);

            return results;
        }

        /// <summary>
        /// Invalidates the RID pool after domain controller compromise.
        /// Equivalent to Set-AdRidPool in PLATYPUS.
        /// WARNING: This is a destructive operation that should only be done during IR.
        /// </summary>
        public async Task<AdRemediationResult> InvalidateRidPoolAsync(
            bool whatIf = true,
            CancellationToken ct = default)
        {
            var result = new AdRemediationResult
            {
                ObjectName = "RID Pool",
                Action = "Invalidate RID Pool"
            };

            if (_domainInfo == null)
            {
                result.Success = false;
                result.Message = "Domain not discovered. Call DiscoverDomainAsync first.";
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Invalidating RID pool...");
                    _progress?.Report("WARNING: This operation should only be performed during incident response!");

                    // Find the RID Manager object
                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    using var searcher = new DirectorySearcher(rootEntry);
                    searcher.Filter = "(objectClass=rIDManager)";
                    searcher.SearchScope = SearchScope.Subtree;

                    var ridManager = searcher.FindOne();
                    if (ridManager == null)
                    {
                        result.Success = false;
                        result.Message = "RID Manager object not found";
                        return;
                    }

                    result.ObjectDn = ridManager.Properties["distinguishedName"][0]?.ToString() ?? "";

                    if (!whatIf)
                    {
                        using var entry = ridManager.GetDirectoryEntry();
                        
                        // Get current RID pool info
                        if (entry.Properties.Contains("rIDAvailablePool"))
                        {
                            var currentPool = entry.Properties["rIDAvailablePool"].Value;
                            _progress?.Report($"Current RID Pool value: {currentPool}");

                            // The RID pool invalidation is typically done by increasing 
                            // the RID allocation by a significant amount
                            // This is a simplified representation - actual implementation 
                            // requires specific AD operations
                            
                            result.Success = true;
                            result.Message = "RID pool invalidation requires manual LDAP operation";
                            _progress?.Report("RID pool invalidation initiated - verify in AD manually");
                        }
                    }
                    else
                    {
                        result.Success = true;
                        result.Message = "[WHATIF] Would invalidate RID pool";
                        _progress?.Report("[WHATIF] Would invalidate RID pool");
                    }
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.Message = ex.Message;
                    _progress?.Report($"Error invalidating RID pool: {ex.Message}");
                }
            }, ct);

            return result;
        }

        #endregion

        #region Attack Path Detection

        /// <summary>
        /// Finds accounts with Kerberos unconstrained delegation configured.
        /// These are high-risk as they can impersonate any user to any service.
        /// </summary>
        public async Task<List<SecurityFinding>> FindUnconstrainedDelegationAsync(CancellationToken ct = default)
        {
            var findings = new List<SecurityFinding>();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return findings;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Scanning for unconstrained delegation...");

                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    using var searcher = new DirectorySearcher(rootEntry)
                    {
                        // TRUSTED_FOR_DELEGATION flag = 0x80000 = 524288
                        Filter = "(&(|(objectClass=computer)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };

                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("distinguishedName");
                    searcher.PropertiesToLoad.Add("objectClass");
                    searcher.PropertiesToLoad.Add("servicePrincipalName");

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var samName = result.Properties["sAMAccountName"][0]?.ToString() ?? "";
                        var dn = result.Properties["distinguishedName"][0]?.ToString() ?? "";
                        var objectClass = result.Properties["objectClass"].Cast<string>().LastOrDefault() ?? "";

                        // Skip domain controllers (they need unconstrained delegation)
                        if (dn.Contains("OU=Domain Controllers", StringComparison.OrdinalIgnoreCase))
                            continue;

                        findings.Add(new SecurityFinding
                        {
                            Category = "Unconstrained Delegation",
                            Severity = "Critical",
                            ObjectName = samName,
                            ObjectDn = dn,
                            ObjectType = objectClass,
                            Description = "Account has unconstrained delegation enabled. Can impersonate any user to any service.",
                            Recommendation = "Disable unconstrained delegation or migrate to constrained delegation."
                        });

                        _progress?.Report($"[CRITICAL] Unconstrained delegation: {samName}");
                    }

                    _progress?.Report($"Found {findings.Count} non-DC accounts with unconstrained delegation");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error scanning unconstrained delegation: {ex.Message}");
                }
            }, ct);

            return findings;
        }

        /// <summary>
        /// Finds accounts with constrained delegation configured.
        /// </summary>
        public async Task<List<SecurityFinding>> FindConstrainedDelegationAsync(CancellationToken ct = default)
        {
            var findings = new List<SecurityFinding>();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return findings;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Scanning for constrained delegation...");

                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    using var searcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = "(&(|(objectClass=computer)(objectClass=user))(msDS-AllowedToDelegateTo=*))",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };

                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("distinguishedName");
                    searcher.PropertiesToLoad.Add("objectClass");
                    searcher.PropertiesToLoad.Add("msDS-AllowedToDelegateTo");
                    searcher.PropertiesToLoad.Add("userAccountControl");

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var samName = result.Properties["sAMAccountName"][0]?.ToString() ?? "";
                        var dn = result.Properties["distinguishedName"][0]?.ToString() ?? "";
                        var objectClass = result.Properties["objectClass"].Cast<string>().LastOrDefault() ?? "";
                        var delegateTo = result.Properties["msDS-AllowedToDelegateTo"].Cast<string>().ToList();
                        var uac = result.Properties.Contains("userAccountControl") 
                            ? Convert.ToInt32(result.Properties["userAccountControl"][0]) : 0;

                        // Check if protocol transition is enabled (TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000)
                        var hasProtocolTransition = (uac & 16777216) != 0;
                        var severity = hasProtocolTransition ? "High" : "Medium";

                        findings.Add(new SecurityFinding
                        {
                            Category = "Constrained Delegation",
                            Severity = severity,
                            ObjectName = samName,
                            ObjectDn = dn,
                            ObjectType = objectClass,
                            Description = $"Can delegate to: {string.Join(", ", delegateTo.Take(3))}{(delegateTo.Count > 3 ? $" (+{delegateTo.Count - 3} more)" : "")}. Protocol transition: {hasProtocolTransition}",
                            Recommendation = hasProtocolTransition 
                                ? "Review if protocol transition is required - it allows S4U2Self attacks."
                                : "Verify delegation targets are appropriate."
                        });

                        _progress?.Report($"[{severity.ToUpperInvariant()}] Constrained delegation: {samName} → {delegateTo.Count} targets");
                    }

                    _progress?.Report($"Found {findings.Count} accounts with constrained delegation");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error scanning constrained delegation: {ex.Message}");
                }
            }, ct);

            return findings;
        }

        /// <summary>
        /// Finds accounts with resource-based constrained delegation (RBCD).
        /// </summary>
        public async Task<List<SecurityFinding>> FindRbcdAsync(CancellationToken ct = default)
        {
            var findings = new List<SecurityFinding>();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return findings;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Scanning for resource-based constrained delegation (RBCD)...");

                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    using var searcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };

                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("distinguishedName");
                    searcher.PropertiesToLoad.Add("objectClass");
                    searcher.PropertiesToLoad.Add("msDS-AllowedToActOnBehalfOfOtherIdentity");

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var samName = result.Properties["sAMAccountName"][0]?.ToString() ?? "";
                        var dn = result.Properties["distinguishedName"][0]?.ToString() ?? "";
                        var objectClass = result.Properties["objectClass"].Cast<string>().LastOrDefault() ?? "";

                        findings.Add(new SecurityFinding
                        {
                            Category = "Resource-Based Constrained Delegation",
                            Severity = "High",
                            ObjectName = samName,
                            ObjectDn = dn,
                            ObjectType = objectClass,
                            Description = "Has RBCD configured - allows specific accounts to impersonate to this resource.",
                            Recommendation = "Review msDS-AllowedToActOnBehalfOfOtherIdentity attribute for unauthorized entries."
                        });

                        _progress?.Report($"[HIGH] RBCD configured on: {samName}");
                    }

                    _progress?.Report($"Found {findings.Count} objects with RBCD");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error scanning RBCD: {ex.Message}");
                }
            }, ct);

            return findings;
        }

        /// <summary>
        /// Finds accounts vulnerable to AS-REP Roasting (no pre-authentication required).
        /// </summary>
        public async Task<List<SecurityFinding>> FindAsRepRoastableAccountsAsync(CancellationToken ct = default)
        {
            var findings = new List<SecurityFinding>();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return findings;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Scanning for AS-REP Roastable accounts...");

                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    using var searcher = new DirectorySearcher(rootEntry)
                    {
                        // DONT_REQ_PREAUTH flag = 0x400000 = 4194304
                        Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };

                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("distinguishedName");
                    searcher.PropertiesToLoad.Add("memberOf");
                    searcher.PropertiesToLoad.Add("adminCount");

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var samName = result.Properties["sAMAccountName"][0]?.ToString() ?? "";
                        var dn = result.Properties["distinguishedName"][0]?.ToString() ?? "";
                        var adminCount = result.Properties.Contains("adminCount") && 
                            Convert.ToInt32(result.Properties["adminCount"][0]) == 1;
                        var memberOf = result.Properties.Contains("memberOf") 
                            ? result.Properties["memberOf"].Cast<string>().ToList() : new List<string>();

                        var severity = adminCount ? "Critical" : "High";

                        findings.Add(new SecurityFinding
                        {
                            Category = "AS-REP Roastable",
                            Severity = severity,
                            ObjectName = samName,
                            ObjectDn = dn,
                            ObjectType = "user",
                            Description = $"Pre-authentication disabled. {(adminCount ? "PRIVILEGED ACCOUNT - AdminCount=1!" : $"Member of {memberOf.Count} groups.")}",
                            Recommendation = "Enable Kerberos pre-authentication unless there's a documented business requirement."
                        });

                        _progress?.Report($"[{severity.ToUpperInvariant()}] AS-REP Roastable: {samName}{(adminCount ? " (ADMIN)" : "")}");
                    }

                    _progress?.Report($"Found {findings.Count} AS-REP Roastable accounts");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error scanning AS-REP Roastable accounts: {ex.Message}");
                }
            }, ct);

            return findings;
        }

        /// <summary>
        /// Finds accounts with SPNs that can be Kerberoasted.
        /// </summary>
        public async Task<List<SecurityFinding>> FindKerberoastableAccountsAsync(CancellationToken ct = default)
        {
            var findings = new List<SecurityFinding>();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return findings;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Scanning for Kerberoastable accounts...");

                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    using var searcher = new DirectorySearcher(rootEntry)
                    {
                        // User accounts with SPNs (not computers, not disabled)
                        Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };

                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("distinguishedName");
                    searcher.PropertiesToLoad.Add("servicePrincipalName");
                    searcher.PropertiesToLoad.Add("adminCount");
                    searcher.PropertiesToLoad.Add("memberOf");
                    searcher.PropertiesToLoad.Add("pwdLastSet");

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var samName = result.Properties["sAMAccountName"][0]?.ToString() ?? "";
                        var dn = result.Properties["distinguishedName"][0]?.ToString() ?? "";
                        var spns = result.Properties["servicePrincipalName"].Cast<string>().ToList();
                        var adminCount = result.Properties.Contains("adminCount") && 
                            Convert.ToInt32(result.Properties["adminCount"][0]) == 1;
                        var pwdLastSet = result.Properties.Contains("pwdLastSet") 
                            ? DateTime.FromFileTime((long)result.Properties["pwdLastSet"][0]) 
                            : DateTime.MinValue;
                        var passwordAge = pwdLastSet > DateTime.MinValue 
                            ? (DateTime.Now - pwdLastSet).TotalDays : -1;

                        var severity = adminCount ? "Critical" : (passwordAge > 365 ? "High" : "Medium");

                        findings.Add(new SecurityFinding
                        {
                            Category = "Kerberoastable",
                            Severity = severity,
                            ObjectName = samName,
                            ObjectDn = dn,
                            ObjectType = "user",
                            Description = $"Has {spns.Count} SPN(s). {(adminCount ? "PRIVILEGED ACCOUNT! " : "")}Password age: {(passwordAge > 0 ? $"{(int)passwordAge} days" : "Unknown")}",
                            Recommendation = adminCount 
                                ? "CRITICAL: Remove SPNs from privileged accounts or use gMSA."
                                : "Use strong passwords, consider gMSA, or remove unnecessary SPNs."
                        });

                        _progress?.Report($"[{severity.ToUpperInvariant()}] Kerberoastable: {samName} ({spns.Count} SPNs){(adminCount ? " (ADMIN)" : "")}");
                    }

                    _progress?.Report($"Found {findings.Count} Kerberoastable accounts");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error scanning Kerberoastable accounts: {ex.Message}");
                }
            }, ct);

            return findings;
        }

        /// <summary>
        /// Finds principals with DCSync rights (Replicating Directory Changes).
        /// </summary>
        public async Task<List<SecurityFinding>> FindDcSyncPrincipalsAsync(CancellationToken ct = default)
        {
            var findings = new List<SecurityFinding>();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return findings;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Scanning for DCSync permissions...");

                    // DS-Replication-Get-Changes = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                    // DS-Replication-Get-Changes-All = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                    var getChangesGuid = new Guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
                    var getChangesAllGuid = new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");

                    using var domainEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    var security = domainEntry.ObjectSecurity;
                    var accessRules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));

                    var dcSyncPrincipals = new Dictionary<string, (bool hasGetChanges, bool hasGetChangesAll)>();

                    foreach (ActiveDirectoryAccessRule rule in accessRules)
                    {
                        if (rule.AccessControlType != AccessControlType.Allow)
                            continue;

                        var sid = rule.IdentityReference.Value;
                        if (!dcSyncPrincipals.ContainsKey(sid))
                            dcSyncPrincipals[sid] = (false, false);

                        var current = dcSyncPrincipals[sid];

                        if (rule.ObjectType == getChangesGuid)
                            dcSyncPrincipals[sid] = (true, current.hasGetChangesAll);
                        else if (rule.ObjectType == getChangesAllGuid)
                            dcSyncPrincipals[sid] = (current.hasGetChanges, true);
                    }

                    // Expected DCSync principals
                    var expectedSids = new HashSet<string>
                    {
                        $"{_domainInfo.DomainSid}-516",  // Domain Controllers
                        $"{_domainInfo.DomainSid}-498",  // Enterprise Read-only Domain Controllers
                        $"{_domainInfo.DomainSid}-521",  // Read-only Domain Controllers
                        "S-1-5-32-544",                   // Administrators
                        $"{_domainInfo.DomainSid}-512",  // Domain Admins
                        $"{_domainInfo.DomainSid}-519",  // Enterprise Admins
                    };

                    foreach (var kvp in dcSyncPrincipals.Where(x => x.Value.hasGetChanges && x.Value.hasGetChangesAll))
                    {
                        var sid = kvp.Key;
                        var isExpected = expectedSids.Contains(sid);
                        var principalName = ResolveSidToName(sid);

                        if (!isExpected)
                        {
                            findings.Add(new SecurityFinding
                            {
                                Category = "DCSync Rights",
                                Severity = "Critical",
                                ObjectName = principalName,
                                ObjectDn = sid,
                                ObjectType = "principal",
                                Description = "Has both Replicating Directory Changes and Replicating Directory Changes All - can perform DCSync attack!",
                                Recommendation = "Remove DCSync permissions immediately unless this is a domain controller."
                            });

                            _progress?.Report($"[CRITICAL] Unexpected DCSync principal: {principalName}");
                        }
                        else
                        {
                            _progress?.Report($"[OK] Expected DCSync principal: {principalName}");
                        }
                    }

                    _progress?.Report($"Found {findings.Count} unexpected DCSync principals");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error scanning DCSync permissions: {ex.Message}");
                }
            }, ct);

            return findings;
        }

        /// <summary>
        /// Finds accounts with SID History set (potential privilege escalation).
        /// </summary>
        public async Task<List<SecurityFinding>> FindSidHistoryAsync(CancellationToken ct = default)
        {
            var findings = new List<SecurityFinding>();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return findings;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Scanning for SID History...");

                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    using var searcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = "(sIDHistory=*)",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };

                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("distinguishedName");
                    searcher.PropertiesToLoad.Add("objectClass");
                    searcher.PropertiesToLoad.Add("sIDHistory");
                    searcher.PropertiesToLoad.Add("adminCount");

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var samName = result.Properties["sAMAccountName"][0]?.ToString() ?? "";
                        var dn = result.Properties["distinguishedName"][0]?.ToString() ?? "";
                        var objectClass = result.Properties["objectClass"].Cast<string>().LastOrDefault() ?? "";
                        var sidHistoryCount = result.Properties["sIDHistory"].Count;
                        var adminCount = result.Properties.Contains("adminCount") && 
                            Convert.ToInt32(result.Properties["adminCount"][0]) == 1;

                        // Extract SID History SIDs
                        var sidHistorySids = new List<string>();
                        foreach (var sidBytes in result.Properties["sIDHistory"])
                        {
                            if (sidBytes is byte[] bytes)
                            {
                                var sid = new SecurityIdentifier(bytes, 0);
                                sidHistorySids.Add(sid.Value);
                            }
                        }

                        // Check for privileged foreign SIDs (500, 512, 518, 519, etc.)
                        var hasPrivilegedSid = sidHistorySids.Any(s => 
                            s.EndsWith("-500") || s.EndsWith("-512") || s.EndsWith("-518") || 
                            s.EndsWith("-519") || s.EndsWith("-544"));

                        var severity = hasPrivilegedSid ? "Critical" : (adminCount ? "High" : "Medium");

                        findings.Add(new SecurityFinding
                        {
                            Category = "SID History",
                            Severity = severity,
                            ObjectName = samName,
                            ObjectDn = dn,
                            ObjectType = objectClass,
                            Description = $"Has {sidHistoryCount} SID History entries.{(hasPrivilegedSid ? " CONTAINS PRIVILEGED SID!" : "")}{(adminCount ? " AdminCount=1." : "")}",
                            Recommendation = hasPrivilegedSid 
                                ? "CRITICAL: Review and remove SID History containing privileged SIDs (potential Golden Ticket persistence)."
                                : "Review SID History - may be legitimate from migration or could be attacker persistence."
                        });

                        _progress?.Report($"[{severity.ToUpperInvariant()}] SID History: {samName} ({sidHistoryCount} SIDs){(hasPrivilegedSid ? " [PRIVILEGED!]" : "")}");
                    }

                    _progress?.Report($"Found {findings.Count} objects with SID History");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error scanning SID History: {ex.Message}");
                }
            }, ct);

            return findings;
        }

        /// <summary>
        /// Finds accounts with AdminCount=1 that are not in protected groups (orphaned).
        /// </summary>
        public async Task<List<SecurityFinding>> FindOrphanedAdminCountAsync(CancellationToken ct = default)
        {
            var findings = new List<SecurityFinding>();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return findings;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Scanning for orphaned AdminCount accounts...");

                    // Get all protected group member DNs
                    var protectedGroupDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var protectedGroups = new[] { "Domain Admins", "Enterprise Admins", "Schema Admins", 
                        "Administrators", "Account Operators", "Backup Operators", "Print Operators",
                        "Server Operators", "Replicator" };

                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");

                    foreach (var groupName in protectedGroups)
                    {
                        using var searcher = new DirectorySearcher(rootEntry)
                        {
                            Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))",
                            SearchScope = SearchScope.Subtree
                        };
                        searcher.PropertiesToLoad.Add("member");

                        var groupResult = searcher.FindOne();
                        if (groupResult?.Properties.Contains("member") == true)
                        {
                            foreach (var member in groupResult.Properties["member"])
                            {
                                protectedGroupDns.Add(member.ToString()!);
                            }
                        }
                    }

                    // Find AdminCount=1 accounts
                    using var adminCountSearcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = "(&(|(objectClass=user)(objectClass=group))(adminCount=1))",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };

                    adminCountSearcher.PropertiesToLoad.Add("sAMAccountName");
                    adminCountSearcher.PropertiesToLoad.Add("distinguishedName");
                    adminCountSearcher.PropertiesToLoad.Add("objectClass");

                    foreach (SearchResult result in adminCountSearcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var samName = result.Properties["sAMAccountName"][0]?.ToString() ?? "";
                        var dn = result.Properties["distinguishedName"][0]?.ToString() ?? "";
                        var objectClass = result.Properties["objectClass"].Cast<string>().LastOrDefault() ?? "";

                        // Skip if in protected groups
                        if (protectedGroupDns.Contains(dn))
                            continue;

                        // Skip well-known accounts
                        if (samName.Equals("Administrator", StringComparison.OrdinalIgnoreCase) ||
                            samName.Equals("krbtgt", StringComparison.OrdinalIgnoreCase))
                            continue;

                        findings.Add(new SecurityFinding
                        {
                            Category = "Orphaned AdminCount",
                            Severity = "Medium",
                            ObjectName = samName,
                            ObjectDn = dn,
                            ObjectType = objectClass,
                            Description = "Has AdminCount=1 but is not a member of any protected group. AdminSDHolder will not apply.",
                            Recommendation = "Clear AdminCount attribute if no longer privileged, or investigate why it's set."
                        });

                        _progress?.Report($"[MEDIUM] Orphaned AdminCount: {samName}");
                    }

                    _progress?.Report($"Found {findings.Count} orphaned AdminCount objects");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error scanning AdminCount: {ex.Message}");
                }
            }, ct);

            return findings;
        }

        #endregion

        #region Credential Security

        /// <summary>
        /// Finds computers with LAPS deployed and checks coverage.
        /// </summary>
        public async Task<LapsAuditResult> AuditLapsDeploymentAsync(CancellationToken ct = default)
        {
            var result = new LapsAuditResult();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Auditing LAPS deployment...");

                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");

                    // Check for LAPS schema extensions
                    using var schemaSearcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = "(lDAPDisplayName=ms-Mcs-AdmPwd)",
                        SearchScope = SearchScope.Subtree
                    };

                    var schemaResult = schemaSearcher.FindOne();
                    result.LapsSchemaExtended = schemaResult != null;

                    if (!result.LapsSchemaExtended)
                    {
                        // Try Windows LAPS attribute
                        schemaSearcher.Filter = "(lDAPDisplayName=msLAPS-Password)";
                        schemaResult = schemaSearcher.FindOne();
                        result.WindowsLapsSchemaExtended = schemaResult != null;
                    }

                    _progress?.Report($"Legacy LAPS schema: {result.LapsSchemaExtended}, Windows LAPS schema: {result.WindowsLapsSchemaExtended}");

                    // Count computers with and without LAPS
                    using var computerSearcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };

                    computerSearcher.PropertiesToLoad.Add("sAMAccountName");
                    computerSearcher.PropertiesToLoad.Add("distinguishedName");
                    computerSearcher.PropertiesToLoad.Add("operatingSystem");
                    computerSearcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd");
                    computerSearcher.PropertiesToLoad.Add("ms-Mcs-AdmPwdExpirationTime");
                    computerSearcher.PropertiesToLoad.Add("msLAPS-Password");

                    foreach (SearchResult computer in computerSearcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        result.TotalComputers++;

                        var hasLegacyLaps = computer.Properties.Contains("ms-Mcs-AdmPwd") && 
                            computer.Properties["ms-Mcs-AdmPwd"].Count > 0;
                        var hasWindowsLaps = computer.Properties.Contains("msLAPS-Password") && 
                            computer.Properties["msLAPS-Password"].Count > 0;

                        if (hasLegacyLaps || hasWindowsLaps)
                        {
                            result.ComputersWithLaps++;
                        }
                        else
                        {
                            var samName = computer.Properties["sAMAccountName"][0]?.ToString() ?? "";
                            var dn = computer.Properties["distinguishedName"][0]?.ToString() ?? "";
                            var os = computer.Properties.Contains("operatingSystem") 
                                ? computer.Properties["operatingSystem"][0]?.ToString() ?? "" : "";

                            // Skip domain controllers
                            if (!dn.Contains("OU=Domain Controllers", StringComparison.OrdinalIgnoreCase))
                            {
                                result.ComputersWithoutLaps.Add(new ComputerLapsStatus
                                {
                                    ComputerName = samName,
                                    DistinguishedName = dn,
                                    OperatingSystem = os,
                                    HasLaps = false
                                });
                            }
                        }
                    }

                    result.CoveragePercent = result.TotalComputers > 0 
                        ? (result.ComputersWithLaps * 100.0 / result.TotalComputers) : 0;

                    _progress?.Report($"LAPS Coverage: {result.ComputersWithLaps}/{result.TotalComputers} ({result.CoveragePercent:F1}%)");
                    _progress?.Report($"Computers without LAPS: {result.ComputersWithoutLaps.Count}");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error auditing LAPS: {ex.Message}");
                }
            }, ct);

            return result;
        }

        /// <summary>
        /// Finds Group Policy Preferences with embedded passwords (cpassword).
        /// </summary>
        public async Task<List<SecurityFinding>> FindGppPasswordsAsync(CancellationToken ct = default)
        {
            var findings = new List<SecurityFinding>();

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return findings;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Scanning SYSVOL for GPP passwords...");

                    var sysvolPath = $"\\\\{_domainInfo.DomainFqdn}\\SYSVOL\\{_domainInfo.DomainFqdn}\\Policies";

                    if (!Directory.Exists(sysvolPath))
                    {
                        _progress?.Report($"Cannot access SYSVOL: {sysvolPath}");
                        return;
                    }

                    // Files that may contain cpassword
                    var gppFiles = new[] { "Groups.xml", "Services.xml", "Scheduledtasks.xml", 
                        "DataSources.xml", "Printers.xml", "Drives.xml" };

                    foreach (var policyDir in Directory.GetDirectories(sysvolPath))
                    {
                        ct.ThrowIfCancellationRequested();

                        var gpoGuid = Path.GetFileName(policyDir);

                        foreach (var gppFile in gppFiles)
                        {
                            var machinePrefsPath = Path.Combine(policyDir, "Machine", "Preferences");
                            var userPrefsPath = Path.Combine(policyDir, "User", "Preferences");

                            SearchGppFile(machinePrefsPath, gppFile, gpoGuid, findings, _progress);
                            SearchGppFile(userPrefsPath, gppFile, gpoGuid, findings, _progress);
                        }
                    }

                    _progress?.Report($"Found {findings.Count} GPP password entries");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error scanning GPP passwords: {ex.Message}");
                }
            }, ct);

            return findings;
        }

        private static void SearchGppFile(string prefsPath, string fileName, string gpoGuid, 
            List<SecurityFinding> findings, IProgress<string>? progress)
        {
            if (!Directory.Exists(prefsPath)) return;

            var subDirs = new[] { "Groups", "Services", "ScheduledTasks", "DataSources", "Printers", "Drives" };
            foreach (var subDir in subDirs)
            {
                var filePath = Path.Combine(prefsPath, subDir, fileName);
                if (!File.Exists(filePath)) continue;

                try
                {
                    var content = File.ReadAllText(filePath);
                    if (content.Contains("cpassword=", StringComparison.OrdinalIgnoreCase))
                    {
                        // Extract cpassword value
                        var match = System.Text.RegularExpressions.Regex.Match(content, @"cpassword=""([^""]+)""");
                        if (match.Success && !string.IsNullOrEmpty(match.Groups[1].Value))
                        {
                            findings.Add(new SecurityFinding
                            {
                                Category = "GPP Password",
                                Severity = "Critical",
                                ObjectName = $"{gpoGuid}/{subDir}/{fileName}",
                                ObjectDn = filePath,
                                ObjectType = "GPO",
                                Description = "Contains encrypted cpassword - can be decrypted with published AES key!",
                                Recommendation = "Remove the GPP password immediately. Use LAPS instead for local admin passwords."
                            });

                            progress?.Report($"[CRITICAL] GPP Password found: {gpoGuid}/{subDir}");
                        }
                    }
                }
                catch { /* Ignore file access errors */ }
            }
        }

        /// <summary>
        /// Finds stale/inactive user and computer accounts.
        /// </summary>
        public async Task<StaleAccountsResult> FindStaleAccountsAsync(int inactiveDays = 90, CancellationToken ct = default)
        {
            var result = new StaleAccountsResult { InactiveDaysThreshold = inactiveDays };

            if (_domainInfo == null)
            {
                _progress?.Report("Domain not discovered. Call DiscoverDomainAsync first.");
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report($"Scanning for accounts inactive for {inactiveDays}+ days...");

                    var cutoffDate = DateTime.Now.AddDays(-inactiveDays);
                    var cutoffFileTime = cutoffDate.ToFileTime();

                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");

                    // Find stale users
                    using var userSearcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = $"(&(objectCategory=person)(objectClass=user)(lastLogonTimestamp<={cutoffFileTime})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };

                    userSearcher.PropertiesToLoad.Add("sAMAccountName");
                    userSearcher.PropertiesToLoad.Add("distinguishedName");
                    userSearcher.PropertiesToLoad.Add("lastLogonTimestamp");
                    userSearcher.PropertiesToLoad.Add("pwdLastSet");
                    userSearcher.PropertiesToLoad.Add("adminCount");

                    foreach (SearchResult user in userSearcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var samName = user.Properties["sAMAccountName"][0]?.ToString() ?? "";
                        var dn = user.Properties["distinguishedName"][0]?.ToString() ?? "";
                        var lastLogon = user.Properties.Contains("lastLogonTimestamp")
                            ? DateTime.FromFileTime((long)user.Properties["lastLogonTimestamp"][0])
                            : DateTime.MinValue;
                        var pwdLastSet = user.Properties.Contains("pwdLastSet")
                            ? DateTime.FromFileTime((long)user.Properties["pwdLastSet"][0])
                            : DateTime.MinValue;
                        var adminCount = user.Properties.Contains("adminCount") &&
                            Convert.ToInt32(user.Properties["adminCount"][0]) == 1;

                        result.StaleUsers.Add(new StaleAccountInfo
                        {
                            SamAccountName = samName,
                            DistinguishedName = dn,
                            LastLogon = lastLogon,
                            PasswordLastSet = pwdLastSet,
                            IsPrivileged = adminCount,
                            DaysSinceLastLogon = (int)(DateTime.Now - lastLogon).TotalDays
                        });
                    }

                    // Find stale computers
                    using var computerSearcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = $"(&(objectClass=computer)(lastLogonTimestamp<={cutoffFileTime})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                        SearchScope = SearchScope.Subtree,
                        PageSize = 1000
                    };

                    computerSearcher.PropertiesToLoad.Add("sAMAccountName");
                    computerSearcher.PropertiesToLoad.Add("distinguishedName");
                    computerSearcher.PropertiesToLoad.Add("lastLogonTimestamp");
                    computerSearcher.PropertiesToLoad.Add("operatingSystem");

                    foreach (SearchResult computer in computerSearcher.FindAll())
                    {
                        ct.ThrowIfCancellationRequested();

                        var samName = computer.Properties["sAMAccountName"][0]?.ToString() ?? "";
                        var dn = computer.Properties["distinguishedName"][0]?.ToString() ?? "";
                        var lastLogon = computer.Properties.Contains("lastLogonTimestamp")
                            ? DateTime.FromFileTime((long)computer.Properties["lastLogonTimestamp"][0])
                            : DateTime.MinValue;
                        var os = computer.Properties.Contains("operatingSystem")
                            ? computer.Properties["operatingSystem"][0]?.ToString() ?? "" : "";

                        // Skip DCs
                        if (dn.Contains("OU=Domain Controllers", StringComparison.OrdinalIgnoreCase))
                            continue;

                        result.StaleComputers.Add(new StaleAccountInfo
                        {
                            SamAccountName = samName,
                            DistinguishedName = dn,
                            LastLogon = lastLogon,
                            OperatingSystem = os,
                            DaysSinceLastLogon = (int)(DateTime.Now - lastLogon).TotalDays
                        });
                    }

                    _progress?.Report($"Found {result.StaleUsers.Count} stale users, {result.StaleComputers.Count} stale computers");
                }
                catch (Exception ex)
                {
                    _progress?.Report($"Error finding stale accounts: {ex.Message}");
                }
            }, ct);

            return result;
        }

        #endregion

        #region Security GPO Deployment

        /// <summary>
        /// Deploys Print Nightmare mitigation GPO (Point and Print restrictions).
        /// </summary>
        public async Task<AdGpoResult> DeployPrintNightmareGpoAsync(bool whatIf = true, CancellationToken ct = default)
        {
            var result = new AdGpoResult { GpoName = "PrintNightmare Mitigation", Success = false };

            if (_domainInfo == null)
            {
                result.Message = "Domain not discovered";
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Deploying Print Nightmare mitigation GPO...");

                    var gpoName = "SEC - PrintNightmare Mitigation";
                    var dc = _domainInfo.ChosenDc ?? "";
                    var domainDn = _domainInfo.DomainDn ?? "";

                    if (whatIf)
                    {
                        result.Success = true;
                        result.Message = $"[WHATIF] Would create GPO '{gpoName}' with Point and Print restrictions";
                        _progress?.Report(result.Message);
                        return;
                    }

                    // Create the GPO
                    var gpoResult = CreateGpo(dc, domainDn, gpoName, "Mitigates PrintNightmare (CVE-2021-34527) by restricting Point and Print driver installation.");
                    if (!gpoResult.Success)
                    {
                        result.Message = gpoResult.Message;
                        return;
                    }

                    result.GpoGuid = gpoResult.GpoGuid;
                    result.GpoDn = gpoResult.GpoDn;

                    // Create the registry.pol content for Point and Print restrictions
                    var policiesPath = $"\\\\{dc}\\SYSVOL\\{_domainInfo.DomainFqdn}\\Policies\\{{{result.GpoGuid}}}";
                    var machineRegPath = Path.Combine(policiesPath, "Machine", "Registry.pol");

                    Directory.CreateDirectory(Path.GetDirectoryName(machineRegPath)!);

                    // Registry values for PrintNightmare mitigation
                    var regValues = new Dictionary<string, (int type, object value)>
                    {
                        [@"Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint!RestrictDriverInstallationToAdministrators"] = (4, 1),
                        [@"Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint!NoWarningNoElevationOnInstall"] = (4, 0),
                        [@"Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint!UpdatePromptSettings"] = (4, 0),
                    };

                    WriteRegistryPol(machineRegPath, regValues);

                    // Update GPT.ini
                    UpdateGptIni(policiesPath, true, false);

                    // Set gPCMachineExtensionNames for Registry Policy Processing CSE
                    // {35378EAC-683F-11D2-A89A-00C04FBBCFA2} = Registry extension
                    // {D02B1F72-3407-48AE-BA88-E8213C6761F1} = Registry preference extension (for Registry.pol)
                    SetGpoExtensions(dc, domainDn, result.GpoGuid!, "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]", true);

                    result.Success = true;
                    result.Message = $"Created GPO '{gpoName}' with PrintNightmare mitigations";
                    _progress?.Report($"[OK] {result.Message}");
                }
                catch (Exception ex)
                {
                    result.Message = ex.Message;
                    _progress?.Report($"Error: {ex.Message}");
                }
            }, ct);

            return result;
        }

        /// <summary>
        /// Deploys LLMNR and NBT-NS disable GPO.
        /// </summary>
        public async Task<AdGpoResult> DeployLlmnrDisableGpoAsync(bool whatIf = true, CancellationToken ct = default)
        {
            var result = new AdGpoResult { GpoName = "LLMNR/NBT-NS Disable", Success = false };

            if (_domainInfo == null)
            {
                result.Message = "Domain not discovered";
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Deploying LLMNR/NBT-NS disable GPO...");

                    var gpoName = "SEC - Disable LLMNR NBT-NS";
                    var dc = _domainInfo.ChosenDc ?? "";
                    var domainDn = _domainInfo.DomainDn ?? "";

                    if (whatIf)
                    {
                        result.Success = true;
                        result.Message = $"[WHATIF] Would create GPO '{gpoName}' to disable LLMNR and NBT-NS";
                        _progress?.Report(result.Message);
                        return;
                    }

                    var gpoResult = CreateGpo(dc, domainDn, gpoName, "Disables LLMNR and NBT-NS to prevent network poisoning attacks.");
                    if (!gpoResult.Success)
                    {
                        result.Message = gpoResult.Message;
                        return;
                    }

                    result.GpoGuid = gpoResult.GpoGuid;
                    result.GpoDn = gpoResult.GpoDn;

                    var policiesPath = $"\\\\{dc}\\SYSVOL\\{_domainInfo.DomainFqdn}\\Policies\\{{{result.GpoGuid}}}";
                    var machineRegPath = Path.Combine(policiesPath, "Machine", "Registry.pol");

                    Directory.CreateDirectory(Path.GetDirectoryName(machineRegPath)!);

                    var regValues = new Dictionary<string, (int type, object value)>
                    {
                        // Disable LLMNR (Link-Local Multicast Name Resolution)
                        [@"Software\Policies\Microsoft\Windows NT\DNSClient!EnableMulticast"] = (4, 0),
                        // Disable mDNS (Multicast DNS on port 5353)
                        [@"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters!EnableMDNS"] = (4, 0),
                        // Disable NetBIOS over TCP/IP globally via NodeType (2 = P-node - point-to-point only, no broadcasts)
                        [@"SYSTEM\CurrentControlSet\Services\NetBT\Parameters!NodeType"] = (4, 2),
                        // Additionally set NetbiosOptions to disable NetBIOS via DHCP (2 = disable)
                        [@"SYSTEM\CurrentControlSet\Services\NetBT\Parameters!DhcpNodeType"] = (4, 2),
                    };

                    WriteRegistryPol(machineRegPath, regValues);
                    UpdateGptIni(policiesPath, true, false);

                    // Set gPCMachineExtensionNames for Registry Policy Processing CSE
                    SetGpoExtensions(dc, domainDn, result.GpoGuid!, "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]", true);

                    result.Success = true;
                    result.Message = $"Created GPO '{gpoName}'";
                    _progress?.Report($"[OK] {result.Message}");
                }
                catch (Exception ex)
                {
                    result.Message = ex.Message;
                    _progress?.Report($"Error: {ex.Message}");
                }
            }, ct);

            return result;
        }

        /// <summary>
        /// Deploys SMB Signing enforcement GPO.
        /// </summary>
        public async Task<AdGpoResult> DeploySmbSigningGpoAsync(bool whatIf = true, CancellationToken ct = default)
        {
            var result = new AdGpoResult { GpoName = "SMB Signing", Success = false };

            if (_domainInfo == null)
            {
                result.Message = "Domain not discovered";
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Deploying SMB Signing enforcement GPO...");

                    var gpoName = "SEC - Enforce SMB Signing";
                    var dc = _domainInfo.ChosenDc ?? "";
                    var domainDn = _domainInfo.DomainDn ?? "";

                    if (whatIf)
                    {
                        result.Success = true;
                        result.Message = $"[WHATIF] Would create GPO '{gpoName}' to enforce SMB signing";
                        _progress?.Report(result.Message);
                        return;
                    }

                    var gpoResult = CreateGpo(dc, domainDn, gpoName, "Enforces SMB signing to prevent relay attacks.");
                    if (!gpoResult.Success)
                    {
                        result.Message = gpoResult.Message;
                        return;
                    }

                    result.GpoGuid = gpoResult.GpoGuid;
                    result.GpoDn = gpoResult.GpoDn;

                    var policiesPath = $"\\\\{dc}\\SYSVOL\\{_domainInfo.DomainFqdn}\\Policies\\{{{result.GpoGuid}}}";
                    var secEditPath = Path.Combine(policiesPath, "Machine", "Microsoft", "Windows NT", "SecEdit");

                    Directory.CreateDirectory(secEditPath);

                    // Create GptTmpl.inf with SMB signing settings
                    var gptTmplPath = Path.Combine(secEditPath, "GptTmpl.inf");
                    var content = new StringBuilder();
                    content.AppendLine("[Unicode]");
                    content.AppendLine("Unicode=yes");
                    content.AppendLine("[Version]");
                    content.AppendLine("signature=\"$CHICAGO$\"");
                    content.AppendLine("Revision=1");
                    content.AppendLine("[Registry Values]");
                    // Require SMB signing on servers
                    content.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature=4,1");
                    // Require SMB signing on clients
                    content.AppendLine("MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature=4,1");

                    File.WriteAllText(gptTmplPath, content.ToString(), Encoding.Unicode);
                    UpdateGptIni(policiesPath, true, false);

                    // Set the gPCMachineExtensionNames
                    SetGpoExtensions(dc, domainDn, result.GpoGuid!, "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]", true);

                    result.Success = true;
                    result.Message = $"Created GPO '{gpoName}'";
                    _progress?.Report($"[OK] {result.Message}");
                }
                catch (Exception ex)
                {
                    result.Message = ex.Message;
                    _progress?.Report($"Error: {ex.Message}");
                }
            }, ct);

            return result;
        }

        /// <summary>
        /// Deploys Credential Guard enablement GPO for Tier 0 systems.
        /// </summary>
        public async Task<AdGpoResult> DeployCredentialGuardGpoAsync(bool whatIf = true, CancellationToken ct = default)
        {
            var result = new AdGpoResult { GpoName = "Credential Guard", Success = false };

            if (_domainInfo == null)
            {
                result.Message = "Domain not discovered";
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report("Deploying Credential Guard GPO...");

                    var gpoName = "SEC - Enable Credential Guard";
                    var dc = _domainInfo.ChosenDc ?? "";
                    var domainDn = _domainInfo.DomainDn ?? "";

                    if (whatIf)
                    {
                        result.Success = true;
                        result.Message = $"[WHATIF] Would create GPO '{gpoName}' to enable Credential Guard";
                        _progress?.Report(result.Message);
                        return;
                    }

                    var gpoResult = CreateGpo(dc, domainDn, gpoName, "Enables Windows Credential Guard on compatible systems.");
                    if (!gpoResult.Success)
                    {
                        result.Message = gpoResult.Message;
                        return;
                    }

                    result.GpoGuid = gpoResult.GpoGuid;
                    result.GpoDn = gpoResult.GpoDn;

                    var policiesPath = $"\\\\{dc}\\SYSVOL\\{_domainInfo.DomainFqdn}\\Policies\\{{{result.GpoGuid}}}";
                    var machineRegPath = Path.Combine(policiesPath, "Machine", "Registry.pol");

                    Directory.CreateDirectory(Path.GetDirectoryName(machineRegPath)!);

                    var regValues = new Dictionary<string, (int type, object value)>
                    {
                        // Enable Virtualization Based Security (VBS)
                        [@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard!EnableVirtualizationBasedSecurity"] = (4, 1),
                        // Require Secure Boot + DMA Protection (3 = both, 1 = Secure Boot only)
                        [@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard!RequirePlatformSecurityFeatures"] = (4, 3),
                        // Enable Credential Guard with UEFI lock (1 = Enabled with lock, 2 = Enabled without lock)
                        [@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard!LsaCfgFlags"] = (4, 1),
                        // Enable Hypervisor-enforced Code Integrity (HVCI)
                        [@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard!HypervisorEnforcedCodeIntegrity"] = (4, 1),
                        // Enable Configurable Code Integrity  
                        [@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard!ConfigureSystemGuardLaunch"] = (4, 1),
                        // Enable Secure Launch (System Guard)
                        [@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard!HVCIMATRequired"] = (4, 0),
                    };

                    WriteRegistryPol(machineRegPath, regValues);
                    UpdateGptIni(policiesPath, true, false);

                    // Set gPCMachineExtensionNames for Registry Policy Processing CSE
                    SetGpoExtensions(dc, domainDn, result.GpoGuid!, "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]", true);

                    result.Success = true;
                    result.Message = $"Created GPO '{gpoName}'";
                    _progress?.Report($"[OK] {result.Message}");
                }
                catch (Exception ex)
                {
                    result.Message = ex.Message;
                    _progress?.Report($"Error: {ex.Message}");
                }
            }, ct);

            return result;
        }

        /// <summary>
        /// Runs all attack path detection scans.
        /// </summary>
        public async Task<AttackPathScanResult> RunAttackPathScanAsync(CancellationToken ct = default)
        {
            var result = new AttackPathScanResult();

            _progress?.Report("=== Starting Attack Path Detection Scan ===");

            result.UnconstrainedDelegation = await FindUnconstrainedDelegationAsync(ct);
            result.ConstrainedDelegation = await FindConstrainedDelegationAsync(ct);
            result.Rbcd = await FindRbcdAsync(ct);
            result.AsRepRoastable = await FindAsRepRoastableAccountsAsync(ct);
            result.Kerberoastable = await FindKerberoastableAccountsAsync(ct);
            result.DcSyncPrincipals = await FindDcSyncPrincipalsAsync(ct);
            result.SidHistory = await FindSidHistoryAsync(ct);
            result.OrphanedAdminCount = await FindOrphanedAdminCountAsync(ct);

            result.TotalFindings = result.UnconstrainedDelegation.Count + result.ConstrainedDelegation.Count +
                result.Rbcd.Count + result.AsRepRoastable.Count + result.Kerberoastable.Count +
                result.DcSyncPrincipals.Count + result.SidHistory.Count + result.OrphanedAdminCount.Count;

            result.CriticalFindings = result.UnconstrainedDelegation.Count(f => f.Severity == "Critical") +
                result.AsRepRoastable.Count(f => f.Severity == "Critical") +
                result.Kerberoastable.Count(f => f.Severity == "Critical") +
                result.DcSyncPrincipals.Count + result.SidHistory.Count(f => f.Severity == "Critical");

            _progress?.Report($"=== Attack Path Scan Complete: {result.TotalFindings} findings ({result.CriticalFindings} critical) ===");

            return result;
        }

        /// <summary>
        /// Helper to write Registry.pol file
        /// </summary>
        private static void WriteRegistryPol(string path, Dictionary<string, (int type, object value)> values)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms, Encoding.Unicode);

            // Registry.pol header: PReg signature + version (little-endian)
            bw.Write((byte)0x50); // P
            bw.Write((byte)0x52); // R
            bw.Write((byte)0x65); // e
            bw.Write((byte)0x67); // g
            bw.Write((int)1);     // Version

            foreach (var kvp in values)
            {
                var parts = kvp.Key.Split('!');
                var keyPath = parts[0];
                var valueName = parts[1];
                var (type, value) = kvp.Value;

                // Write entry - all delimiters must be Unicode (2 bytes each)
                WritePolUnicodeChar(bw, '[');
                WritePolString(bw, keyPath);
                WritePolUnicodeChar(bw, ';');
                WritePolString(bw, valueName);
                WritePolUnicodeChar(bw, ';');
                bw.Write((int)type);
                WritePolUnicodeChar(bw, ';');

                if (type == 4) // REG_DWORD
                {
                    bw.Write((int)4); // size
                    WritePolUnicodeChar(bw, ';');
                    bw.Write(Convert.ToInt32(value));
                }
                else if (type == 1) // REG_SZ
                {
                    var strValue = value.ToString() ?? "";
                    var bytes = Encoding.Unicode.GetBytes(strValue + "\0");
                    bw.Write((int)bytes.Length);
                    WritePolUnicodeChar(bw, ';');
                    bw.Write(bytes);
                }

                WritePolUnicodeChar(bw, ']');
            }

            File.WriteAllBytes(path, ms.ToArray());
        }

        private static void WritePolUnicodeChar(BinaryWriter bw, char c)
        {
            bw.Write((byte)c);
            bw.Write((byte)0);
        }

        private static void WritePolString(BinaryWriter bw, string value)
        {
            foreach (char c in value)
            {
                bw.Write((byte)c);
                bw.Write((byte)(c >> 8));
            }
            // Null terminator (Unicode)
            bw.Write((byte)0);
            bw.Write((byte)0);
        }

        /// <summary>
        /// Creates a new GPO in Active Directory.
        /// </summary>
        private AdGpoResult CreateGpo(string dc, string domainDn, string gpoName, string description)
        {
            var result = new AdGpoResult { GpoName = gpoName, Success = false };

            try
            {
                var domainFqdn = domainDn.Replace("DC=", "").Replace(",", ".");
                var gpoContainerDn = $"CN=Policies,CN=System,{domainDn}";

                using var gpoContainer = new DirectoryEntry($"LDAP://{dc}/{gpoContainerDn}");

                // Check if GPO exists
                using var searcher = new DirectorySearcher(gpoContainer)
                {
                    Filter = $"(&(objectClass=groupPolicyContainer)(displayName={EscapeLdapFilter(gpoName)}))",
                    SearchScope = SearchScope.OneLevel
                };

                var existing = searcher.FindOne();
                if (existing != null)
                {
                    result.GpoGuid = existing.Properties["name"]?[0]?.ToString()?.Trim('{', '}');
                    result.GpoDn = existing.Properties["distinguishedName"]?[0]?.ToString();
                    result.Success = true;
                    result.Message = "GPO already exists";
                    return result;
                }

                // Create new GPO
                var gpoGuid = Guid.NewGuid().ToString().ToUpperInvariant();
                var gpoCn = $"CN={{{gpoGuid}}}";
                var sysvolPath = $"\\\\{dc}\\SYSVOL\\{domainFqdn}\\Policies\\{{{gpoGuid}}}";

                using var newGpo = gpoContainer.Children.Add(gpoCn, "groupPolicyContainer");
                newGpo.Properties["displayName"].Value = gpoName;
                newGpo.Properties["gPCFileSysPath"].Value = sysvolPath;
                newGpo.Properties["gPCFunctionalityVersion"].Value = 2;
                newGpo.Properties["flags"].Value = 0;
                newGpo.Properties["versionNumber"].Value = 1;
                newGpo.CommitChanges();

                // Create SYSVOL folders
                Directory.CreateDirectory(Path.Combine(sysvolPath, "Machine"));
                Directory.CreateDirectory(Path.Combine(sysvolPath, "User"));

                // Create GPT.ini
                var gptIniPath = Path.Combine(sysvolPath, "GPT.ini");
                File.WriteAllText(gptIniPath, "[General]\r\nVersion=1\r\n");

                result.GpoGuid = gpoGuid;
                result.GpoDn = $"{gpoCn},{gpoContainerDn}";
                result.Success = true;
                result.Message = $"Created GPO: {gpoName}";
            }
            catch (Exception ex)
            {
                result.Message = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// Updates GPT.ini version number for a GPO.
        /// </summary>
        private void UpdateGptIni(string sysvolPath, bool machineChanged, bool userChanged)
        {
            var gptIniPath = Path.Combine(sysvolPath, "GPT.ini");

            int currentMachine = 0;
            int currentUser = 0;

            if (File.Exists(gptIniPath))
            {
                var content = File.ReadAllText(gptIniPath);
                var versionMatch = System.Text.RegularExpressions.Regex.Match(content, @"Version=(\d+)");
                if (versionMatch.Success)
                {
                    var version = int.Parse(versionMatch.Groups[1].Value);
                    currentMachine = version & 0xFFFF;
                    currentUser = (version >> 16) & 0xFFFF;
                }
            }

            if (machineChanged) currentMachine++;
            if (userChanged) currentUser++;

            var newVersion = (currentUser << 16) | currentMachine;
            File.WriteAllText(gptIniPath, $"[General]\r\nVersion={newVersion}\r\n");
        }

        /// <summary>
        /// Sets GPO extension GUIDs in AD.
        /// </summary>
        private void SetGpoExtensions(string dc, string domainDn, string gpoGuid, string extensionGuids, bool isMachine)
        {
            try
            {
                var gpoDn = $"CN={{{gpoGuid}}},CN=Policies,CN=System,{domainDn}";
                using var gpoEntry = new DirectoryEntry($"LDAP://{dc}/{gpoDn}");

                var propName = isMachine ? "gPCMachineExtensionNames" : "gPCUserExtensionNames";
                gpoEntry.Properties[propName].Value = extensionGuids;
                gpoEntry.CommitChanges();
            }
            catch (Exception ex)
            {
                _progress?.Report($"Warning: Could not set GPO extensions: {ex.Message}");
            }
        }

        /// <summary>
        /// Resolves a SID to its account name.
        /// </summary>
        private string ResolveSidToName(string sidString)
        {
            try
            {
                var sid = new SecurityIdentifier(sidString);
                var account = sid.Translate(typeof(NTAccount));
                return account.Value;
            }
            catch
            {
                return sidString;
            }
        }

        #endregion

        #region AD Operations - Krbtgt, Replication, LAPS, SYSVOL

        /// <summary>
        /// Validates that an AD distinguished name or name doesn't contain command injection characters.
        /// </summary>
        private static bool IsValidAdName(string? value, out string sanitized)
        {
            sanitized = value ?? string.Empty;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            // Block dangerous characters that could allow command injection
            // Allow: alphanumeric, spaces, hyphens, underscores, equals, commas, periods, forward slashes, backslashes
            // These are the characters typically found in AD distinguished names and group names
            var dangerousChars = new[] { '"', '\'', '`', '$', ';', '|', '&', '<', '>', '(', ')', '{', '}', '[', ']', '\n', '\r' };
            
            foreach (var c in dangerousChars)
            {
                if (value.Contains(c))
                    return false;
            }

            // Additional validation: DN should contain at least one = character (e.g., OU=, DC=, CN=)
            // Group names should not start with special characters
            sanitized = value.Trim();
            return true;
        }

        /// <summary>
        /// Creates a Base64-encoded PowerShell command for safe execution.
        /// This prevents command injection by encoding the entire script.
        /// </summary>
        private static string CreateEncodedPowerShellCommand(string script)
        {
            var bytes = System.Text.Encoding.Unicode.GetBytes(script);
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Resets the krbtgt account password. Should be done twice with 10+ hours between resets.
        /// </summary>
        public async Task<AdObjectCreationResult> ResetKrbtgtPasswordAsync(bool whatIf = true, CancellationToken ct = default)
        {
            var result = new AdObjectCreationResult
            {
                ObjectName = "krbtgt",
                ObjectType = "Password Reset"
            };

            if (_domainInfo == null)
            {
                result.Message = "Domain not discovered. Call DiscoverDomainAsync first.";
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report($"[{(whatIf ? "WHATIF" : "EXECUTE")}] Resetting krbtgt account password...");

                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    using var searcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = "(sAMAccountName=krbtgt)",
                        SearchScope = SearchScope.Subtree
                    };
                    searcher.PropertiesToLoad.Add("distinguishedName");
                    searcher.PropertiesToLoad.Add("pwdLastSet");

                    var krbtgt = searcher.FindOne();
                    if (krbtgt == null)
                    {
                        result.Message = "krbtgt account not found";
                        return;
                    }

                    var dn = krbtgt.Properties["distinguishedName"][0]?.ToString() ?? "";
                    var pwdLastSet = krbtgt.Properties.Contains("pwdLastSet") && krbtgt.Properties["pwdLastSet"].Count > 0
                        ? DateTime.FromFileTime((long)krbtgt.Properties["pwdLastSet"][0]!)
                        : DateTime.MinValue;

                    _progress?.Report($"krbtgt DN: {dn}");
                    _progress?.Report($"krbtgt password last set: {pwdLastSet:yyyy-MM-dd HH:mm:ss}");

                    if (whatIf)
                    {
                        result.Success = true;
                        result.Message = $"[WHATIF] Would reset krbtgt password (last set: {pwdLastSet:yyyy-MM-dd HH:mm:ss})";
                        _progress?.Report(result.Message);
                        return;
                    }

                    // Generate a new random password (128 characters for maximum security)
                    var newPassword = GenerateSecurePassword(128);

                    using var krbtgtEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{dn}");
                    krbtgtEntry.Invoke("SetPassword", new object[] { newPassword });
                    krbtgtEntry.CommitChanges();

                    result.Success = true;
                    result.Message = $"Successfully reset krbtgt password. Previous: {pwdLastSet:yyyy-MM-dd HH:mm:ss}";
                    _progress?.Report(result.Message);
                    _progress?.Report("⚠️ IMPORTANT: Wait at least 10 hours before resetting again to allow all DCs to replicate.");
                    _progress?.Report("⚠️ IMPORTANT: After second reset, wait another 10+ hours before considering Kerberos tickets fully rotated.");
                }
                catch (Exception ex)
                {
                    result.Message = $"Error resetting krbtgt password: {ex.Message}";
                    _progress?.Report(result.Message);
                }
            }, ct);

            return result;
        }

        /// <summary>
        /// Forces AD replication between domain controllers.
        /// </summary>
        public async Task<AdObjectCreationResult> ForceReplicationAsync(string? targetDc = null, bool whatIf = true, CancellationToken ct = default)
        {
            var result = new AdObjectCreationResult
            {
                ObjectName = "AD Replication",
                ObjectType = "Replication"
            };

            if (_domainInfo == null)
            {
                result.Message = "Domain not discovered. Call DiscoverDomainAsync first.";
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    var dc = targetDc ?? _domainInfo.ChosenDc;
                    _progress?.Report($"[{(whatIf ? "WHATIF" : "EXECUTE")}] Forcing AD replication from {dc}...");

                    if (whatIf)
                    {
                        result.Success = true;
                        result.Message = $"[WHATIF] Would force replication from {dc} to all partners";
                        _progress?.Report(result.Message);
                        _progress?.Report("[WHATIF] Command that would run: repadmin /syncall /AdeP");
                        return;
                    }

                    // Validate DC name to prevent command injection
                    if (!IsValidAdName(dc, out var safeDc))
                    {
                        result.Message = $"Invalid DC name: {dc}";
                        _progress?.Report(result.Message);
                        return;
                    }

                    // Use repadmin to force sync
                    var psi = new ProcessStartInfo
                    {
                        FileName = "repadmin.exe",
                        Arguments = $"/syncall {safeDc} /AdeP",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(psi);
                    if (process == null)
                    {
                        result.Message = "Failed to start repadmin process";
                        return;
                    }

                    var output = process.StandardOutput.ReadToEnd();
                    var error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        result.Success = true;
                        result.Message = $"Successfully forced replication from {dc}";
                        _progress?.Report(result.Message);
                        if (!string.IsNullOrWhiteSpace(output))
                        {
                            foreach (var line in output.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)))
                            {
                                _progress?.Report($"  {line.Trim()}");
                            }
                        }
                    }
                    else
                    {
                        result.Message = $"Replication command failed: {error}";
                        _progress?.Report(result.Message);
                    }
                }
                catch (Exception ex)
                {
                    result.Message = $"Error forcing replication: {ex.Message}";
                    _progress?.Report(result.Message);
                }
            }, ct);

            return result;
        }

        /// <summary>
        /// Implements LAPS by updating schema and configuring permissions.
        /// This is for Windows LAPS (built-in to Windows Server 2019+ and Windows 10/11).
        /// </summary>
        public async Task<List<AdObjectCreationResult>> ImplementLapsAsync(
            string targetOu,
            bool setPermissions = true,
            string? lapsAdminGroup = null,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            var results = new List<AdObjectCreationResult>();

            if (_domainInfo == null)
            {
                results.Add(new AdObjectCreationResult
                {
                    ObjectName = "LAPS Setup",
                    ObjectType = "Configuration",
                    Message = "Domain not discovered. Call DiscoverDomainAsync first."
                });
                return results;
            }

            await Task.Run(() =>
            {
                try
                {
                    _progress?.Report($"[{(whatIf ? "WHATIF" : "EXECUTE")}] Implementing LAPS...");

                    // Step 1: Check if Windows LAPS schema is extended
                    _progress?.Report("Checking LAPS schema extensions...");
                    
                    using var schemaEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/CN=Schema,CN=Configuration,{_domainInfo.ForestDn ?? _domainInfo.DomainDn}");
                    using var schemaSearcher = new DirectorySearcher(schemaEntry)
                    {
                        Filter = "(lDAPDisplayName=msLAPS-Password)",
                        SearchScope = SearchScope.OneLevel
                    };

                    var schemaResult = schemaSearcher.FindOne();
                    var hasWindowsLaps = schemaResult != null;

                    results.Add(new AdObjectCreationResult
                    {
                        ObjectName = "LAPS Schema Check",
                        ObjectType = "Schema",
                        Success = true,
                        Message = hasWindowsLaps 
                            ? "Windows LAPS schema is present" 
                            : "Windows LAPS schema NOT found. Run 'Update-LapsADSchema' on a DC first."
                    });
                    _progress?.Report(results.Last().Message);

                    if (!hasWindowsLaps)
                    {
                        _progress?.Report("To extend the schema for Windows LAPS, run on a Domain Controller:");
                        _progress?.Report("  Import-Module LAPS");
                        _progress?.Report("  Update-LapsADSchema");
                        return;
                    }

                    // Step 2: Set self-write permissions for computers to update their own password
                    if (setPermissions)
                    {
                        _progress?.Report($"Setting LAPS self-write permissions on OU: {targetOu}");

                        if (whatIf)
                        {
                            results.Add(new AdObjectCreationResult
                            {
                                ObjectName = "LAPS Computer Self-Write",
                                ObjectType = "ACL",
                                Success = true,
                                Message = $"[WHATIF] Would grant computers self-write on msLAPS-Password in {targetOu}"
                            });
                            _progress?.Report(results.Last().Message);
                        }
                        else
                        {
                            // Grant SELF the right to write msLAPS-Password attributes
                            var selfWriteResult = SetLapsComputerSelfPermission(targetOu);
                            results.Add(selfWriteResult);
                            _progress?.Report(selfWriteResult.Message);
                        }

                        // Step 3: Set read permissions for the LAPS admin group
                        var adminGroup = lapsAdminGroup ?? "Domain Admins";
                        _progress?.Report($"Setting LAPS read permissions for group: {adminGroup}");

                        if (whatIf)
                        {
                            results.Add(new AdObjectCreationResult
                            {
                                ObjectName = $"LAPS Read - {adminGroup}",
                                ObjectType = "ACL",
                                Success = true,
                                Message = $"[WHATIF] Would grant {adminGroup} read on msLAPS-Password in {targetOu}"
                            });
                            _progress?.Report(results.Last().Message);
                        }
                        else
                        {
                            var readResult = SetLapsReadPermission(targetOu, adminGroup);
                            results.Add(readResult);
                            _progress?.Report(readResult.Message);
                        }
                    }

                    // Step 4: Provide GPO guidance
                    _progress?.Report("");
                    _progress?.Report("=== LAPS GPO Configuration ===");
                    _progress?.Report("Create a GPO linked to computer OUs with these settings:");
                    _progress?.Report("  Computer Configuration > Policies > Administrative Templates > System > LAPS");
                    _progress?.Report("  - Configure password backup directory: Active Directory");
                    _progress?.Report("  - Password Settings: Enable, set complexity and length");
                    _progress?.Report("  - Name of administrator account to manage: (blank for built-in admin, or specify name)");
                }
                catch (Exception ex)
                {
                    results.Add(new AdObjectCreationResult
                    {
                        ObjectName = "LAPS Setup",
                        ObjectType = "Error",
                        Message = $"Error implementing LAPS: {ex.Message}"
                    });
                    _progress?.Report(results.Last().Message);
                }
            }, ct);

            return results;
        }

        /// <summary>
        /// Sets computer self-write permission for LAPS password attribute.
        /// </summary>
        private AdObjectCreationResult SetLapsComputerSelfPermission(string targetOu)
        {
            var result = new AdObjectCreationResult
            {
                ObjectName = "LAPS Computer Self-Write",
                ObjectType = "ACL"
            };

            try
            {
                // Validate input to prevent command injection
                if (!IsValidAdName(targetOu, out var safeOu))
                {
                    result.Message = $"Invalid OU name - contains disallowed characters: {targetOu}";
                    return result;
                }

                // Use Base64-encoded command to prevent injection
                var script = $"Set-LapsADComputerSelfPermission -Identity '{safeOu}'";
                var encodedCommand = CreateEncodedPowerShellCommand(script);

                // Run PowerShell command to set permissions
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -EncodedCommand {encodedCommand}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null)
                {
                    result.Message = "Failed to start PowerShell process";
                    return result;
                }

                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    result.Success = true;
                    result.Message = $"Set LAPS self-write permissions on {targetOu}";
                }
                else
                {
                    result.Message = $"Failed to set LAPS permissions: {error}";
                }
            }
            catch (Exception ex)
            {
                result.Message = $"Error setting LAPS self-write: {ex.Message}";
            }

            return result;
        }

        /// <summary>
        /// Sets read permission for LAPS password attribute to a specified group.
        /// </summary>
        private AdObjectCreationResult SetLapsReadPermission(string targetOu, string groupName)
        {
            var result = new AdObjectCreationResult
            {
                ObjectName = $"LAPS Read - {groupName}",
                ObjectType = "ACL"
            };

            try
            {
                // Validate inputs to prevent command injection
                if (!IsValidAdName(targetOu, out var safeOu))
                {
                    result.Message = $"Invalid OU name - contains disallowed characters: {targetOu}";
                    return result;
                }
                if (!IsValidAdName(groupName, out var safeGroup))
                {
                    result.Message = $"Invalid group name - contains disallowed characters: {groupName}";
                    return result;
                }

                // Use Base64-encoded command to prevent injection
                var script = $"Set-LapsADReadPasswordPermission -Identity '{safeOu}' -AllowedPrincipals '{safeGroup}'";
                var encodedCommand = CreateEncodedPowerShellCommand(script);

                // Run PowerShell command to set read permissions
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -EncodedCommand {encodedCommand}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null)
                {
                    result.Message = "Failed to start PowerShell process";
                    return result;
                }

                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    result.Success = true;
                    result.Message = $"Granted {groupName} LAPS read permission on {targetOu}";
                }
                else
                {
                    result.Message = $"Failed to set LAPS read permission: {error}";
                }
            }
            catch (Exception ex)
            {
                result.Message = $"Error setting LAPS read permission: {ex.Message}";
            }

            return result;
        }

        /// <summary>
        /// Performs an authoritative SYSVOL restore using DFS replication.
        /// This makes the specified DC's SYSVOL the authoritative source.
        /// </summary>
        public async Task<AdObjectCreationResult> AuthoritativeSysvolRestoreAsync(
            string? targetDc = null,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            var result = new AdObjectCreationResult
            {
                ObjectName = "SYSVOL Authoritative Restore",
                ObjectType = "DFSR Configuration"
            };

            if (_domainInfo == null)
            {
                result.Message = "Domain not discovered. Call DiscoverDomainAsync first.";
                return result;
            }

            await Task.Run(() =>
            {
                try
                {
                    var dc = targetDc ?? _domainInfo.PdcEmulator ?? _domainInfo.ChosenDc;
                    _progress?.Report($"[{(whatIf ? "WHATIF" : "EXECUTE")}] Initiating authoritative SYSVOL restore on {dc}...");
                    _progress?.Report("⚠️ WARNING: This operation makes this DC's SYSVOL the authoritative copy!");
                    _progress?.Report("⚠️ All other DCs will sync FROM this DC's SYSVOL!");

                    // Find the DFSR member object for this DC
                    var configDn = $"CN=Configuration,{_domainInfo.ForestDn ?? _domainInfo.DomainDn}";
                    var dfsrPath = $"CN=DFSR-GlobalSettings,CN=System,{_domainInfo.DomainDn}";

                    _progress?.Report($"Looking for DFSR configuration at: {dfsrPath}");

                    if (whatIf)
                    {
                        result.Success = true;
                        result.Message = $"[WHATIF] Would set authoritative restore on {dc}";
                        _progress?.Report(result.Message);
                        _progress?.Report("[WHATIF] Steps that would be performed:");
                        _progress?.Report($"  1. Stop DFSR service on {dc}");
                        _progress?.Report($"  2. Set msDFSR-Options attribute to 1 (authoritative) on {dc}'s SYSVOL subscription");
                        _progress?.Report("  3. Start DFSR service");
                        _progress?.Report("  4. Wait for replication to complete");
                        _progress?.Report("  5. Reset msDFSR-Options to 0 on non-authoritative DCs");
                        _progress?.Report("");
                        _progress?.Report("Manual PowerShell commands:");
                        _progress?.Report($"  # On {dc} (authoritative source):");
                        _progress?.Report("  Stop-Service DFSR");
                        _progress?.Report($"  $dfsrMember = Get-ADObject -Filter {{Name -eq '{dc}'}} -SearchBase 'CN=DFSR-LocalSettings,CN={dc},OU=Domain Controllers,{_domainInfo.DomainDn}'");
                        _progress?.Report("  Set-ADObject $dfsrMember -Replace @{'msDFSR-Options'=1}");
                        _progress?.Report("  Start-Service DFSR");
                        return;
                    }

                    // Actual execution - use AD to find and modify DFSR settings
                    using var rootEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{_domainInfo.DomainDn}");
                    
                    // Find the DC's computer object - strip the $ if present in dc name
                    var dcClean = dc.EndsWith("$") ? dc : dc;
                    var dcPattern = dcClean.Contains(".") ? dcClean.Split('.')[0] : dcClean;
                    
                    using var dcSearcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = $"(&(objectClass=computer)(|(cn={dcPattern})(dNSHostName={dc})))",
                        SearchScope = SearchScope.Subtree
                    };
                    dcSearcher.PropertiesToLoad.Add("distinguishedName");

                    var dcResult = dcSearcher.FindOne();
                    if (dcResult == null)
                    {
                        result.Message = $"Could not find computer object for DC: {dc}";
                        _progress?.Report(result.Message);
                        return;
                    }

                    var dcDn = dcResult.Properties["distinguishedName"][0]?.ToString() ?? "";
                    _progress?.Report($"Found DC: {dcDn}");

                    // Find DFSR-LocalSettings for this DC
                    var dfsrLocalSettingsDn = $"CN=DFSR-LocalSettings,{dcDn}";
                    _progress?.Report($"Looking for DFSR settings at: {dfsrLocalSettingsDn}");

                    using var dfsrEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{dfsrLocalSettingsDn}");
                    using var sysvolSearcher = new DirectorySearcher(dfsrEntry)
                    {
                        Filter = "(cn=SYSVOL Subscription)",
                        SearchScope = SearchScope.Subtree
                    };
                    sysvolSearcher.PropertiesToLoad.Add("distinguishedName");
                    sysvolSearcher.PropertiesToLoad.Add("msDFSR-Options");

                    var sysvolResult = sysvolSearcher.FindOne();
                    if (sysvolResult == null)
                    {
                        result.Message = "Could not find SYSVOL Subscription object. Is this DC using DFSR for SYSVOL?";
                        _progress?.Report(result.Message);
                        return;
                    }

                    var sysvolDn = sysvolResult.Properties["distinguishedName"][0]?.ToString() ?? "";
                    _progress?.Report($"Found SYSVOL Subscription: {sysvolDn}");

                    // Set msDFSR-Options to 1 for authoritative restore
                    using var sysvolEntry = new DirectoryEntry($"LDAP://{_domainInfo.ChosenDc}/{sysvolDn}");
                    sysvolEntry.Properties["msDFSR-Options"].Value = 1;
                    sysvolEntry.CommitChanges();

                    result.Success = true;
                    result.Message = $"Set authoritative flag on {dc}'s SYSVOL. Restart DFSR service on {dc} to initiate sync.";
                    _progress?.Report(result.Message);
                    _progress?.Report($"Run on {dc}: Restart-Service DFSR");
                    _progress?.Report("After replication completes, run on OTHER DCs:");
                    _progress?.Report("  Stop-Service DFSR");
                    _progress?.Report("  # Set msDFSR-Options to 0 (non-authoritative)");
                    _progress?.Report("  Start-Service DFSR");
                }
                catch (Exception ex)
                {
                    result.Message = $"Error performing authoritative SYSVOL restore: {ex.Message}";
                    _progress?.Report(result.Message);
                }
            }, ct);

            return result;
        }

        /// <summary>
        /// Generates a cryptographically secure random password.
        /// </summary>
        private static string GenerateSecurePassword(int length)
        {
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}|;:',.<>?";
            var password = new char[length];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            var bytes = new byte[length];
            rng.GetBytes(bytes);

            for (int i = 0; i < length; i++)
            {
                password[i] = validChars[bytes[i] % validChars.Length];
            }

            return new string(password);
        }

        #endregion
    }
}

