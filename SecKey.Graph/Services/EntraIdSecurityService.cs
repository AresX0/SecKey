using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure.Identity;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using SecKey.Core.Models;

namespace SecKey.Graph.Services
{
    /// <summary>
    /// Entra ID (Azure AD) Security Analysis Service.
    /// Provides security assessment capabilities for Microsoft Entra ID tenants.
    /// Implements functionality similar to PLATYPUS Azure analysis functions.
    /// </summary>
    public class EntraIdSecurityService
    {
        private readonly IProgress<string>? _progress;
        private GraphServiceClient? _graphClient;
        private string? _tenantId;

        /// <summary>
        /// Client ID used for Graph API authentication.
        /// Defaults to the well-known Microsoft Graph PowerShell client ID if not specified.
        /// </summary>    
        private readonly string _graphClientId;

        /// <summary>
        /// Well-known Microsoft Graph PowerShell client ID. Public, not tenant-specific.
        /// </summary>
        public const string DefaultGraphClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e";

        public EntraIdSecurityService(IProgress<string>? progress = null, string? graphClientId = null)
        {
            _progress = progress;
            _graphClientId = string.IsNullOrWhiteSpace(graphClientId) ? DefaultGraphClientId : graphClientId;
        }

        #region Authentication

        /// <summary>
        /// Connects to Microsoft Graph using interactive browser authentication.
        /// </summary>
        public async Task<bool> ConnectAsync(string tenantId, CancellationToken ct = default)
        {
            try
            {
                _tenantId = tenantId;
                _progress?.Report($"Connecting to Entra ID tenant: {tenantId}...");

                // Use interactive browser authentication
                var options = new InteractiveBrowserCredentialOptions
                {
                    TenantId = tenantId,
                    ClientId = _graphClientId,
                    AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
                    RedirectUri = new Uri("http://localhost")
                };

                var credential = new InteractiveBrowserCredential(options);
                
                _graphClient = new GraphServiceClient(credential, new[] { 
                    "https://graph.microsoft.com/.default" 
                });

                // Test connection by getting organization info
                var org = await _graphClient.Organization.GetAsync(cancellationToken: ct);
                if (org?.Value?.FirstOrDefault() != null)
                {
                    _progress?.Report($"Connected to tenant: {org.Value.First().DisplayName}");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _progress?.Report($"Failed to connect to Entra ID: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Connects using device code flow (useful for headless scenarios).
        /// </summary>
        public async Task<bool> ConnectWithDeviceCodeAsync(string tenantId, CancellationToken ct = default)
        {
            try
            {
                _tenantId = tenantId;
                _progress?.Report($"Initiating device code authentication for tenant: {tenantId}...");

                var options = new DeviceCodeCredentialOptions
                {
                    TenantId = tenantId,
                    ClientId = _graphClientId,
                    DeviceCodeCallback = (code, cancellation) =>
                    {
                        _progress?.Report(code.Message);
                        return Task.CompletedTask;
                    }
                };

                var credential = new DeviceCodeCredential(options);
                _graphClient = new GraphServiceClient(credential);

                var org = await _graphClient.Organization.GetAsync(cancellationToken: ct);
                if (org?.Value?.FirstOrDefault() != null)
                {
                    _progress?.Report($"Connected to tenant: {org.Value.First().DisplayName}");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _progress?.Report($"Failed to connect to Entra ID: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Checks if we're connected to Microsoft Graph.
        /// </summary>
        public bool IsConnected => _graphClient != null;

        /// <summary>
        /// Disconnects from Microsoft Graph and clears the client.
        /// </summary>
        public void Disconnect()
        {
            _graphClient = null;
            _tenantId = null;
            _progress?.Report("Disconnected from Entra ID");
        }

        #endregion

        #region Tenant Discovery

        /// <summary>
        /// Gets basic tenant information.
        /// </summary>
        public async Task<EntraIdTenant?> GetTenantInfoAsync(CancellationToken ct = default)
        {
            if (_graphClient == null)
            {
                _progress?.Report("Not connected to Entra ID. Call ConnectAsync first.");
                return null;
            }

            try
            {
                _progress?.Report("Getting tenant information...");

                var org = await _graphClient.Organization.GetAsync(cancellationToken: ct);
                var orgInfo = org?.Value?.FirstOrDefault();

                if (orgInfo == null)
                    return null;

                var domains = await _graphClient.Domains.GetAsync(cancellationToken: ct);

                return new EntraIdTenant
                {
                    TenantId = orgInfo.Id ?? "",
                    DisplayName = orgInfo.DisplayName ?? "",
                    DefaultDomain = domains?.Value?.FirstOrDefault(d => d.IsDefault == true)?.Id ?? "",
                    VerifiedDomains = domains?.Value?.Where(d => d.IsVerified == true).Select(d => d.Id ?? "").ToList() ?? new List<string>(),
                    DiscoveryTime = DateTime.Now
                };
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error getting tenant info: {ex.Message}");
                return null;
            }
        }

        #endregion

        #region Privileged Role Analysis

        /// <summary>
        /// Gets all privileged role assignments in the tenant.
        /// Mirrors PLATYPUS Get-AzureAdPrivObjects functionality.
        /// </summary>
        public async Task<List<EntraIdPrivilegedRole>> GetPrivilegedRolesAsync(
            bool usersOnly = false, 
            CancellationToken ct = default)
        {
            if (_graphClient == null)
            {
                _progress?.Report("Not connected to Entra ID. Call ConnectAsync first.");
                return new List<EntraIdPrivilegedRole>();
            }

            var privilegedRoles = new List<EntraIdPrivilegedRole>();

            try
            {
                _progress?.Report("Getting privileged role assignments...");

                // Get all directory roles (activated roles)
                var directoryRoles = await _graphClient.DirectoryRoles.GetAsync(cancellationToken: ct);

                if (directoryRoles?.Value == null)
                    return privilegedRoles;

                // Filter for admin roles
                var adminRoles = directoryRoles.Value
                    .Where(r => r.DisplayName?.Contains("Administrator") == true || 
                                r.DisplayName?.Contains("Admin") == true ||
                                IsPrivilegedRole(r.DisplayName))
                    .ToList();

                int processed = 0;
                foreach (var role in adminRoles)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        var privilegedRole = new EntraIdPrivilegedRole
                        {
                            RoleId = role.Id ?? "",
                            RoleDisplayName = role.DisplayName ?? "",
                            RoleTemplateId = role.RoleTemplateId ?? "",
                            IsBuiltIn = true,
                            Members = new List<EntraIdRoleMember>()
                        };

                        // Get role members
                        var members = await _graphClient.DirectoryRoles[role.Id].Members.GetAsync(cancellationToken: ct);

                        if (members?.Value != null)
                        {
                            foreach (var member in members.Value)
                            {
                                var roleMember = await CreateRoleMemberAsync(member, role.DisplayName ?? "", usersOnly, ct);
                                if (roleMember != null)
                                {
                                    privilegedRole.Members.Add(roleMember);
                                }
                            }
                        }

                        if (privilegedRole.Members.Count > 0)
                        {
                            privilegedRoles.Add(privilegedRole);
                        }

                        processed++;
                        if (processed % 5 == 0)
                        {
                            _progress?.Report($"Processed {processed}/{adminRoles.Count} roles...");
                        }
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"Error processing role {role.DisplayName}: {ex.Message}");
                    }
                }

                _progress?.Report($"Found {privilegedRoles.Sum(r => r.Members.Count)} privileged role assignments");
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error getting privileged roles: {ex.Message}");
            }

            return privilegedRoles;
        }

        private async Task<EntraIdRoleMember?> CreateRoleMemberAsync(
            DirectoryObject member, 
            string roleName, 
            bool usersOnly,
            CancellationToken ct)
        {
            try
            {
                var odataType = member.OdataType ?? "";
                var objectType = odataType.Split('.').LastOrDefault() ?? "Unknown";

                if (usersOnly && objectType != "user")
                    return null;

                var roleMember = new EntraIdRoleMember
                {
                    ObjectId = member.Id ?? "",
                    ObjectType = objectType,
                    RoleName = roleName,
                    AssignmentType = "Permanent"
                };

                // Get additional details based on type
                if (objectType == "user" && _graphClient != null)
                {
                    try
                    {
                        var user = await _graphClient.Users[member.Id].GetAsync(cancellationToken: ct);
                        if (user != null)
                        {
                            roleMember.DisplayName = user.DisplayName ?? "";
                            roleMember.UserPrincipalName = user.UserPrincipalName ?? "";
                        }
                    }
                    catch { }
                }
                else if (objectType == "servicePrincipal" && _graphClient != null)
                {
                    try
                    {
                        var sp = await _graphClient.ServicePrincipals[member.Id].GetAsync(cancellationToken: ct);
                        if (sp != null)
                        {
                            roleMember.DisplayName = sp.DisplayName ?? "";
                            roleMember.UserPrincipalName = sp.AppId ?? "";
                        }
                    }
                    catch { }
                }
                else if (objectType == "group" && _graphClient != null)
                {
                    try
                    {
                        var group = await _graphClient.Groups[member.Id].GetAsync(cancellationToken: ct);
                        if (group != null)
                        {
                            roleMember.DisplayName = group.DisplayName ?? "";
                        }
                    }
                    catch { }
                }

                return roleMember;
            }
            catch
            {
                return null;
            }
        }

        private bool IsPrivilegedRole(string? roleName)
        {
            // Use the comprehensive privileged roles list from the models
            return EntraIdPrivilegedRoles.IsPrivilegedRole(roleName);
        }

        #endregion

        #region PIM Analysis

        /// <summary>
        /// Analyzes PIM settings to find roles with permanent (active) assignments
        /// that should be eligible only. Returns role assignments that violate 
        /// PIM best practices (permanent assignments to privileged roles).
        /// </summary>
        public async Task<List<EntraIdPimViolation>> GetPimViolationsAsync(CancellationToken ct = default)
        {
            if (_graphClient == null)
            {
                _progress?.Report("Not connected to Entra ID. Call ConnectAsync first.");
                return new List<EntraIdPimViolation>();
            }

            var violations = new List<EntraIdPimViolation>();

            try
            {
                _progress?.Report("Analyzing PIM settings for permanent role assignments...");

                // Get all directory roles
                var roles = await _graphClient.DirectoryRoles.GetAsync(cancellationToken: ct);
                if (roles?.Value == null)
                    return violations;

                _progress?.Report($"Analyzing {roles.Value.Count} active roles...");

                foreach (var role in roles.Value)
                {
                    ct.ThrowIfCancellationRequested();

                    if (role == null || string.IsNullOrEmpty(role.Id))
                        continue;

                    var roleName = role.DisplayName ?? "Unknown";
                    
                    // Check if this role should never have permanent assignments
                    bool shouldBePimOnly = EntraIdPrivilegedRoles.ShouldNeverBePermanent(roleName);

                    // Get members of this role
                    var members = await _graphClient.DirectoryRoles[role.Id].Members.GetAsync(cancellationToken: ct);
                    if (members?.Value == null || members.Value.Count == 0)
                        continue;

                    foreach (var member in members.Value)
                    {
                        if (member == null)
                            continue;

                        // All direct role assignments are "Active/Permanent" 
                        // (vs PIM eligible which requires activation)
                        var violation = new EntraIdPimViolation
                        {
                            RoleId = role.RoleTemplateId ?? role.Id,
                            RoleName = roleName,
                            RoleDescription = role.Description ?? "",
                            PrincipalId = member.Id ?? "",
                            AssignmentType = "Permanent",
                            ViolationType = shouldBePimOnly ? "Critical" : "Warning",
                            Recommendation = shouldBePimOnly 
                                ? $"Remove permanent assignment. {roleName} should ONLY have PIM eligible assignments."
                                : $"Consider converting to PIM eligible assignment for better security."
                        };

                        // Get member details
                        if (member is Microsoft.Graph.Models.User user)
                        {
                            violation.PrincipalType = "User";
                            violation.PrincipalDisplayName = user.DisplayName ?? "";
                            violation.PrincipalUpn = user.UserPrincipalName ?? "";
                        }
                        else if (member is Microsoft.Graph.Models.ServicePrincipal sp)
                        {
                            violation.PrincipalType = "ServicePrincipal";
                            violation.PrincipalDisplayName = sp.DisplayName ?? "";
                            violation.PrincipalUpn = sp.AppId ?? "";
                        }
                        else if (member is Microsoft.Graph.Models.Group grp)
                        {
                            violation.PrincipalType = "Group";
                            violation.PrincipalDisplayName = grp.DisplayName ?? "";
                            violation.PrincipalUpn = grp.Id ?? "";
                        }
                        else
                        {
                            violation.PrincipalType = member.OdataType?.Replace("#microsoft.graph.", "") ?? "Unknown";
                            violation.PrincipalDisplayName = member.Id ?? "";
                        }

                        violations.Add(violation);
                        
                        if (shouldBePimOnly)
                        {
                            _progress?.Report($"⚠️ PIM VIOLATION: {violation.PrincipalDisplayName} has PERMANENT {roleName} assignment");
                        }
                    }
                }

                _progress?.Report($"Found {violations.Count(v => v.ViolationType == "Critical")} critical PIM violations and {violations.Count(v => v.ViolationType == "Warning")} warnings");
                return violations;
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error analyzing PIM settings: {ex.Message}");
                return violations;
            }
        }

        #endregion

        #region Risky Applications Analysis

        /// <summary>
        /// Gets applications with risky API permissions.
        /// Mirrors PLATYPUS Get-AzureAdRiskyApps functionality.
        /// </summary>
        public async Task<List<EntraIdRiskyApp>> GetRiskyAppsAsync(CancellationToken ct = default)
        {
            if (_graphClient == null)
            {
                _progress?.Report("Not connected to Entra ID. Call ConnectAsync first.");
                return new List<EntraIdRiskyApp>();
            }

            var riskyApps = new List<EntraIdRiskyApp>();

            try
            {
                _progress?.Report("Scanning applications for risky API permissions...");

                // Get all applications
                var applications = await _graphClient.Applications.GetAsync(cancellationToken: ct);

                if (applications?.Value == null)
                    return riskyApps;

                _progress?.Report($"Found {applications.Value.Count} applications to analyze...");

                int processed = 0;
                foreach (var app in applications.Value)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        var riskyPermissions = AnalyzeAppPermissions(app);

                        if (riskyPermissions.Count > 0)
                        {
                            var riskyApp = new EntraIdRiskyApp
                            {
                                AppId = app.AppId ?? "",
                                DisplayName = app.DisplayName ?? "",
                                ObjectId = app.Id ?? "",
                                CreatedDateTime = app.CreatedDateTime?.UtcDateTime,
                                Permissions = riskyPermissions,
                                Owners = new List<string>()
                            };

                            // Determine severity based on permissions
                            riskyApp.Severity = DetermineAppSeverity(riskyPermissions);
                            riskyApp.RiskReason = string.Join(", ", riskyPermissions.Select(p => p.PermissionName).Distinct());

                            // Get owners
                            try
                            {
                                var owners = await _graphClient.Applications[app.Id].Owners.GetAsync(cancellationToken: ct);
                                if (owners?.Value != null)
                                {
                                    foreach (var owner in owners.Value)
                                    {
                                        if (owner is User user)
                                        {
                                            riskyApp.Owners.Add(user.UserPrincipalName ?? user.DisplayName ?? owner.Id ?? "");
                                        }
                                    }
                                }
                            }
                            catch { }

                            riskyApps.Add(riskyApp);
                        }

                        processed++;
                        if (processed % 50 == 0)
                        {
                            _progress?.Report($"Analyzed {processed}/{applications.Value.Count} applications...");
                        }
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"Error analyzing app {app.DisplayName}: {ex.Message}");
                    }
                }

                _progress?.Report($"Found {riskyApps.Count} applications with risky permissions");
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error scanning applications: {ex.Message}");
            }

            return riskyApps.OrderByDescending(a => a.Severity == "Critical")
                           .ThenByDescending(a => a.Severity == "High")
                           .ToList();
        }

        private List<EntraIdAppPermissionInfo> AnalyzeAppPermissions(Application app)
        {
            var riskyPermissions = new List<EntraIdAppPermissionInfo>();

            if (app.RequiredResourceAccess == null)
                return riskyPermissions;

            foreach (var resource in app.RequiredResourceAccess)
            {
                if (resource.ResourceAccess == null)
                    continue;

                foreach (var permission in resource.ResourceAccess)
                {
                    var permId = permission.Id?.ToString() ?? "";
                    
                    if (RiskyEntraIdPermissions.HighRiskPermissions.TryGetValue(permId, out var permName))
                    {
                        var permInfo = new EntraIdAppPermissionInfo
                        {
                            PermissionId = permId,
                            PermissionName = permName,
                            PermissionDescription = RiskyEntraIdPermissions.GetPermissionDescription(permName),
                            ResourceAppId = resource.ResourceAppId?.ToString() ?? "",
                            PermissionType = permission.Type == "Role" ? "Application" : "Delegated",
                            IsHighRisk = true,
                            ConsentType = permission.Type == "Role" ? "Admin" : "User"
                        };

                        riskyPermissions.Add(permInfo);
                    }
                }
            }

            return riskyPermissions;
        }

        private string DetermineAppSeverity(List<EntraIdAppPermissionInfo> permissions)
        {
            var permNames = permissions.Select(p => p.PermissionName).ToHashSet();

            // Critical: Directory write, role management, or app management
            if (permNames.Any(p => RiskyEntraIdPermissions.CriticalPermissions.Contains(p)))
                return "Critical";

            // High: Mail access, file access with write
            if (permNames.Any(p => p.Contains("Mail") || p.Contains("Files.ReadWrite")))
                return "High";

            // Medium: Read-only sensitive access
            return "Medium";
        }

        #endregion

        #region Conditional Access Policy Analysis

        /// <summary>
        /// Gets all Conditional Access policies.
        /// Mirrors PLATYPUS Get-AzureAdCAPolicies functionality.
        /// </summary>
        public async Task<List<EntraIdConditionalAccessPolicy>> GetConditionalAccessPoliciesAsync(
            CancellationToken ct = default)
        {
            if (_graphClient == null)
            {
                _progress?.Report("Not connected to Entra ID. Call ConnectAsync first.");
                return new List<EntraIdConditionalAccessPolicy>();
            }

            var policies = new List<EntraIdConditionalAccessPolicy>();

            try
            {
                _progress?.Report("Getting Conditional Access policies...");

                var caPolicies = await _graphClient.Identity.ConditionalAccess.Policies.GetAsync(cancellationToken: ct);

                if (caPolicies?.Value == null)
                    return policies;

                foreach (var caPolicy in caPolicies.Value)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        var policy = new EntraIdConditionalAccessPolicy
                        {
                            Id = caPolicy.Id ?? "",
                            DisplayName = caPolicy.DisplayName ?? "",
                            State = caPolicy.State?.ToString() ?? "Unknown",
                            CreatedDateTime = caPolicy.CreatedDateTime?.UtcDateTime,
                            ModifiedDateTime = caPolicy.ModifiedDateTime?.UtcDateTime
                        };

                        // Parse conditions
                        if (caPolicy.Conditions?.Users != null)
                        {
                            policy.IncludedUsers = caPolicy.Conditions.Users.IncludeUsers?.ToList() ?? new List<string>();
                            policy.ExcludedUsers = caPolicy.Conditions.Users.ExcludeUsers?.ToList() ?? new List<string>();
                        }

                        if (caPolicy.Conditions?.Applications != null)
                        {
                            policy.IncludedApplications = caPolicy.Conditions.Applications.IncludeApplications?.ToList() ?? new List<string>();
                        }

                        // Parse grant controls
                        if (caPolicy.GrantControls != null)
                        {
                            policy.GrantControls = caPolicy.GrantControls.BuiltInControls?
                                .Select(c => c.ToString() ?? "")
                                .ToList() ?? new List<string>();
                        }

                        // Parse session controls
                        if (caPolicy.SessionControls != null)
                        {
                            var sessionControls = new List<string>();
                            if (caPolicy.SessionControls.SignInFrequency != null)
                                sessionControls.Add($"SignInFrequency: {caPolicy.SessionControls.SignInFrequency.Value} {caPolicy.SessionControls.SignInFrequency.Type}");
                            if (caPolicy.SessionControls.PersistentBrowser != null)
                                sessionControls.Add($"PersistentBrowser: {caPolicy.SessionControls.PersistentBrowser.Mode}");
                            policy.SessionControls = string.Join("; ", sessionControls);
                        }

                        policies.Add(policy);
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"Error parsing CA policy {caPolicy.DisplayName}: {ex.Message}");
                    }
                }

                _progress?.Report($"Found {policies.Count} Conditional Access policies");
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error getting CA policies: {ex.Message}");
            }

            return policies;
        }

        #endregion

        #region Full Analysis

        /// <summary>
        /// Runs a complete Entra ID security analysis.
        /// </summary>
        public async Task<EntraIdSecurityResult> RunFullAnalysisAsync(
            string tenantId,
            bool usersOnly = false,
            CancellationToken ct = default)
        {
            var result = new EntraIdSecurityResult
            {
                StartTime = DateTime.Now
            };

            try
            {
                // Connect if not already connected
                if (!IsConnected || _tenantId != tenantId)
                {
                    var connected = await ConnectAsync(tenantId, ct);
                    if (!connected)
                    {
                        result.Errors.Add("Failed to connect to Entra ID");
                        return result;
                    }
                }

                // Get tenant info
                result.Tenant = await GetTenantInfoAsync(ct);

                // Get privileged roles
                _progress?.Report("Analyzing privileged role assignments...");
                result.PrivilegedRoles = await GetPrivilegedRolesAsync(usersOnly, ct);

                // Get risky apps
                _progress?.Report("Analyzing application permissions...");
                result.RiskyApps = await GetRiskyAppsAsync(ct);

                // Get CA policies
                _progress?.Report("Getting Conditional Access policies...");
                result.ConditionalAccessPolicies = await GetConditionalAccessPoliciesAsync(ct);

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

            _progress?.Report($"Entra ID analysis complete. " +
                $"Privileged users: {result.TotalPrivilegedUsers}, " +
                $"Risky apps: {result.RiskyApps.Count}, " +
                $"CA policies: {result.ConditionalAccessPolicies.Count}");

            return result;
        }

        #endregion

        #region Tenant Takeback / Remediation Methods (PLATYPUS IR Operations)

        /// <summary>
        /// Performs a tenant takeback operation - resets passwords, revokes sessions, 
        /// and optionally removes users from privileged roles (including PIM eligible).
        /// Equivalent to Invoke-AzureAdTenantTakeBack in PLATYPUS.
        /// </summary>
        public async Task<TenantTakebackResult> TakebackTenantAsync(
            TenantTakebackOptions options,
            CancellationToken ct = default)
        {
            var result = new TenantTakebackResult
            {
                StartTime = DateTime.Now,
                TenantId = options.TenantId
            };

            if (_graphClient == null)
            {
                _progress?.Report("Not connected to Entra ID. Call ConnectAsync first.");
                result.Errors.Add("Not connected to Entra ID");
                return result;
            }

            try
            {
                _progress?.Report("Starting tenant takeback operation...");
                _progress?.Report($"Exempted users: {string.Join(", ", options.ExemptedUserUpns)}");

                // Get all privileged role assignments (direct/permanent)
                var privilegedRoles = await GetPrivilegedRolesAsync(true, ct);
                var allPrivilegedMembers = privilegedRoles.SelectMany(r => r.Members).ToList();

                // Also get PIM eligible assignments
                var pimEligibleAssignments = await GetPimEligibleAssignmentsAsync(ct);
                _progress?.Report($"Found {allPrivilegedMembers.Count} direct role members and {pimEligibleAssignments.Count} PIM eligible assignments");

                // Combine and deduplicate users
                var allUsersToProcess = new Dictionary<string, (string ObjectId, string Upn, bool IsExternal)>();
                
                foreach (var member in allPrivilegedMembers)
                {
                    if (!allUsersToProcess.ContainsKey(member.ObjectId))
                    {
                        allUsersToProcess[member.ObjectId] = (member.ObjectId, member.UserPrincipalName, 
                            member.UserPrincipalName.Contains("#EXT#"));
                    }
                }

                foreach (var pim in pimEligibleAssignments.Where(p => p.PrincipalType == "User"))
                {
                    if (!allUsersToProcess.ContainsKey(pim.PrincipalId))
                    {
                        allUsersToProcess[pim.PrincipalId] = (pim.PrincipalId, pim.PrincipalUpn,
                            pim.PrincipalUpn.Contains("#EXT#"));
                    }
                }

                _progress?.Report($"Total unique users to process: {allUsersToProcess.Count}");

                foreach (var userEntry in allUsersToProcess.Values)
                {
                    ct.ThrowIfCancellationRequested();

                    // Skip exempted users
                    if (options.ExemptedUserUpns.Any(e => 
                        e.Equals(userEntry.Upn, StringComparison.OrdinalIgnoreCase)))
                    {
                        _progress?.Report($"Skipping exempted user: {userEntry.Upn}");
                        result.SkippedUsers.Add(userEntry.Upn);
                        continue;
                    }

                    var userResult = new UserTakebackResult
                    {
                        UserPrincipalName = userEntry.Upn,
                        ObjectId = userEntry.ObjectId
                    };

                    try
                    {
                        if (!options.WhatIf)
                        {
                            // 1. Reset password (skip external users)
                            if (options.ResetPasswords && !userEntry.IsExternal)
                            {
                                var newPassword = GenerateSecurePassword();
                                await ResetUserPasswordAsync(userEntry.ObjectId, newPassword, ct);
                                userResult.PasswordReset = true;
                                userResult.NewPassword = options.SavePasswordsToResult ? newPassword : "[REDACTED]";
                                _progress?.Report($"Password reset for: {userEntry.Upn}");
                            }
                            else if (userEntry.IsExternal)
                            {
                                _progress?.Report($"Skipping password reset for external user: {userEntry.Upn}");
                            }

                            // 2. Revoke sessions
                            if (options.RevokeSessions)
                            {
                                await RevokeUserSessionsAsync(userEntry.ObjectId, ct);
                                userResult.SessionsRevoked = true;
                                _progress?.Report($"Sessions revoked for: {userEntry.Upn}");
                            }

                            // 3. Remove from roles (external users always, others if option set)
                            if (options.RemoveFromRoles || userEntry.IsExternal)
                            {
                                await RemoveUserFromAllPrivilegedRolesAsync(userEntry.ObjectId, ct);
                                userResult.RolesRemoved = true;
                                _progress?.Report($"Removed from roles: {userEntry.Upn}");
                            }
                        }
                        else
                        {
                            _progress?.Report($"[WHATIF] Would process: {userEntry.Upn}");
                            userResult.WhatIfOnly = true;
                        }

                        result.ProcessedUsers.Add(userResult);
                    }
                    catch (Exception ex)
                    {
                        userResult.Error = ex.Message;
                        result.ProcessedUsers.Add(userResult);
                        _progress?.Report($"Error processing {userEntry.Upn}: {ex.Message}");
                    }
                }

                // Summary of PIM eligible removals
                if (!options.WhatIf && options.RemoveFromRoles)
                {
                    var pimRemovals = pimEligibleAssignments
                        .Where(p => !options.ExemptedUserUpns.Contains(p.PrincipalUpn, StringComparer.OrdinalIgnoreCase))
                        .Count();
                    _progress?.Report($"Removed {pimRemovals} PIM eligible role assignments");
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Takeback error: {ex.Message}");
                _progress?.Report($"Takeback failed: {ex.Message}");
            }
            finally
            {
                result.EndTime = DateTime.Now;
            }

            return result;
        }

        /// <summary>
        /// Resets password for all users in tenant (mass password reset).
        /// Equivalent to Invoke-EntraMassPasswordReset in PLATYPUS.
        /// </summary>
        public async Task<MassPasswordResetResult> MassPasswordResetAsync(
            List<string> exemptedUserUpns,
            bool savePasswords = false,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            var result = new MassPasswordResetResult { StartTime = DateTime.Now };

            if (_graphClient == null)
            {
                result.Errors.Add("Not connected to Entra ID");
                return result;
            }

            try
            {
                _progress?.Report("Starting mass password reset...");

                // Get all users (excluding guests)
                var users = await _graphClient.Users.GetAsync(r => r.QueryParameters.Select = 
                    new[] { "id", "userPrincipalName", "userType" }, ct);

                if (users?.Value == null)
                {
                    result.Errors.Add("No users found");
                    return result;
                }

                var allUsers = users.Value.ToList();
                
                // Handle pagination
                var pageIterator = users.OdataNextLink;
                while (!string.IsNullOrEmpty(pageIterator))
                {
                    ct.ThrowIfCancellationRequested();
                    var nextPage = await _graphClient.Users
                        .WithUrl(pageIterator)
                        .GetAsync(cancellationToken: ct);
                    if (nextPage?.Value != null)
                    {
                        allUsers.AddRange(nextPage.Value);
                    }
                    pageIterator = nextPage?.OdataNextLink;
                }

                _progress?.Report($"Found {allUsers.Count} total users");

                foreach (var user in allUsers)
                {
                    ct.ThrowIfCancellationRequested();

                    if (user.UserPrincipalName == null) continue;

                    // Skip external users
                    if (user.UserPrincipalName.Contains("#EXT#"))
                    {
                        result.SkippedCount++;
                        continue;
                    }

                    // Skip exempted users
                    if (exemptedUserUpns.Any(e => 
                        e.Equals(user.UserPrincipalName, StringComparison.OrdinalIgnoreCase)))
                    {
                        result.SkippedCount++;
                        continue;
                    }

                    try
                    {
                        if (!whatIf)
                        {
                            var newPassword = GenerateSecurePassword();
                            await ResetUserPasswordAsync(user.Id!, newPassword, ct);
                            
                            if (savePasswords)
                            {
                                result.ResetPasswords[user.UserPrincipalName] = newPassword;
                            }
                        }
                        result.ResetCount++;
                    }
                    catch
                    {
                        result.FailedCount++;
                    }
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Errors.Add(ex.Message);
            }
            finally
            {
                result.EndTime = DateTime.Now;
            }

            return result;
        }

        /// <summary>
        /// Revokes all user refresh tokens in the tenant.
        /// Equivalent to Revoke-EntraAllUserRefreshTokens in PLATYPUS.
        /// </summary>
        public async Task<int> RevokeAllUserTokensAsync(
            List<string>? exemptedUserUpns = null,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            if (_graphClient == null) return 0;

            exemptedUserUpns ??= new List<string>();
            int revokedCount = 0;

            try
            {
                _progress?.Report("Revoking all user refresh tokens...");

                var users = await _graphClient.Users.GetAsync(r => 
                    r.QueryParameters.Select = new[] { "id", "userPrincipalName" }, ct);

                if (users?.Value == null) return 0;

                foreach (var user in users.Value)
                {
                    ct.ThrowIfCancellationRequested();

                    if (user.UserPrincipalName == null) continue;

                    if (exemptedUserUpns.Any(e => 
                        e.Equals(user.UserPrincipalName, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue;
                    }

                    if (!whatIf)
                    {
                        await RevokeUserSessionsAsync(user.Id!, ct);
                    }
                    revokedCount++;
                }

                _progress?.Report($"Revoked tokens for {revokedCount} users");
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error revoking tokens: {ex.Message}");
            }

            return revokedCount;
        }

        /// <summary>
        /// Removes all members from specified privileged roles.
        /// Equivalent to Remove-EntraPrivilegedRoleMembers in PLATYPUS.
        /// </summary>
        public async Task<int> RemovePrivilegedRoleMembersAsync(
            List<string> roleNames,
            List<string> exemptedUserUpns,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            if (_graphClient == null) return 0;

            int removedCount = 0;

            try
            {
                var directoryRoles = await _graphClient.DirectoryRoles.GetAsync(cancellationToken: ct);
                if (directoryRoles?.Value == null) return 0;

                foreach (var role in directoryRoles.Value)
                {
                    ct.ThrowIfCancellationRequested();

                    if (role.DisplayName == null || !roleNames.Contains(role.DisplayName))
                        continue;

                    _progress?.Report($"Processing role: {role.DisplayName}");

                    var members = await _graphClient.DirectoryRoles[role.Id].Members.GetAsync(cancellationToken: ct);
                    if (members?.Value == null) continue;

                    foreach (var member in members.Value)
                    {
                        if (member.Id == null) continue;

                        // Get UPN for exemption check
                        try
                        {
                            var user = await _graphClient.Users[member.Id].GetAsync(cancellationToken: ct);
                            if (user?.UserPrincipalName != null && 
                                exemptedUserUpns.Any(e => e.Equals(user.UserPrincipalName, StringComparison.OrdinalIgnoreCase)))
                            {
                                _progress?.Report($"Skipping exempted user: {user.UserPrincipalName}");
                                continue;
                            }

                            if (!whatIf)
                            {
                                await _graphClient.DirectoryRoles[role.Id].Members[member.Id].Ref.DeleteAsync(cancellationToken: ct);
                                _progress?.Report($"Removed {user?.UserPrincipalName ?? member.Id} from {role.DisplayName}");
                            }
                            removedCount++;
                        }
                        catch { /* Not a user or access denied */ }
                    }
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error removing role members: {ex.Message}");
            }

            return removedCount;
        }

        /// <summary>
        /// Removes owners from applications (for malicious app cleanup).
        /// Equivalent to Remove-EntraAppOwners in PLATYPUS.
        /// </summary>
        public async Task<int> RemoveAppOwnersAsync(
            string appId,
            List<string>? ownerIdsToRemove = null,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            if (_graphClient == null) return 0;

            int removedCount = 0;

            try
            {
                var app = await _graphClient.Applications
                    .GetAsync(r => r.QueryParameters.Filter = $"appId eq '{appId}'", ct);

                if (app?.Value == null || app.Value.Count == 0)
                {
                    _progress?.Report($"Application not found: {appId}");
                    return 0;
                }

                var appObjectId = app.Value[0].Id;
                var owners = await _graphClient.Applications[appObjectId].Owners.GetAsync(cancellationToken: ct);

                if (owners?.Value == null) return 0;

                foreach (var owner in owners.Value)
                {
                    ct.ThrowIfCancellationRequested();

                    if (owner.Id == null) continue;

                    // Remove specific owners or all owners
                    if (ownerIdsToRemove == null || ownerIdsToRemove.Contains(owner.Id))
                    {
                        if (!whatIf)
                        {
                            await _graphClient.Applications[appObjectId].Owners[owner.Id].Ref.DeleteAsync(cancellationToken: ct);
                            _progress?.Report($"Removed owner {owner.Id} from app {appId}");
                        }
                        removedCount++;
                    }
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error removing app owners: {ex.Message}");
            }

            return removedCount;
        }

        /// <summary>
        /// Disables Conditional Access policies (for IR scenarios).
        /// Equivalent to disable-oldcapolicies in PLATYPUS.
        /// </summary>
        public async Task<int> DisableConditionalAccessPoliciesAsync(
            List<string>? policyIdsToExempt = null,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            if (_graphClient == null) return 0;

            policyIdsToExempt ??= new List<string>();
            int disabledCount = 0;

            try
            {
                var policies = await _graphClient.Identity.ConditionalAccess.Policies.GetAsync(cancellationToken: ct);
                if (policies?.Value == null) return 0;

                foreach (var policy in policies.Value)
                {
                    ct.ThrowIfCancellationRequested();

                    if (policy.Id == null || policyIdsToExempt.Contains(policy.Id))
                        continue;

                    if (policy.State?.ToString() == "enabled")
                    {
                        if (!whatIf)
                        {
                            policy.State = Microsoft.Graph.Models.ConditionalAccessPolicyState.Disabled;
                            await _graphClient.Identity.ConditionalAccess.Policies[policy.Id].PatchAsync(policy, cancellationToken: ct);
                            _progress?.Report($"Disabled CA policy: {policy.DisplayName}");
                        }
                        disabledCount++;
                    }
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error disabling CA policies: {ex.Message}");
            }

            return disabledCount;
        }

        #endregion

        #region PIM Eligible Assignments (PLATYPUS Remove-EntraPrivilegedRoleMembers)

        /// <summary>
        /// Gets all PIM eligible role assignments in the tenant.
        /// These are assignments where users must activate to use the role.
        /// </summary>
        public async Task<List<PimEligibleAssignment>> GetPimEligibleAssignmentsAsync(
            CancellationToken ct = default)
        {
            if (_graphClient == null)
            {
                _progress?.Report("Not connected to Entra ID. Call ConnectAsync first.");
                return new List<PimEligibleAssignment>();
            }

            var eligibleAssignments = new List<PimEligibleAssignment>();

            try
            {
                _progress?.Report("Getting PIM eligible role assignments...");

                // Get role eligibility schedules using beta API
                var schedules = await _graphClient.RoleManagement.Directory.RoleEligibilitySchedules
                    .GetAsync(cancellationToken: ct);

                if (schedules?.Value == null)
                    return eligibleAssignments;

                foreach (var schedule in schedules.Value)
                {
                    if (schedule == null || string.IsNullOrEmpty(schedule.PrincipalId))
                        continue;

                    try
                    {
                        // Get role definition details
                        var roleDefinition = await _graphClient.RoleManagement.Directory
                            .RoleDefinitions[schedule.RoleDefinitionId]
                            .GetAsync(cancellationToken: ct);

                        // Get principal details
                        string principalDisplayName = "";
                        string principalUpn = "";
                        string principalType = "Unknown";

                        try
                        {
                            var user = await _graphClient.Users[schedule.PrincipalId]
                                .GetAsync(cancellationToken: ct);
                            if (user != null)
                            {
                                principalDisplayName = user.DisplayName ?? "";
                                principalUpn = user.UserPrincipalName ?? "";
                                principalType = "User";
                            }
                        }
                        catch
                        {
                            // Might be a service principal or group
                            try
                            {
                                var sp = await _graphClient.ServicePrincipals[schedule.PrincipalId]
                                    .GetAsync(cancellationToken: ct);
                                if (sp != null)
                                {
                                    principalDisplayName = sp.DisplayName ?? "";
                                    principalUpn = sp.AppId ?? "";
                                    principalType = "ServicePrincipal";
                                }
                            }
                            catch
                            {
                                try
                                {
                                    var group = await _graphClient.Groups[schedule.PrincipalId]
                                        .GetAsync(cancellationToken: ct);
                                    if (group != null)
                                    {
                                        principalDisplayName = group.DisplayName ?? "";
                                        principalType = "Group";
                                    }
                                }
                                catch { }
                            }
                        }

                        eligibleAssignments.Add(new PimEligibleAssignment
                        {
                            ScheduleId = schedule.Id ?? "",
                            RoleDefinitionId = schedule.RoleDefinitionId ?? "",
                            RoleDisplayName = roleDefinition?.DisplayName ?? "",
                            PrincipalId = schedule.PrincipalId,
                            PrincipalDisplayName = principalDisplayName,
                            PrincipalUpn = principalUpn,
                            PrincipalType = principalType,
                            DirectoryScopeId = schedule.DirectoryScopeId ?? "/",
                            StartDateTime = schedule.ScheduleInfo?.StartDateTime?.UtcDateTime,
                            EndDateTime = schedule.ScheduleInfo?.Expiration?.EndDateTime?.UtcDateTime
                        });
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"Error processing eligibility schedule: {ex.Message}");
                    }
                }

                _progress?.Report($"Found {eligibleAssignments.Count} PIM eligible role assignments");
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error getting PIM eligible assignments: {ex.Message}");
            }

            return eligibleAssignments;
        }

        /// <summary>
        /// Removes a PIM eligible role assignment using AdminRemove action.
        /// Equivalent to PLATYPUS's New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest with action "AdminRemove".
        /// </summary>
        public async Task<bool> RemovePimEligibleAssignmentAsync(
            string principalId,
            string roleDefinitionId,
            string directoryScopeId = "/",
            string justification = "PLATYPUS Tenant Takeback",
            CancellationToken ct = default)
        {
            if (_graphClient == null)
            {
                _progress?.Report("Not connected to Entra ID. Call ConnectAsync first.");
                return false;
            }

            try
            {
                var request = new Microsoft.Graph.Models.UnifiedRoleEligibilityScheduleRequest
                {
                    PrincipalId = principalId,
                    RoleDefinitionId = roleDefinitionId,
                    DirectoryScopeId = directoryScopeId,
                    Action = Microsoft.Graph.Models.UnifiedRoleScheduleRequestActions.AdminRemove,
                    Justification = justification
                };

                await _graphClient.RoleManagement.Directory.RoleEligibilityScheduleRequests
                    .PostAsync(request, cancellationToken: ct);

                _progress?.Report($"Removed PIM eligible assignment for principal {principalId} from role {roleDefinitionId}");
                return true;
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error removing PIM eligible assignment: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Removes all PIM eligible role assignments for a user.
        /// </summary>
        public async Task<int> RemoveAllPimEligibleAssignmentsAsync(
            string userId,
            List<string>? exemptedRoleIds = null,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            if (_graphClient == null) return 0;

            exemptedRoleIds ??= new List<string>();
            int removedCount = 0;

            try
            {
                var eligibleAssignments = await GetPimEligibleAssignmentsAsync(ct);
                var userAssignments = eligibleAssignments
                    .Where(a => a.PrincipalId == userId && !exemptedRoleIds.Contains(a.RoleDefinitionId))
                    .ToList();

                foreach (var assignment in userAssignments)
                {
                    ct.ThrowIfCancellationRequested();

                    if (!whatIf)
                    {
                        var success = await RemovePimEligibleAssignmentAsync(
                            assignment.PrincipalId,
                            assignment.RoleDefinitionId,
                            assignment.DirectoryScopeId,
                            "PLATYPUS Tenant Takeback",
                            ct);

                        if (success) removedCount++;
                    }
                    else
                    {
                        removedCount++;
                    }
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error removing PIM eligible assignments: {ex.Message}");
            }

            return removedCount;
        }

        /// <summary>
        /// Compatibility wrapper used by SecKey UI for listing eligible PIM assignments.
        /// </summary>
        public async Task<List<EntraIdPimAssignment>> GetEligiblePimAssignmentsAsync(CancellationToken ct = default)
        {
            var eligible = await GetPimEligibleAssignmentsAsync(ct);
            return eligible.Select(a => new EntraIdPimAssignment
            {
                AssignmentId = a.ScheduleId,
                RoleId = a.RoleDefinitionId,
                RoleName = a.RoleDisplayName,
                PrincipalId = a.PrincipalId,
                PrincipalDisplayName = a.PrincipalDisplayName,
                PrincipalUpn = a.PrincipalUpn,
                PrincipalType = a.PrincipalType,
                AssignmentType = "Eligible",
                StartDateTime = a.StartDateTime,
                EndDateTime = a.EndDateTime,
                Status = "Provisioned"
            }).ToList();
        }

        /// <summary>
        /// Gets active PIM role assignment schedule instances.
        /// </summary>
        public async Task<List<EntraIdPimAssignment>> GetActivePimAssignmentsAsync(CancellationToken ct = default)
        {
            var assignments = new List<EntraIdPimAssignment>();
            if (_graphClient == null)
            {
                _progress?.Report("Not connected to Entra ID. Call ConnectAsync first.");
                return assignments;
            }

            try
            {
                var result = await _graphClient.RoleManagement.Directory.RoleAssignmentScheduleInstances.GetAsync(cancellationToken: ct);
                if (result?.Value == null)
                    return assignments;

                foreach (var item in result.Value)
                {
                    if (item == null || string.IsNullOrEmpty(item.PrincipalId))
                        continue;

                    string roleName = item.RoleDefinitionId ?? string.Empty;
                    string principalDisplayName = string.Empty;
                    string principalUpn = string.Empty;
                    string principalType = "Unknown";

                    if (!string.IsNullOrWhiteSpace(item.RoleDefinitionId))
                    {
                        try
                        {
                            var roleDefinition = await _graphClient.RoleManagement.Directory.RoleDefinitions[item.RoleDefinitionId].GetAsync(cancellationToken: ct);
                            if (roleDefinition != null)
                                roleName = roleDefinition.DisplayName ?? roleName;
                        }
                        catch { }
                    }

                    try
                    {
                        var user = await _graphClient.Users[item.PrincipalId].GetAsync(cancellationToken: ct);
                        if (user != null)
                        {
                            principalDisplayName = user.DisplayName ?? string.Empty;
                            principalUpn = user.UserPrincipalName ?? string.Empty;
                            principalType = "User";
                        }
                    }
                    catch
                    {
                        try
                        {
                            var sp = await _graphClient.ServicePrincipals[item.PrincipalId].GetAsync(cancellationToken: ct);
                            if (sp != null)
                            {
                                principalDisplayName = sp.DisplayName ?? string.Empty;
                                principalUpn = sp.AppId ?? string.Empty;
                                principalType = "ServicePrincipal";
                            }
                        }
                        catch
                        {
                            try
                            {
                                var group = await _graphClient.Groups[item.PrincipalId].GetAsync(cancellationToken: ct);
                                if (group != null)
                                {
                                    principalDisplayName = group.DisplayName ?? string.Empty;
                                    principalType = "Group";
                                }
                            }
                            catch { }
                        }
                    }

                    assignments.Add(new EntraIdPimAssignment
                    {
                        AssignmentId = item.Id ?? string.Empty,
                        RoleId = item.RoleDefinitionId ?? string.Empty,
                        RoleName = roleName,
                        PrincipalId = item.PrincipalId ?? string.Empty,
                        PrincipalDisplayName = principalDisplayName,
                        PrincipalUpn = principalUpn,
                        PrincipalType = principalType,
                        AssignmentType = string.IsNullOrWhiteSpace(item.AssignmentType) ? "Active" : item.AssignmentType,
                        StartDateTime = item.StartDateTime?.UtcDateTime,
                        EndDateTime = item.EndDateTime?.UtcDateTime,
                        Status = "Provisioned"
                    });
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error getting active PIM assignments: {ex.Message}");
            }

            return assignments;
        }

        /// <summary>
        /// Creates a new eligible PIM assignment for a user and role.
        /// </summary>
        public async Task<(bool Success, string Message)> CreatePimEligibleAssignmentAsync(
            string principalUpn,
            string roleName,
            string justification,
            int durationDays = 365,
            CancellationToken ct = default)
        {
            if (_graphClient == null)
                return (false, "Not connected to Entra ID. Call ConnectAsync first.");

            try
            {
                var users = await _graphClient.Users.GetAsync(r =>
                {
                    r.QueryParameters.Filter = $"userPrincipalName eq '{principalUpn}'";
                    r.QueryParameters.Select = new[] { "id", "displayName", "userPrincipalName" };
                }, ct);

                var user = users?.Value?.FirstOrDefault();
                if (user?.Id == null)
                    return (false, $"User not found: {principalUpn}");

                var roleDefinitions = await _graphClient.RoleManagement.Directory.RoleDefinitions.GetAsync(r =>
                {
                    r.QueryParameters.Filter = $"displayName eq '{roleName}'";
                    r.QueryParameters.Select = new[] { "id", "displayName" };
                }, ct);

                var role = roleDefinitions?.Value?.FirstOrDefault();
                if (role?.Id == null)
                    return (false, $"Role not found: {roleName}");

                var now = DateTimeOffset.UtcNow;
                var request = new UnifiedRoleEligibilityScheduleRequest
                {
                    PrincipalId = user.Id,
                    RoleDefinitionId = role.Id,
                    DirectoryScopeId = "/",
                    Action = UnifiedRoleScheduleRequestActions.AdminAssign,
                    Justification = string.IsNullOrWhiteSpace(justification) ? "SecKey PIM assignment" : justification,
                    ScheduleInfo = new RequestSchedule
                    {
                        StartDateTime = now,
                        Expiration = durationDays > 0
                            ? new ExpirationPattern
                            {
                                Type = ExpirationPatternType.AfterDateTime,
                                EndDateTime = now.AddDays(durationDays)
                            }
                            : new ExpirationPattern
                            {
                                Type = ExpirationPatternType.NoExpiration
                            }
                    }
                };

                await _graphClient.RoleManagement.Directory.RoleEligibilityScheduleRequests.PostAsync(request, cancellationToken: ct);
                return (true, $"Created eligible assignment for {principalUpn} -> {roleName}");
            }
            catch (Exception ex)
            {
                return (false, $"Failed to create PIM eligible assignment: {ex.Message}");
            }
        }

        #endregion

        #region App Registration Management

        /// <summary>
        /// Creates or returns an app registration configured for SecKey operations.
        /// </summary>
        public async Task<AppRegistrationResult> CreateAppRegistrationAsync(string appDisplayName, CancellationToken ct = default)
        {
            var result = new AppRegistrationResult { DisplayName = appDisplayName };
            if (_graphClient == null)
            {
                result.Message = "Not connected to Entra ID. Call ConnectAsync first.";
                return result;
            }

            try
            {
                var existing = await _graphClient.Applications.GetAsync(r =>
                {
                    r.QueryParameters.Filter = $"displayName eq '{appDisplayName}'";
                    r.QueryParameters.Select = new[] { "id", "appId", "displayName" };
                }, ct);

                var existingApp = existing?.Value?.FirstOrDefault();
                if (existingApp != null)
                {
                    result.Success = true;
                    result.AlreadyExisted = true;
                    result.ObjectId = existingApp.Id ?? string.Empty;
                    result.AppId = existingApp.AppId ?? string.Empty;
                    result.Message = $"App registration already exists. AppId: {result.AppId}";
                    return result;
                }

                const string graphResourceId = "00000003-0000-0000-c000-000000000000";
                var requiredResourceAccess = new List<RequiredResourceAccess>
                {
                    new RequiredResourceAccess
                    {
                        ResourceAppId = graphResourceId,
                        ResourceAccess = new List<ResourceAccess>
                        {
                            new() { Id = Guid.Parse("c5366453-9fb0-48a5-a156-24f0c49a4b84"), Type = "Scope" },
                            new() { Id = Guid.Parse("7b3f05d5-f68c-4b8d-8c59-a2ecd12f24af"), Type = "Scope" },
                            new() { Id = Guid.Parse("0883f392-0a7a-443d-8297-f0d35e8e0e5c"), Type = "Scope" },
                            new() { Id = Guid.Parse("5ac13192-7ace-4fcf-b828-1a26f28068ee"), Type = "Scope" },
                            new() { Id = Guid.Parse("ad902697-1014-4ef5-81ef-2b4301988e8c"), Type = "Scope" },
                            new() { Id = Guid.Parse("4e46008b-f24c-477d-8fff-7bb4ec7aafe0"), Type = "Scope" },
                            new() { Id = Guid.Parse("204e0828-b5ca-4ad8-b9f3-f32a958e7cc4"), Type = "Scope" },
                            new() { Id = Guid.Parse("d01b97e9-cbc3-49e7-9f57-b992144efd35"), Type = "Scope" }
                        }
                    }
                };

                var app = new Application
                {
                    DisplayName = appDisplayName,
                    SignInAudience = "AzureADMyOrg",
                    RequiredResourceAccess = requiredResourceAccess,
                    IsFallbackPublicClient = true,
                    PublicClient = new PublicClientApplication
                    {
                        RedirectUris = new List<string>
                        {
                            "https://login.microsoftonline.com/common/oauth2/nativeclient",
                            "http://localhost"
                        }
                    }
                };

                var created = await _graphClient.Applications.PostAsync(app, cancellationToken: ct);
                if (created == null)
                {
                    result.Message = "Graph returned null while creating app registration.";
                    return result;
                }

                result.Success = true;
                result.ObjectId = created.Id ?? string.Empty;
                result.AppId = created.AppId ?? string.Empty;
                result.Message = $"App registration created. AppId: {result.AppId}";
                return result;
            }
            catch (Exception ex)
            {
                result.Message = $"Failed to create app registration: {ex.Message}";
                return result;
            }
        }

        #endregion

        #region IR Conditional Access Policies (PLATYPUS New-EntraIRCAPolicies)

        /// <summary>
        /// Deploys IR Conditional Access policy templates.
        /// Equivalent to New-EntraIRCAPolicies in PLATYPUS.
        /// </summary>
        public async Task<List<IrCaPolicyDeploymentResult>> DeployIrCaPoliciesAsync(
            IrCaPolicyDeploymentOptions options,
            CancellationToken ct = default)
        {
            var results = new List<IrCaPolicyDeploymentResult>();

            if (_graphClient == null)
            {
                _progress?.Report("Not connected to Entra ID. Call ConnectAsync first.");
                return results;
            }

            try
            {
                _progress?.Report("Deploying IR Conditional Access policies...");

                // Validate breakglass accounts exist
                var breakglassIds = new List<string>();
                foreach (var upn in options.BreakglassAccountUpns)
                {
                    try
                    {
                        var user = await _graphClient.Users[upn].GetAsync(cancellationToken: ct);
                        if (user != null)
                        {
                            breakglassIds.Add(user.Id ?? "");
                            _progress?.Report($"Validated breakglass account: {upn}");
                        }
                    }
                    catch
                    {
                        _progress?.Report($"WARNING: Breakglass account not found: {upn}");
                    }
                }

                if (breakglassIds.Count == 0)
                {
                    _progress?.Report("ERROR: No valid breakglass accounts found. Cannot deploy IR CA policies.");
                    return results;
                }

                // Get privileged role IDs for policy targeting
                var privilegedRoleIds = await GetPrivilegedRoleIdsAsync(ct);

                // Get existing policies
                var existingPolicies = await _graphClient.Identity.ConditionalAccess.Policies
                    .GetAsync(cancellationToken: ct);
                var existingPolicyNames = existingPolicies?.Value?.Select(p => p.DisplayName).ToHashSet() 
                    ?? new HashSet<string?>();

                // Deploy each template
                foreach (var templateName in options.TemplatesToDeploy)
                {
                    var result = new IrCaPolicyDeploymentResult { TemplateName = templateName };
                    var policyName = $"{options.Prefix} {templateName}";

                    if (existingPolicyNames.Contains(policyName))
                    {
                        result.Status = "Skipped";
                        result.Message = "Policy already exists";
                        _progress?.Report($"Skipped: {policyName} (already exists)");
                        results.Add(result);
                        continue;
                    }

                    try
                    {
                        var policy = CreateIrCaPolicy(templateName, policyName, breakglassIds, 
                            privilegedRoleIds, options.EnablePolicies);

                        if (policy != null && !options.WhatIf)
                        {
                            await _graphClient.Identity.ConditionalAccess.Policies
                                .PostAsync(policy, cancellationToken: ct);
                            result.Status = "Created";
                            result.Message = options.EnablePolicies ? "Enabled" : "Report-only mode";
                            _progress?.Report($"Created: {policyName}");
                        }
                        else if (policy != null)
                        {
                            result.Status = "WhatIf";
                            result.Message = "Would be created";
                            _progress?.Report($"[WHATIF] Would create: {policyName}");
                        }
                        else
                        {
                            result.Status = "Skipped";
                            result.Message = "Unknown template";
                        }
                    }
                    catch (Exception ex)
                    {
                        result.Status = "Failed";
                        result.Message = ex.Message;
                        _progress?.Report($"Failed to create {policyName}: {ex.Message}");
                    }

                    results.Add(result);
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error deploying IR CA policies: {ex.Message}");
            }

            return results;
        }

        private async Task<List<string>> GetPrivilegedRoleIdsAsync(CancellationToken ct)
        {
            var roleIds = new List<string>();

            try
            {
                var roleDefinitions = await _graphClient!.RoleManagement.Directory.RoleDefinitions
                    .GetAsync(cancellationToken: ct);

                if (roleDefinitions?.Value != null)
                {
                    // Get roles that are privileged (use displayname check since IsPrivileged is beta API only)
                    roleIds = roleDefinitions.Value
                        .Where(r => EntraIdPrivilegedRoles.IsPrivilegedRole(r.DisplayName))
                        .Select(r => r.Id ?? "")
                        .Where(id => !string.IsNullOrEmpty(id))
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error getting privileged role IDs: {ex.Message}");
            }

            return roleIds;
        }

        private ConditionalAccessPolicy? CreateIrCaPolicy(
            string templateName,
            string displayName,
            List<string> excludeUserIds,
            List<string> adminRoleIds,
            bool enable)
        {
            var state = enable 
                ? ConditionalAccessPolicyState.Enabled 
                : ConditionalAccessPolicyState.EnabledForReportingButNotEnforced;

            return templateName switch
            {
                "Block legacy authentication" => new ConditionalAccessPolicy
                {
                    DisplayName = displayName,
                    State = state,
                    Conditions = new ConditionalAccessConditionSet
                    {
                        Users = new ConditionalAccessUsers
                        {
                            IncludeUsers = new List<string> { "All" },
                            ExcludeUsers = excludeUserIds
                        },
                        Applications = new ConditionalAccessApplications
                        {
                            IncludeApplications = new List<string> { "All" }
                        },
                        ClientAppTypes = new List<ConditionalAccessClientApp?>
                        {
                            ConditionalAccessClientApp.ExchangeActiveSync,
                            ConditionalAccessClientApp.Other
                        }
                    },
                    GrantControls = new ConditionalAccessGrantControls
                    {
                        Operator = "OR",
                        BuiltInControls = new List<ConditionalAccessGrantControl?>
                        {
                            ConditionalAccessGrantControl.Block
                        }
                    }
                },

                "Require multifactor authentication for admins" => new ConditionalAccessPolicy
                {
                    DisplayName = displayName,
                    State = state,
                    Conditions = new ConditionalAccessConditionSet
                    {
                        Users = new ConditionalAccessUsers
                        {
                            IncludeRoles = adminRoleIds,
                            ExcludeUsers = excludeUserIds
                        },
                        Applications = new ConditionalAccessApplications
                        {
                            IncludeApplications = new List<string> { "All" }
                        }
                    },
                    GrantControls = new ConditionalAccessGrantControls
                    {
                        Operator = "OR",
                        BuiltInControls = new List<ConditionalAccessGrantControl?>
                        {
                            ConditionalAccessGrantControl.Mfa
                        }
                    }
                },

                "Require multifactor authentication for Azure management" => new ConditionalAccessPolicy
                {
                    DisplayName = displayName,
                    State = state,
                    Conditions = new ConditionalAccessConditionSet
                    {
                        Users = new ConditionalAccessUsers
                        {
                            IncludeUsers = new List<string> { "All" },
                            ExcludeUsers = excludeUserIds
                        },
                        Applications = new ConditionalAccessApplications
                        {
                            // Azure Management app ID
                            IncludeApplications = new List<string> { "797f4846-ba00-4fd7-ba43-dac1f8f63013" }
                        }
                    },
                    GrantControls = new ConditionalAccessGrantControls
                    {
                        Operator = "OR",
                        BuiltInControls = new List<ConditionalAccessGrantControl?>
                        {
                            ConditionalAccessGrantControl.Mfa
                        }
                    }
                },

                "Require multifactor authentication for risky sign-ins" => new ConditionalAccessPolicy
                {
                    DisplayName = displayName,
                    State = state,
                    Conditions = new ConditionalAccessConditionSet
                    {
                        Users = new ConditionalAccessUsers
                        {
                            IncludeUsers = new List<string> { "All" },
                            ExcludeUsers = excludeUserIds
                        },
                        Applications = new ConditionalAccessApplications
                        {
                            IncludeApplications = new List<string> { "All" }
                        },
                        SignInRiskLevels = new List<RiskLevel?>
                        {
                            RiskLevel.Medium,
                            RiskLevel.High
                        }
                    },
                    GrantControls = new ConditionalAccessGrantControls
                    {
                        Operator = "OR",
                        BuiltInControls = new List<ConditionalAccessGrantControl?>
                        {
                            ConditionalAccessGrantControl.Mfa
                        }
                    }
                },

                "Require password change for high-risk users" => new ConditionalAccessPolicy
                {
                    DisplayName = displayName,
                    State = state,
                    Conditions = new ConditionalAccessConditionSet
                    {
                        Users = new ConditionalAccessUsers
                        {
                            IncludeUsers = new List<string> { "All" },
                            ExcludeUsers = excludeUserIds
                        },
                        Applications = new ConditionalAccessApplications
                        {
                            IncludeApplications = new List<string> { "All" }
                        },
                        UserRiskLevels = new List<RiskLevel?>
                        {
                            RiskLevel.High
                        }
                    },
                    GrantControls = new ConditionalAccessGrantControls
                    {
                        Operator = "AND",
                        BuiltInControls = new List<ConditionalAccessGrantControl?>
                        {
                            ConditionalAccessGrantControl.Mfa,
                            ConditionalAccessGrantControl.PasswordChange
                        }
                    }
                },

                _ => null
            };
        }

        #endregion

        #region Convert Synced Users to Cloud Only (PLATYPUS Convert-EntraSyncedToCloudOnly)

        /// <summary>
        /// Exports synced users and optionally disables directory sync.
        /// Equivalent to Convert-EntraSyncedToCloudOnly in PLATYPUS.
        /// </summary>
        public async Task<SyncedUsersExportResult> ExportSyncedUsersAsync(
            string exportFilePath,
            bool disableSync = false,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            var result = new SyncedUsersExportResult { ExportFilePath = exportFilePath };

            if (_graphClient == null)
            {
                result.ErrorMessage = "Not connected to Entra ID";
                return result;
            }

            try
            {
                _progress?.Report("Getting synced users...");

                // Get all users that are synced from on-premises
                var users = await _graphClient.Users.GetAsync(r =>
                {
                    r.QueryParameters.Select = new[] { 
                        "id", "userPrincipalName", "displayName", "mail", 
                        "onPremisesSyncEnabled", "onPremisesDistinguishedName",
                        "onPremisesSamAccountName", "onPremisesSecurityIdentifier"
                    };
                    r.QueryParameters.Filter = "onPremisesSyncEnabled eq true";
                }, ct);

                if (users?.Value == null)
                {
                    result.ErrorMessage = "No synced users found";
                    return result;
                }

                var syncedUsers = users.Value.ToList();
                
                // Handle pagination
                var nextPageLink = users.OdataNextLink;
                while (!string.IsNullOrEmpty(nextPageLink))
                {
                    ct.ThrowIfCancellationRequested();
                    var nextPage = await _graphClient.Users.WithUrl(nextPageLink)
                        .GetAsync(cancellationToken: ct);
                    if (nextPage?.Value != null)
                    {
                        syncedUsers.AddRange(nextPage.Value);
                    }
                    nextPageLink = nextPage?.OdataNextLink;
                }

                _progress?.Report($"Found {syncedUsers.Count} synced users");
                result.SyncedUserCount = syncedUsers.Count;

                // Export to JSON
                if (!whatIf)
                {
                    var exportData = syncedUsers.Select(u => new
                    {
                        id = u.Id,
                        userPrincipalName = u.UserPrincipalName,
                        displayName = u.DisplayName,
                        mail = u.Mail,
                        onPremisesDistinguishedName = u.OnPremisesDistinguishedName,
                        onPremisesSamAccountName = u.OnPremisesSamAccountName,
                        onPremisesSecurityIdentifier = u.OnPremisesSecurityIdentifier
                    }).ToList();

                    var json = System.Text.Json.JsonSerializer.Serialize(exportData, 
                        new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                    await System.IO.File.WriteAllTextAsync(exportFilePath, json, ct);
                    result.ExportedSuccessfully = true;
                    _progress?.Report($"Exported synced users to: {exportFilePath}");
                }
                else
                {
                    _progress?.Report($"[WHATIF] Would export {syncedUsers.Count} synced users to: {exportFilePath}");
                }

                // Disable sync if requested
                if (disableSync && !whatIf)
                {
                    _progress?.Report("WARNING: Disabling directory synchronization is a significant change.");
                    _progress?.Report("This requires Organization.ReadWrite.All permission.");
                    
                    try
                    {
                        var org = await _graphClient.Organization.GetAsync(cancellationToken: ct);
                        if (org?.Value?.FirstOrDefault() != null)
                        {
                            var orgToUpdate = new Microsoft.Graph.Models.Organization
                            {
                                OnPremisesSyncEnabled = false
                            };
                            await _graphClient.Organization[org.Value.First().Id]
                                .PatchAsync(orgToUpdate, cancellationToken: ct);
                            result.SyncDisabled = true;
                            _progress?.Report("Directory synchronization has been disabled");
                        }
                    }
                    catch (Exception ex)
                    {
                        result.ErrorMessage = $"Failed to disable sync: {ex.Message}";
                        _progress?.Report($"Error disabling sync: {ex.Message}");
                    }
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                _progress?.Report($"Error exporting synced users: {ex.Message}");
            }

            return result;
        }

        #endregion

        #region App Owners Management (PLATYPUS Remove-EntraAppOwners)

        /// <summary>
        /// Exports all application and service principal owners to a JSON file.
        /// Equivalent to Remove-EntraAppOwners -Export in PLATYPUS.
        /// </summary>
        public async Task<AppOwnersExportResult> ExportAppOwnersAsync(
            string exportFilePath,
            CancellationToken ct = default)
        {
            var result = new AppOwnersExportResult { ExportFilePath = exportFilePath };

            if (_graphClient == null)
            {
                result.ErrorMessage = "Not connected to Entra ID";
                return result;
            }

            try
            {
                _progress?.Report("Exporting application and service principal owners...");

                var ownerData = new List<AppOwnerInfo>();

                // Get all applications
                var apps = await _graphClient.Applications.GetAsync(cancellationToken: ct);
                if (apps?.Value != null)
                {
                    foreach (var app in apps.Value)
                    {
                        ct.ThrowIfCancellationRequested();

                        try
                        {
                            var owners = await _graphClient.Applications[app.Id].Owners
                                .GetAsync(cancellationToken: ct);
                            
                            if (owners?.Value != null && owners.Value.Count > 0)
                            {
                                var ownerList = new List<OwnerDetails>();
                                foreach (var owner in owners.Value)
                                {
                                    string upn = "";
                                    string displayName = "";
                                    
                                    if (owner is User user)
                                    {
                                        upn = user.UserPrincipalName ?? "";
                                        displayName = user.DisplayName ?? "";
                                    }

                                    ownerList.Add(new OwnerDetails
                                    {
                                        Id = owner.Id ?? "",
                                        DisplayName = displayName,
                                        UserPrincipalName = upn
                                    });
                                }

                                ownerData.Add(new AppOwnerInfo
                                {
                                    ObjectType = "application",
                                    ObjectId = app.Id ?? "",
                                    DisplayName = app.DisplayName ?? "",
                                    AppId = app.AppId ?? "",
                                    Owners = ownerList
                                });
                            }
                        }
                        catch { }
                    }
                }

                // Get all service principals
                var servicePrincipals = await _graphClient.ServicePrincipals.GetAsync(cancellationToken: ct);
                if (servicePrincipals?.Value != null)
                {
                    foreach (var sp in servicePrincipals.Value)
                    {
                        ct.ThrowIfCancellationRequested();

                        try
                        {
                            var owners = await _graphClient.ServicePrincipals[sp.Id].Owners
                                .GetAsync(cancellationToken: ct);
                            
                            if (owners?.Value != null && owners.Value.Count > 0)
                            {
                                var ownerList = new List<OwnerDetails>();
                                foreach (var owner in owners.Value)
                                {
                                    string upn = "";
                                    string displayName = "";
                                    
                                    if (owner is User user)
                                    {
                                        upn = user.UserPrincipalName ?? "";
                                        displayName = user.DisplayName ?? "";
                                    }

                                    ownerList.Add(new OwnerDetails
                                    {
                                        Id = owner.Id ?? "",
                                        DisplayName = displayName,
                                        UserPrincipalName = upn
                                    });
                                }

                                ownerData.Add(new AppOwnerInfo
                                {
                                    ObjectType = "servicePrincipal",
                                    ObjectId = sp.Id ?? "",
                                    DisplayName = sp.DisplayName ?? "",
                                    AppId = sp.AppId ?? "",
                                    Owners = ownerList
                                });
                            }
                        }
                        catch { }
                    }
                }

                // Save to file
                var json = System.Text.Json.JsonSerializer.Serialize(ownerData,
                    new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                await System.IO.File.WriteAllTextAsync(exportFilePath, json, ct);

                result.ExportedCount = ownerData.Count;
                result.Success = true;
                _progress?.Report($"Exported {ownerData.Count} apps/service principals with owners to: {exportFilePath}");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                _progress?.Report($"Error exporting app owners: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// Removes all owners from applications based on a previously exported file.
        /// Equivalent to Remove-EntraAppOwners -delete in PLATYPUS.
        /// </summary>
        public async Task<int> RemoveAppOwnersFromExportAsync(
            string exportFilePath,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            if (_graphClient == null) return 0;

            int removedCount = 0;

            try
            {
                if (!System.IO.File.Exists(exportFilePath))
                {
                    _progress?.Report($"Export file not found: {exportFilePath}");
                    return 0;
                }

                var json = await System.IO.File.ReadAllTextAsync(exportFilePath, ct);
                var ownerData = System.Text.Json.JsonSerializer.Deserialize<List<AppOwnerInfo>>(json);

                if (ownerData == null || ownerData.Count == 0)
                {
                    _progress?.Report("No owner data found in export file");
                    return 0;
                }

                foreach (var app in ownerData)
                {
                    ct.ThrowIfCancellationRequested();

                    foreach (var owner in app.Owners)
                    {
                        try
                        {
                            if (!whatIf)
                            {
                                if (app.ObjectType == "application")
                                {
                                    await _graphClient.Applications[app.ObjectId].Owners[owner.Id].Ref
                                        .DeleteAsync(cancellationToken: ct);
                                }
                                else if (app.ObjectType == "servicePrincipal")
                                {
                                    await _graphClient.ServicePrincipals[app.ObjectId].Owners[owner.Id].Ref
                                        .DeleteAsync(cancellationToken: ct);
                                }
                                _progress?.Report($"Removed owner {owner.DisplayName} from {app.DisplayName}");
                            }
                            else
                            {
                                _progress?.Report($"[WHATIF] Would remove owner {owner.DisplayName} from {app.DisplayName}");
                            }
                            removedCount++;
                        }
                        catch (Exception ex)
                        {
                            _progress?.Report($"Error removing owner from {app.DisplayName}: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error removing app owners: {ex.Message}");
            }

            return removedCount;
        }

        /// <summary>
        /// Restores app owners from a previously exported file.
        /// Equivalent to Remove-EntraAppOwners -restore in PLATYPUS.
        /// </summary>
        public async Task<int> RestoreAppOwnersFromExportAsync(
            string exportFilePath,
            bool whatIf = true,
            CancellationToken ct = default)
        {
            if (_graphClient == null) return 0;

            int restoredCount = 0;

            try
            {
                if (!System.IO.File.Exists(exportFilePath))
                {
                    _progress?.Report($"Export file not found: {exportFilePath}");
                    return 0;
                }

                var json = await System.IO.File.ReadAllTextAsync(exportFilePath, ct);
                var ownerData = System.Text.Json.JsonSerializer.Deserialize<List<AppOwnerInfo>>(json);

                if (ownerData == null || ownerData.Count == 0)
                {
                    _progress?.Report("No owner data found in export file");
                    return 0;
                }

                foreach (var app in ownerData)
                {
                    ct.ThrowIfCancellationRequested();

                    foreach (var owner in app.Owners)
                    {
                        try
                        {
                            if (!whatIf)
                            {
                                var ownerRef = new ReferenceCreate
                                {
                                    OdataId = $"https://graph.microsoft.com/v1.0/directoryObjects/{owner.Id}"
                                };

                                if (app.ObjectType == "application")
                                {
                                    await _graphClient.Applications[app.ObjectId].Owners.Ref
                                        .PostAsync(ownerRef, cancellationToken: ct);
                                }
                                else if (app.ObjectType == "servicePrincipal")
                                {
                                    await _graphClient.ServicePrincipals[app.ObjectId].Owners.Ref
                                        .PostAsync(ownerRef, cancellationToken: ct);
                                }
                                _progress?.Report($"Restored owner {owner.DisplayName} to {app.DisplayName}");
                            }
                            else
                            {
                                _progress?.Report($"[WHATIF] Would restore owner {owner.DisplayName} to {app.DisplayName}");
                            }
                            restoredCount++;
                        }
                        catch (Exception ex)
                        {
                            _progress?.Report($"Error restoring owner to {app.DisplayName}: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"Error restoring app owners: {ex.Message}");
            }

            return restoredCount;
        }

        #endregion

        #region Helper Methods

        private async Task ResetUserPasswordAsync(string userId, string newPassword, CancellationToken ct)
        {
            if (_graphClient == null) return;

            var passwordProfile = new Microsoft.Graph.Models.PasswordProfile
            {
                Password = newPassword,
                ForceChangePasswordNextSignIn = true
            };

            var user = new Microsoft.Graph.Models.User { PasswordProfile = passwordProfile };
            await _graphClient.Users[userId].PatchAsync(user, cancellationToken: ct);
        }

        private async Task RevokeUserSessionsAsync(string userId, CancellationToken ct)
        {
            if (_graphClient == null) return;
            // Use the new method name as PostAsync is obsolete
            await _graphClient.Users[userId].RevokeSignInSessions.PostAsRevokeSignInSessionsPostResponseAsync(cancellationToken: ct);
        }

        private async Task RemoveUserFromAllPrivilegedRolesAsync(string userId, CancellationToken ct)
        {
            if (_graphClient == null) return;

            // Remove from direct role assignments
            var memberOf = await _graphClient.Users[userId].MemberOf.GetAsync(cancellationToken: ct);
            if (memberOf?.Value != null)
            {
                foreach (var membership in memberOf.Value)
                {
                    if (membership.OdataType == "#microsoft.graph.directoryRole" && membership.Id != null)
                    {
                        try
                        {
                            await _graphClient.DirectoryRoles[membership.Id].Members[userId].Ref.DeleteAsync(cancellationToken: ct);
                            _progress?.Report($"Removed user from direct role: {membership.Id}");
                        }
                        catch { /* Role removal failed, might not be removable */ }
                    }
                }
            }

            // Also remove PIM eligible assignments
            await RemoveAllPimEligibleAssignmentsAsync(userId, null, false, ct);
        }

        private static string GenerateSecurePassword(int length = 16)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
            // Use cryptographically-secure RNG; passwords are returned to callers and may be set
            // on user accounts, so non-secure System.Random is unacceptable here.
            var result = new char[length];
            for (int i = 0; i < length; i++)
            {
                result[i] = chars[System.Security.Cryptography.RandomNumberGenerator.GetInt32(chars.Length)];
            }
            return new string(result);
        }

        #endregion
    }

    #region Supporting Models for PLATYPUS IR Operations

    /// <summary>
    /// Represents a PIM eligible role assignment.
    /// </summary>
    public class PimEligibleAssignment
    {
        public string ScheduleId { get; set; } = "";
        public string RoleDefinitionId { get; set; } = "";
        public string RoleDisplayName { get; set; } = "";
        public string PrincipalId { get; set; } = "";
        public string PrincipalDisplayName { get; set; } = "";
        public string PrincipalUpn { get; set; } = "";
        public string PrincipalType { get; set; } = "";
        public string DirectoryScopeId { get; set; } = "/";
        public DateTime? StartDateTime { get; set; }
        public DateTime? EndDateTime { get; set; }
    }

    /// <summary>
    /// Options for deploying IR Conditional Access policies.
    /// </summary>
    public class IrCaPolicyDeploymentOptions
    {
        public List<string> BreakglassAccountUpns { get; set; } = new List<string>();
        public string Prefix { get; set; } = "[IR]";
        public bool EnablePolicies { get; set; } = false; // Default to report-only mode
        public bool WhatIf { get; set; } = true;
        public List<string> TemplatesToDeploy { get; set; } = new List<string>
        {
            "Block legacy authentication",
            "Require multifactor authentication for admins",
            "Require multifactor authentication for Azure management",
            "Require multifactor authentication for risky sign-ins",
            "Require password change for high-risk users"
        };
    }

    /// <summary>
    /// Result of IR CA policy deployment.
    /// </summary>
    public class IrCaPolicyDeploymentResult
    {
        public string TemplateName { get; set; } = "";
        public string Status { get; set; } = ""; // Created, Skipped, Failed, WhatIf
        public string Message { get; set; } = "";
    }

    /// <summary>
    /// Result of synced users export operation.
    /// </summary>
    public class SyncedUsersExportResult
    {
        public string ExportFilePath { get; set; } = "";
        public int SyncedUserCount { get; set; }
        public bool ExportedSuccessfully { get; set; }
        public bool SyncDisabled { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; } = "";
    }

    /// <summary>
    /// Result of app owners export operation.
    /// </summary>
    public class AppOwnersExportResult
    {
        public string ExportFilePath { get; set; } = "";
        public int ExportedCount { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; } = "";
    }

    /// <summary>
    /// App/ServicePrincipal owner information for export/restore.
    /// </summary>
    public class AppOwnerInfo
    {
        public string ObjectType { get; set; } = "";
        public string ObjectId { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string AppId { get; set; } = "";
        public List<OwnerDetails> Owners { get; set; } = new List<OwnerDetails>();
    }

    /// <summary>
    /// Owner details for export/restore.
    /// </summary>
    public class OwnerDetails
    {
        public string Id { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string UserPrincipalName { get; set; } = "";
    }

    #endregion
}
