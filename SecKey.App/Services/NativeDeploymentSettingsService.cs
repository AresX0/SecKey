using System.Text.Json;
using System.IO;
using System.Linq;

namespace SecKey.App.Services;

public sealed record DeploymentSettingDefinition(
    string Key,
    string Scope,
    string DisplayName,
    string Description,
    string DefaultValue,
    string EditScope);

public sealed record DeploymentSettingSnapshot(
    string Key,
    string Scope,
    string DisplayName,
    string Description,
    string Source,
    string Value,
    string EditScope);

public interface INativeDeploymentSettingsService
{
    IReadOnlyList<DeploymentSettingSnapshot> GetSettingsForScope(string scope);
    void SaveValue(string key, string value);
    IReadOnlyDictionary<string, string> GetAllOverrides();
    void ReplaceOverrides(IReadOnlyDictionary<string, string> overrides);
}

public sealed class NativeDeploymentSettingsService : INativeDeploymentSettingsService
{
    private const string NativeSource = "native-code";
    private const string OverrideSource = "native-code+override";

    private static readonly IReadOnlyList<DeploymentSettingDefinition> Definitions =
    [
        new("tenant.defaultCountry", "Dashboard", "Default Country", "Default country code for generated tenant artifacts.", "US", "Dashboard"),
        new("tenant.namingPrefix", "Dashboard", "Naming Prefix", "Prefix used for generated SecKey objects.", "SECKEY", "Dashboard"),
        new("seckey.version", "Dashboard", "SecKey Version", "Native deployment version label used by deployment orchestration.", "2201", "Dashboard"),
        new("seckey.controlPlaneIdentifier", "Dashboard", "Control Plane Identifier", "Suffix/identifier used for control-plane naming.", "-cp", "Dashboard"),
        new("seckey.managementPlaneIdentifier", "Dashboard", "Management Plane Identifier", "Suffix/identifier used for management-plane naming.", "-mp", "Dashboard"),
        new("seckey.dataPlaneIdentifier", "Dashboard", "Data Plane Identifier", "Suffix/identifier used for data-plane naming.", "-dp", "Dashboard"),
        new("seckey.accessPlaneIdentifier", "Dashboard", "Access Plane Identifier", "Suffix/identifier used for access-plane naming.", "-ap", "Dashboard"),

        new("intuneapps.includeStoreAssignments", "Intune Apps", "Include Store Assignments", "Whether Deploy Intune Apps also deploys Store assignments.", "true", "Intune Apps"),
        new("intuneapps.ring", "Intune Apps", "Deployment Ring", "Default deployment ring for Intune app assignment groups.", "pilot", "Intune Apps"),
        new("intuneapps.rootPath", "Intune Apps", "Intune Apps Root Path", "Root path used for Intune app package configurations.", "[PROJECTPATH]\\IntuneApps", "Intune Apps"),
        new("intuneapps.configJsonList", "Intune Apps", "Intune App Config JSON List", "Semicolon-separated list of Intune app config JSON files deployed by default.", "[PROJECTPATH]\\IntuneApps\\Install-BGInfo\\config.json;[PROJECTPATH]\\IntuneApps\\Install-SetBDEPinTool\\config.json;[PROJECTPATH]\\IntuneApps\\Set-DeviceConfigSecKey\\config.json;[PROJECTPATH]\\IntuneApps\\Install-PowerShellModules\\config.json;[PROJECTPATH]\\IntuneApps\\Install-SecKeyModule\\config.json", "Intune Apps"),
        new("intuneapps.storeAssignmentsJsonList", "Intune Apps", "Store Assignments JSON List", "Semicolon-separated list of Store App assignment JSON files.", "[PROJECTPATH]\\JSON\\StoreAppsAssignment\\seckey.settings.json", "Intune Apps"),
        new("intuneapps.remediationConfigJsonList", "Intune Apps", "Remediation Script Config List", "Semicolon-separated list of proactive remediation config JSON files.", "[PROJECTPATH]\\RemediationScripts\\VSCode-Updater\\config.json;[PROJECTPATH]\\RemediationScripts\\Git-Updater\\config.json;[PROJECTPATH]\\RemediationScripts\\remove-widgets\\config.json;[PROJECTPATH]\\RemediationScripts\\Remove-OneDrive\\config.json;[PROJECTPATH]\\RemediationScripts\\Fix-ServicePaths\\config.json;[PROJECTPATH]\\RemediationScripts\\remove-newsandinterests\\config.json;[PROJECTPATH]\\RemediationScripts\\remove-Teams\\config.json", "Intune Apps"),

        new("groups.defaultNamingPattern", "Groups", "Group Naming Pattern", "Naming pattern for generated Entra groups.", "SECKEY-{scope}-{role}", "Groups"),
        new("groups.includeDynamicRules", "Groups", "Enable Dynamic Group Rules", "Generate dynamic membership rules where supported.", "true", "Groups"),
        new("groups.userJsonPath", "Groups", "Users JSON Path", "Primary users JSON path for user provisioning.", "[PROJECTPATH]\\JSON\\Users\\seckey.users.json", "Groups"),
        new("groups.groupJsonPath", "Groups", "Groups JSON Path", "Primary groups JSON path for group provisioning.", "[PROJECTPATH]\\JSON\\Groups\\seckey.groups.json", "Groups"),
        new("groups.roleScopeTagPath", "Groups", "Role Scope Tag JSON Path", "Path to RBAC role scope tag JSON directory.", "[PROJECTPATH]\\JSON\\RBAC", "Groups"),

        new("policies.baselineProfile", "Policies", "Baseline Profile", "Default baseline profile to deploy from policy commands.", "seckey.deploy", "Policies"),
        new("policies.includeSettingsCatalog", "Policies", "Include Settings Catalog", "Include settings catalog during policy deployment sequences.", "true", "Policies"),
        new("policies.deviceEnrollmentRestrictionJsonList", "Policies", "Enrollment Restriction JSON List", "Semicolon-separated list of Device Enrollment Restriction JSON files.", "[PROJECTPATH]\\JSON\\DeviceEnrollmentRestrictions\\seckey.globalIntuneEnrollmentDeviceLimitRestrictions.json;[PROJECTPATH]\\JSON\\DeviceEnrollmentRestrictions\\seckey.globalIntuneEnrollmentDeviceTypeRestrictions.json", "Policies"),
        new("policies.deviceConfigurationJsonList", "Policies", "Device Configuration JSON List", "Semicolon-separated list of Device Configuration JSON files.", "[PROJECTPATH]\\JSON\\DeviceConfiguration\\seckey.win10logonRestrictions.json;[PROJECTPATH]\\JSON\\DeviceConfiguration\\seckey.win10logonRestrictionsUserRightsEndpointProtetcion.json;[PROJECTPATH]\\JSON\\DeviceConfiguration\\seckey.win10AppLockerCSP.json;[PROJECTPATH]\\JSON\\DeviceConfiguration\\seckey.win10DefenderDeviceGuardCSP.json;[PROJECTPATH]\\JSON\\DeviceConfiguration\\seckey.win10SinkHoleProxyDeviceRestrictionsUI.json;[PROJECTPATH]\\JSON\\DeviceConfiguration\\seckey.win10SystemHardeningCSP.json;[PROJECTPATH]\\JSON\\DeviceConfiguration\\seckey.win10SystemHardeningDeviceRestrictionsUI.json;[PROJECTPATH]\\JSON\\DeviceConfiguration\\seckey.win10SystemHardeningEndpointProtectionUI.json;[PROJECTPATH]\\JSON\\DeviceConfiguration\\seckey.win10UpdateRingBroad.json", "Policies"),
        new("policies.appLockerCspPath", "Policies", "AppLocker CSP JSON Path", "Direct path to AppLocker CSP configuration JSON.", "[PROJECTPATH]\\JSON\\DeviceConfiguration\\seckey.win10AppLockerCSP.json", "Policies"),
        new("policies.deviceConfigurationAdmxJsonList", "Policies", "ADMX Configuration JSON List", "Semicolon-separated list of Device Configuration ADMX JSON files.", "[PROJECTPATH]\\JSON\\DeviceConfigurationADMX\\seckey.edge.computer.json", "Policies"),
        new("policies.deviceComplianceJsonList", "Policies", "Device Compliance JSON List", "Semicolon-separated list of Device Compliance policy JSON files.", "[PROJECTPATH]\\JSON\\DeviceCompliancePolicies\\seckey.mde.json;[PROJECTPATH]\\JSON\\DeviceCompliancePolicies\\seckey.delayed.json;[PROJECTPATH]\\JSON\\DeviceCompliancePolicies\\seckey.immediate.json", "Policies"),
        new("policies.settingsCatalogJsonList", "Policies", "Settings Catalog JSON List", "Semicolon-separated list of Settings Catalog JSON files.", "[PROJECTPATH]\\JSON\\DeviceSettingsCatalog\\seckey.win10Edge.json;[PROJECTPATH]\\JSON\\DeviceSettingsCatalog\\seckey.win10PowerSettings.json;[PROJECTPATH]\\JSON\\DeviceSettingsCatalog\\seckey.win10SystemHardening.json;[PROJECTPATH]\\JSON\\DeviceSettingsCatalog\\seckey.win10UserAccountHardening.json", "Policies"),
        new("policies.endpointSecurityJsonList", "Policies", "Endpoint Security JSON List", "Semicolon-separated list of Endpoint Security policy JSON files.", "[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.accountProtection.json;[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.applicationControl.json;[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.attackSurfaceReduction.json;[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.bitlocker.json;[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.defenderAntiVirus.json;[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.defenderFirewallPolicy.json;[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.defenderFirewallRules.json;[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.deviceControl.json;[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.endpointDetectionAndResponse.json;[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.SecurityCenter.json;[PROJECTPATH]\\JSON\\EndpointSecurity\\seckey.win10.webProtection.json", "Policies"),
        new("policies.enrollmentStatusPageJsonPath", "Policies", "Enrollment Status Page JSON Path", "Path to Enrollment Status Page configuration JSON.", "[PROJECTPATH]\\JSON\\EnrollmentStatusPage\\seckey.enrollmentStatusPage.json", "Policies"),
        new("policies.autoPilotProfileJsonPath", "Policies", "Autopilot Profile JSON Path", "Path to Autopilot deployment profile JSON.", "[PROJECTPATH]\\JSON\\AutoPilot\\seckey.profile.json", "Policies"),
        new("policies.reusableSettingsJsonList", "Policies", "Reusable Settings JSON List", "Semicolon-separated list of reusable settings JSON files.", "[PROJECTPATH]\\JSON\\ReusableSettings\\seckey.DefenderforEndpoint.json;[PROJECTPATH]\\JSON\\ReusableSettings\\seckey.IntuneAutopilot.json;[PROJECTPATH]\\JSON\\ReusableSettings\\seckey.Microsoft365Common.json;[PROJECTPATH]\\JSON\\ReusableSettings\\seckey.Microsoft365encryptionchains.json;[PROJECTPATH]\\JSON\\ReusableSettings\\seckey.Windows11.json", "Policies"),
        new("policies.platformScriptsConfigJsonList", "Policies", "Platform Scripts Config List", "Semicolon-separated list of platform script config JSON files.", "[PROJECTPATH]\\JSON\\PlatformScripts\\SECKEY-Global-Install-Windows-Defender-Updates\\config.json;[PROJECTPATH]\\JSON\\PlatformScripts\\SECKEY-Global-Set-Network-to-Private\\config.json", "Policies"),
        new("policies.administrativeUnitsJsonPath", "Policies", "Administrative Units JSON Path", "Path to Administrative Units JSON deployment file.", "[PROJECTPATH]\\JSON\\AdministrativeUnits\\seckey.administrativeUnits.json", "Policies"),

        new("ca.breakGlassAccount", "Conditional Access", "Break Glass Account", "Emergency account excluded from risky CA lockout policies.", "breakglass@contoso.com", "Conditional Access"),
        new("ca.namedLocationTrusted", "Conditional Access", "Trusted Named Location", "Trusted named location identifier for deployment templates.", "Headquarters", "Conditional Access"),
        new("ca.authContextJsonPath", "Conditional Access", "Authentication Context JSON Path", "Path to Authentication Context JSON deployment file.", "[PROJECTPATH]\\JSON\\AuthenticationContext\\seckey.authenticationContext.json", "Conditional Access"),
        new("ca.authStrengthJsonPath", "Conditional Access", "Authentication Strength JSON Path", "Path to Authentication Strength JSON deployment file.", "[PROJECTPATH]\\JSON\\AuthenticationStrength\\seckey.authenticationStrength.json", "Conditional Access"),
        new("ca.namedLocationJsonPath", "Conditional Access", "Named Location JSON Path", "Path to trusted/blocked named location JSON file.", "[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.namedLocation.SECKEYCountryBlockList.json", "Conditional Access"),
        new("ca.conditionalAccessPolicyJsonList", "Conditional Access", "Conditional Access Policy JSON List", "Semicolon-separated list of Conditional Access policy JSON files.", "[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.allow.MFAandCompliantDevice.json;[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.block.DeviceFilter.json;[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.block.legacyAuth.json;[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.block.unsupportedOS.json;[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.block.unsupportedSigninLocation.json;[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.block.unsupportedSignInRisk.json;[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.block.unsupportedUserRisk.json;[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.allow.MFAAADJoin.json;[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.allow.SessionManagement.json;[PROJECTPATH]\\JSON\\ConditionalAccessPolicy\\seckey.allow.PhishingResistantAuthMicrosoftAdminPortals.json", "Conditional Access"),

        new("infrastructure.additionalBreakGlass", "Infrastructure", "Additional Break-Glass Accounts", "Comma-separated break-glass accounts included in infrastructure deployment guardrails.", "", "Infrastructure"),
        new("infrastructure.optionalFeaturesDefault", "Infrastructure", "Default Optional Feature Mode", "Default selection mode when opening optional archive feature bundles.", "manual", "Infrastructure"),
        new("infrastructure.projectPath", "Infrastructure", "Project Root Path", "Root path used to resolve JSON and Intune assets.", "[PROJECTPATH]", "Infrastructure"),

        new("devicetagging.defaultAttributeNumber", "Device Tagging", "Default Extension Attribute", "Default extension attribute number used for device tagging.", "1", "Device Tagging"),
        new("devicetagging.defaultAttributeValue", "Device Tagging", "Default Attribute Value", "Default extension attribute value applied when tagging devices.", "SECKEY", "Device Tagging"),

        new("wdac.profileFilter", "WDAC / AppLocker", "Profile Filter", "Default filter used when browsing WDAC/AppLocker profiles.", "", "WDAC / AppLocker"),
        new("wdac.exportFolder", "WDAC / AppLocker", "Export Folder", "Default folder used for decoded policy exports.", "Policies", "WDAC / AppLocker"),

        new("gsa.previewLimit", "Global Secure Access", "Preview Limit", "Maximum characters shown in the Global Secure Access preview panel.", "8000", "Global Secure Access"),
        new("gsa.exportFolder", "Global Secure Access", "Export Folder", "Default folder used for Global Secure Access preview exports.", "Exports", "Global Secure Access")
    ];

    private readonly string _settingsPath;
    private Dictionary<string, string>? _overrides;

    public NativeDeploymentSettingsService()
    {
        var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey");
        Directory.CreateDirectory(dataDir);
        _settingsPath = Path.Combine(dataDir, "deployment-settings.json");
    }

    public NativeDeploymentSettingsService(string settingsPath)
    {
        var parent = Path.GetDirectoryName(settingsPath);
        if (!string.IsNullOrWhiteSpace(parent))
            Directory.CreateDirectory(parent);

        _settingsPath = settingsPath;
    }

    public IReadOnlyList<DeploymentSettingSnapshot> GetSettingsForScope(string scope)
    {
        EnsureLoaded();

        return Definitions
            .Where(d => string.Equals(d.Scope, scope, StringComparison.OrdinalIgnoreCase))
            .Select(d =>
            {
                var hasOverride = _overrides!.TryGetValue(d.Key, out var overrideValue);
                var value = hasOverride && !string.IsNullOrWhiteSpace(overrideValue)
                    ? overrideValue!
                    : d.DefaultValue;

                return new DeploymentSettingSnapshot(
                    d.Key,
                    d.Scope,
                    d.DisplayName,
                    d.Description,
                    hasOverride ? OverrideSource : NativeSource,
                    value,
                    d.EditScope);
            })
            .ToList();
    }

    public void SaveValue(string key, string value)
    {
        EnsureLoaded();

        var normalized = (value ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            if (_overrides!.Remove(key))
            {
                Persist();
            }
            return;
        }

        _overrides![key] = normalized;
        Persist();
    }

    public IReadOnlyDictionary<string, string> GetAllOverrides()
    {
        EnsureLoaded();
        return new Dictionary<string, string>(_overrides!, StringComparer.OrdinalIgnoreCase);
    }

    public void ReplaceOverrides(IReadOnlyDictionary<string, string> overrides)
    {
        EnsureLoaded();

        _overrides!.Clear();
        foreach (var kv in overrides)
        {
            if (string.IsNullOrWhiteSpace(kv.Key))
                continue;

            var val = (kv.Value ?? string.Empty).Trim();
            if (val.Length == 0)
                continue;

            _overrides[kv.Key] = val;
        }

        Persist();
    }

    private void EnsureLoaded()
    {
        if (_overrides is not null)
        {
            return;
        }

        if (File.Exists(_settingsPath))
        {
            try
            {
                var json = File.ReadAllText(_settingsPath);
                var model = JsonSerializer.Deserialize<PersistedSettings>(json) ?? new PersistedSettings();
                _overrides = model.Overrides
                    .Where(kv => !string.IsNullOrWhiteSpace(kv.Key))
                    .ToDictionary(kv => kv.Key, kv => kv.Value ?? string.Empty, StringComparer.OrdinalIgnoreCase);
                return;
            }
            catch
            {
                // Fall back to reseeding below.
            }
        }

        _overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Persist();
    }

    private void Persist()
    {
        var model = new PersistedSettings
        {
            LastUpdatedUtc = DateTime.UtcNow,
            Overrides = _overrides!
        };

        var json = JsonSerializer.Serialize(model, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_settingsPath, json);
    }

    private sealed class PersistedSettings
    {
        public DateTime LastUpdatedUtc { get; set; } = DateTime.UtcNow;
        public Dictionary<string, string> Overrides { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
