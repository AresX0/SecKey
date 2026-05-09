using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SecKey.Graph.Services.EntraID;
using SecKey.Graph.Services.Intune;
using SecKey.Graph.Services.Win32Lob;

namespace SecKey.Graph.Services;

public sealed class SecKeyManifestDeploymentSummary
{
    public int CreatedCount { get; set; }
    public int SkippedCount { get; set; }
    public int UpdatedCount { get; set; }
    public int DeletedCount { get; set; }
    public List<string> Notes { get; } = new();

    public string ToStatusText()
        => $"Created {CreatedCount} items, updated {UpdatedCount}, deleted {DeletedCount}, skipped {SkippedCount}.";
}

public sealed class SecKeyManifestDeploymentOptions
{
    public IReadOnlyList<string> AdditionalBreakGlassAccounts { get; init; } = Array.Empty<string>();
    public Action<DeploymentProgressEvent>? Progress { get; init; }
}

public sealed record SecKeyOptionalFeatureDefinition(string Id, string DisplayName, string Description, string Command);

public sealed record DeploymentProgressEvent(string Command, string Stage, string Message, bool IsError);

public sealed class SecKeyManifestDeploymentService
{
    private static readonly Dictionary<string, int> CommandExecutionOrder = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Import-AdministrativeUnitList"] = 5,
        ["Import-EntraUserList"] = 10,
        ["Import-EntraGroupList"] = 20,
        ["Import-IntuneRoleScopeTagList"] = 30,
        ["Import-AuthenticationContextList"] = 35,
        ["Import-AuthenticationStrengthList"] = 36,
        ["Import-NamedLocationList"] = 40,
        ["Import-ConditionalAccessPolicyList"] = 50,
        ["Import-DeviceEnrollmentRestrictionList"] = 60,
        ["Import-DeviceConfigurationList"] = 70,
        ["Import-DeviceConfigurationADMXList"] = 80,
        ["Import-DeviceCompliancePolicyList"] = 90,
        ["Import-DeviceSettingsCatalog"] = 100,
        ["Import-EnrollmentStatusPageList"] = 110,
        ["Import-AutoPilotPolicyList"] = 120,
        ["Import-EndpointSecurityPolicyList"] = 130,
        ["Import-IntuneApplicationList"] = 140,
        ["Import-StoreAppsEntraGroupAssignmentList"] = 150,
        ["Import-ProactiveRemediationScripts"] = 160,
        ["Import-ReusableSettingsList"] = 170,
        ["Import-PlatformScripts"] = 180,
    };

    public static IReadOnlyList<SecKeyOptionalFeatureDefinition> OptionalFeatures { get; } =
    [
        new("administrative-units", "Administrative Units", "Restricted management administrative units imported from the archived deployment set.", "Import-AdministrativeUnitList"),
        new("reusable-settings", "Reusable Settings", "Reusable policy settings referenced by advanced Windows configuration and security bundles.", "Import-ReusableSettingsList"),
        new("platform-scripts", "Platform Scripts", "Optional Intune platform scripts for Defender updates and private-network remediation.", "Import-PlatformScripts")
    ];

    private readonly GraphHttpClient _client;
    private readonly ILoggerFactory _loggerFactory;

    private readonly EntraIdUserService _users;
    private readonly EntraIdGroupService _groups;
    private readonly ConditionalAccessPolicyService _caPolicies;
    private readonly NamedLocationService _namedLocations;
    private readonly AuthenticationContextService _authContexts;
    private readonly AuthenticationStrengthService _authStrengths;
    private readonly AdministrativeUnitService _administrativeUnits;
    private readonly IntuneRoleScopeTagService _scopeTags;
    private readonly DeviceEnrollmentRestrictionService _enrollmentRestrictions;
    private readonly DeviceConfigurationService _deviceConfigurations;
    private readonly GroupPolicyConfigurationService _groupPolicyConfigurations;
    private readonly DeviceCompliancePolicyService _compliancePolicies;
    private readonly DeviceSettingsCatalogService _settingsCatalog;
    private readonly ReusablePolicySettingService _reusableSettings;
    private readonly EnrollmentStatusPageService _enrollmentStatusPages;
    private readonly AutopilotProfileService _autopilotProfiles;
    private readonly EndpointSecurityPolicyService _endpointSecurityPolicies;
    private readonly ProactiveRemediationService _proactiveRemediation;
    private readonly PlatformScriptService _platformScripts;

    private readonly Dictionary<string, string> _groupIdToDisplayName = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _userIdToDisplayName = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _tagIdToDisplayName = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _namedLocationIdByDisplayName = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _scopeTagGraphIdBySymbolicId = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _authContextIdBySymbolicId = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _authStrengthIdBySymbolicId = new(StringComparer.OrdinalIgnoreCase);

    public SecKeyManifestDeploymentService(GraphHttpClient client, ILoggerFactory? loggerFactory = null)
    {
        _client = client;
        _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;

        _users = new EntraIdUserService(client);
        _groups = new EntraIdGroupService(client);
        _caPolicies = new ConditionalAccessPolicyService(client);
        _namedLocations = new NamedLocationService(client);
        _authContexts = new AuthenticationContextService(client);
        _authStrengths = new AuthenticationStrengthService(client);
        _administrativeUnits = new AdministrativeUnitService(client);
        _scopeTags = new IntuneRoleScopeTagService(client);
        _enrollmentRestrictions = new DeviceEnrollmentRestrictionService(client);
        _deviceConfigurations = new DeviceConfigurationService(client);
        _groupPolicyConfigurations = new GroupPolicyConfigurationService(client);
        _compliancePolicies = new DeviceCompliancePolicyService(client);
        _settingsCatalog = new DeviceSettingsCatalogService(client);
        _reusableSettings = new ReusablePolicySettingService(client);
        _enrollmentStatusPages = new EnrollmentStatusPageService(client);
        _autopilotProfiles = new AutopilotProfileService(client);
        _endpointSecurityPolicies = new EndpointSecurityPolicyService(client);
        _proactiveRemediation = new ProactiveRemediationService(client);
        _platformScripts = new PlatformScriptService(client);
    }

    public Task<SecKeyManifestDeploymentSummary> DeployCsmAsync(string repoRoot, SecKeyManifestDeploymentOptions? options = null, CancellationToken ct = default)
        => DeployManifestAsync(ResolveDeploymentManifestPath(repoRoot), repoRoot, ct, options: options);

    public Task<SecKeyManifestDeploymentSummary> DeployCsmCommandAsync(string repoRoot, string command, SecKeyManifestDeploymentOptions? options = null, CancellationToken ct = default)
        => DeployManifestAsync(ResolveDeploymentManifestPath(repoRoot), repoRoot, ct, command, options);

    public Task<SecKeyManifestDeploymentSummary> DeployOptionalFeaturesAsync(string repoRoot, IEnumerable<string> commands, SecKeyManifestDeploymentOptions? options = null, CancellationToken ct = default)
        => DeploySelectedManifestCommandsAsync(ResolveOptionalManifestPath(repoRoot), repoRoot, commands, options, ct);

    public Task<SecKeyManifestDeploymentSummary> UndoCsmAsync(string repoRoot, SecKeyManifestDeploymentOptions? options = null, CancellationToken ct = default)
        => UndoManifestAsync(ResolveDeploymentManifestPath(repoRoot), repoRoot, ct, options: options);

    public Task<SecKeyManifestDeploymentSummary> UndoCsmCommandAsync(string repoRoot, string command, SecKeyManifestDeploymentOptions? options = null, CancellationToken ct = default)
        => UndoManifestAsync(ResolveDeploymentManifestPath(repoRoot), repoRoot, ct, command, options);

    public Task<SecKeyManifestDeploymentSummary> UndoOptionalFeaturesAsync(string repoRoot, IEnumerable<string> commands, SecKeyManifestDeploymentOptions? options = null, CancellationToken ct = default)
        => UndoSelectedManifestCommandsAsync(ResolveOptionalManifestPath(repoRoot), repoRoot, commands, options, ct);

    private static string ResolveDeploymentManifestPath(string repoRoot)
    {
        var secKeyManifest = Path.Combine(repoRoot, "JSON", "seckey.deploy.json");
        if (File.Exists(secKeyManifest))
            return secKeyManifest;

        return Path.Combine(repoRoot, "JSON", "csm.deploy.json");
    }

    private static string ResolveOptionalManifestPath(string repoRoot)
        => Path.Combine(repoRoot, "JSON", "seckey.optional.deploy.json");

    private Task<SecKeyManifestDeploymentSummary> DeploySelectedManifestCommandsAsync(string manifestPath, string repoRoot, IEnumerable<string> commands, SecKeyManifestDeploymentOptions? options, CancellationToken ct)
        => ExecuteSelectedManifestCommandsAsync(manifestPath, repoRoot, commands, deploy: true, options, ct);

    private Task<SecKeyManifestDeploymentSummary> UndoSelectedManifestCommandsAsync(string manifestPath, string repoRoot, IEnumerable<string> commands, SecKeyManifestDeploymentOptions? options, CancellationToken ct)
        => ExecuteSelectedManifestCommandsAsync(manifestPath, repoRoot, commands, deploy: false, options, ct);

    private async Task<SecKeyManifestDeploymentSummary> ExecuteSelectedManifestCommandsAsync(string manifestPath, string repoRoot, IEnumerable<string> commands, bool deploy, SecKeyManifestDeploymentOptions? options, CancellationToken ct)
    {
        var selectedCommands = commands
            .Where(command => !string.IsNullOrWhiteSpace(command))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (selectedCommands.Count == 0)
            return new SecKeyManifestDeploymentSummary { Notes = { "No optional feature commands were selected." } };

        var aggregate = new SecKeyManifestDeploymentSummary();
        foreach (var command in selectedCommands)
        {
            var result = deploy
                ? await DeployManifestAsync(manifestPath, repoRoot, ct, command, options)
                : await UndoManifestAsync(manifestPath, repoRoot, ct, command, options);

            aggregate.CreatedCount += result.CreatedCount;
            aggregate.SkippedCount += result.SkippedCount;
            aggregate.UpdatedCount += result.UpdatedCount;
            aggregate.DeletedCount += result.DeletedCount;
            foreach (var note in result.Notes)
                aggregate.Notes.Add(note);
        }

        return aggregate;
    }

    private async Task<SecKeyManifestDeploymentSummary> DeployManifestAsync(string manifestPath, string repoRoot, CancellationToken ct, string? onlyCommand = null, SecKeyManifestDeploymentOptions? options = null)
    {
        if (!File.Exists(manifestPath))
            throw new FileNotFoundException("SecKey deployment manifest not found.", manifestPath);

        var manifest = (JsonObject?)JsonNode.Parse(await File.ReadAllTextAsync(manifestPath, ct))
            ?? throw new InvalidOperationException("Deployment manifest is invalid JSON.");
        var settings = manifest["settings"]?.AsObject()
            ?? throw new InvalidOperationException("Deployment manifest is missing settings.");
        var commandList = manifest["commandList"]?.AsArray()
            ?? throw new InvalidOperationException("Deployment manifest is missing commandList.");

        var summary = new SecKeyManifestDeploymentSummary();
        var secKeyVersion = settings["SecKeyVersion"]?.GetValue<string>() ?? "";

        await LoadIdentityCatalogsAsync(repoRoot, secKeyVersion, ct);

        var commandsToRun = commandList.OfType<JsonObject>().ToList();
        if (string.IsNullOrWhiteSpace(onlyCommand))
        {
            commandsToRun = commandsToRun
                .OrderBy(commandObject =>
                {
                    var commandName = commandObject["command"]?.GetValue<string>() ?? string.Empty;
                    return CommandExecutionOrder.TryGetValue(commandName, out var sortOrder) ? sortOrder : int.MaxValue;
                })
                .ToList();
        }

        var deploymentErrors = new List<(string CommandName, Exception Ex)>();

        foreach (var commandObject in commandsToRun)
        {
            var command = commandObject["command"]?.GetValue<string>() ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(onlyCommand) &&
                !string.Equals(command, onlyCommand, StringComparison.OrdinalIgnoreCase))
                continue;

            var parameterPaths = commandObject["parameters"]?["JSONFileList"] as JsonArray;
            var files = ResolveManifestFiles(parameterPaths, repoRoot).ToList();

            var startCreated = summary.CreatedCount;
            var startUpdated = summary.UpdatedCount;
            var startSkipped = summary.SkippedCount;
            var startNotes = summary.Notes.Count;

            options?.Progress?.Invoke(new DeploymentProgressEvent(command, "Start", $"Running {command} ({files.Count} file(s)).", false));
            try
            {
                await ExecuteManifestCommandAsync(command, files, repoRoot, secKeyVersion, summary, options, ct);
                var created = summary.CreatedCount - startCreated;
                var updated = summary.UpdatedCount - startUpdated;
                var skipped = summary.SkippedCount - startSkipped;
                var newNotes = summary.Notes.Count - startNotes;
                var noteSuffix = newNotes > 0 ? $" Notes: {string.Join(" | ", summary.Notes.Skip(startNotes))}" : string.Empty;
                options?.Progress?.Invoke(new DeploymentProgressEvent(command, "Complete", $"Created {created}, updated {updated}, skipped {skipped}.{noteSuffix}", false));
            }
            catch (Exception ex)
            {
                deploymentErrors.Add((command, ex));
                var errorMsg = $"{ex.GetType().Name}: {ex.Message}";
                summary.Notes.Add($"[ERROR] {command}: {errorMsg}");
                options?.Progress?.Invoke(new DeploymentProgressEvent(command, "Failed", errorMsg, true));
                // Continue with next command instead of throwing
            }
        }

        // Add deployment error summary at end
        if (deploymentErrors.Count > 0)
        {
            var failedCommands = string.Join(", ", deploymentErrors.Select(e => e.CommandName));
            summary.Notes.Add($"\n[DEPLOYMENT SUMMARY] Completed with {deploymentErrors.Count} error(s): {failedCommands}");
        }

        options?.Progress?.Invoke(new DeploymentProgressEvent("BreakGlass", "Start", "Enforcing break-glass account membership.", false));
        await EnsureBreakGlassAccountsAsync(summary, options, ct);
        options?.Progress?.Invoke(new DeploymentProgressEvent("BreakGlass", "Complete", "Break-glass enforcement done.", false));

        if (!string.IsNullOrWhiteSpace(onlyCommand) &&
            summary.CreatedCount == 0 && summary.UpdatedCount == 0 && summary.SkippedCount == 0 && summary.Notes.Count == 0)
            summary.Notes.Add($"Command not found in manifest: {onlyCommand}");

        return summary;
    }

    private async Task ExecuteManifestCommandAsync(string command, IReadOnlyList<string> files, string repoRoot, string secKeyVersion, SecKeyManifestDeploymentSummary summary, SecKeyManifestDeploymentOptions? options, CancellationToken ct)
    {
        switch (command)
        {
            case "Import-AdministrativeUnitList":
                await ImportAdministrativeUnitsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-EntraUserList":
            case "Import-AADUserList": // legacy alias
                await ImportUsersAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-EntraGroupList":
            case "Import-AADGroupList": // legacy alias
                await ImportGroupsAsync(files, secKeyVersion, summary, options, ct);
                break;
            case "Import-IntuneRoleScopeTagList":
                await ImportScopeTagsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-AuthenticationContextList":
                await ImportAuthenticationContextsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-AuthenticationStrengthList":
                await ImportAuthenticationStrengthsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-NamedLocationList":
                await ImportNamedLocationsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-ConditionalAccessPolicyList":
                await ImportConditionalAccessPoliciesAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-DeviceEnrollmentRestrictionList":
                await ImportEnrollmentRestrictionsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-DeviceConfigurationList":
                await ImportDeviceConfigurationsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-DeviceConfigurationADMXList":
                await ImportAdmxConfigurationsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-DeviceCompliancePolicyList":
                await ImportCompliancePoliciesAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-DeviceSettingsCatalog":
                await ImportSettingsCatalogAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-EnrollmentStatusPageList":
                await ImportEnrollmentStatusPagesAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-AutoPilotPolicyList":
                await ImportAutopilotProfilesAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-EndpointSecurityPolicyList":
                await ImportEndpointSecurityPoliciesAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-StoreAppsEntraGroupAssignmentList":
            case "Import-StoreAppsAADGroupAssignmentList": // legacy alias
                await ImportStoreAppAssignmentsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-IntuneApplicationList":
                await ImportIntuneApplicationsAsync(files, repoRoot, summary, ct);
                break;
            case "Import-ProactiveRemediationScripts":
                await ImportProactiveRemediationScriptsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-ReusableSettingsList":
                await ImportReusableSettingsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-PlatformScripts":
                await ImportPlatformScriptsAsync(files, secKeyVersion, summary, ct);
                break;
            default:
                summary.Notes.Add($"Skipped unsupported manifest step: {command}");
                break;
        }
    }

    private async Task<SecKeyManifestDeploymentSummary> UndoManifestAsync(string manifestPath, string repoRoot, CancellationToken ct, string? onlyCommand = null, SecKeyManifestDeploymentOptions? options = null)
    {
        if (!File.Exists(manifestPath))
            throw new FileNotFoundException("SecKey deployment manifest not found.", manifestPath);

        var manifest = (JsonObject?)JsonNode.Parse(await File.ReadAllTextAsync(manifestPath, ct))
            ?? throw new InvalidOperationException("Deployment manifest is invalid JSON.");
        var settings = manifest["settings"]?.AsObject()
            ?? throw new InvalidOperationException("Deployment manifest is missing settings.");
        var commandList = manifest["commandList"]?.AsArray()
            ?? throw new InvalidOperationException("Deployment manifest is missing commandList.");

        var summary = new SecKeyManifestDeploymentSummary();
        var secKeyVersion = settings["SecKeyVersion"]?.GetValue<string>() ?? "";

        await LoadIdentityCatalogsAsync(repoRoot, secKeyVersion, ct);

        var commandsToRun = commandList.OfType<JsonObject>().ToList();
        if (string.IsNullOrWhiteSpace(onlyCommand))
        {
            commandsToRun = commandsToRun
                .OrderByDescending(commandObject =>
                {
                    var commandName = commandObject["command"]?.GetValue<string>() ?? string.Empty;
                    return CommandExecutionOrder.TryGetValue(commandName, out var sortOrder) ? sortOrder : int.MinValue;
                })
                .ToList();
        }

        var undoErrors = new List<(string CommandName, Exception Ex)>();

        foreach (var commandObject in commandsToRun)
        {
            var command = commandObject["command"]?.GetValue<string>() ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(onlyCommand) &&
                !string.Equals(command, onlyCommand, StringComparison.OrdinalIgnoreCase))
                continue;

            var parameterPaths = commandObject["parameters"]?["JSONFileList"] as JsonArray;
            var files = ResolveManifestFiles(parameterPaths, repoRoot).ToList();

            var startDeleted = summary.DeletedCount;
            var startSkipped = summary.SkippedCount;
            var startNotes = summary.Notes.Count;

            options?.Progress?.Invoke(new DeploymentProgressEvent(command, "UndoStart", $"Running undo for {command} ({files.Count} file(s)).", false));
            try
            {
                await ExecuteUndoManifestCommandAsync(command, files, repoRoot, secKeyVersion, summary, ct);
                var deleted = summary.DeletedCount - startDeleted;
                var skipped = summary.SkippedCount - startSkipped;
                var newNotes = summary.Notes.Count - startNotes;
                var noteSuffix = newNotes > 0 ? $" Notes: {string.Join(" | ", summary.Notes.Skip(startNotes))}" : string.Empty;
                options?.Progress?.Invoke(new DeploymentProgressEvent(command, "UndoComplete", $"Deleted {deleted}, skipped {skipped}.{noteSuffix}", false));
            }
            catch (Exception ex)
            {
                undoErrors.Add((command, ex));
                var errorMsg = $"{ex.GetType().Name}: {ex.Message}";
                summary.Notes.Add($"[UNDO ERROR] {command}: {errorMsg}");
                options?.Progress?.Invoke(new DeploymentProgressEvent(command, "UndoFailed", errorMsg, true));
                // Continue with next command instead of throwing
            }
        }

        // Add undo error summary at end
        if (undoErrors.Count > 0)
        {
            var failedCommands = string.Join(", ", undoErrors.Select(e => e.CommandName));
            summary.Notes.Add($"\n[UNDO SUMMARY] Completed with {undoErrors.Count} error(s): {failedCommands}");
        }

        if (!string.IsNullOrWhiteSpace(onlyCommand) &&
            summary.DeletedCount == 0 && summary.SkippedCount == 0 && summary.Notes.Count == 0)
            summary.Notes.Add($"Command not found in manifest: {onlyCommand}");

        return summary;
    }

    private async Task ExecuteUndoManifestCommandAsync(string command, IReadOnlyList<string> files, string repoRoot, string secKeyVersion, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        switch (command)
        {
            case "Import-PlatformScripts":
                await RemovePlatformScriptsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-ReusableSettingsList":
                await RemoveReusableSettingsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-ProactiveRemediationScripts":
                await RemoveProactiveRemediationScriptsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-StoreAppsEntraGroupAssignmentList":
            case "Import-StoreAppsAADGroupAssignmentList": // legacy alias
                summary.Notes.Add("Undo skipped for Import-StoreAppsEntraGroupAssignmentList (non-destructive assignment step).");
                break;
            case "Import-IntuneApplicationList":
                await RemoveIntuneApplicationsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-EndpointSecurityPolicyList":
                await RemoveEndpointSecurityPoliciesAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-AutoPilotPolicyList":
                await RemoveAutopilotProfilesAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-EnrollmentStatusPageList":
                await RemoveEnrollmentStatusPagesAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-DeviceSettingsCatalog":
                await RemoveSettingsCatalogAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-DeviceCompliancePolicyList":
                await RemoveCompliancePoliciesAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-DeviceConfigurationADMXList":
                await RemoveAdmxConfigurationsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-DeviceConfigurationList":
                await RemoveDeviceConfigurationsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-DeviceEnrollmentRestrictionList":
                await RemoveEnrollmentRestrictionsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-ConditionalAccessPolicyList":
                await RemoveConditionalAccessPoliciesAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-NamedLocationList":
                await RemoveNamedLocationsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-IntuneRoleScopeTagList":
                await RemoveScopeTagsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-AuthenticationContextList":
                await RemoveAuthenticationContextsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-AuthenticationStrengthList":
                await RemoveAuthenticationStrengthsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-AdministrativeUnitList":
                await RemoveAdministrativeUnitsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-EntraGroupList":
            case "Import-AADGroupList": // legacy alias
                await RemoveGroupsAsync(files, secKeyVersion, summary, ct);
                break;
            case "Import-EntraUserList":
            case "Import-AADUserList": // legacy alias
                await RemoveUsersAsync(files, secKeyVersion, summary, ct);
                break;
            default:
                summary.Notes.Add($"Undo skipped for unsupported manifest step: {command}");
                break;
        }
    }

    private async Task LoadIdentityCatalogsAsync(string repoRoot, string secKeyVersion, CancellationToken ct)
    {
        _groupIdToDisplayName.Clear();
        _userIdToDisplayName.Clear();
        _tagIdToDisplayName.Clear();
        _namedLocationIdByDisplayName.Clear();
        _scopeTagGraphIdBySymbolicId.Clear();
        _authContextIdBySymbolicId.Clear();
        _authStrengthIdBySymbolicId.Clear();

        foreach (var groupFile in Directory.EnumerateFiles(Path.Combine(repoRoot, "JSON", "Groups"), "*.json", SearchOption.TopDirectoryOnly))
        {
            var node = await LoadJsonAsync(groupFile, secKeyVersion, ct);
            if (node is not JsonArray groups) continue;
            foreach (var group in groups.OfType<JsonObject>())
            {
                var id = group["Id"]?.GetValue<string>();
                var displayName = group["DisplayName"]?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(displayName))
                    _groupIdToDisplayName[id] = displayName;
            }
        }

        foreach (var userFile in Directory.EnumerateFiles(Path.Combine(repoRoot, "JSON", "Users"), "*.json", SearchOption.TopDirectoryOnly))
        {
            var node = await LoadJsonAsync(userFile, secKeyVersion, ct);
            if (node is not JsonArray users) continue;
            foreach (var user in users.OfType<JsonObject>())
            {
                var id = user["Id"]?.GetValue<string>();
                var displayName = user["DisplayName"]?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(displayName))
                    _userIdToDisplayName[id] = displayName;
            }
        }

        var rbacPath = Path.Combine(repoRoot, "JSON", "RBAC");
        if (!Directory.Exists(rbacPath)) return;

        foreach (var tagFile in Directory.EnumerateFiles(rbacPath, "*.json", SearchOption.TopDirectoryOnly))
        {
            var node = await LoadJsonAsync(tagFile, secKeyVersion, ct);
            if (node is not JsonObject tag) continue;
            var id = tag["Id"]?.GetValue<string>();
            var displayName = tag["displayName"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(displayName))
                _tagIdToDisplayName[id] = displayName;
        }

        var authContextPath = Path.Combine(repoRoot, "JSON", "AuthenticationContext");
        if (Directory.Exists(authContextPath))
        {
            foreach (var contextFile in Directory.EnumerateFiles(authContextPath, "*.json", SearchOption.TopDirectoryOnly))
            {
                var node = await LoadJsonAsync(contextFile, secKeyVersion, ct);
                if (node is not JsonArray contexts) continue;
                foreach (var context in contexts.OfType<JsonObject>())
                {
                    var symbolicId = context["Id"]?.GetValue<string>() ?? context["id"]?.GetValue<string>();
                    var displayName = context["DisplayName"]?.GetValue<string>() ?? context["displayName"]?.GetValue<string>();
                    if (!string.IsNullOrWhiteSpace(symbolicId) && !string.IsNullOrWhiteSpace(displayName))
                        _authContextIdBySymbolicId[symbolicId] = displayName;
                }
            }
        }

        var authStrengthPath = Path.Combine(repoRoot, "JSON", "AuthenticationStrength");
        if (Directory.Exists(authStrengthPath))
        {
            foreach (var strengthFile in Directory.EnumerateFiles(authStrengthPath, "*.json", SearchOption.TopDirectoryOnly))
            {
                var node = await LoadJsonAsync(strengthFile, secKeyVersion, ct);
                if (node is not JsonArray strengths) continue;
                foreach (var strength in strengths.OfType<JsonObject>())
                {
                    var symbolicId = strength["Id"]?.GetValue<string>() ?? strength["id"]?.GetValue<string>();
                    var displayName = strength["DisplayName"]?.GetValue<string>() ?? strength["displayName"]?.GetValue<string>();
                    if (!string.IsNullOrWhiteSpace(symbolicId) && !string.IsNullOrWhiteSpace(displayName))
                        _authStrengthIdBySymbolicId[symbolicId] = displayName;
                }
            }
        }
    }

    private async Task ImportUsersAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray users) continue;
            foreach (var user in users.OfType<JsonObject>())
            {
                var displayName = user["DisplayName"]?.GetValue<string>() ?? string.Empty;
                var mailNickname = user["MailNickname"]?.GetValue<string>() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(displayName) || string.IsNullOrWhiteSpace(mailNickname))
                    continue;

                if (await _users.GetByDisplayNameAsync(displayName, ct) is not null)
                {
                    summary.SkippedCount++;
                    continue;
                }

                await _users.CreateAsync(displayName, mailNickname, ct: ct);
                summary.CreatedCount++;
            }
        }
    }

    private async Task ImportAdministrativeUnitsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray administrativeUnits)
                continue;

            foreach (var administrativeUnit in administrativeUnits.OfType<JsonObject>())
            {
                NormalizeLegacyBranding(administrativeUnit, version);

                var displayName = administrativeUnit["displayName"]?.GetValue<string>() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(displayName))
                {
                    summary.SkippedCount++;
                    continue;
                }

                if (await _administrativeUnits.GetByDisplayNameAsync(displayName, ct) is not null)
                {
                    summary.SkippedCount++;
                    continue;
                }

                var createBody = CloneObjectWithout(administrativeUnit, "id");
                await _administrativeUnits.CreateAsync(createBody, ct);
                summary.CreatedCount++;
            }
        }
    }

    private async Task ImportGroupsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, SecKeyManifestDeploymentOptions? options, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray groups) continue;

            foreach (var group in groups.OfType<JsonObject>())
            {
                var displayName = group["DisplayName"]?.GetValue<string>() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(displayName))
                    continue;

                if (await _groups.GetByDisplayNameAsync(displayName, ct) is not null)
                {
                    summary.SkippedCount++;
                    continue;
                }

                var description = group["Description"]?.GetValue<string>();
                var membershipRule = group["Rule"]?.GetValue<string>();
                var isAssignableToRole = group["IsAssignableToRole"]?.GetValue<bool>() ?? false;
                await _groups.CreateAsync(displayName, description, membershipRule, isAssignableToRole, ct);
                summary.CreatedCount++;
            }

            foreach (var group in groups.OfType<JsonObject>())
            {
                var displayName = group["DisplayName"]?.GetValue<string>() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(displayName))
                    continue;

                var groupNode = await _groups.GetByDisplayNameAsync(displayName, ct);
                var groupId = groupNode?["id"]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(groupId))
                    continue;

                if (group["MemberRef"] is not JsonArray members) continue;

                foreach (var memberRefNode in members)
                {
                    var memberRef = memberRefNode?.GetValue<string>();
                    if (string.IsNullOrWhiteSpace(memberRef))
                        continue;

                    var member = memberRef.StartsWith("group-", StringComparison.OrdinalIgnoreCase)
                        ? await _groups.GetByDisplayNameAsync(ResolveGroupDisplayName(memberRef), ct)
                        : await _users.GetByDisplayNameAsync(ResolveUserDisplayName(memberRef), ct);
                    var memberId = member?["id"]?.GetValue<string>();
                    if (string.IsNullOrWhiteSpace(memberId))
                        continue;

                    if (await GroupHasMemberAsync(groupId, memberId, ct))
                    {
                        summary.SkippedCount++;
                        continue;
                    }

                    await _groups.AddMemberAsync(groupId, memberId, ct);
                    summary.UpdatedCount++;
                }
            }
        }

        await EnsureBreakGlassAccountsAsync(summary, options, ct);
    }

    private async Task ImportScopeTagsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var tag = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (tag is null) continue;

            var symbolicId = tag["Id"]?.GetValue<string>();
            var displayName = tag["displayName"]?.GetValue<string>() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(displayName))
                continue;

            var existing = await FindByPropertyAsync(_scopeTags, "displayName", displayName, ct);
            JsonNode? targetTag = existing;

            if (existing is null)
            {
                var createBody = CloneObjectWithout(tag, "Id", "assignments");
                targetTag = await _scopeTags.CreateAsync(createBody, ct);
                summary.CreatedCount++;
            }
            else
            {
                summary.SkippedCount++;
            }

            var targetTagId = targetTag?["id"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(symbolicId) && !string.IsNullOrWhiteSpace(targetTagId))
                _scopeTagGraphIdBySymbolicId[symbolicId!] = targetTagId!;

            if (string.IsNullOrWhiteSpace(targetTagId) || tag["assignments"] is not JsonArray assignments || assignments.Count == 0)
                continue;

            var resolvedAssignments = (JsonArray)assignments.DeepClone();
            await ResolveAssignmentsAsync(resolvedAssignments, ct);
            await _scopeTags.SetAssignmentsAsync(targetTagId, resolvedAssignments, ct);
            summary.UpdatedCount++;
        }
    }

    private async Task ImportNamedLocationsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var namedLocation = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (namedLocation is null) continue;

            var displayName = namedLocation["displayName"]?.GetValue<string>() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(displayName))
                continue;

            var existing = await _namedLocations.GetByDisplayNameAsync(displayName, ct);
            if (existing is not null)
            {
                if (existing["id"]?.GetValue<string>() is { } existingId)
                    _namedLocationIdByDisplayName[displayName] = existingId;
                summary.SkippedCount++;
                continue;
            }

            var createBody = CloneObjectWithout(namedLocation, "id", "createdDateTime", "modifiedDateTime");
            var created = await _namedLocations.CreateAsync(createBody, ct);
            if (created?["id"]?.GetValue<string>() is { } createdId)
                _namedLocationIdByDisplayName[displayName] = createdId;
            summary.CreatedCount++;
        }
    }

    private async Task ImportAuthenticationContextsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray contexts) continue;

            foreach (var context in contexts.OfType<JsonObject>())
            {
                var displayName = context["DisplayName"]?.GetValue<string>() ?? context["displayName"]?.GetValue<string>() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(displayName))
                {
                    summary.SkippedCount++;
                    continue;
                }

                var body = new JsonObject
                {
                    ["displayName"] = displayName,
                    ["description"] = context["Description"]?.GetValue<string>() ?? context["description"]?.GetValue<string>(),
                    ["isAvailable"] = context["isAvailable"]?.GetValue<bool>() ?? false
                };

                var existing = await _authContexts.GetByDisplayNameAsync(displayName, ct);
                JsonNode? target;
                if (existing is null)
                {
                    target = await _authContexts.CreateAsync(body, ct);
                    summary.CreatedCount++;
                }
                else
                {
                    target = await _authContexts.UpdateAsync(existing["id"]?.GetValue<string>() ?? string.Empty, body, ct);
                    summary.UpdatedCount++;
                }

                var symbolicId = context["Id"]?.GetValue<string>() ?? context["id"]?.GetValue<string>();
                var graphId = target?["id"]?.GetValue<string>() ?? existing?["id"]?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(symbolicId) && !string.IsNullOrWhiteSpace(graphId))
                    _authContextIdBySymbolicId[symbolicId] = graphId;
            }
        }
    }

    private async Task ImportAuthenticationStrengthsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray strengths) continue;

            foreach (var strength in strengths.OfType<JsonObject>())
            {
                var displayName = strength["DisplayName"]?.GetValue<string>() ?? strength["displayName"]?.GetValue<string>() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(displayName))
                {
                    summary.SkippedCount++;
                    continue;
                }

                var body = new JsonObject
                {
                    ["displayName"] = displayName,
                    ["description"] = strength["Description"]?.GetValue<string>() ?? strength["description"]?.GetValue<string>(),
                    ["allowedCombinations"] = (strength["allowedCombinations"] as JsonArray)?.DeepClone()
                };

                var existing = await _authStrengths.GetByDisplayNameAsync(displayName, ct);
                JsonNode? target;
                if (existing is null)
                {
                    target = await _authStrengths.CreateAsync(body, ct);
                    summary.CreatedCount++;
                }
                else
                {
                    target = await _authStrengths.UpdateAsync(existing["id"]?.GetValue<string>() ?? string.Empty, body, ct);
                    summary.UpdatedCount++;
                }

                var symbolicId = strength["Id"]?.GetValue<string>() ?? strength["id"]?.GetValue<string>();
                var graphId = target?["id"]?.GetValue<string>() ?? existing?["id"]?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(symbolicId) && !string.IsNullOrWhiteSpace(graphId))
                    _authStrengthIdBySymbolicId[symbolicId] = graphId;
            }
        }
    }

    private async Task<string?> ResolveNamedLocationIdAsync(string displayName, CancellationToken ct)
    {
        if (_namedLocationIdByDisplayName.TryGetValue(displayName, out var cached))
            return cached;

        // Fallback to Graph (handles existing locations not seen during this run).
        // Retry briefly to cover post-create eventual consistency on the namedLocations $filter index.
        for (var attempt = 0; attempt < 6; attempt++)
        {
            var node = await _namedLocations.GetByDisplayNameAsync(displayName, ct);
            if (node?["id"]?.GetValue<string>() is { } id)
            {
                _namedLocationIdByDisplayName[displayName] = id;
                return id;
            }
            await Task.Delay(TimeSpan.FromSeconds(2), ct);
        }
        return null;
    }

    private async Task ImportConditionalAccessPoliciesAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;

            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(displayName))
                continue;

            if (await _caPolicies.GetByDisplayNameAsync(displayName, ct) is not null)
            {
                summary.SkippedCount++;
                continue;
            }

            await ResolveConditionalAccessPolicyAsync(policy, ct);
            var createBody = CloneObjectWithout(policy, "id", "createdDateTime", "modifiedDateTime");
            await _caPolicies.CreateAsync(createBody, ct);
            summary.CreatedCount++;
        }
    }

    private async Task ImportEnrollmentRestrictionsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        // Microsoft.Graph no longer accepts a single-policy "deviceEnrollmentPlatformRestrictionsConfiguration"
        // POST. Each platform must be created as its own "deviceEnrollmentPlatformRestrictionConfiguration".
        // Legacy device-limit restrictions still POST as a single policy.
        // Map legacy per-platform property names to the per-platform platformType value Graph expects.
        var platformMap = new (string Property, string PlatformType, string Suffix)[]
        {
            ("iosRestriction", "ios", "iOS"),
            ("windowsRestriction", "windows", "Windows"),
            ("android", "android", "Android"),
            ("androidRestriction", "android", "Android"),
            ("androidForWorkRestriction", "androidForWork", "AndroidForWork"),
            ("macOSRestriction", "mac", "macOS"),
            ("macRestriction", "mac", "macOS"),
            // windowsMobileRestriction omitted — platform deprecated and rejected by Graph
        };

        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;

            await ResolveRoleScopeTagsAsync(policy, ct);

            var odataType = policy["@odata.type"]?.GetValue<string>() ?? string.Empty;
            var baseDisplayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            var baseDescription = policy["description"]?.GetValue<string>();
            var roleScopeTagIds = policy["roleScopeTagIds"] as JsonArray;
            var assignments = policy["assignments"] as JsonArray;

            var isPlatformRestrictions =
                odataType.IndexOf("deviceEnrollmentPlatformRestrictions", StringComparison.OrdinalIgnoreCase) >= 0;

            if (!isPlatformRestrictions)
            {
                if (await FindByDisplayNameFromListAsync(_enrollmentRestrictions, baseDisplayName, ct) is not null)
                {
                    summary.SkippedCount++;
                    continue;
                }

                var createBody = CloneObjectWithout(policy, "id", "version", "priority", "createdDateTime", "lastModifiedDateTime", "assignments", "assignments@odata.context");
                var created = await _enrollmentRestrictions.CreateAsync(createBody, ct);
                summary.CreatedCount++;

                if (assignments is not null && created?["id"]?.GetValue<string>() is { } id)
                {
                    var resolvedAssignments = (JsonArray)assignments.DeepClone();
                    await ResolveAssignmentsAsync(resolvedAssignments, ct);
                    await _enrollmentRestrictions.SetAssignmentsAsync(id, resolvedAssignments, ct);
                    summary.UpdatedCount++;
                }
                continue;
            }

            // Split into per-platform policies. Track which platform property names we've already
            // processed so legacy duplicates (mac vs macOS, android vs androidRestriction) don't
            // POST twice.
            JsonArray? sharedResolvedAssignments = null;
            if (assignments is not null)
            {
                sharedResolvedAssignments = (JsonArray)assignments.DeepClone();
                await ResolveAssignmentsAsync(sharedResolvedAssignments, ct);
            }

            var emittedPlatformTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var (property, platformType, suffix) in platformMap)
            {
                if (emittedPlatformTypes.Contains(platformType)) continue;
                if (policy[property] is not JsonObject platformBody) continue;

                var perPlatformDisplayName = $"{baseDisplayName} - {suffix}";
                if (await FindByDisplayNameFromListAsync(_enrollmentRestrictions, perPlatformDisplayName, ct) is not null)
                {
                    summary.SkippedCount++;
                    emittedPlatformTypes.Add(platformType);
                    continue;
                }

                var createBody = new JsonObject
                {
                    ["@odata.type"] = "#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration",
                    ["displayName"] = perPlatformDisplayName,
                    ["description"] = baseDescription,
                    ["platformType"] = platformType,
                    ["platformRestriction"] = (JsonObject)platformBody.DeepClone(),
                };
                if (roleScopeTagIds is not null)
                    createBody["roleScopeTagIds"] = (JsonArray)roleScopeTagIds.DeepClone();

                var created = await _enrollmentRestrictions.CreateAsync(createBody, ct);
                summary.CreatedCount++;
                emittedPlatformTypes.Add(platformType);

                if (sharedResolvedAssignments is not null && created?["id"]?.GetValue<string>() is { } id)
                {
                    var assignmentsClone = (JsonArray)sharedResolvedAssignments.DeepClone();
                    await _enrollmentRestrictions.SetAssignmentsAsync(id, assignmentsClone, ct);
                    summary.UpdatedCount++;
                }
            }
        }
    }

    private async Task ImportDeviceConfigurationsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;

            await ResolveRoleScopeTagsAsync(policy, ct);
            await ResolveDynamicCommandsAsync(policy, ct);

            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            if (await _deviceConfigurations.GetByDisplayNameAsync(displayName, ct) is not null)
            {
                summary.SkippedCount++;
                continue;
            }

            var assignments = policy["assignments"] as JsonArray;
            var createBody = CloneObjectWithout(policy, "id", "createdDateTime", "lastModifiedDateTime", "version", "supportsScopeTags", "assignments", "assignments@odata.context");
            var created = await _deviceConfigurations.CreateAsync(createBody, ct);
            summary.CreatedCount++;

            if (assignments is not null && created?["id"]?.GetValue<string>() is { } id)
            {
                var resolvedAssignments = (JsonArray)assignments.DeepClone();
                await ResolveAssignmentsAsync(resolvedAssignments, ct);
                await _deviceConfigurations.SetAssignmentsAsync(id, resolvedAssignments, ct);
                summary.UpdatedCount++;
            }
        }
    }

    private async Task ImportAdmxConfigurationsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;

            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            if (await _groupPolicyConfigurations.GetByDisplayNameAsync(displayName, ct) is not null)
            {
                summary.SkippedCount++;
                continue;
            }

            var createBody = new JsonObject
            {
                ["displayName"] = displayName,
                ["description"] = policy["description"]?.DeepClone()
            };
            await ResolveRoleScopeTagsAsync(policy, ct);
            if (policy["roleScopeTagIds"] is JsonArray roleScopeTagIds)
                createBody["roleScopeTagIds"] = roleScopeTagIds.DeepClone();

            var created = await _groupPolicyConfigurations.CreateAsync(createBody, ct);
            if (created?["id"]?.GetValue<string>() is not { } id)
            {
                summary.SkippedCount++;
                continue;
            }

            summary.CreatedCount++;

            if (policy["Definitions"] is JsonArray definitions)
            {
                foreach (var definition in definitions)
                    await _groupPolicyConfigurations.SetDefinitionValueAsync(id, definition!.DeepClone(), ct);
                summary.UpdatedCount++;
            }

            var globalDevicesId = await ResolveGroupObjectIdAsync("group-SECKEY-global-devices", ct);
            if (!string.IsNullOrWhiteSpace(globalDevicesId))
            {
                var assignments = new JsonArray
                {
                    new JsonObject
                    {
                        ["target"] = new JsonObject
                        {
                            ["@odata.type"] = "#microsoft.graph.groupAssignmentTarget",
                            ["groupId"] = globalDevicesId
                        }
                    }
                };
                await _groupPolicyConfigurations.SetAssignmentsAsync(id, assignments, ct);
                summary.UpdatedCount++;
            }
        }
    }

    private async Task ImportCompliancePoliciesAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;

            await ResolveRoleScopeTagsAsync(policy, ct);
            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            if (await _compliancePolicies.GetByDisplayNameAsync(displayName, ct) is not null)
            {
                summary.SkippedCount++;
                continue;
            }

            var assignments = policy["assignments"] as JsonArray;
            var createBody = CloneObjectWithout(policy, "id", "createdDateTime", "lastModifiedDateTime", "version", "assignments", "assignments@odata.context");
            var created = await _compliancePolicies.CreateAsync(createBody, ct);
            summary.CreatedCount++;

            if (assignments is not null && created?["id"]?.GetValue<string>() is { } id)
            {
                var resolvedAssignments = (JsonArray)assignments.DeepClone();
                await ResolveAssignmentsAsync(resolvedAssignments, ct);
                await _compliancePolicies.SetAssignmentsAsync(id, resolvedAssignments, ct);
                summary.UpdatedCount++;
            }
        }
    }

    private async Task ImportSettingsCatalogAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;

            await ResolveRoleScopeTagsAsync(policy, ct);
            var name = policy["name"]?.GetValue<string>() ?? string.Empty;
            if (await FindByPropertyAsync(_settingsCatalog, "name", name, ct) is not null)
            {
                summary.SkippedCount++;
                continue;
            }

            var assignments = policy["assignments"] as JsonArray;
            var createBody = CloneObjectWithout(policy, "id", "createdDateTime", "lastModifiedDateTime", "version", "supportsScopeTags", "assignments", "assignments@odata.context");
            var created = await _settingsCatalog.CreateAsync(createBody, ct);
            summary.CreatedCount++;

            if (assignments is not null && created?["id"]?.GetValue<string>() is { } id)
            {
                var resolvedAssignments = (JsonArray)assignments.DeepClone();
                await ResolveAssignmentsAsync(resolvedAssignments, ct);
                await _settingsCatalog.SetAssignmentsAsync(id, resolvedAssignments, ct);
                summary.UpdatedCount++;
            }
        }
    }

    private async Task ImportReusableSettingsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var reusableSetting = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (reusableSetting is null)
                continue;

            NormalizeLegacyBranding(reusableSetting, version);

            var displayName = reusableSetting["displayName"]?.GetValue<string>() ?? reusableSetting["DisplayName"]?.GetValue<string>() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(displayName))
            {
                summary.SkippedCount++;
                continue;
            }

            var existing = await _reusableSettings.GetByDisplayNameAsync(displayName, ct);
            var body = CloneObjectWithout(reusableSetting, "id", "createdDateTime", "lastModifiedDateTime", "version", "@odata.context");

            if (existing is null)
            {
                await _reusableSettings.CreateAsync(body, ct);
                summary.CreatedCount++;
            }
            else
            {
                await _reusableSettings.UpdateAsync(existing["id"]?.GetValue<string>() ?? string.Empty, body, ct);
                summary.UpdatedCount++;
            }
        }
    }

    private async Task ImportEnrollmentStatusPagesAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;

            await ResolveRoleScopeTagsAsync(policy, ct);
            await ResolveSelectedMobileAppIdsAsync(policy, ct);

            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            if (await FindByDisplayNameFromListAsync(_enrollmentStatusPages, displayName, ct) is not null)
            {
                summary.SkippedCount++;
                continue;
            }

            var assignments = policy["assignments"] as JsonArray;
            var createBody = CloneObjectWithout(policy, "id", "createdDateTime", "lastModifiedDateTime", "version", "assignments", "assignments@odata.context");
            var created = await _enrollmentStatusPages.CreateAsync(createBody, ct);
            summary.CreatedCount++;

            if (assignments is not null && created?["id"]?.GetValue<string>() is { } id)
            {
                var resolvedAssignments = (JsonArray)assignments.DeepClone();
                await ResolveAssignmentsAsync(resolvedAssignments, ct);
                await _enrollmentStatusPages.SetAssignmentsAsync(id, resolvedAssignments, ct);
                summary.UpdatedCount++;
            }
        }
    }

    private async Task ImportAutopilotProfilesAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var profile = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (profile is null) continue;

            await ResolveRoleScopeTagsAsync(profile, ct);
            var displayName = profile["displayName"]?.GetValue<string>() ?? string.Empty;
            if (await _autopilotProfiles.GetByDisplayNameAsync(displayName, ct) is not null)
            {
                summary.SkippedCount++;
                continue;
            }

            var assignments = profile["assignments"] as JsonArray;
            var createBody = CloneObjectWithout(profile, "id", "createdDateTime", "lastModifiedDateTime", "version", "assignments", "assignments@odata.context");
            var created = await _autopilotProfiles.CreateAsync(createBody, ct);
            summary.CreatedCount++;

            if (assignments is not null && created?["id"]?.GetValue<string>() is { } id)
            {
                var resolvedAssignments = (JsonArray)assignments.DeepClone();
                await ResolveAssignmentsAsync(resolvedAssignments, ct);
                await _autopilotProfiles.SetAssignmentsAsync(id, resolvedAssignments, ct);
                summary.UpdatedCount++;
            }
        }
    }

    private async Task ImportEndpointSecurityPoliciesAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "seckey-endpoint-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var rewrittenFiles = new List<string>();
            foreach (var file in files)
            {
                var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
                if (policy is null) continue;

                await ResolveRoleScopeTagsAsync(policy, ct);
                if (policy["assignments"] is JsonArray assignments)
                    await ResolveAssignmentsAsync(assignments, ct);

                var rewrittenPath = Path.Combine(tempDir, Path.GetFileName(file));
                await File.WriteAllTextAsync(rewrittenPath, policy.ToJsonString(), ct);
                rewrittenFiles.Add(rewrittenPath);
            }

            var importer = new EndpointSecurityImporter(
                _endpointSecurityPolicies,
                _groups,
                _loggerFactory.CreateLogger<EndpointSecurityImporter>());
            var created = await importer.ImportAsync(rewrittenFiles, ct);
            summary.CreatedCount += created.Count(node => node is not null);
            summary.SkippedCount += Math.Max(0, rewrittenFiles.Count - created.Count(node => node is not null));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    private async Task ImportIntuneApplicationsAsync(IEnumerable<string> configFiles, string repoRoot, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        var intuneWinAppUtilPath = ResolveIntuneWinAppUtilPath(repoRoot);
        if (string.IsNullOrWhiteSpace(intuneWinAppUtilPath) || !File.Exists(intuneWinAppUtilPath))
        {
            summary.Notes.Add("Skipped Import-IntuneApplicationList: IntuneWinAppUtil.exe not found.");
            return;
        }

        var packager = new IntuneWinAppUtilRunner(intuneWinAppUtilPath, _loggerFactory.CreateLogger<IntuneWinAppUtilRunner>());
        var uploader = new Win32LobUploader(_client, new HttpClient(), _loggerFactory.CreateLogger<Win32LobUploader>());
        var apps = new IntuneApplicationService(_client);
        var orchestrator = new IntuneAppOrchestrator(
            packager,
            uploader,
            apps,
            _groups,
            _loggerFactory.CreateLogger<IntuneAppOrchestrator>());

        foreach (var configFile in configFiles)
        {
            var appFolder = Path.GetDirectoryName(configFile);
            if (string.IsNullOrWhiteSpace(appFolder) || !Directory.Exists(appFolder))
            {
                summary.SkippedCount++;
                continue;
            }

            JsonObject? appConfig = null;
            var appDisplayName = string.Empty;
            try
            {
                appConfig = (await LoadJsonAsync(configFile, string.Empty, ct)) as JsonObject;
                appDisplayName = appConfig?["displayName"]?.GetValue<string>() ?? string.Empty;
            }
            catch
            {
                // ignore; normal import path will surface parsing issues
            }

            var completed = false;
            for (var attempt = 1; attempt <= 3 && !completed; attempt++)
            {
                if (!string.IsNullOrWhiteSpace(appDisplayName) && await apps.GetByDisplayNameAsync(appDisplayName, ct) is not null)
                {
                    summary.SkippedCount++;
                    completed = true;
                    break;
                }

                try
                {
                    var result = await orchestrator.ImportAsync(appFolder, progress: null, ct);
                    if (result is null)
                        summary.SkippedCount++;
                    else
                        summary.CreatedCount++;
                    completed = true;
                }
                catch (Exception ex) when (
                    attempt < 3 &&
                    ex.Message.Contains("azureStorageUriRequestPending", StringComparison.OrdinalIgnoreCase))
                {
                    await Task.Delay(TimeSpan.FromSeconds(20), ct);
                }
            }

            if (!completed)
                throw new InvalidOperationException($"Failed to import app from {configFile} after retries.");
        }
    }

    private async Task ImportStoreAppAssignmentsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        var apps = new IntuneApplicationService(_client);

        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray appAssignments)
                continue;

            foreach (var assignment in appAssignments.OfType<JsonObject>())
            {
                var packageName = assignment["packageName"]?.GetValue<string>();
                var symbolicGroupId = assignment["groupIdToAdd"]?.GetValue<string>();
                var intent = assignment["assignmentType"]?.GetValue<string>()?.ToLowerInvariant();
                var appType = assignment["appType"]?.GetValue<string>() ?? "Store";
                var licenseType = assignment["licenseType"]?.GetValue<string>() ?? "User";

                if (string.IsNullOrWhiteSpace(packageName) || string.IsNullOrWhiteSpace(symbolicGroupId) || string.IsNullOrWhiteSpace(intent))
                {
                    summary.SkippedCount++;
                    continue;
                }

                var groupId = await ResolveGroupObjectIdAsync(symbolicGroupId, ct);
                if (string.IsNullOrWhiteSpace(groupId))
                {
                    summary.SkippedCount++;
                    continue;
                }

                var app = await apps.GetByDisplayNameAsync(packageName, ct) ??
                          await apps.GetByDisplayNameAsync(Uri.UnescapeDataString(packageName), ct);
                var appId = app?["id"]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(appId))
                {
                    summary.SkippedCount++;
                    continue;
                }

                if (await HasAppAssignmentAsync(appId, groupId, intent, ct))
                {
                    summary.SkippedCount++;
                    continue;
                }

                var resolvedAppType = ResolveStoreAssignmentAppType(app, appType);

                var payload = new JsonObject
                {
                    ["@odata.type"] = "#microsoft.graph.mobileAppAssignment",
                    ["intent"] = intent,
                    ["source"] = "direct",
                    ["target"] = new JsonObject
                    {
                        ["@odata.type"] = "#microsoft.graph.groupAssignmentTarget",
                        ["groupId"] = groupId
                    }
                };

                var settings = BuildMobileAppAssignmentSettings(resolvedAppType, licenseType);
                if (settings is not null)
                    payload["settings"] = settings;

                await _client.PostAsync($"deviceAppManagement/mobileApps/{appId}/assignments", payload, true, ct);
                summary.UpdatedCount++;
            }
        }
    }

    private static string ResolveStoreAssignmentAppType(JsonNode? app, string fallbackAppType)
    {
        var odataType = app?["@odata.type"]?.GetValue<string>() ?? string.Empty;
        if (odataType.Contains("winGetApp", StringComparison.OrdinalIgnoreCase))
            return "WinGet";
        if (odataType.Contains("win32LobApp", StringComparison.OrdinalIgnoreCase))
            return "Win32";
        if (odataType.Contains("windowsMicrosoftEdgeApp", StringComparison.OrdinalIgnoreCase))
            return "Edge";
        if (odataType.Contains("microsoftStoreForBusinessApp", StringComparison.OrdinalIgnoreCase))
            return "Store";
        if (odataType.Contains("androidForWork", StringComparison.OrdinalIgnoreCase))
            return "AndroidForWork";
        if (odataType.Contains("androidManagedStoreApp", StringComparison.OrdinalIgnoreCase))
            return "AndroidManaged";

        return fallbackAppType;
    }

    private static JsonObject? BuildMobileAppAssignmentSettings(string appType, string licenseType)
    {
        // AndroidForWork and managed Android Enterprise apps do not accept custom assignment settings.
        if (appType.Equals("AndroidForWork", StringComparison.OrdinalIgnoreCase) ||
            appType.Equals("AndroidManaged", StringComparison.OrdinalIgnoreCase))
            return null;

        if (appType.Equals("Store", StringComparison.OrdinalIgnoreCase))
        {
            return new JsonObject
            {
                ["@odata.type"] = "#microsoft.graph.microsoftStoreForBusinessAppAssignmentSettings",
                ["useDeviceContext"] = string.Equals(licenseType, "Device", StringComparison.OrdinalIgnoreCase)
            };
        }

        if (appType.Equals("WinGet", StringComparison.OrdinalIgnoreCase))
        {
            return new JsonObject
            {
                ["@odata.type"] = "#microsoft.graph.winGetAppAssignmentSettings",
                ["notifications"] = "showAll",
                ["restartSettings"] = null,
                ["installTimeSettings"] = null
            };
        }

        if (appType.Equals("Win32", StringComparison.OrdinalIgnoreCase))
        {
            return new JsonObject
            {
                ["@odata.type"] = "#microsoft.graph.win32LobAppAssignmentSettings",
                ["notifications"] = "showAll",
                ["restartSettings"] = null,
                ["deliveryOptimizationPriority"] = "notConfigured",
                ["installTimeSettings"] = null
            };
        }

        return null;
    }

    private async Task ImportProactiveRemediationScriptsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var configFile in files)
        {
            var config = (await LoadJsonAsync(configFile, version, ct)) as JsonObject;
            if (config is null)
                continue;

            var displayName = config["displayName"]?.GetValue<string>() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(displayName))
            {
                summary.SkippedCount++;
                continue;
            }

            if (await _proactiveRemediation.GetByDisplayNameAsync(displayName, ct) is not null)
            {
                summary.SkippedCount++;
                continue;
            }

            var folder = Path.GetDirectoryName(configFile) ?? string.Empty;
            var detectionPath = Path.Combine(folder, "detection.ps1");
            var remediationPath = Path.Combine(folder, "remediation.ps1");
            if (!File.Exists(detectionPath) || !File.Exists(remediationPath))
            {
                summary.Notes.Add($"Skipped proactive remediation '{displayName}' because detection/remediation script files are missing.");
                summary.SkippedCount++;
                continue;
            }

            var body = new JsonObject
            {
                ["@odata.type"] = "#microsoft.graph.deviceHealthScript",
                ["publisher"] = config["publisher"]?.GetValue<string>(),
                ["version"] = config["version"]?.GetValue<string>(),
                ["displayName"] = displayName,
                ["description"] = config["description"]?.GetValue<string>(),
                ["detectionScriptContent"] = Convert.ToBase64String(await File.ReadAllBytesAsync(detectionPath, ct)),
                ["remediationScriptContent"] = Convert.ToBase64String(await File.ReadAllBytesAsync(remediationPath, ct)),
                ["runAsAccount"] = config["runAsAccount"]?.GetValue<string>(),
                ["enforceSignatureCheck"] = ParseBooleanNode(config["enforceSignatureCheck"]),
                ["runAs32Bit"] = ParseBooleanNode(config["runAs32Bit"])
            };

            await _proactiveRemediation.CreateAsync(body, ct);
            summary.CreatedCount++;
        }
    }

    private async Task ImportPlatformScriptsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var configFile in files)
        {
            var config = (await LoadJsonAsync(configFile, version, ct)) as JsonObject;
            if (config is null)
                continue;

            NormalizeLegacyBranding(config, version);

            var displayName = config["displayName"]?.GetValue<string>() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(displayName))
            {
                summary.SkippedCount++;
                continue;
            }

            var roleScopeTagIds = NormalizeRoleScopeTagIds(config["roleScopeTagIds"]);
            var assignments = NormalizePlatformScriptAssignments(config["assignments"] ?? config["Assignments"]);
            if (assignments is not null)
                await ResolveAssignmentsAsync(assignments, ct);

            var scriptPath = Path.Combine(Path.GetDirectoryName(configFile) ?? string.Empty, "script.ps1");
            if (!File.Exists(scriptPath))
            {
                summary.Notes.Add($"Skipped platform script '{displayName}' because script.ps1 was not found.");
                summary.SkippedCount++;
                continue;
            }

            var body = new JsonObject
            {
                ["@odata.type"] = "#microsoft.graph.deviceManagementScript",
                ["displayName"] = displayName,
                ["description"] = config["description"]?.GetValue<string>(),
                ["scriptContent"] = Convert.ToBase64String(await File.ReadAllBytesAsync(scriptPath, ct)),
                ["runAsAccount"] = config["runAsAccount"]?.GetValue<string>(),
                ["enforceSignatureCheck"] = ParseBooleanNode(config["enforceSignatureCheck"]),
                ["runAs32Bit"] = ParseBooleanNode(config["runAs32Bit"]),
                ["roleScopeTagIds"] = roleScopeTagIds,
                ["fileName"] = "script.ps1"
            };

            var existing = await _platformScripts.GetByDisplayNameAsync(displayName, ct);
            var scriptId = existing?["id"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(scriptId))
            {
                var created = await _platformScripts.CreateAsync(body, ct);
                scriptId = created?["id"]?.GetValue<string>();
                summary.CreatedCount++;
            }
            else
            {
                await _platformScripts.UpdateAsync(scriptId, body, ct);
                summary.UpdatedCount++;
            }

            if (!string.IsNullOrWhiteSpace(scriptId) && assignments is not null)
            {
                await _platformScripts.SetAssignmentsAsync(scriptId, assignments, ct);
                summary.UpdatedCount++;
            }
        }
    }

    private async Task<bool> HasAppAssignmentAsync(string appId, string groupId, string intent, CancellationToken ct)
    {
        var node = await _client.GetAsync($"deviceAppManagement/mobileApps/{appId}?$expand=assignments", true, ct);
        var assignments = node?["assignments"] as JsonArray;
        if (assignments is null) return false;
        return assignments.Any(a =>
            string.Equals(a?["target"]?["groupId"]?.GetValue<string>(), groupId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(a?["intent"]?.GetValue<string>(), intent, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ParseBooleanNode(JsonNode? node)
    {
        if (node is null) return false;
        if (node is JsonValue jv)
        {
            if (jv.TryGetValue<bool>(out var b)) return b;
            if (jv.TryGetValue<string>(out var s) && bool.TryParse(s, out var fromString)) return fromString;
        }
        return false;
    }

    private static JsonArray NormalizeRoleScopeTagIds(JsonNode? node)
    {
        if (node is JsonArray array)
            return (JsonArray)array.DeepClone();
        if (node is JsonValue value && value.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text))
            return new JsonArray(text);

        return new JsonArray();
    }

    private static JsonArray? NormalizePlatformScriptAssignments(JsonNode? node)
    {
        if (node is JsonArray assignments)
            return (JsonArray)assignments.DeepClone();
        return null;
    }

    private static string? ResolveIntuneWinAppUtilPath(string repoRoot)
    {
        var primary = Path.Combine(repoRoot, "IntuneApps", "Install-SecKeyModule", "Source", "private", "utilities", "IntuneWinAppUtil.exe");
        if (File.Exists(primary)) return primary;

        var archive = Path.Combine(repoRoot, "archive", "SecKey-PowerShell", "private", "utilities", "IntuneWinAppUtil.exe");
        return File.Exists(archive) ? archive : null;
    }

    private async Task EnsureBreakGlassAccountsAsync(SecKeyManifestDeploymentSummary summary, SecKeyManifestDeploymentOptions? options, CancellationToken ct)
    {
        var breakGlassGroupId = await ResolveGroupObjectIdAsync("group-SECKEY-global-breakglass-accounts", ct);
        if (string.IsNullOrWhiteSpace(breakGlassGroupId))
            return;

        var wantedAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "user-azure-break-glass-1",
            "user-azure-break-glass-2"
        };

        foreach (var account in options?.AdditionalBreakGlassAccounts ?? Array.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(account))
                wantedAccounts.Add(account.Trim());
        }

        foreach (var account in wantedAccounts)
        {
            var user = await ResolveUserForBreakGlassAsync(account, ct);
            var userId = user?["id"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(userId))
            {
                summary.Notes.Add($"Break-glass account not found: {account}");
                continue;
            }

            if (!await GroupHasMemberAsync(breakGlassGroupId, userId, ct))
            {
                await _groups.AddMemberAsync(breakGlassGroupId, userId, ct);
                summary.UpdatedCount++;
            }

            await RemoveUserFromGroupIfPresentAsync("group-SECKEY-global-users", userId, summary, ct);
            await RemoveUserFromGroupIfPresentAsync("group-SECKEY-global-users", userId, summary, ct);
        }
    }

    private async Task<JsonNode?> ResolveUserForBreakGlassAsync(string identifier, CancellationToken ct)
    {
        if (identifier.StartsWith("user-", StringComparison.OrdinalIgnoreCase) &&
            _userIdToDisplayName.TryGetValue(identifier, out var symbolicDisplayName))
        {
            return await _users.GetByDisplayNameAsync(symbolicDisplayName, ct);
        }

        var escaped = identifier.Replace("'", "''");

        var byUpn = await _client.GetAsync($"users?$filter=userPrincipalName eq '{escaped}'&$select=id,displayName,userPrincipalName", false, ct);
        var upnUser = (byUpn?["value"] as JsonArray)?.FirstOrDefault();
        if (upnUser is not null) return upnUser;

        var byMail = await _client.GetAsync($"users?$filter=mail eq '{escaped}'&$select=id,displayName,mail", false, ct);
        var mailUser = (byMail?["value"] as JsonArray)?.FirstOrDefault();
        if (mailUser is not null) return mailUser;

        return await _users.GetByDisplayNameAsync(identifier, ct);
    }

    private async Task RemoveUserFromGroupIfPresentAsync(string symbolicGroupId, string userId, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        var groupId = await ResolveGroupObjectIdAsync(symbolicGroupId, ct);
        if (string.IsNullOrWhiteSpace(groupId))
            return;

        if (!await GroupHasMemberAsync(groupId, userId, ct))
            return;

        await _groups.RemoveMemberAsync(groupId, userId, ct);
        summary.UpdatedCount++;
    }

    private async Task ResolveConditionalAccessPolicyAsync(JsonObject policy, CancellationToken ct)
    {
        if (policy["grantControls"] is JsonObject grantControls)
            grantControls.Remove("authenticationStrength@odata.context");

        var includeGroups = policy["conditions"]?["users"]?["includeGroups"] as JsonArray;
        if (includeGroups is not null)
        {
            for (var i = 0; i < includeGroups.Count; i++)
            {
                var placeholder = includeGroups[i]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(placeholder)) continue;
                includeGroups[i] = await ResolveGroupObjectIdAsync(placeholder, ct);
            }
        }

        var usersNode = policy["conditions"]?["users"] as JsonObject;
        var excludeGroups = usersNode?["excludeGroups"] as JsonArray;
        excludeGroups ??= new JsonArray();
        if (usersNode is not null)
            usersNode["excludeGroups"] = excludeGroups;

        var hasBreakGlassExclude = excludeGroups.Any(n =>
            string.Equals(n?.GetValue<string>(), "group-SECKEY-global-breakglass-accounts", StringComparison.OrdinalIgnoreCase));
        if (!hasBreakGlassExclude)
            excludeGroups.Add("group-SECKEY-global-breakglass-accounts");

        if (excludeGroups is not null)
        {
            for (var i = 0; i < excludeGroups.Count; i++)
            {
                var placeholder = excludeGroups[i]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(placeholder)) continue;
                excludeGroups[i] = await ResolveGroupObjectIdAsync(placeholder, ct);
            }
        }

        var includeLocations = policy["conditions"]?["locations"]?["includeLocations"] as JsonArray;
        if (includeLocations is not null)
        {
            for (var i = 0; i < includeLocations.Count; i++)
            {
                var displayName = includeLocations[i]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(displayName) ||
                    string.Equals(displayName, "All", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(displayName, "AllTrusted", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (await ResolveNamedLocationIdAsync(displayName, ct) is { } id)
                    includeLocations[i] = id;
            }
        }

        var excludeLocations = policy["conditions"]?["locations"]?["excludeLocations"] as JsonArray;
        if (excludeLocations is not null)
        {
            for (var i = 0; i < excludeLocations.Count; i++)
            {
                var displayName = excludeLocations[i]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(displayName) ||
                    string.Equals(displayName, "All", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(displayName, "AllTrusted", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (await ResolveNamedLocationIdAsync(displayName, ct) is { } id)
                    excludeLocations[i] = id;
            }
        }

        var includeAuthContexts = policy["conditions"]?["applications"]?["includeAuthenticationContextClassReferences"] as JsonArray;
        if (includeAuthContexts is not null)
        {
            for (var i = 0; i < includeAuthContexts.Count; i++)
            {
                var symbolicId = includeAuthContexts[i]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(symbolicId))
                    continue;

                if (await ResolveAuthenticationContextIdAsync(symbolicId, ct) is { } contextId)
                    includeAuthContexts[i] = contextId;
            }
        }

        if (policy["grantControls"]?["authenticationStrength"] is JsonObject authenticationStrength)
        {
            var symbolicId = authenticationStrength["id"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(symbolicId) && await ResolveAuthenticationStrengthIdAsync(symbolicId, ct) is { } strengthId)
                authenticationStrength["id"] = strengthId;
        }
    }

    private async Task<string?> ResolveAuthenticationContextIdAsync(string symbolicId, CancellationToken ct)
    {
        if (_authContextIdBySymbolicId.TryGetValue(symbolicId, out var cachedId) && Guid.TryParse(cachedId, out _))
            return cachedId;

        var displayName = _authContextIdBySymbolicId.TryGetValue(symbolicId, out var mappedDisplayName)
            ? mappedDisplayName
            : symbolicId;

        var existing = await _authContexts.GetByDisplayNameAsync(displayName, ct);
        var id = existing?["id"]?.GetValue<string>();
        if (!string.IsNullOrWhiteSpace(id))
            _authContextIdBySymbolicId[symbolicId] = id;
        return id;
    }

    private async Task<string?> ResolveAuthenticationStrengthIdAsync(string symbolicId, CancellationToken ct)
    {
        if (_authStrengthIdBySymbolicId.TryGetValue(symbolicId, out var cachedId) && Guid.TryParse(cachedId, out _))
            return cachedId;

        var displayName = _authStrengthIdBySymbolicId.TryGetValue(symbolicId, out var mappedDisplayName)
            ? mappedDisplayName
            : symbolicId;

        var existing = await _authStrengths.GetByDisplayNameAsync(displayName, ct);
        var id = existing?["id"]?.GetValue<string>();
        if (!string.IsNullOrWhiteSpace(id))
            _authStrengthIdBySymbolicId[symbolicId] = id;
        return id;
    }

    private async Task ResolveRoleScopeTagsAsync(JsonObject policy, CancellationToken ct)
    {
        if (policy["roleScopeTagIds"] is not JsonArray roleScopeTagIds) return;

        var resolved = new JsonArray();
        for (var i = 0; i < roleScopeTagIds.Count; i++)
        {
            var node = roleScopeTagIds[i];
            if (node is null) continue;

            // JSON numbers (e.g. 0) are real Graph scope tag ids — convert to string and pass through.
            string token;
            if (node is JsonValue jv)
            {
                if (jv.TryGetValue<string>(out var sv))
                    token = sv;
                else if (jv.TryGetValue<long>(out var lv))
                { resolved.Add(lv.ToString()); continue; }
                else if (jv.TryGetValue<int>(out var iv))
                { resolved.Add(iv.ToString()); continue; }
                else
                    continue; // unknown value type, skip
            }
            else continue;
            if (string.IsNullOrWhiteSpace(token)) continue;

            // Numeric string ids (e.g. "0", "5") are real Graph ids — pass through unchanged.
            if (int.TryParse(token, out _))
            {
                resolved.Add(token);
                continue;
            }

            // Allow either bare symbolic id ("tag-SECKEY") or {placeholder} form.
            var lookupKey = token;
            if (lookupKey.StartsWith("{") && lookupKey.EndsWith("}"))
                lookupKey = lookupKey.Substring(1, lookupKey.Length - 2);

            // Prefer the cache populated when scope tags were created (Import-IntuneRoleScopeTagList).
            if (_scopeTagGraphIdBySymbolicId.TryGetValue(lookupKey, out var cachedId))
            {
                resolved.Add(cachedId);
                continue;
            }

            // Fall back: look up via local catalog displayName -> Graph id.
            if (_tagIdToDisplayName.TryGetValue(lookupKey, out var displayName))
            {
                var scopeTag = await FindByPropertyAsync(_scopeTags, "displayName", displayName, ct);
                if (scopeTag?["id"]?.GetValue<string>() is { } id)
                {
                    _scopeTagGraphIdBySymbolicId[lookupKey] = id;
                    resolved.Add(id);
                    continue;
                }
            }

            // Unknown token — preserve original behaviour and pass through.
            resolved.Add(token);
        }

        policy["roleScopeTagIds"] = resolved;
    }

    private async Task ResolveAssignmentsAsync(JsonArray assignments, CancellationToken ct)
    {
        foreach (var assignment in assignments.OfType<JsonObject>())
        {
            var target = assignment["target"] as JsonObject;
            if (target is null) continue;

            var groupToken = target["groupId"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(groupToken))
            {
                if (target["@odata.type"] is null)
                    target["@odata.type"] = "#microsoft.graph.groupAssignmentTarget";

                var resolvedId = await ResolveGroupObjectIdAsync(groupToken, ct);
                if (!string.IsNullOrWhiteSpace(resolvedId))
                    target["groupId"] = resolvedId;
            }
            else if (target["@odata.type"] is null)
            {
                // Default to all-devices target when no group is specified.
                target["@odata.type"] = "#microsoft.graph.allDevicesAssignmentTarget";
            }
        }
    }

    private static void NormalizeLegacyBranding(JsonNode? node, string secKeyVersion)
    {
        _ = NormalizeLegacyBrandingNode(node, secKeyVersion);
    }

    private static JsonNode? NormalizeLegacyBrandingNode(JsonNode? node, string secKeyVersion)
    {
        switch (node)
        {
            case JsonObject jsonObject:
                foreach (var key in jsonObject.Select(pair => pair.Key).ToList())
                    jsonObject[key] = NormalizeLegacyBrandingNode(jsonObject[key], secKeyVersion);
                return jsonObject;
            case JsonArray jsonArray:
                for (var i = 0; i < jsonArray.Count; i++)
                    jsonArray[i] = NormalizeLegacyBrandingNode(jsonArray[i], secKeyVersion);
                return jsonArray;
            case JsonValue jsonValue when jsonValue.TryGetValue<string>(out var text):
                return JsonValue.Create(NormalizeLegacyBranding(text, secKeyVersion));
            default:
                return node;
        }
    }

    private static string NormalizeLegacyBranding(string text, string secKeyVersion)
    {
        if (string.IsNullOrWhiteSpace(text))
            return text;

        return text
            .Replace("{PAWCSMVersion}", secKeyVersion, StringComparison.OrdinalIgnoreCase)
            .Replace("{PAWVersion}", secKeyVersion, StringComparison.OrdinalIgnoreCase)
            .Replace("tag-paw-csm", "tag-SECKEY", StringComparison.OrdinalIgnoreCase)
            .Replace("group-paw-global-devices", "group-SECKEY-global-devices", StringComparison.OrdinalIgnoreCase)
            .Replace("group-paw-global-users", "group-SECKEY-global-users", StringComparison.OrdinalIgnoreCase)
            .Replace("group-paw-global-breakglass-accounts", "group-SECKEY-global-breakglass-accounts", StringComparison.OrdinalIgnoreCase)
            .Replace("[OrderID]:PAW", "[OrderID]:SECKEY", StringComparison.OrdinalIgnoreCase)
            .Replace("extensionAttribute1 -eq \"PAW\"", "extensionAttribute1 -eq \"SECKEY\"", StringComparison.OrdinalIgnoreCase)
            .Replace("PAW-CSM", "SECKEY", StringComparison.OrdinalIgnoreCase)
            .Replace("PAW CSM", "SECKEY", StringComparison.OrdinalIgnoreCase)
            .Replace("PAW", "SECKEY", StringComparison.OrdinalIgnoreCase);
    }

    private async Task ResolveSelectedMobileAppIdsAsync(JsonObject policy, CancellationToken ct)
    {
        if (policy["selectedMobileAppIds"] is not JsonArray selectedApps) return;

        var apps = new IntuneApplicationService(_client);
        for (var i = 0; i < selectedApps.Count; i++)
        {
            if (selectedApps[i] is not JsonValue appNode || !appNode.TryGetValue<string>(out var displayName))
                continue;
            if (string.IsNullOrWhiteSpace(displayName)) continue;
            var app = await apps.GetByDisplayNameAsync(displayName, ct);
            if (app?["id"]?.GetValue<string>() is { } id)
                selectedApps[i] = id;
        }
    }

    private async Task ResolveDynamicCommandsAsync(JsonObject policy, CancellationToken ct)
    {
        if (policy["omaSettings"] is not JsonArray omaSettings) return;

        foreach (var setting in omaSettings.OfType<JsonObject>())
        {
            // value may be any JSON type (string, int, bool) — only process string values
            if (setting["value"] is not JsonValue valueNode || !valueNode.TryGetValue<string>(out var value))
                continue;
            if (string.IsNullOrWhiteSpace(value)) continue;

            const string pattern = "{command:(Get-LogonRestrictionsXMLString";
            if (!value.StartsWith(pattern, StringComparison.Ordinal))
                continue;

            var adminSid = await ResolveGroupSidAsync("group-SECKEY-admin", ct);
            var allowSid = await ResolveGroupSidAsync("group-SECKEY-global-users", ct);
            setting["value"] = BuildLogonRestrictionsXml(adminSid, allowSid, null);
        }
    }

    private async Task<string?> ResolveGroupSidAsync(string symbolicGroupId, CancellationToken ct)
    {
        var displayName = ResolveGroupDisplayName(symbolicGroupId);
        var query = $"groups?$filter=displayName eq '{Uri.EscapeDataString(displayName)}'&$select=id,displayName,securityIdentifier";
        var node = await _client.GetAsync(query, false, ct);
        return (node?["value"] as JsonArray)?.FirstOrDefault()?["securityIdentifier"]?.GetValue<string>();
    }

    private async Task<string?> ResolveGroupObjectIdAsync(string symbolicGroupId, CancellationToken ct)
    {
        var displayName = ResolveGroupDisplayName(symbolicGroupId);
        var group = await _groups.GetByDisplayNameAsync(displayName, ct);
        return group?["id"]?.GetValue<string>();
    }

    private async Task RemoveUsersAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray users) continue;
            foreach (var user in users.OfType<JsonObject>())
            {
                var displayName = user["DisplayName"]?.GetValue<string>() ?? string.Empty;
                await TryDeleteByDisplayNameAsync(_users, displayName, summary, ct);
            }
        }
    }

    private async Task RemoveGroupsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray groups) continue;
            foreach (var group in groups.OfType<JsonObject>())
            {
                var displayName = group["DisplayName"]?.GetValue<string>() ?? string.Empty;
                await TryDeleteByDisplayNameAsync(_groups, displayName, summary, ct);
            }
        }
    }

    private async Task RemoveAdministrativeUnitsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray administrativeUnits) continue;
            foreach (var administrativeUnit in administrativeUnits.OfType<JsonObject>())
            {
                NormalizeLegacyBranding(administrativeUnit, version);
                var displayName = administrativeUnit["displayName"]?.GetValue<string>() ?? string.Empty;
                await TryDeleteByDisplayNameAsync(_administrativeUnits, displayName, summary, ct);
            }
        }
    }

    private async Task RemoveScopeTagsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var tag = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (tag is null) continue;
            var displayName = tag["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByDisplayNameAsync(_scopeTags, displayName, summary, ct);
        }
    }

    private async Task RemoveAuthenticationContextsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray contexts) continue;
            foreach (var context in contexts.OfType<JsonObject>())
            {
                var displayName = context["DisplayName"]?.GetValue<string>() ?? context["displayName"]?.GetValue<string>() ?? string.Empty;
                await TryDeleteByDisplayNameAsync(_authContexts, displayName, summary, ct);
            }
        }
    }

    private async Task RemoveAuthenticationStrengthsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var node = await LoadJsonAsync(file, version, ct);
            if (node is not JsonArray strengths) continue;
            foreach (var strength in strengths.OfType<JsonObject>())
            {
                var displayName = strength["DisplayName"]?.GetValue<string>() ?? strength["displayName"]?.GetValue<string>() ?? string.Empty;
                await TryDeleteByDisplayNameAsync(_authStrengths, displayName, summary, ct);
            }
        }
    }

    private async Task RemoveNamedLocationsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var location = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (location is null) continue;
            var displayName = location["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteNamedLocationByDisplayNameAsync(displayName, summary, ct);
        }
    }

    private async Task TryDeleteNamedLocationByDisplayNameAsync(string displayName, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(displayName))
        {
            summary.SkippedCount++;
            return;
        }

        var existing = await FindByDisplayNameFromListAsync(_namedLocations, displayName, ct);
        var id = existing?["id"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(id))
        {
            summary.SkippedCount++;
            return;
        }

        for (var attempt = 1; attempt <= 6; attempt++)
        {
            try
            {
                await _namedLocations.DeleteAsync(id, ct);
                summary.DeletedCount++;
                return;
            }
            catch (SecKey.Core.SecKeyException ex) when (ex.StatusCode == 404)
            {
                summary.SkippedCount++;
                return;
            }
            catch (SecKey.Core.SecKeyException ex) when (ex.StatusCode == 400 &&
                ex.Message.IndexOf("cannot be deleted because it is referenced", StringComparison.OrdinalIgnoreCase) >= 0 &&
                attempt < 6)
            {
                await Task.Delay(TimeSpan.FromSeconds(10), ct);
            }
        }

        await _namedLocations.DeleteAsync(id, ct);
        summary.DeletedCount++;
    }

    private async Task RemoveConditionalAccessPoliciesAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;
            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByDisplayNameAsync(_caPolicies, displayName, summary, ct);
        }
    }

    private async Task RemoveEnrollmentRestrictionsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;

            var baseDisplayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            var odataType = policy["@odata.type"]?.GetValue<string>() ?? string.Empty;
            var isPlatformRestrictions = odataType.IndexOf("deviceEnrollmentPlatformRestrictions", StringComparison.OrdinalIgnoreCase) >= 0;

            if (!isPlatformRestrictions)
            {
                await TryDeleteByDisplayNameAsync(_enrollmentRestrictions, baseDisplayName, summary, ct);
                continue;
            }

            foreach (var suffix in new[] { "iOS", "Windows", "WindowsMobile", "Android", "AndroidForWork", "macOS" })
                await TryDeleteByDisplayNameAsync(_enrollmentRestrictions, $"{baseDisplayName} - {suffix}", summary, ct);

            await TryDeleteByDisplayNameAsync(_enrollmentRestrictions, baseDisplayName, summary, ct);
        }
    }

    private async Task RemoveDeviceConfigurationsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;
            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByDisplayNameAsync(_deviceConfigurations, displayName, summary, ct);
        }
    }

    private async Task RemoveAdmxConfigurationsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;
            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByDisplayNameAsync(_groupPolicyConfigurations, displayName, summary, ct);
        }
    }

    private async Task RemoveCompliancePoliciesAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;
            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByDisplayNameAsync(_compliancePolicies, displayName, summary, ct);
        }
    }

    private async Task RemoveSettingsCatalogAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;
            var name = policy["name"]?.GetValue<string>() ?? policy["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByPropertyAsync(_settingsCatalog, "name", name, summary, ct);
        }
    }

    private async Task RemoveEnrollmentStatusPagesAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;
            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByDisplayNameAsync(_enrollmentStatusPages, displayName, summary, ct);
        }
    }

    private async Task RemoveAutopilotProfilesAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var profile = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (profile is null) continue;
            var displayName = profile["displayName"]?.GetValue<string>() ?? string.Empty;
            var existing = await _autopilotProfiles.GetByDisplayNameAsync(displayName, ct);
            var id = existing?["id"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(id))
            {
                summary.SkippedCount++;
                continue;
            }

            await _autopilotProfiles.ClearAssignmentsAsync(id, ct);

            for (var attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), ct);
                    await _autopilotProfiles.DeleteAsync(id, ct);
                    summary.DeletedCount++;
                    break;
                }
                catch (SecKey.Core.SecKeyException ex) when (ex.StatusCode == 404)
                {
                    summary.SkippedCount++;
                    break;
                }
                catch (SecKey.Core.SecKeyException) when (attempt < 3)
                {
                    // Allow Graph assignment changes to settle before retrying delete.
                }
            }
        }
    }

    private async Task RemoveEndpointSecurityPoliciesAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var policy = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (policy is null) continue;
            var displayName = policy["displayName"]?.GetValue<string>() ?? string.Empty;
            var existing = await _endpointSecurityPolicies.FindByDisplayNameAsync(displayName, ct);
            var id = existing?["id"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(id))
            {
                summary.SkippedCount++;
                continue;
            }
            await _endpointSecurityPolicies.DeleteAsync(id, ct);
            summary.DeletedCount++;
        }
    }

    private async Task RemoveIntuneApplicationsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var config = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (config is null) continue;
            var displayName = config["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByDisplayNameAsync(new IntuneApplicationService(_client), displayName, summary, ct);
        }
    }

    private async Task RemoveProactiveRemediationScriptsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var config = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (config is null) continue;
            var displayName = config["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByDisplayNameAsync(_proactiveRemediation, displayName, summary, ct);
        }
    }

    private async Task RemoveReusableSettingsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var reusableSetting = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (reusableSetting is null) continue;
            NormalizeLegacyBranding(reusableSetting, version);
            var displayName = reusableSetting["displayName"]?.GetValue<string>() ?? reusableSetting["DisplayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByDisplayNameAsync(_reusableSettings, displayName, summary, ct);
        }
    }

    private async Task RemovePlatformScriptsAsync(IEnumerable<string> files, string version, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        foreach (var file in files)
        {
            var config = (await LoadJsonAsync(file, version, ct)) as JsonObject;
            if (config is null) continue;
            NormalizeLegacyBranding(config, version);
            var displayName = config["displayName"]?.GetValue<string>() ?? string.Empty;
            await TryDeleteByDisplayNameAsync(_platformScripts, displayName, summary, ct);
        }
    }

    private static async Task TryDeleteByDisplayNameAsync(GraphServiceBase service, string displayName, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(displayName))
        {
            summary.SkippedCount++;
            return;
        }

        var existing = await FindByDisplayNameFromListAsync(service, displayName, ct);
        await TryDeleteNodeAsync(service, existing, summary, ct);
    }

    private static async Task TryDeleteByPropertyAsync(GraphServiceBase service, string propertyName, string propertyValue, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(propertyValue))
        {
            summary.SkippedCount++;
            return;
        }

        var existing = await FindByPropertyAsync(service, propertyName, propertyValue, ct);
        await TryDeleteNodeAsync(service, existing, summary, ct);
    }

    private static async Task TryDeleteNodeAsync(GraphServiceBase service, JsonNode? existing, SecKeyManifestDeploymentSummary summary, CancellationToken ct)
    {
        var id = existing?["id"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(id))
        {
            summary.SkippedCount++;
            return;
        }

        try
        {
            await service.DeleteAsync(id, ct);
            summary.DeletedCount++;
        }
        catch (SecKey.Core.SecKeyException ex) when (ex.StatusCode == 404)
        {
            summary.SkippedCount++;
        }
    }

    private string ResolveGroupDisplayName(string symbolicGroupId)
        => _groupIdToDisplayName.TryGetValue(symbolicGroupId, out var displayName) ? displayName : symbolicGroupId;

    private string ResolveUserDisplayName(string symbolicUserId)
        => _userIdToDisplayName.TryGetValue(symbolicUserId, out var displayName) ? displayName : symbolicUserId;

    private async Task<bool> GroupHasMemberAsync(string groupId, string memberId, CancellationToken ct)
    {
        var members = await _groups.ListMembersAsync(groupId, ct);
        var values = members?["value"] as JsonArray;
        return values?.Any(v => string.Equals(v?["id"]?.GetValue<string>(), memberId, StringComparison.OrdinalIgnoreCase)) == true;
    }

    private static IEnumerable<string> ResolveManifestFiles(JsonArray? jsonFileList, string repoRoot)
    {
        if (jsonFileList is null) yield break;
        foreach (var file in jsonFileList)
        {
            var path = file?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(path)) continue;
            yield return path.Replace("[PROJECTPATH]", repoRoot, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static JsonObject CloneObjectWithout(JsonObject source, params string[] properties)
    {
        var clone = (JsonObject)source.DeepClone();
        foreach (var property in properties)
            clone.Remove(property);
        return clone;
    }

    private static async Task<JsonNode?> LoadJsonAsync(string path, string secKeyVersion, CancellationToken ct)
    {
        var text = await File.ReadAllTextAsync(path, ct);
        return JsonNode.Parse(text.Replace("{SecKeyVersion}", secKeyVersion, StringComparison.OrdinalIgnoreCase));
    }

    private static string BuildLogonRestrictionsXml(string? deviceAdminSid, string? allowLogonSid, string? denyLogonSid)
    {
        var sb = new StringBuilder();
        sb.Append("<GroupConfiguration>");
        sb.Append("<accessgroup desc=\"Administrators\">");
        sb.Append("<group action=\"R\" />");
        sb.Append("<add member=\"Administrator\" />");
        if (!string.IsNullOrWhiteSpace(deviceAdminSid))
            sb.Append($"<add member=\"{deviceAdminSid}\" />");
        sb.Append("</accessgroup>");
        sb.Append("<accessgroup desc=\"Guests\">");
        sb.Append("<group action=\"R\" />");
        sb.Append("<add member=\"Guest\" />");
        if (!string.IsNullOrWhiteSpace(denyLogonSid))
            sb.Append($"<add member=\"{denyLogonSid}\" />");
        sb.Append("</accessgroup>");
        sb.Append("<accessgroup desc=\"Remote Desktop Users\">");
        sb.Append("<group action=\"R\" />");
        if (!string.IsNullOrWhiteSpace(allowLogonSid))
            sb.Append($"<add member=\"{allowLogonSid}\" />");
        sb.Append("</accessgroup>");
        sb.Append("</GroupConfiguration>");
        return sb.ToString();
    }

    private static async Task<JsonNode?> FindByDisplayNameFromListAsync(GraphServiceBase service, string displayName, CancellationToken ct)
        => await FindByPropertyAsync(service, "displayName", displayName, ct);

    private static async Task<JsonNode?> FindByPropertyAsync(GraphServiceBase service, string propertyName, string propertyValue, CancellationToken ct)
    {
        var values = await service.ListAsync(ct);
        return values.FirstOrDefault(node =>
            string.Equals(node?[propertyName]?.GetValue<string>(), propertyValue, StringComparison.OrdinalIgnoreCase));
    }
}