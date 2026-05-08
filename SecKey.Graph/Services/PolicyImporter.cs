using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using SecKey.Core;
using SecKey.Graph.Services.EntraID;
using SecKey.Graph.Services.Intune;

namespace SecKey.Graph.Services;

/// <summary>
/// Bulk JSON-list importers (analogs of Import-DeviceCompliancePolicyList, Import-DeviceConfigurationList,
/// Import-DeviceSettingsCatalog, Import-AutoPilotPolicyList, Import-EnrollmentStatusPageList,
/// Import-NamedLocationList, Import-ConditionalAccessPolicyList, Import-EntraIdGroupList, Import-EntraIdUserList,
/// Import-IntuneRoleScopeTagList, Import-EndpointSecurityPolicyList).
/// </summary>
public sealed class PolicyImporter
{
    private readonly ILogger<PolicyImporter> _log;
    public PolicyImporter(ILogger<PolicyImporter> log) { _log = log; }

    /// <summary>Reads JSON files from a directory (or accepts a list of files) and creates each entity if missing.</summary>
    public async Task<List<JsonNode>> ImportAsync(GraphServiceBase service, IEnumerable<string> jsonFiles,
        Func<JsonNode, string?>? displayNameSelector = null, CancellationToken ct = default)
    {
        displayNameSelector ??= n => n["displayName"]?.GetValue<string>() ?? n["DisplayName"]?.GetValue<string>();
        var created = new List<JsonNode>();
        foreach (var path in jsonFiles)
        {
            var node = JsonHelpers.ReadFile(path);
            if (node is null)
            {
                _log.LogWarning("Empty/invalid JSON: {Path}", path);
                continue;
            }
            var name = displayNameSelector(node);
            if (!string.IsNullOrEmpty(name) && await service.ExistsAsync(name, ct))
            {
                _log.LogInformation("Existing: {Name}", name);
                continue;
            }
            try
            {
                var result = await service.CreateAsync(node, ct);
                if (result is not null) created.Add(result);
                _log.LogInformation("Created: {Name}", name);
            }
            catch (SecKeyException ex)
            {
                _log.LogError(ex, "Failed to import {Name}: {Body}", name, ex.ResponseBody);
            }
        }
        return created;
    }

    public Task<List<JsonNode>> ImportFromDirectoryAsync(GraphServiceBase service, string directory,
        string searchPattern = "*.json", CancellationToken ct = default)
    {
        var files = Directory.EnumerateFiles(directory, searchPattern);
        return ImportAsync(service, files, ct: ct);
    }
}
