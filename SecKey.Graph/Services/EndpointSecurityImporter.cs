using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using SecKey.Core;
using SecKey.Graph.Services.EntraID;
using SecKey.Graph.Services.Intune;

namespace SecKey.Graph.Services;

/// <summary>
/// Imports Endpoint Security (Defender for Endpoint) baseline policies from JSON files,
/// resolving the appropriate template at import time.
/// </summary>
public sealed class EndpointSecurityImporter
{
    private readonly EndpointSecurityPolicyService _policies;
    private readonly EntraIdGroupService _groups;
    private readonly ILogger<EndpointSecurityImporter> _log;

    public EndpointSecurityImporter(
        EndpointSecurityPolicyService policies,
        EntraIdGroupService groups,
        ILogger<EndpointSecurityImporter> log)
    {
        _policies = policies;
        _groups = groups;
        _log = log;
    }

    public async Task<List<JsonNode?>> ImportFromDirectoryAsync(string directory, CancellationToken ct = default)
    {
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException(directory);
        var files = Directory.EnumerateFiles(directory, "*.json", SearchOption.TopDirectoryOnly).ToArray();
        return await ImportAsync(files, ct);
    }

    public async Task<List<JsonNode?>> ImportAsync(IReadOnlyList<string> jsonFiles, CancellationToken ct = default)
    {
        var created = new List<JsonNode?>();
        var templates = await _policies.ListTemplatesAsync(ct);

        foreach (var file in jsonFiles)
        {
            var policy = (await JsonHelpers.ReadFileAsync(file, ct)) as JsonObject
                ?? throw new SecKeyException($"Invalid policy JSON: {file}");

            var displayName = policy["displayName"]?.GetValue<string>() ?? "";
            var existing = await _policies.FindByDisplayNameAsync(displayName, ct);
            if (existing is not null)
            {
                _log.LogInformation("  Existing: {DisplayName}", displayName);
                continue;
            }

            var templateId = ResolveTemplateId(policy, templates);
            if (templateId is null)
            {
                _log.LogWarning("  Skipping (template not found): {DisplayName}", displayName);
                continue;
            }

            // Resolve any group display-name → groupId substitutions in assignments before posting.
            await ResolveAssignmentTargetsAsync(policy, ct);

            // Strip metadata properties not accepted by createInstance.
            var clone = (JsonObject)policy.DeepClone();
            clone.Remove("templateId");
            clone.Remove("templateDisplayName");
            clone.Remove("id");
            clone.Remove("createdDateTime");
            clone.Remove("lastModifiedDateTime");

            _log.LogInformation("  Creating: {DisplayName}", displayName);
            try
            {
                var result = await _policies.CreateInstanceAsync(templateId, clone, ct);
                created.Add(result);

                // PS module re-applies assignments via Set-EndpointSecurityPolicyAssignment.
                if (clone["assignments"] is JsonArray assignments && assignments.Count > 0
                    && result?["id"]?.GetValue<string>() is { } newId)
                {
                    await _policies.SetAssignmentsAsync(newId, (JsonArray)assignments.DeepClone(), ct);
                }
            }
            catch (SecKeyException ex)
            {
                _log.LogError(ex, "Failed to create endpoint security policy {DisplayName}", displayName);
            }
        }
        return created;
    }

    private static string? ResolveTemplateId(JsonObject policy, JsonArray templates)
    {
        var requested = policy["templateId"]?.GetValue<string>();
        var requestedName = policy["templateDisplayName"]?.GetValue<string>();

        // Try exact id match first.
        foreach (var t in templates)
        {
            if (t?["id"]?.GetValue<string>() == requested)
            {
                var ttype = t["templateType"]?.GetValue<string>() ?? "";
                var deprecated = t["isDeprecated"]?.GetValue<bool>() ?? false;
                if (ttype.Contains("microsoftEdgeSecurityBaseline", StringComparison.OrdinalIgnoreCase)
                    || ttype.Contains("securityBaseline", StringComparison.OrdinalIgnoreCase)
                    || ttype.Contains("advancedThreatProtectionSecurityBaseline", StringComparison.OrdinalIgnoreCase))
                {
                    return requested;
                }
                if (deprecated)
                {
                    // PS behaviour: pick a non-deprecated template that matches the policy display name.
                    var name = policy["displayName"]?.GetValue<string>();
                    foreach (var t2 in templates)
                        if (t2?["displayName"]?.GetValue<string>() == name)
                            return t2["id"]?.GetValue<string>();
                }
                return requested;
            }
        }

        // Fall back to template display name.
        if (!string.IsNullOrEmpty(requestedName))
        {
            foreach (var t in templates)
                if (t?["displayName"]?.GetValue<string>() == requestedName)
                    return t["id"]?.GetValue<string>();
        }
        return null;
    }

    private async Task ResolveAssignmentTargetsAsync(JsonObject policy, CancellationToken ct)
    {
        if (policy["assignments"] is not JsonArray assignments) return;

        foreach (var a in assignments)
        {
            var target = a?["target"];
            var odata = target?["@odata.type"]?.GetValue<string>() ?? "";
            if (target is null) continue;

            // Only group targets need resolution; allDevices/allUsers carry no group id.
            if (!odata.Contains("group", StringComparison.OrdinalIgnoreCase)) continue;

            // The exported JSON used a group displayName placeholder in PS; if a real id is already a GUID, leave it.
            var existing = target["groupId"]?.GetValue<string>();
            if (string.IsNullOrEmpty(existing)) continue;
            if (Guid.TryParse(existing, out _)) continue;

            var group = await _groups.GetByDisplayNameAsync(existing, ct);
            var resolvedId = group?["id"]?.GetValue<string>();
            if (resolvedId is not null)
                target["groupId"] = resolvedId;
        }
    }
}
