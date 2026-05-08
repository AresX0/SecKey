using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using SecKey.Core;
using SecKey.Core.Configuration;
using SecKey.Graph.Services.EntraID;
using SecKey.Graph.Services.Intune;

namespace SecKey.Graph.Services.Win32Lob;

/// <summary>
/// High-level orchestrator that mirrors public/Intune/Import-IntuneApp.ps1 + New-IntuneApplicationPackage.ps1
/// + Set-IntuneApplication.ps1 (configure detection rules, package, upload, assign).
/// </summary>
public sealed class IntuneAppOrchestrator
{
    private readonly IntuneWinAppUtilRunner _packager;
    private readonly Win32LobUploader _uploader;
    private readonly IntuneApplicationService _apps;
    private readonly EntraIdGroupService _groups;
    private readonly ILogger<IntuneAppOrchestrator> _log;

    public IntuneAppOrchestrator(IntuneWinAppUtilRunner packager, Win32LobUploader uploader,
        IntuneApplicationService apps, EntraIdGroupService groups, ILogger<IntuneAppOrchestrator> log)
    {
        _packager = packager;
        _uploader = uploader;
        _apps = apps;
        _groups = groups;
        _log = log;
    }

    /// <summary>
    /// Imports an Intune app from an "IntuneApps\AppName" folder layout.
    /// </summary>
    public async Task<JsonNode?> ImportAsync(string appFolder, IProgress<UploadProgress>? progress = null, CancellationToken ct = default)
    {
        var configPath = Path.Combine(appFolder, "config.json");
        var groupsPath = Path.Combine(appFolder, "groups.json");

        var cfg = JsonHelpers.ReadFile<IntuneAppConfig>(configPath)
            ?? throw new InvalidOperationException($"Failed to parse {configPath}");

        // Skip if app already exists
        if (await _apps.ExistsAsync(cfg.DisplayName, ct))
        {
            _log.LogInformation("Existing app already in tenant: {Name}", cfg.DisplayName);
            return await _apps.GetByDisplayNameAsync(cfg.DisplayName, ct);
        }

        // 1. Package
        progress?.Report(new(UploadStage.CreatingApp, 0, "Packaging .intunewin"));
        var intuneWin = await _packager.PackageAsync(cfg.AppType, appFolder, cfg.PackageName, ct);

        // 2. Build detection rules (auto-generate if RuleType present, otherwise use explicit list)
        var rules = BuildDetectionRules(cfg, appFolder);

        // 3. Build return codes
        var returnCodes = (cfg.ReturnCodes ?? new()).Count == 0
            ? null
            : cfg.ReturnCodes!
                .Select(rc => (JsonNode)new JsonObject { ["returnCode"] = rc.ReturnCode, ["type"] = rc.Type })
                .ToList();

        // 4. Read logo
        var logoPath = Path.Combine(appFolder, cfg.LogoFile);
        var logoBytes = File.Exists(logoPath) ? File.ReadAllBytes(logoPath) : Array.Empty<byte>();

        // 5. Upload
        var app = await _uploader.UploadAsync(cfg, intuneWin, logoBytes, rules, returnCodes, progress, ct);
        var appId = app["id"]!.GetValue<string>();

        // 6. Assign groups
        if (File.Exists(groupsPath))
            await AssignGroupsAsync(appId, groupsPath, ct);

        return app;
    }

    private List<JsonNode> BuildDetectionRules(IntuneAppConfig cfg, string appFolder)
    {
        // Explicit detection rules in config win
        if (cfg.DetectionRules is { Count: > 0 })
            return cfg.DetectionRules.Select(r => (JsonNode)DetectionRuleBuilder.FromConfig(r, appFolder)).ToList();

        // Otherwise infer based on RuleType (PS1/EXE)
        if (cfg.AppType.Equals("MSI", StringComparison.OrdinalIgnoreCase))
            return new(); // MSI rule auto-generated in uploader from intunewin metadata

        var ruleType = (cfg.RuleType ?? "TAGFILE").ToUpperInvariant();
        var isUser = cfg.InstallExperience.Equals("user", StringComparison.OrdinalIgnoreCase);
        return ruleType switch
        {
            "TAGFILE" => new()
            {
                DetectionRuleBuilder.File(
                    path: isUser ? @"%LOCALAPPDATA%\Microsoft\IntuneApps\" + cfg.PackageName
                                 : @"%PROGRAMDATA%\Microsoft\IntuneApps\" + cfg.PackageName,
                    fileOrFolderName: cfg.PackageName + ".tag",
                    detectionType: "exists")
            },
            "REGTAG" => new()
            {
                DetectionRuleBuilder.Registry(
                    keyPath: isUser ? @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\" + cfg.PackageName
                                    : @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\" + cfg.PackageName,
                    valueName: "Installed",
                    detectionType: "exists",
                    check32On64: true)
            },
            _ => throw new InvalidOperationException($"Unsupported RuleType: {ruleType}")
        };
    }

    private async Task AssignGroupsAsync(string appId, string groupsPath, CancellationToken ct)
    {
        var groupConfigs = JsonHelpers.ReadFile<List<GroupAssignmentConfig>>(groupsPath);
        if (groupConfigs is null || groupConfigs.Count == 0) return;

        var assignments = new JsonArray();
        foreach (var g in groupConfigs)
        {
            var groupId = g.GroupId;
            if (string.IsNullOrEmpty(groupId) && !string.IsNullOrEmpty(g.DisplayName))
            {
                var node = await _groups.GetByDisplayNameAsync(g.DisplayName, ct);
                groupId = node?["id"]?.GetValue<string>();
            }
            if (string.IsNullOrEmpty(groupId))
            {
                _log.LogWarning("Skipping unresolved group: {Name}", g.DisplayName);
                continue;
            }
            assignments.Add(new JsonObject
            {
                ["@odata.type"] = "#microsoft.graph.mobileAppAssignment",
                ["intent"] = g.Intent,
                ["target"] = new JsonObject
                {
                    ["@odata.type"] = "#microsoft.graph.groupAssignmentTarget",
                    ["groupId"] = groupId
                }
            });
        }
        if (assignments.Count > 0)
            await _apps.SetAssignmentsAsync(appId, assignments, ct);
    }
}
