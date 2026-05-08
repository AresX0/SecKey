using System.Text.Json.Nodes;
using SecKey.Core.Configuration;

namespace SecKey.Graph.Services.Win32Lob;

/// <summary>
/// Builds Win32 detection-rule JSON nodes from IntuneApp config (ports private New-DetectionRule.ps1).
/// </summary>
public static class DetectionRuleBuilder
{
    public static JsonObject Msi(string productCode, string? versionOperator = null, string? version = null)
    {
        var o = new JsonObject
        {
            ["@odata.type"] = "#microsoft.graph.win32LobAppProductCodeDetection",
            ["productCode"] = productCode,
            ["productVersionOperator"] = versionOperator ?? "notConfigured",
            ["productVersion"] = version
        };
        return o;
    }

    public static JsonObject File(string path, string fileOrFolderName, string detectionType,
        string? @operator = null, string? value = null, bool check32On64 = false)
    {
        return new JsonObject
        {
            ["@odata.type"] = "#microsoft.graph.win32LobAppFileSystemDetection",
            ["path"] = path,
            ["fileOrFolderName"] = fileOrFolderName,
            ["detectionType"] = detectionType,
            ["operator"] = @operator ?? "notConfigured",
            ["detectionValue"] = value,
            ["check32BitOn64System"] = check32On64
        };
    }

    public static JsonObject Registry(string keyPath, string? valueName, string detectionType,
        string? @operator = null, string? value = null, bool check32On64 = false)
    {
        return new JsonObject
        {
            ["@odata.type"] = "#microsoft.graph.win32LobAppRegistryDetection",
            ["keyPath"] = keyPath,
            ["valueName"] = valueName,
            ["detectionType"] = detectionType,
            ["operator"] = @operator ?? "notConfigured",
            ["detectionValue"] = value,
            ["check32BitOn64System"] = check32On64
        };
    }

    public static JsonObject Script(string scriptContentBase64, bool runAs32 = false, bool enforceSig = false)
    {
        return new JsonObject
        {
            ["@odata.type"] = "#microsoft.graph.win32LobAppPowerShellScriptDetection",
            ["enforceSignatureCheck"] = enforceSig,
            ["runAs32Bit"] = runAs32,
            ["scriptContent"] = scriptContentBase64
        };
    }

    public static JsonObject FromConfig(DetectionRuleConfig cfg, string? scriptDir = null)
    {
        return cfg.Type.ToLowerInvariant() switch
        {
            "msi" => Msi(cfg.ProductCode ?? throw new ArgumentException("ProductCode missing"),
                          cfg.ProductVersionOperator, cfg.ProductVersion),
            "file" => File(cfg.Path ?? "", cfg.FileOrFolderName ?? "",
                            cfg.DetectionType ?? "exists", cfg.Operator, cfg.DetectionValue,
                            cfg.Check32BitOn64System ?? false),
            "registry" => Registry(cfg.KeyPath ?? "", cfg.ValueName,
                            cfg.DetectionType ?? "exists", cfg.Operator, cfg.DetectionValue,
                            cfg.Check32BitOn64System ?? false),
            "script" => Script(
                Convert.ToBase64String(System.IO.File.ReadAllBytes(
                    System.IO.Path.Combine(scriptDir ?? Environment.CurrentDirectory, cfg.ScriptFile ?? ""))),
                cfg.RunAs32Bit ?? false, cfg.EnforceSignatureCheck ?? false),
            _ => throw new ArgumentException($"Unknown detection rule type: {cfg.Type}")
        };
    }
}
