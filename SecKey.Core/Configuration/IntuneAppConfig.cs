using System.Text.Json.Serialization;

namespace SecKey.Core.Configuration;

/// <summary>
/// Mirrors the IntuneApps/*/config.json schema (SECKEYintuneapp.schema.json).
/// </summary>
public sealed class IntuneAppConfig
{
    public string AppType { get; set; } = "EXE";   // MSI | EXE | PS1 | Edge
    public string? RuleType { get; set; }          // TAGFILE | FILE | REGTAG
    public string? ReturnCodeType { get; set; }    // do not edit
    public string InstallExperience { get; set; } = "system";
    public string PackageName { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Description { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string Category { get; set; } = "";
    public string LogoFile { get; set; } = "";

    public string? InstallCommandLine { get; set; }
    public string? UninstallCommandLine { get; set; }
    public string? Channel { get; set; } // edge

    [JsonPropertyName("DetectionRules")]
    public List<DetectionRuleConfig>? DetectionRules { get; set; }

    [JsonPropertyName("ReturnCodes")]
    public List<ReturnCodeConfig>? ReturnCodes { get; set; }
}

public sealed class DetectionRuleConfig
{
    public string Type { get; set; } = ""; // MSI | File | Registry | Script
    public string? Path { get; set; }
    public string? FileOrFolderName { get; set; }
    public string? DetectionType { get; set; }
    public string? KeyPath { get; set; }
    public string? ValueName { get; set; }
    public string? Operator { get; set; }
    public string? DetectionValue { get; set; }
    public bool? Check32BitOn64System { get; set; }
    public string? ProductCode { get; set; }
    public string? ProductVersionOperator { get; set; }
    public string? ProductVersion { get; set; }
    public string? ScriptFile { get; set; }
    public bool? RunAs32Bit { get; set; }
    public bool? EnforceSignatureCheck { get; set; }
}

public sealed class ReturnCodeConfig
{
    public int ReturnCode { get; set; }
    public string Type { get; set; } = ""; // success | softReboot | hardReboot | retry | failed
}

public sealed class GroupAssignmentConfig
{
    public string DisplayName { get; set; } = "";
    public string? GroupId { get; set; }
    public string Intent { get; set; } = "required"; // required | available | uninstall
}
