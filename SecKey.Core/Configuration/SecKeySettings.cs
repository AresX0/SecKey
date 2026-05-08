namespace SecKey.Core.Configuration;

/// <summary>
/// SecKey deployment-wide settings (mirrors $script:settings used in the PowerShell module).
/// </summary>
public sealed record SecKeySettings
{
    public string TenantId { get; init; } = "";
    public string ClientId { get; init; } = "";
    public string? ClientSecret { get; init; }
    public string? CertificateThumbprint { get; init; }

    public string? ControlPlaneIdentifier { get; init; }
    public string? ManagementPlaneIdentifier { get; init; }
    public string? DataPlaneIdentifier { get; init; }
    public string? AccessPlaneIdentifier { get; init; }

    public string? IntuneAppsPath { get; init; }
    public string? JsonPath { get; init; }
    public string? RemediationScriptsPath { get; init; }

    public IReadOnlyDictionary<string, string?> AsTokenDictionary() => new Dictionary<string, string?>
    {
        ["controlPlaneIdentifier"] = ControlPlaneIdentifier,
        ["managementPlaneIdentifier"] = ManagementPlaneIdentifier,
        ["dataPlaneIdentifier"] = DataPlaneIdentifier,
        ["accessPlaneIdentifier"] = AccessPlaneIdentifier
    };
}
