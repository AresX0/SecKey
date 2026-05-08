namespace SecKey.Graph.Auth;

/// <summary>Authentication mode selection.</summary>
public enum AuthMode
{
    Interactive,
    DeviceCode,
    ClientCredentials
}

public sealed record AuthOptions
{
    public string TenantId { get; init; } = "common";
    public string ClientId { get; init; } = "14d82eec-204b-4c2f-b7e8-296a70dab67e"; // Microsoft Graph PowerShell public client
    public AuthMode Mode { get; init; } = AuthMode.Interactive;
    public string? ClientSecret { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = new[]
    {
        "https://graph.microsoft.com/.default"
    };
    public string? RedirectUri { get; init; } = "http://localhost";
}
