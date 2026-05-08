using CommunityToolkit.Mvvm.ComponentModel;
using SecKey.Graph.Auth;

namespace SecKey.App.Services;

/// <summary>Holds the active auth provider so the rest of the app can adapt to sign-in/out.</summary>
public sealed partial class AuthState : ObservableObject
{
    [ObservableProperty] private bool _isSignedIn;
    [ObservableProperty] private string? _displayName;
    [ObservableProperty] private string? _tenantId;
    [ObservableProperty] private string? _statusMessage = "Not signed in";

    public ITokenProvider? TokenProvider { get; private set; }

    public void SetSignedIn(ITokenProvider provider, string? user, string? tenant)
    {
        TokenProvider = provider;
        DisplayName = user;
        TenantId = tenant;
        IsSignedIn = true;
        StatusMessage = $"Signed in: {user}";
    }

    public void SignOut()
    {
        TokenProvider = null;
        IsSignedIn = false;
        DisplayName = null;
        StatusMessage = "Not signed in";
    }
}
