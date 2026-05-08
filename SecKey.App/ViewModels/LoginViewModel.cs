using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecKey.App.Services;
using SecKey.Graph.Auth;

namespace SecKey.App.ViewModels;

public sealed partial class LoginViewModel : ObservableObject
{
    private readonly AuthState _auth;

    [ObservableProperty] private string _tenantId = "common";
    [ObservableProperty] private string _clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e";
    [ObservableProperty] private string? _clientSecret;
    [ObservableProperty] private bool _useAppOnly;
    [ObservableProperty] private bool _useDeviceCode;
    [ObservableProperty] private string? _status;
    [ObservableProperty] private bool _busy;

    public LoginViewModel(AuthState auth) => _auth = auth;

    [RelayCommand]
    private async Task SignInAsync()
    {
        Busy = true;
        try
        {
            var mode = UseAppOnly ? AuthMode.ClientCredentials
                     : UseDeviceCode ? AuthMode.DeviceCode
                     : AuthMode.Interactive;

            var options = new AuthOptions
            {
                TenantId = string.IsNullOrWhiteSpace(TenantId) ? "common" : TenantId,
                ClientId = string.IsNullOrWhiteSpace(ClientId) ? "14d82eec-204b-4c2f-b7e8-296a70dab67e" : ClientId,
                ClientSecret = UseAppOnly ? ClientSecret : null,
                Mode = mode,
                Scopes = UseAppOnly
                    ? new[] { "https://graph.microsoft.com/.default" }
                    : new[]
                    {
                        "https://graph.microsoft.com/Directory.ReadWrite.All",
                        "https://graph.microsoft.com/DeviceManagementApps.ReadWrite.All",
                        "https://graph.microsoft.com/DeviceManagementConfiguration.ReadWrite.All",
                        "https://graph.microsoft.com/DeviceManagementServiceConfig.ReadWrite.All",
                        "https://graph.microsoft.com/Group.ReadWrite.All",
                        "https://graph.microsoft.com/User.ReadWrite.All",
                        "https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess"
                    }
            };

            var provider = new MsalTokenProvider(options);
            // Acquire to validate
            await provider.GetAccessTokenAsync();
            var account = provider.CurrentAccount;
            _auth.SetSignedIn(provider, account?.Username ?? (UseAppOnly ? "(app-only)" : "(unknown)"), TenantId);
            Status = "Signed in.";
        }
        catch (Exception ex)
        {
            Status = $"Sign-in failed: {ex.Message}";
        }
        finally { Busy = false; }
    }

    [RelayCommand]
    private void SignOut()
    {
        _auth.SignOut();
        Status = "Signed out.";
    }
}
