using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Net.Http;
using System.Text.Json.Nodes;
using SecKey.App.Services;
using SecKey.Core;
using SecKey.Graph.Auth;
using SecKey.Graph;

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

    public Task AutoSignInInteractiveAsync()
    {
        if (_auth.IsSignedIn || Busy || UseAppOnly || UseDeviceCode)
            return Task.CompletedTask;
        return SignInAsync();
    }

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
                        "https://graph.microsoft.com/DeviceManagementScripts.ReadWrite.All",
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
            Status = "Signed in. Use 'Validate Access' to verify Conditional Access and device write permissions before importing policies.";
        }
        catch (Exception ex)
        {
            Status = $"Sign-in failed: {ex.Message}";
        }
        finally { Busy = false; }
    }

    [RelayCommand]
    private async Task ValidateAccessAsync()
    {
        if (_auth.TokenProvider is null)
        {
            Status = "Sign in first.";
            return;
        }

        Busy = true;
        try
        {
            var http = new HttpClient();
            var log = (Microsoft.Extensions.Logging.ILogger<GraphHttpClient>)
                Microsoft.Extensions.Logging.Abstractions.NullLogger<GraphHttpClient>.Instance;
            var graph = new GraphHttpClient(http, _auth.TokenProvider, log);

            var results = new List<string>();

            // Conditional Access read probe.
            try
            {
                await graph.GetAsync("identity/conditionalAccess/policies?$top=1", false);
                results.Add("CA read: OK");
            }
            catch (SecKeyException ex) when (ex.StatusCode == 403)
            {
                results.Add("CA read: FORBIDDEN (need Policy.Read.All or Policy.ReadWrite.ConditionalAccess plus CA/Security/Global Admin role)");
            }

            // Device write probe. 404 implies permission is present but object is missing.
            var fakeId = "00000000-0000-0000-0000-000000000001";
            try
            {
                await graph.PatchAsync($"devices/{fakeId}", new JsonObject
                {
                    ["extensionAttributes"] = new JsonObject { ["extensionAttribute1"] = "SECKEY" }
                }, false);
                results.Add("Device extension write: OK");
            }
            catch (SecKeyException ex) when (ex.StatusCode == 404 || ex.StatusCode == 400)
            {
                results.Add("Device extension write: OK (permission appears sufficient; test target was intentionally nonexistent)");
            }
            catch (SecKeyException ex) when (ex.StatusCode == 403)
            {
                results.Add("Device extension write: FORBIDDEN (need Device.ReadWrite.All or Directory.ReadWrite.All and device-management admin role)");
            }

            Status = string.Join(" | ", results);
        }
        catch (Exception ex)
        {
            Status = $"Validation failed: {ex.Message}";
        }
        finally
        {
            Busy = false;
        }
    }

    [RelayCommand]
    private void SignOut()
    {
        _auth.SignOut();
        Status = "Signed out.";
    }
}
