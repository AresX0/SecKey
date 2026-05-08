using Microsoft.Identity.Client;

namespace SecKey.Graph.Auth;

/// <summary>
/// MSAL-based token provider supporting interactive, device code, and client credentials flows.
/// Caches tokens via MSAL's in-memory cache.
/// </summary>
public sealed class MsalTokenProvider : ITokenProvider
{
    private readonly AuthOptions _options;
    private readonly IPublicClientApplication? _publicApp;
    private readonly IConfidentialClientApplication? _confidentialApp;
    private IAccount? _account;

    public AuthOptions Options => _options;
    public IAccount? CurrentAccount => _account;

    public MsalTokenProvider(AuthOptions options)
    {
        _options = options;

        if (options.Mode == AuthMode.ClientCredentials)
        {
            if (string.IsNullOrWhiteSpace(options.ClientSecret))
                throw new ArgumentException("ClientSecret required for ClientCredentials mode.");
            _confidentialApp = ConfidentialClientApplicationBuilder
                .Create(options.ClientId)
                .WithClientSecret(options.ClientSecret)
                .WithAuthority($"https://login.microsoftonline.com/{options.TenantId}")
                .Build();
        }
        else
        {
            _publicApp = PublicClientApplicationBuilder
                .Create(options.ClientId)
                .WithAuthority($"https://login.microsoftonline.com/{options.TenantId}")
                .WithRedirectUri(options.RedirectUri ?? "http://localhost")
                .Build();
        }
    }

    public async Task<string> GetAccessTokenAsync(CancellationToken ct = default)
    {
        if (_options.Mode == AuthMode.ClientCredentials)
        {
            var r = await _confidentialApp!
                .AcquireTokenForClient(_options.Scopes)
                .ExecuteAsync(ct);
            return r.AccessToken;
        }

        // Try silent first
        try
        {
            _account ??= (await _publicApp!.GetAccountsAsync()).FirstOrDefault();
            if (_account is not null)
            {
                var silent = await _publicApp!
                    .AcquireTokenSilent(_options.Scopes, _account)
                    .ExecuteAsync(ct);
                _account = silent.Account;
                return silent.AccessToken;
            }
        }
        catch (MsalUiRequiredException) { /* fall through */ }

        AuthenticationResult result;
        if (_options.Mode == AuthMode.DeviceCode)
        {
            result = await _publicApp!
                .AcquireTokenWithDeviceCode(_options.Scopes, dc =>
                {
                    Console.WriteLine(dc.Message);
                    return Task.CompletedTask;
                })
                .ExecuteAsync(ct);
        }
        else
        {
            result = await _publicApp!
                .AcquireTokenInteractive(_options.Scopes)
                .WithUseEmbeddedWebView(false)
                .ExecuteAsync(ct);
        }

        _account = result.Account;
        return result.AccessToken;
    }

    public async Task SignOutAsync()
    {
        if (_publicApp is null) return;
        var accounts = await _publicApp.GetAccountsAsync();
        foreach (var a in accounts) await _publicApp.RemoveAsync(a);
        _account = null;
    }
}

public interface ITokenProvider
{
    Task<string> GetAccessTokenAsync(CancellationToken ct = default);
}
