using System.Collections.ObjectModel;
using System.Net.Http;
using System.Text.Json.Nodes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using SecKey.Core;
using SecKey.App.Services;
using SecKey.Graph;
using SecKey.Graph.Services;

namespace SecKey.App.ViewModels;

/// <summary>Shared base — wires auth-aware GraphHttpClient construction for the page-level VMs.</summary>
public abstract partial class GraphPageViewModel : ObservableObject
{
    protected readonly AuthState Auth;
    protected readonly IServiceProvider Services;
    private readonly INativeDeploymentSettingsService _nativeSettings;
    private string _settingsScope = "Dashboard";

    [ObservableProperty] private bool _busy;
    [ObservableProperty] private string? _statusMessage;
    public ObservableCollection<EntityRow> Items { get; } = new();
    public ObservableCollection<DeploymentSettingItemViewModel> SettingsInventory { get; } = new();

    protected GraphPageViewModel(AuthState auth, IServiceProvider sp)
    {
        Auth = auth;
        Services = sp;
        _nativeSettings = sp.GetRequiredService<INativeDeploymentSettingsService>();
    }

    protected void InitializeSettingsInventory(string scope)
    {
        _settingsScope = scope;
        SettingsInventory.Clear();

        foreach (var setting in _nativeSettings.GetSettingsForScope(scope))
        {
            SettingsInventory.Add(new DeploymentSettingItemViewModel(
                setting.Key,
                setting.Scope,
                setting.DisplayName,
                setting.Description,
                setting.Source,
                setting.Value,
                setting.EditScope));
        }
    }

    /// <summary>Builds a transient GraphHttpClient that uses the AuthState's current token provider.</summary>
    protected GraphHttpClient BuildClient()
    {
        if (Auth.TokenProvider is null)
            throw new InvalidOperationException("Not signed in. Visit the Login page first.");
        var http = new HttpClient();
        var log = (Microsoft.Extensions.Logging.ILogger<GraphHttpClient>)
            Microsoft.Extensions.Logging.Abstractions.NullLogger<GraphHttpClient>.Instance;
        return new GraphHttpClient(http, Auth.TokenProvider, log);
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        Busy = true;
        StatusMessage = "Loading...";
        try
        {
            Items.Clear();
            await foreach (var row in LoadAsync())
                Items.Add(row);
            StatusMessage = $"{Items.Count} items";
        }
        catch (SecKeyException ex) when (ex.StatusCode == 403)
        {
            StatusMessage = BuildForbiddenGuidance(ex);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
        finally { Busy = false; }
    }

    [RelayCommand]
    private void SaveSetting(DeploymentSettingItemViewModel? setting)
    {
        if (setting is null)
            return;

        _nativeSettings.SaveValue(setting.Key, setting.Value);
        setting.Source = "native-code+override";
        StatusMessage = $"Saved setting '{setting.DisplayName}'.";
    }

    [RelayCommand]
    private void NavigateToSetting(DeploymentSettingItemViewModel? setting)
    {
        if (setting is null)
            return;

        if (string.Equals(setting.EditScope, _settingsScope, StringComparison.OrdinalIgnoreCase))
        {
            StatusMessage = $"Edit '{setting.DisplayName}' in this tab and click Save.";
            return;
        }

        var main = Services.GetService<MainViewModel>();
        if (main is null)
        {
            StatusMessage = "Unable to navigate to target tab.";
            return;
        }

        if (!main.NavigateToScope(setting.EditScope))
        {
            StatusMessage = $"No tab mapping for scope '{setting.EditScope}'.";
            return;
        }

        StatusMessage = $"Navigated to {setting.EditScope} to edit '{setting.DisplayName}'.";
    }

    protected abstract IAsyncEnumerable<EntityRow> LoadAsync();

    private static string BuildForbiddenGuidance(SecKeyException ex)
    {
        var uri = ex.RequestUri ?? string.Empty;
        if (uri.Contains("conditionalAccess", StringComparison.OrdinalIgnoreCase))
        {
            return "Access denied (403) for Conditional Access. Required: Graph Policy.Read.All or Policy.ReadWrite.ConditionalAccess, and tenant role like Conditional Access Administrator/Security Administrator/Global Administrator.";
        }

        if (uri.Contains("/devices", StringComparison.OrdinalIgnoreCase))
        {
            return "Access denied (403) for device operations. Required: Graph Device.ReadWrite.All or Directory.ReadWrite.All, with a role that can update devices (for example Intune Administrator or Global Administrator).";
        }

        return $"Access denied (403). {ex.Message}";
    }
}

public sealed record EntityRow(string? Id, string? DisplayName, string? Description = null, string? ExtraJson = null);

internal static class GraphPageHelpers
{
    public static async IAsyncEnumerable<EntityRow> ListAsRowsAsync(GraphServiceBase svc)
    {
        var arr = await svc.ListAsync();
        foreach (var n in arr)
        {
            yield return new EntityRow(
                n?["id"]?.GetValue<string>(),
                n?["displayName"]?.GetValue<string>(),
                n?["description"]?.GetValue<string>(),
                n?.ToJsonString());
        }
    }
}
