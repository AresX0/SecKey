using System.Collections.ObjectModel;
using System.Net.Http;
using System.Text.Json.Nodes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecKey.App.Services;
using SecKey.Graph;
using SecKey.Graph.Services;

namespace SecKey.App.ViewModels;

/// <summary>Shared base — wires auth-aware GraphHttpClient construction for the page-level VMs.</summary>
public abstract partial class GraphPageViewModel : ObservableObject
{
    protected readonly AuthState Auth;
    protected readonly IServiceProvider Services;

    [ObservableProperty] private bool _busy;
    [ObservableProperty] private string? _statusMessage;
    public ObservableCollection<EntityRow> Items { get; } = new();

    protected GraphPageViewModel(AuthState auth, IServiceProvider sp)
    {
        Auth = auth;
        Services = sp;
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
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
        finally { Busy = false; }
    }

    protected abstract IAsyncEnumerable<EntityRow> LoadAsync();
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
