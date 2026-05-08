using System.Text.Json.Nodes;

namespace SecKey.Graph.Services;

/// <summary>
/// Generic helpers shared by Get/Set/Test/Import/Remove service patterns from the PowerShell module.
/// </summary>
public abstract class GraphServiceBase
{
    protected readonly GraphHttpClient Client;
    protected GraphServiceBase(GraphHttpClient client) { Client = client; }

    /// <summary>Resource collection (e.g. "deviceManagement/deviceCompliancePolicies").</summary>
    protected abstract string Resource { get; }

    /// <summary>Whether this resource lives on the beta endpoint.</summary>
    protected virtual bool UseBeta => true;

    public virtual async Task<JsonArray> ListAsync(CancellationToken ct = default)
    {
        var arr = new JsonArray();
        await foreach (var n in Client.PagedAsync(Resource, UseBeta, ct))
            arr.Add(n.DeepClone());
        return arr;
    }

    public virtual async Task<JsonNode?> GetByIdAsync(string id, CancellationToken ct = default)
        => await Client.GetAsync($"{Resource}/{id}", UseBeta, ct);

    public virtual async Task<JsonNode?> GetByDisplayNameAsync(string displayName, CancellationToken ct = default)
    {
        var filter = $"?$filter=displayName eq '{Uri.EscapeDataString(displayName)}'";
        var node = await Client.GetAsync(Resource + filter, UseBeta, ct);
        return (node?["value"] as JsonArray)?.FirstOrDefault();
    }

    public virtual async Task<bool> ExistsAsync(string displayName, CancellationToken ct = default)
        => (await GetByDisplayNameAsync(displayName, ct)) is not null;

    public virtual Task<JsonNode?> CreateAsync(JsonNode body, CancellationToken ct = default)
        => Client.PostAsync(Resource, body, UseBeta, ct);

    public virtual Task<JsonNode?> UpdateAsync(string id, JsonNode body, CancellationToken ct = default)
        => Client.PatchAsync($"{Resource}/{id}", body, UseBeta, ct);

    public virtual Task DeleteAsync(string id, CancellationToken ct = default)
        => Client.DeleteAsync($"{Resource}/{id}", UseBeta, ct);
}
