using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using SecKey.Core;
using SecKey.Graph.Auth;

namespace SecKey.Graph;

/// <summary>
/// Thin Graph HTTP client modeled after PowerShell Invoke-MgGraphRequest / MakeRequest helper.
/// Supports both v1.0 and beta endpoints with automatic auth token injection.
/// </summary>
public sealed class GraphHttpClient
{
    public const string BaseV1 = "https://graph.microsoft.com/v1.0/";
    public const string BaseBeta = "https://graph.microsoft.com/beta/";

    private readonly HttpClient _http;
    private readonly ITokenProvider _tokens;
    private readonly ILogger<GraphHttpClient> _log;

    public GraphHttpClient(HttpClient http, ITokenProvider tokens, ILogger<GraphHttpClient> log)
    {
        _http = http;
        _tokens = tokens;
        _log = log;
    }

    private async Task<HttpRequestMessage> BuildAsync(HttpMethod method, string url, HttpContent? content, CancellationToken ct)
    {
        var token = await _tokens.GetAccessTokenAsync(ct);
        var req = new HttpRequestMessage(method, url) { Content = content };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return req;
    }

    public Task<JsonNode?> GetAsync(string relative, bool beta = true, CancellationToken ct = default)
        => SendJsonAsync(HttpMethod.Get, MakeUrl(relative, beta), null, ct);

    public Task<JsonNode?> PostAsync(string relative, JsonNode? body, bool beta = true, CancellationToken ct = default)
        => SendJsonAsync(HttpMethod.Post, MakeUrl(relative, beta), body, ct);

    public Task<JsonNode?> PostAsync(string relative, object body, bool beta = true, CancellationToken ct = default)
        => SendJsonAsync(HttpMethod.Post, MakeUrl(relative, beta), JsonSerializer.SerializeToNode(body, JsonHelpers.Options), ct);

    public Task<JsonNode?> PatchAsync(string relative, JsonNode? body, bool beta = true, CancellationToken ct = default)
        => SendJsonAsync(HttpMethod.Patch, MakeUrl(relative, beta), body, ct);

    public Task<JsonNode?> PatchAsync(string relative, object body, bool beta = true, CancellationToken ct = default)
        => SendJsonAsync(HttpMethod.Patch, MakeUrl(relative, beta), JsonSerializer.SerializeToNode(body, JsonHelpers.Options), ct);

    public Task<JsonNode?> PutAsync(string relative, JsonNode? body, bool beta = true, CancellationToken ct = default)
        => SendJsonAsync(HttpMethod.Put, MakeUrl(relative, beta), body, ct);

    public async Task DeleteAsync(string relative, bool beta = true, CancellationToken ct = default)
    {
        await SendJsonAsync(HttpMethod.Delete, MakeUrl(relative, beta), null, ct);
    }

    private static string MakeUrl(string relative, bool beta)
        => relative.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? relative
            : (beta ? BaseBeta : BaseV1) + relative.TrimStart('/');

    private async Task<JsonNode?> SendJsonAsync(HttpMethod method, string url, JsonNode? body, CancellationToken ct)
    {
        HttpContent? content = null;
        if (body is not null)
            content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");

        using var req = await BuildAsync(method, url, content, ct);
        _log.LogDebug("{Method} {Url}", method, url);

        using var resp = await _http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);

        if (!resp.IsSuccessStatusCode)
        {
            _log.LogError("Graph {Method} {Url} -> {Status}: {Body}", method, url, (int)resp.StatusCode, text);
            var detail = ExtractGraphErrorSummary(text);
            throw new SecKeyException(
                string.IsNullOrWhiteSpace(detail)
                    ? $"Graph {method} {url} returned {(int)resp.StatusCode}"
                    : $"Graph {method} {url} returned {(int)resp.StatusCode}: {detail}",
                requestUri: url,
                responseBody: text,
                statusCode: (int)resp.StatusCode);
        }

        if (string.IsNullOrWhiteSpace(text)) return null;
        return JsonNode.Parse(text);
    }

    /// <summary>Page through all values of a Graph collection (handles @odata.nextLink).</summary>
    public async IAsyncEnumerable<JsonNode> PagedAsync(string relative, bool beta = true,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        var url = MakeUrl(relative, beta);
        while (!string.IsNullOrEmpty(url))
        {
            using var req = await BuildAsync(HttpMethod.Get, url, null, ct);
            using var resp = await _http.SendAsync(req, ct);
            var text = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode)
                throw new SecKeyException($"Graph GET {url} -> {(int)resp.StatusCode}",
                    requestUri: url, responseBody: text, statusCode: (int)resp.StatusCode);

            var node = JsonNode.Parse(text);
            var array = node?["value"] as JsonArray;
            if (array is not null)
                foreach (var item in array)
                    if (item is not null) yield return item;

            url = node?["@odata.nextLink"]?.GetValue<string>() ?? "";
        }
    }

    private static string? ExtractGraphErrorSummary(string? responseBody)
    {
        if (string.IsNullOrWhiteSpace(responseBody)) return null;
        try
        {
            var root = JsonNode.Parse(responseBody);
            var err = root?["error"];
            if (err is null) return null;

            var code = err["code"]?.GetValue<string>();
            var message = err["message"]?.GetValue<string>();

            if (!string.IsNullOrWhiteSpace(code) && !string.IsNullOrWhiteSpace(message))
                return $"{code} - {message}";
            if (!string.IsNullOrWhiteSpace(message))
                return message;
            return code;
        }
        catch
        {
            return null;
        }
    }
}
