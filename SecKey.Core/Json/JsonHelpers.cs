using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecKey.Core;

/// <summary>
/// Centralized JSON helpers used across SecKey services.
/// </summary>
public static class JsonHelpers
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static readonly JsonSerializerOptions Pretty = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static async Task<JsonNode?> ReadFileAsync(string path, CancellationToken ct = default)
    {
        await using var s = File.OpenRead(path);
        return await JsonNode.ParseAsync(s, cancellationToken: ct);
    }

    public static JsonNode? ReadFile(string path)
    {
        using var s = File.OpenRead(path);
        return JsonNode.Parse(s);
    }

    public static T? ReadFile<T>(string path) where T : class
    {
        using var s = File.OpenRead(path);
        return JsonSerializer.Deserialize<T>(s, Options);
    }

    public static string ToJson(object? value, bool pretty = false)
        => JsonSerializer.Serialize(value, pretty ? Pretty : Options);

    public static string ToJson(JsonNode? node, bool pretty = false)
        => node?.ToJsonString(pretty ? Pretty : Options) ?? "null";

    /// <summary>Substitute {tokens} in a string using a dictionary.</summary>
    public static string SubstituteTokens(string input, IReadOnlyDictionary<string, string?> tokens)
    {
        if (string.IsNullOrEmpty(input)) return input;
        foreach (var kv in tokens)
        {
            if (kv.Value is null) continue;
            input = input.Replace("{" + kv.Key + "}", kv.Value, StringComparison.OrdinalIgnoreCase);
        }
        return input;
    }
}
