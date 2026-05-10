using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecKey.App.ViewModels;

namespace SecKey.App.Services;

public sealed class JsonPolicySettingsService
{
    private static readonly string DefaultSnapshotRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SecKey",
        "JsonDefaultsSnapshot");

    private readonly string _snapshotRoot;

    public JsonPolicySettingsService()
        : this(DefaultSnapshotRoot)
    {
    }

    public JsonPolicySettingsService(string snapshotRoot)
    {
        _snapshotRoot = snapshotRoot;
    }

    public IReadOnlyList<JsonPolicySettingItemViewModel> LoadAllSettings(string repoRoot)
    {
        var files = ResolveManifestJsonFiles(repoRoot)
            .Where(File.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var items = new List<JsonPolicySettingItemViewModel>();
        foreach (var file in files)
        {
            try
            {
                var json = JsonNode.Parse(File.ReadAllText(file));
                if (json is null)
                    continue;

                var relative = Path.GetRelativePath(repoRoot, file).Replace('\\', '/');
                var category = ResolveCategory(relative);
                var azureUrl = ResolveAzureUrl(relative);

                FlattenLeaves(json, "$", (path, value, type) =>
                {
                    var displayName = BuildDisplayName(path);
                    items.Add(new JsonPolicySettingItemViewModel(
                        category,
                        displayName,
                        relative,
                        file,
                        path,
                        value,
                        type,
                        azureUrl));
                });
            }
            catch
            {
                // Ignore malformed files and continue loading the rest.
            }
        }

        return items
            .OrderBy(i => i.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.RelativeFilePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.JsonPath, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public int SaveCurrentAsDefaults(string repoRoot)
    {
        var files = ResolveManifestJsonFiles(repoRoot)
            .Where(File.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (Directory.Exists(_snapshotRoot))
            Directory.Delete(_snapshotRoot, true);
        Directory.CreateDirectory(_snapshotRoot);

        var copied = 0;
        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(repoRoot, file);
            var target = Path.Combine(_snapshotRoot, relative);
            var parent = Path.GetDirectoryName(target);
            if (!string.IsNullOrWhiteSpace(parent))
                Directory.CreateDirectory(parent);

            File.Copy(file, target, true);
            copied++;
        }

        return copied;
    }

    public int ResetToSavedDefaults(string repoRoot)
    {
        if (!Directory.Exists(_snapshotRoot))
            return 0;

        var snapshotFiles = Directory
            .EnumerateFiles(_snapshotRoot, "*.json", SearchOption.AllDirectories)
            .ToList();

        var restored = 0;
        foreach (var file in snapshotFiles)
        {
            var relative = Path.GetRelativePath(_snapshotRoot, file);
            var destination = Path.Combine(repoRoot, relative);
            var parent = Path.GetDirectoryName(destination);
            if (!string.IsNullOrWhiteSpace(parent))
                Directory.CreateDirectory(parent);

            File.Copy(file, destination, true);
            restored++;
        }

        return restored;
    }

    public bool SaveSetting(JsonPolicySettingItemViewModel item, out string error)
    {
        error = string.Empty;
        try
        {
            var root = JsonNode.Parse(File.ReadAllText(item.AbsoluteFilePath));
            if (root is null)
            {
                error = "Invalid JSON file.";
                return false;
            }

            if (!TrySetLeafValue(root, item.JsonPath, item.Value, item.ValueType, out error))
                return false;

            var jsonText = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(item.AbsoluteFilePath, jsonText + Environment.NewLine, Encoding.UTF8);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static IEnumerable<string> ResolveManifestJsonFiles(string repoRoot)
    {
        var manifestFiles = new[]
        {
            Path.Combine(repoRoot, "JSON", "seckey.deploy.json"),
            Path.Combine(repoRoot, "JSON", "seckey.optional.deploy.json")
        };

        foreach (var manifest in manifestFiles)
        {
            if (!File.Exists(manifest))
                continue;

            var root = JsonNode.Parse(File.ReadAllText(manifest));
            var commands = root?["commandList"]?.AsArray();
            if (commands is null)
                continue;

            foreach (var cmd in commands.OfType<JsonObject>())
            {
                var list = cmd["parameters"]?["JSONFileList"]?.AsArray();
                if (list is null)
                    continue;

                foreach (var fileNode in list)
                {
                    var raw = fileNode?.GetValue<string>();
                    if (string.IsNullOrWhiteSpace(raw))
                        continue;

                    var expanded = raw!
                        .Replace("[PROJECTPATH]", repoRoot, StringComparison.OrdinalIgnoreCase)
                        .Replace('/', Path.DirectorySeparatorChar)
                        .Replace('\\', Path.DirectorySeparatorChar);

                    yield return Path.GetFullPath(expanded);
                }
            }
        }
    }

    private static void FlattenLeaves(JsonNode node, string path, Action<string, string, string> onLeaf)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var kv in obj)
                {
                    if (kv.Value is null)
                        continue;
                    var childPath = $"{path}.{kv.Key}";
                    FlattenLeaves(kv.Value, childPath, onLeaf);
                }
                break;

            case JsonArray arr:
                for (var i = 0; i < arr.Count; i++)
                {
                    var v = arr[i];
                    if (v is null)
                        continue;
                    var childPath = $"{path}[{i}]";
                    FlattenLeaves(v, childPath, onLeaf);
                }
                break;

            case JsonValue val:
                var kind = val.GetValue<JsonElement>().ValueKind;
                var type = kind.ToString();
                onLeaf(path, ExtractValueString(val), type);
                break;
        }
    }

    private static string ExtractValueString(JsonValue val)
    {
        var elem = val.GetValue<JsonElement>();
        return elem.ValueKind switch
        {
            JsonValueKind.String => elem.GetString() ?? string.Empty,
            JsonValueKind.Number => elem.ToString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => string.Empty,
            _ => elem.ToString()
        };
    }

    private static bool TrySetLeafValue(JsonNode root, string path, string newValue, string valueType, out string error)
    {
        error = string.Empty;
        var tokens = TokenizePath(path);
        if (tokens.Count == 0)
        {
            error = "Invalid JSON path.";
            return false;
        }

        JsonNode? current = root;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            var token = tokens[i];
            current = token.IsIndex
                ? (current as JsonArray)?[token.Index]
                : (current as JsonObject)?[token.PropertyName!];

            if (current is null)
            {
                error = "Path not found in JSON.";
                return false;
            }
        }

        var last = tokens[^1];
        var replacement = ParseReplacementValue(newValue, valueType, out error);
        if (error.Length > 0)
            return false;

        if (last.IsIndex)
        {
            var arr = current as JsonArray;
            if (arr is null || last.Index < 0 || last.Index >= arr.Count)
            {
                error = "Array target not found.";
                return false;
            }

            arr[last.Index] = replacement;
            return true;
        }

        var obj = current as JsonObject;
        if (obj is null || last.PropertyName is null)
        {
            error = "Object target not found.";
            return false;
        }

        obj[last.PropertyName] = replacement;
        return true;
    }

    private static JsonNode? ParseReplacementValue(string input, string valueType, out string error)
    {
        error = string.Empty;
        var normalizedType = valueType?.Trim() ?? string.Empty;

        if (normalizedType.Equals("True", StringComparison.OrdinalIgnoreCase) ||
            normalizedType.Equals("False", StringComparison.OrdinalIgnoreCase) ||
            normalizedType.Equals("Boolean", StringComparison.OrdinalIgnoreCase))
        {
            if (bool.TryParse(input, out var b))
                return JsonValue.Create(b);

            error = "Expected boolean value (true/false).";
            return null;
        }

        if (normalizedType.Equals("Number", StringComparison.OrdinalIgnoreCase))
        {
            if (long.TryParse(input, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l))
                return JsonValue.Create(l);
            if (double.TryParse(input, NumberStyles.Float, CultureInfo.InvariantCulture, out var d))
                return JsonValue.Create(d);

            error = "Expected numeric value.";
            return null;
        }

        if (normalizedType.Equals("Null", StringComparison.OrdinalIgnoreCase))
        {
            return string.IsNullOrWhiteSpace(input) ? null : JsonValue.Create(input);
        }

        return JsonValue.Create(input);
    }

    private static List<PathToken> TokenizePath(string path)
    {
        var tokens = new List<PathToken>();
        if (string.IsNullOrWhiteSpace(path) || !path.StartsWith("$", StringComparison.Ordinal))
            return tokens;

        var matches = Regex.Matches(path, @"\.?([A-Za-z0-9_\-]+)|\[(\d+)\]");
        foreach (Match m in matches)
        {
            if (m.Groups[2].Success)
            {
                if (int.TryParse(m.Groups[2].Value, out var idx))
                    tokens.Add(PathToken.ForIndex(idx));
                continue;
            }

            if (m.Groups[1].Success)
                tokens.Add(PathToken.ForProperty(m.Groups[1].Value));
        }

        return tokens;
    }

    private static string BuildDisplayName(string jsonPath)
    {
        var trimmed = jsonPath.TrimStart('$', '.');
        if (trimmed.Length == 0)
            return jsonPath;

        var parts = Regex.Split(trimmed, @"\.|\[\d+\]")
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .ToArray();

        return parts.Length == 0 ? jsonPath : parts[^1];
    }

    private static string ResolveCategory(string relativePath)
    {
        var p = relativePath.Replace('\\', '/');

        if (p.Contains("/AutoPilot/", StringComparison.OrdinalIgnoreCase)) return "Autopilot";
        if (p.Contains("/EndpointSecurity/", StringComparison.OrdinalIgnoreCase)) return "Endpoint Security";
        if (p.Contains("/DeviceConfiguration/", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("/DeviceConfigurationADMX/", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("/DeviceSettingsCatalog/", StringComparison.OrdinalIgnoreCase)) return "Configuration Profiles";
        if (p.Contains("/DeviceCompliancePolicies/", StringComparison.OrdinalIgnoreCase)) return "Compliance Policies";
        if (p.Contains("/ConditionalAccessPolicy/", StringComparison.OrdinalIgnoreCase)) return "Conditional Access";
        if (p.Contains("/AuthenticationContext/", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("/AuthenticationStrength/", StringComparison.OrdinalIgnoreCase)) return "Auth Context and Strength";
        if (p.Contains("/IntuneApps/", StringComparison.OrdinalIgnoreCase)) return "Intune Apps";
        if (p.Contains("/RemediationScripts/", StringComparison.OrdinalIgnoreCase)) return "Remediation Scripts";
        if (p.Contains("/PlatformScripts/", StringComparison.OrdinalIgnoreCase)) return "Platform Scripts";
        if (p.Contains("/ReusableSettings/", StringComparison.OrdinalIgnoreCase)) return "Reusable Settings";

        return "Other";
    }

    private static string ResolveAzureUrl(string relativePath)
    {
        var p = relativePath.Replace('\\', '/');

        if (p.Contains("/AutoPilot/", StringComparison.OrdinalIgnoreCase))
            return "https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/AutopilotDevices.ReactView";
        if (p.Contains("/EndpointSecurity/", StringComparison.OrdinalIgnoreCase))
            return "https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/endpointSecurity";
        if (p.Contains("/DeviceConfiguration/", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("/DeviceConfigurationADMX/", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("/DeviceSettingsCatalog/", StringComparison.OrdinalIgnoreCase))
            return "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/configurationProfiles";
        if (p.Contains("/DeviceCompliancePolicies/", StringComparison.OrdinalIgnoreCase))
            return "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/compliancePolicies";
        if (p.Contains("/ConditionalAccessPolicy/", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("/AuthenticationContext/", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("/AuthenticationStrength/", StringComparison.OrdinalIgnoreCase))
            return "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade";
        if (p.Contains("/IntuneApps/", StringComparison.OrdinalIgnoreCase))
            return "https://intune.microsoft.com/#view/Microsoft_Intune_Apps/AppsMenu/~/appApps";
        if (p.Contains("/PlatformScripts/", StringComparison.OrdinalIgnoreCase))
            return "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/scripts";
        if (p.Contains("/RemediationScripts/", StringComparison.OrdinalIgnoreCase))
            return "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/proactiveRemediations";

        return "https://intune.microsoft.com/";
    }

    private readonly struct PathToken
    {
        public bool IsIndex { get; }
        public int Index { get; }
        public string? PropertyName { get; }

        private PathToken(bool isIndex, int index, string? propertyName)
        {
            IsIndex = isIndex;
            Index = index;
            PropertyName = propertyName;
        }

        public static PathToken ForIndex(int index) => new(true, index, null);
        public static PathToken ForProperty(string name) => new(false, -1, name);
    }
}
