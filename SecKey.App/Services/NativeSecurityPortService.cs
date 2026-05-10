using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace SecKey.App.Services;

public sealed record VaultSecretItem(
    string Id,
    string Name,
    string Username,
    string SecretCipher,
    string Notes,
    DateTime UpdatedAtUtc);

public sealed record VaultSecretPlain(
    string Id,
    string Name,
    string Username,
    string Secret,
    string Notes,
    DateTime UpdatedAtUtc);

public sealed record YaraLiteRule(string Name, string Pattern, bool IsRegex, bool CaseSensitive);

public sealed record YaraLiteMatch(string FilePath, string RuleName, int MatchCount);

public sealed record CveEntry(string Id, string Summary, string Severity, string SourceUrl, DateTime? PublishedUtc);

public sealed record ProcessSnapshot(string Name, int Pid, string Path, bool Responding, long WorkingSetMb);

public sealed record TimelineEntry(DateTime Timestamp, string Source, string Message, string Level);

public sealed class NativeSecurityPortService
{
    private readonly string _dataRoot;
    private readonly string _vaultPath;

    public NativeSecurityPortService()
    {
        _dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "NativePort");
        Directory.CreateDirectory(_dataRoot);
        _vaultPath = Path.Combine(_dataRoot, "security-vault.json");
    }

    public List<VaultSecretItem> LoadVault()
    {
        if (!File.Exists(_vaultPath))
        {
            return [];
        }

        try
        {
            var json = File.ReadAllText(_vaultPath);
            var items = JsonSerializer.Deserialize<List<VaultSecretItem>>(json);
            return items ?? [];
        }
        catch
        {
            return [];
        }
    }

    public void SaveVault(List<VaultSecretItem> items)
    {
        var json = JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_vaultPath, json);
    }

    public VaultSecretItem ProtectSecret(string id, string name, string username, string secret, string notes)
    {
        var secretBytes = Encoding.UTF8.GetBytes(secret);
        var cipher = ProtectedData.Protect(secretBytes, null, DataProtectionScope.CurrentUser);
        return new VaultSecretItem(
            string.IsNullOrWhiteSpace(id) ? Guid.NewGuid().ToString("N") : id,
            name,
            username,
            Convert.ToBase64String(cipher),
            notes,
            DateTime.UtcNow);
    }

    public VaultSecretPlain UnprotectSecret(VaultSecretItem item)
    {
        var cipher = Convert.FromBase64String(item.SecretCipher);
        var plain = ProtectedData.Unprotect(cipher, null, DataProtectionScope.CurrentUser);
        return new VaultSecretPlain(item.Id, item.Name, item.Username, Encoding.UTF8.GetString(plain), item.Notes, item.UpdatedAtUtc);
    }

    public List<YaraLiteRule> ParseYaraLiteRules(string input)
    {
        var rules = new List<YaraLiteRule>();
        var lines = input.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.StartsWith("#", StringComparison.Ordinal) || line.Length == 0)
            {
                continue;
            }

            // Format: RuleName|pattern|regex|case
            var parts = line.Split('|');
            if (parts.Length < 2)
            {
                continue;
            }

            var ruleName = parts[0].Trim();
            var pattern = parts[1].Trim();
            var isRegex = parts.Length > 2 && parts[2].Trim().Equals("regex", StringComparison.OrdinalIgnoreCase);
            var caseSensitive = parts.Length > 3 && parts[3].Trim().Equals("case", StringComparison.OrdinalIgnoreCase);

            rules.Add(new YaraLiteRule(ruleName, pattern, isRegex, caseSensitive));
        }

        return rules;
    }

    public async Task<List<YaraLiteMatch>> ScanWithYaraLiteAsync(string targetPath, List<YaraLiteRule> rules, CancellationToken ct)
    {
        var matches = new List<YaraLiteMatch>();
        if (rules.Count == 0)
        {
            return matches;
        }

        var files = new List<string>();
        if (File.Exists(targetPath))
        {
            files.Add(targetPath);
        }
        else if (Directory.Exists(targetPath))
        {
            files.AddRange(Directory.EnumerateFiles(targetPath, "*", SearchOption.AllDirectories));
        }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            string content;
            try
            {
                var bytes = await File.ReadAllBytesAsync(file, ct);
                content = Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                continue;
            }

            foreach (var rule in rules)
            {
                var count = CountMatches(content, rule);
                if (count > 0)
                {
                    matches.Add(new YaraLiteMatch(file, rule.Name, count));
                }
            }
        }

        return matches;
    }

    private static int CountMatches(string content, YaraLiteRule rule)
    {
        if (rule.IsRegex)
        {
            var options = rule.CaseSensitive ? System.Text.RegularExpressions.RegexOptions.None : System.Text.RegularExpressions.RegexOptions.IgnoreCase;
            try
            {
                return System.Text.RegularExpressions.Regex.Matches(content, rule.Pattern, options).Count;
            }
            catch
            {
                return 0;
            }
        }

        var comparison = rule.CaseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        var index = 0;
        var count = 0;
        while (true)
        {
            index = content.IndexOf(rule.Pattern, index, comparison);
            if (index < 0)
            {
                break;
            }

            count++;
            index += Math.Max(1, rule.Pattern.Length);
        }

        return count;
    }

    public async Task<List<CveEntry>> SearchCvesAsync(string keyword, int take, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(keyword))
        {
            return [];
        }

        using var client = new HttpClient();
        client.Timeout = TimeSpan.FromSeconds(20);
        var url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={Uri.EscapeDataString(keyword)}&resultsPerPage={take}";
        var json = await client.GetStringAsync(url, ct);

        using var doc = JsonDocument.Parse(json);
        var results = new List<CveEntry>();
        if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulnerabilities))
        {
            return results;
        }

        foreach (var item in vulnerabilities.EnumerateArray())
        {
            if (!item.TryGetProperty("cve", out var cve))
            {
                continue;
            }

            var id = cve.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? "(unknown)" : "(unknown)";
            var summary = "";
            if (cve.TryGetProperty("descriptions", out var descs))
            {
                foreach (var d in descs.EnumerateArray())
                {
                    if (d.TryGetProperty("lang", out var lang) && string.Equals(lang.GetString(), "en", StringComparison.OrdinalIgnoreCase))
                    {
                        summary = d.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
                        break;
                    }
                }
            }

            var severity = "Unknown";
            if (cve.TryGetProperty("metrics", out var metrics))
            {
                if (metrics.TryGetProperty("cvssMetricV31", out var v31) && v31.GetArrayLength() > 0)
                {
                    severity = v31[0].GetProperty("cvssData").GetProperty("baseSeverity").GetString() ?? "Unknown";
                }
                else if (metrics.TryGetProperty("cvssMetricV30", out var v30) && v30.GetArrayLength() > 0)
                {
                    severity = v30[0].GetProperty("cvssData").GetProperty("baseSeverity").GetString() ?? "Unknown";
                }
            }

            DateTime? published = null;
            if (cve.TryGetProperty("published", out var publishedEl) && DateTime.TryParse(publishedEl.GetString(), out var pubDt))
            {
                published = pubDt;
            }

            results.Add(new CveEntry(
                id,
                summary,
                severity,
                $"https://nvd.nist.gov/vuln/detail/{id}",
                published));
        }

        return results;
    }

    public List<ProcessSnapshot> CaptureProcessSnapshot(int maxItems = 300)
    {
        var list = new List<ProcessSnapshot>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                list.Add(new ProcessSnapshot(
                    process.ProcessName,
                    process.Id,
                    process.MainModule?.FileName ?? string.Empty,
                    process.Responding,
                    process.WorkingSet64 / (1024 * 1024)));
            }
            catch
            {
                // Ignore inaccessible process details.
            }
        }

        return list.OrderByDescending(x => x.WorkingSetMb).Take(maxItems).ToList();
    }

    public List<TimelineEntry> CaptureRecentTimeline(int maxEventsPerLog = 120)
    {
        var entries = new List<TimelineEntry>();
        var logNames = new[] { "System", "Application", "Security" };
        foreach (var logName in logNames)
        {
            try
            {
                using var log = new EventLog(logName);
                var count = log.Entries.Count;
                var start = Math.Max(0, count - maxEventsPerLog);
                for (var i = count - 1; i >= start; i--)
                {
                    var entry = log.Entries[i];
                    entries.Add(new TimelineEntry(
                        entry.TimeGenerated,
                        logName,
                        Truncate(entry.Message, 280),
                        entry.EntryType.ToString()));
                }
            }
            catch
            {
                // Ignore inaccessible logs.
            }
        }

        return entries.OrderByDescending(x => x.Timestamp).ToList();
    }

    public List<string> ReadGsaPolicyFiles(string workspaceRoot)
    {
        var candidates = new[]
        {
            Path.Combine(workspaceRoot, "archive", "newPaw", "PAWCSM", "JSON", "GlobalSecureAccess"),
            Path.Combine(workspaceRoot, "JSON", "GlobalSecureAccess")
        };

        foreach (var folder in candidates)
        {
            if (Directory.Exists(folder))
            {
                return Directory.EnumerateFiles(folder, "*.json", SearchOption.AllDirectories).OrderBy(x => x).ToList();
            }
        }

        return [];
    }

    public List<string> ReadWdacAppLockerProfiles(string workspaceRoot)
    {
        var roots = new[]
        {
            Path.Combine(workspaceRoot, "JSON", "DeviceConfiguration"),
            Path.Combine(workspaceRoot, "archive", "newPaw", "PAWCSM", "JSON", "DeviceConfiguration")
        };

        var profiles = new List<string>();
        foreach (var root in roots)
        {
            if (!Directory.Exists(root))
            {
                continue;
            }

            profiles.AddRange(Directory.EnumerateFiles(root, "*AppLocker*.json", SearchOption.AllDirectories));
            profiles.AddRange(Directory.EnumerateFiles(root, "*WDAC*.json", SearchOption.AllDirectories));
        }

        return profiles.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToList();
    }

    public string DecodeEmbeddedPolicyXml(string jsonPath)
    {
        var json = File.ReadAllText(jsonPath);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var base64Candidates = new List<string>();
        CollectPotentialBase64(root, base64Candidates);
        foreach (var candidate in base64Candidates)
        {
            try
            {
                var bytes = Convert.FromBase64String(candidate);
                var text = Encoding.UTF8.GetString(bytes);
                if (text.Contains("<RuleCollection", StringComparison.OrdinalIgnoreCase)
                    || text.Contains("<AppLockerPolicy", StringComparison.OrdinalIgnoreCase))
                {
                    return text;
                }
            }
            catch
            {
                // Not base64 policy payload.
            }
        }

        return string.Empty;
    }

    private static void CollectPotentialBase64(JsonElement el, List<string> output)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    CollectPotentialBase64(prop.Value, output);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                {
                    CollectPotentialBase64(item, output);
                }
                break;
            case JsonValueKind.String:
                var value = el.GetString();
                if (!string.IsNullOrWhiteSpace(value) && value.Length > 200)
                {
                    output.Add(value);
                }
                break;
        }
    }

    private static string Truncate(string input, int maxLength)
    {
        if (string.IsNullOrEmpty(input) || input.Length <= maxLength)
        {
            return input;
        }

        return input[..maxLength] + "...";
    }
}
