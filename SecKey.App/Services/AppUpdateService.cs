using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SecKey.App.Services;

public sealed record AppUpdateAsset(string Name, string DownloadUrl, long Size);

public sealed record AppReleaseInfo(
    string Tag,
    Version Version,
    string Title,
    string HtmlUrl,
    string Notes,
    IReadOnlyList<AppUpdateAsset> Assets);

public sealed record AppUpdateCheckResult(bool IsUpdateAvailable, Version CurrentVersion, AppReleaseInfo? Release, string Message);

public sealed record AppUpdateInstallResult(bool Started, string Message);

public sealed class AppUpdateService
{
    private const string RepoOwner = "AresX0";
    private const string RepoName = "SecKey";
    private const string ReleasesLatestUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases/latest";
    private const string ReleasesListUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases?per_page=20";

    public async Task<AppUpdateCheckResult> CheckForUpdateAsync(CancellationToken ct = default)
    {
        var currentVersion = GetCurrentVersion();

        try
        {
            using var http = CreateGitHubClient();
            var release = await ResolveLatestReleaseAsync(http, ct);
            if (release is null)
            {
                return new AppUpdateCheckResult(false, currentVersion, null, "No usable release metadata was found from GitHub.");
            }

            var updateAvailable = release.Version > currentVersion;
            var message = updateAvailable
                ? $"Update available: {release.Version} (current {currentVersion})."
                : $"SecKey is up to date ({currentVersion}).";

            return new AppUpdateCheckResult(updateAvailable, currentVersion, release, message);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return new AppUpdateCheckResult(false, currentVersion, null,
                "Update metadata was not found (HTTP 404). If this repository is private, set GITHUB_TOKEN or SECKEY_GITHUB_TOKEN for authenticated update checks.");
        }
        catch (Exception ex)
        {
            return new AppUpdateCheckResult(false, currentVersion, null, $"Update check failed: {ex.Message}");
        }
    }

    public async Task<AppUpdateInstallResult> StartUpdateAsync(AppReleaseInfo release, CancellationToken ct = default)
    {
        var preferredAsset = PickInstallAsset(release.Assets);
        if (preferredAsset is null)
        {
            return new AppUpdateInstallResult(false, "No installable asset was found in the release. Open release page to update manually.");
        }

        var tempDir = Path.Combine(Path.GetTempPath(), "SecKey", "Updates", release.Tag);
        Directory.CreateDirectory(tempDir);
        var downloadPath = Path.Combine(tempDir, preferredAsset.Name);

        using (var http = new HttpClient())
        {
            http.DefaultRequestHeaders.UserAgent.ParseAdd("SecKey.App/Updater");
            using var response = await http.GetAsync(preferredAsset.DownloadUrl, ct);
            response.EnsureSuccessStatusCode();
            await using var src = await response.Content.ReadAsStreamAsync(ct);
            await using var dst = File.Create(downloadPath);
            await src.CopyToAsync(dst, ct);
        }

        var ext = Path.GetExtension(downloadPath).ToLowerInvariant();
        if (ext is ".msi" or ".exe")
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = downloadPath,
                UseShellExecute = true
            });

            return new AppUpdateInstallResult(true, "Installer launched. SecKey will close so the update can continue.");
        }

        if (ext == ".zip")
        {
            var appDir = AppContext.BaseDirectory;
            var currentExe = Environment.ProcessPath ?? Path.Combine(appDir, "SecKey.App.exe");
            var exeName = Path.GetFileName(currentExe);
            var updaterScript = CreateZipUpdaterScript(tempDir);

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = true,
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{updaterScript}\" -ProcessId {Environment.ProcessId} -ZipPath \"{downloadPath}\" -InstallDir \"{appDir}\" -ExeName \"{exeName}\""
            };
            Process.Start(psi);

            return new AppUpdateInstallResult(true, "Updater started. SecKey will close and relaunch after files are updated.");
        }

        return new AppUpdateInstallResult(false, "Downloaded release asset type is not supported for automatic update.");
    }

    private static AppUpdateAsset? PickInstallAsset(IReadOnlyList<AppUpdateAsset> assets)
    {
        static bool HasExt(AppUpdateAsset asset, string ext) =>
            asset.Name.EndsWith(ext, StringComparison.OrdinalIgnoreCase);

        // Prefer architecture-specific MSI first, then generic MSI/EXE/ZIP.
        return assets.FirstOrDefault(a => HasExt(a, ".msi") && a.Name.Contains("win-x64", StringComparison.OrdinalIgnoreCase))
            ?? assets.FirstOrDefault(a => HasExt(a, ".msi"))
            ?? assets.FirstOrDefault(a => HasExt(a, ".exe"))
            ?? assets.FirstOrDefault(a => HasExt(a, ".zip"));
    }

    private static HttpClient CreateGitHubClient()
    {
        var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.ParseAdd("SecKey.App/UpdateChecker");

        var token = Environment.GetEnvironmentVariable("SECKEY_GITHUB_TOKEN")
            ?? Environment.GetEnvironmentVariable("GITHUB_TOKEN");

        if (!string.IsNullOrWhiteSpace(token))
        {
            http.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        }

        return http;
    }

    private static async Task<AppReleaseInfo?> ResolveLatestReleaseAsync(HttpClient http, CancellationToken ct)
    {
        using var latestResponse = await http.GetAsync(ReleasesLatestUrl, ct);
        if (latestResponse.IsSuccessStatusCode)
        {
            var latestJson = await latestResponse.Content.ReadAsStringAsync(ct);
            using var latestDoc = JsonDocument.Parse(latestJson);
            return ParseRelease(latestDoc.RootElement);
        }

        // Some repos/channels return 404 for /latest. Fall back to /releases list and pick the best non-draft release.
        if (latestResponse.StatusCode != System.Net.HttpStatusCode.NotFound)
        {
            latestResponse.EnsureSuccessStatusCode();
        }

        using var listResponse = await http.GetAsync(ReleasesListUrl, ct);
        listResponse.EnsureSuccessStatusCode();

        var listJson = await listResponse.Content.ReadAsStringAsync(ct);
        using var listDoc = JsonDocument.Parse(listJson);
        if (listDoc.RootElement.ValueKind != JsonValueKind.Array)
            return null;

        AppReleaseInfo? bestStable = null;
        AppReleaseInfo? bestAny = null;

        foreach (var releaseNode in listDoc.RootElement.EnumerateArray())
        {
            if (releaseNode.TryGetProperty("draft", out var draftNode) && draftNode.ValueKind == JsonValueKind.True)
                continue;

            var parsed = ParseRelease(releaseNode);
            if (parsed is null)
                continue;

            if (bestAny is null || parsed.Version > bestAny.Version)
                bestAny = parsed;

            var isPrerelease = releaseNode.TryGetProperty("prerelease", out var prereleaseNode) && prereleaseNode.ValueKind == JsonValueKind.True;
            if (!isPrerelease && (bestStable is null || parsed.Version > bestStable.Version))
                bestStable = parsed;
        }

        return bestStable ?? bestAny;
    }

    private static AppReleaseInfo? ParseRelease(JsonElement root)
    {
        var tag = root.TryGetProperty("tag_name", out var tagNode) ? (tagNode.GetString() ?? string.Empty) : string.Empty;
        if (!TryParseVersionFromTag(tag, out var latestVersion))
            return null;

        var title = root.TryGetProperty("name", out var nameNode) ? (nameNode.GetString() ?? tag) : tag;
        var htmlUrl = root.TryGetProperty("html_url", out var urlNode) ? (urlNode.GetString() ?? string.Empty) : string.Empty;
        var notes = root.TryGetProperty("body", out var bodyNode) ? (bodyNode.GetString() ?? string.Empty) : string.Empty;

        var assets = new List<AppUpdateAsset>();
        if (root.TryGetProperty("assets", out var assetsNode) && assetsNode.ValueKind == JsonValueKind.Array)
        {
            foreach (var asset in assetsNode.EnumerateArray())
            {
                var assetName = asset.TryGetProperty("name", out var assetNameNode)
                    ? (assetNameNode.GetString() ?? string.Empty)
                    : string.Empty;
                var assetUrl = asset.TryGetProperty("browser_download_url", out var assetUrlNode)
                    ? (assetUrlNode.GetString() ?? string.Empty)
                    : string.Empty;
                var assetSize = asset.TryGetProperty("size", out var assetSizeNode) && assetSizeNode.TryGetInt64(out var size)
                    ? size
                    : 0L;

                if (!string.IsNullOrWhiteSpace(assetName) && !string.IsNullOrWhiteSpace(assetUrl))
                {
                    assets.Add(new AppUpdateAsset(assetName, assetUrl, assetSize));
                }
            }
        }

        return new AppReleaseInfo(tag, latestVersion, title, htmlUrl, notes, assets);
    }

    private static string CreateZipUpdaterScript(string dir)
    {
        var scriptPath = Path.Combine(dir, "apply-update.ps1");
        var script = """
param(
    [int]$ProcessId,
    [string]$ZipPath,
    [string]$InstallDir,
    [string]$ExeName
)

$ErrorActionPreference = 'Stop'

try {
    Wait-Process -Id $ProcessId -ErrorAction SilentlyContinue

    $extractRoot = Join-Path ([System.IO.Path]::GetDirectoryName($ZipPath)) 'extract'
    if (Test-Path $extractRoot) {
        Remove-Item -LiteralPath $extractRoot -Recurse -Force
    }

    Expand-Archive -LiteralPath $ZipPath -DestinationPath $extractRoot -Force

    $sourceDir = $extractRoot
    $children = Get-ChildItem -LiteralPath $extractRoot
    if ($children.Count -eq 1 -and $children[0].PSIsContainer) {
        $sourceDir = $children[0].FullName
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    robocopy $sourceDir $InstallDir /E /R:2 /W:1 | Out-Null

    $exePath = Join-Path $InstallDir $ExeName
    if (Test-Path $exePath) {
        Start-Process -FilePath $exePath | Out-Null
    }
}
catch {
    [System.Windows.MessageBox]::Show("SecKey update failed: $($_.Exception.Message)", "SecKey Updater") | Out-Null
}
""";

        File.WriteAllText(scriptPath, script);
        return scriptPath;
    }

    private static Version GetCurrentVersion()
    {
        var executablePath = Environment.ProcessPath ?? Assembly.GetEntryAssembly()?.Location;
        if (!string.IsNullOrWhiteSpace(executablePath) && File.Exists(executablePath))
        {
            var fileVersion = FileVersionInfo.GetVersionInfo(executablePath).FileVersion;
            if (Version.TryParse(fileVersion, out var parsedVersion))
                return parsedVersion;
        }

        var entry = Assembly.GetEntryAssembly();
        if (entry?.GetName().Version is { } v)
            return v;

        return new Version(0, 0, 0, 0);
    }

    private static bool TryParseVersionFromTag(string tag, out Version version)
    {
        version = new Version(0, 0, 0, 0);
        if (string.IsNullOrWhiteSpace(tag))
            return false;

        var normalized = tag.Trim().TrimStart('v', 'V');
        var suffixIndex = normalized.IndexOf('-');
        if (suffixIndex > 0)
            normalized = normalized[..suffixIndex];

        return Version.TryParse(normalized, out version);
    }
}