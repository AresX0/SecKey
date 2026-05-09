using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using SecKey.Core;
using SecKey.Core.Configuration;
using SecKey.Core.Utilities;

namespace SecKey.Graph.Services.Win32Lob;

/// <summary>
/// Ports private/Intune/Upload-Win32Lob.ps1 (and helpers UploadFileToAzureStorage, UploadAzureStorageChunk,
/// FinalizeAzureStorageUpload, RenewAzureStorageUpload, WaitForFileProcessing, GetWin32AppBody, GetAppCommitBody).
/// </summary>
public sealed class Win32LobUploader
{
    private const string LobType = "microsoft.graph.win32LobApp";
    private const string MobileAppsPath = "deviceAppManagement/mobileApps";

    private readonly GraphHttpClient _graph;
    private readonly HttpClient _http;
    private readonly ILogger<Win32LobUploader> _log;

    public int ChunkSizeMb { get; init; } = 6;
    public int SasRenewalThresholdMs { get; init; } = 450_000;
    public int CompletionPollSeconds { get; init; } = 20;

    public Win32LobUploader(GraphHttpClient graph, HttpClient http, ILogger<Win32LobUploader> log)
    {
        _graph = graph;
        _http = http;
        _log = log;
    }

    public async Task<JsonNode> UploadAsync(IntuneAppConfig config, string intuneWinFile,
        byte[] logoPngBytes, IReadOnlyList<JsonNode> detectionRules, IReadOnlyList<JsonNode>? returnCodes,
        IProgress<UploadProgress>? progress = null, CancellationToken ct = default)
    {
        if (string.Equals(config.AppType, "Edge", StringComparison.OrdinalIgnoreCase))
            return await UploadEdgeAsync(config, ct);

        using var pkg = new IntuneWinPackage(intuneWinFile);

        var fileName = pkg.FileName;
        var setupFileName = pkg.SetupFile;

        // 1. Build app body
        var appBody = BuildAppBody(config, pkg, fileName, setupFileName, logoPngBytes);

        var detectionArr = new JsonArray();
        foreach (var d in detectionRules) detectionArr.Add(d.DeepClone());
        appBody["detectionRules"] = detectionArr;

        var rcArr = new JsonArray();
        foreach (var r in returnCodes ?? DefaultReturnCodesAsNodes()) rcArr.Add(r.DeepClone());
        appBody["returnCodes"] = rcArr;

        progress?.Report(new(UploadStage.CreatingApp, 0, "Creating mobile app"));
        var mobileApp = await _graph.PostAsync(MobileAppsPath, appBody, beta: true, ct)
            ?? throw new SecKeyException("Failed to create mobileApp");
        var appId = mobileApp["id"]!.GetValue<string>();

        // 2. Content version
        progress?.Report(new(UploadStage.CreatingContentVersion, 0.05));
        var contentVersion = await _graph.PostAsync(
            $"{MobileAppsPath}/{appId}/{LobType}/contentVersions", new JsonObject(), beta: true, ct)
            ?? throw new SecKeyException("Failed to create content version");
        var contentVersionId = contentVersion["id"]!.GetValue<string>();

        // 3. Extract inner file & encryption metadata
        var innerPath = pkg.ExtractInnerFile(fileName);
        try
        {
            var enc = pkg.EncryptionInfo;
            var encryptionInfo = new JsonObject
            {
                ["fileEncryptionInfo"] = new JsonObject
                {
                    ["encryptionKey"] = NormalizeBase64Value(GetEncElement(enc, "EncryptionKey"), 32, "EncryptionKey"),
                    ["macKey"] = NormalizeBase64Value(GetEncElement(enc, "MacKey"), 32, "MacKey"),
                    ["initializationVector"] = NormalizeBase64Value(GetEncElement(enc, "InitializationVector"), 16, "InitializationVector"),
                    ["mac"] = NormalizeBase64Value(GetEncElement(enc, "Mac"), 32, "Mac"),
                    ["profileIdentifier"] = "ProfileVersion1",
                    ["fileDigest"] = NormalizeBase64Value(GetEncElement(enc, "FileDigest"), 32, "FileDigest"),
                    ["fileDigestAlgorithm"] = GetEncElement(enc, "FileDigestAlgorithm")
                }
            };

            var unencryptedSize = pkg.UnencryptedContentSize;
            var encryptedSize = new FileInfo(innerPath).Length;

            // 4. Create file entry
            progress?.Report(new(UploadStage.CreatingFileEntry, 0.10));
            var fileBody = new JsonObject
            {
                ["@odata.type"] = "#microsoft.graph.mobileAppContentFile",
                ["name"] = fileName,
                ["size"] = unencryptedSize,
                ["sizeEncrypted"] = encryptedSize,
                ["manifest"] = null,
                ["isDependency"] = false
            };
            var filesUri = $"{MobileAppsPath}/{appId}/{LobType}/contentVersions/{contentVersionId}/files";
            var file = await _graph.PostAsync(filesUri, fileBody, beta: true, ct)
                       ?? throw new SecKeyException("Failed to create file entry");
            var fileId = file["id"]!.GetValue<string>();
            var fileUri = $"{MobileAppsPath}/{appId}/{LobType}/contentVersions/{contentVersionId}/files/{fileId}";

            // 5. Wait for SAS URI
            progress?.Report(new(UploadStage.WaitingForSasUri, 0.15));
            file = await WaitForFileStateAsync(fileUri, "AzureStorageUriRequest", ct);
            var sasUri = file["azureStorageUri"]!.GetValue<string>();

            // 6. Upload chunks
            progress?.Report(new(UploadStage.Uploading, 0.20));
            await UploadFileToAzureStorageAsync(sasUri, innerPath, fileUri, progress, ct);

            // 7. Commit file
            progress?.Report(new(UploadStage.Committing, 0.85));
            await _graph.PostAsync($"{fileUri}/commit", encryptionInfo, beta: true, ct);

            file = await WaitForFileStateAsync(fileUri, "CommitFile", ct);

            // 8. Commit app
            var commitBody = new JsonObject
            {
                ["@odata.type"] = "#" + LobType,
                ["committedContentVersion"] = contentVersionId
            };
            await _graph.PatchAsync($"{MobileAppsPath}/{appId}", commitBody, beta: true, ct);

            await Task.Delay(TimeSpan.FromSeconds(CompletionPollSeconds), ct);
            progress?.Report(new(UploadStage.Completed, 1.0));
            return mobileApp;
        }
        finally
        {
            try { File.Delete(innerPath); } catch { /* swallow */ }
        }
    }

    // XML element names in Detection.xml vary in casing across intunewin tool versions; match case-insensitively.
    private static string? GetEncElement(System.Xml.Linq.XElement parent, string name)
        => parent.Elements()
                 .FirstOrDefault(e => string.Equals(e.Name.LocalName, name, StringComparison.OrdinalIgnoreCase))
                 ?.Value;

    private static string NormalizeBase64Value(string? value, int expectedByteLength, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException($"Detection.xml is missing {fieldName}.");

        try
        {
            var bytes = Convert.FromBase64String(value.Trim());
            if (bytes.Length != expectedByteLength)
                throw new InvalidOperationException($"Detection.xml {fieldName} decoded to {bytes.Length} bytes, expected {expectedByteLength}.");

            return Convert.ToBase64String(bytes);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException($"Detection.xml {fieldName} is not valid base64.", ex);
        }
    }

    private async Task<JsonNode> UploadEdgeAsync(IntuneAppConfig config, CancellationToken ct)
    {
        var body = new JsonObject
        {
            ["@odata.type"] = "#microsoft.graph.windowsMicrosoftEdgeApp",
            ["displayName"] = config.DisplayName,
            ["description"] = config.Description,
            ["publisher"] = config.Publisher,
            ["isFeatured"] = false,
            ["privacyInformationUrl"] = "https://privacy.microsoft.com/en-US/privacystatement",
            ["informationUrl"] = "https://www.microsoft.com/en-us/windows/microsoft-edge",
            ["owner"] = "Microsoft",
            ["developer"] = "Microsoft",
            ["channel"] = config.Channel ?? "stable"
        };
        return await _graph.PostAsync(MobileAppsPath, body, beta: true, ct)
            ?? throw new SecKeyException("Failed to create Edge mobileApp");
    }

    private static JsonObject BuildAppBody(IntuneAppConfig cfg, IntuneWinPackage pkg, string fileName, string setupFileName, byte[] logo)
    {
        var b = new JsonObject
        {
            ["@odata.type"] = "#microsoft.graph.win32LobApp",
            ["description"] = cfg.Description,
            ["developer"] = "",
            ["displayName"] = cfg.DisplayName,
            ["fileName"] = fileName,
            ["installExperience"] = new JsonObject
            {
                ["runAsAccount"] = cfg.InstallExperience,
                ["deviceRestartBehavior"] = "suppress"
            },
            ["informationUrl"] = null,
            ["isFeatured"] = false,
            ["minimumSupportedOperatingSystem"] = new JsonObject { ["v10_2H20"] = true },
            ["notes"] = "",
            ["owner"] = "",
            ["privacyInformationUrl"] = null,
            ["publisher"] = cfg.Publisher,
            ["runAs32bit"] = false,
            ["setupFilePath"] = setupFileName,
            ["largeIcon"] = new JsonObject
            {
                ["type"] = "image/png",
                ["value"] = Convert.ToBase64String(logo)
            }
        };

        if (string.Equals(cfg.AppType, "MSI", StringComparison.OrdinalIgnoreCase))
        {
            var msi = pkg.MsiInfo ?? throw new InvalidOperationException("MsiInfo missing");
            var ctx = msi.Element("MsiExecutionContext")?.Value ?? "System";
            var packageType = ctx switch
            {
                "System" => "PerMachine",
                "User" => "PerUser",
                _ => "DualPurpose"
            };
            var productCode = msi.Element("MsiProductCode")?.Value ?? "";
            b["installCommandLine"] = string.IsNullOrEmpty(cfg.InstallCommandLine)
                ? $"msiexec /i \"{setupFileName}\""
                : $"msiexec /i \"{setupFileName}\" {cfg.InstallCommandLine}";
            b["uninstallCommandLine"] = string.IsNullOrEmpty(cfg.UninstallCommandLine)
                ? $"msiexec /x \"{productCode}\""
                : $"msiexec /x \"{productCode}\" {cfg.UninstallCommandLine}";
            b["msiInformation"] = new JsonObject
            {
                ["packageType"] = packageType,
                ["productCode"] = productCode,
                ["productName"] = cfg.DisplayName,
                ["productVersion"] = msi.Element("MsiProductVersion")?.Value,
                ["publisher"] = msi.Element("MsiPublisher")?.Value,
                ["requiresReboot"] = bool.TryParse(msi.Element("MsiRequiresReboot")?.Value, out var rr) && rr,
                ["upgradeCode"] = msi.Element("MsiUpgradeCode")?.Value
            };
            b["applicableArchitectures"] = "x64,x86";
        }
        else // EXE or PS1
        {
            var install = ResolveInstallCommandLine(cfg, setupFileName);
            var uninstall = ResolveUninstallCommandLine(cfg, setupFileName);

            b["installCommandLine"] = install;
            b["uninstallCommandLine"] = uninstall;
            b["msiInformation"] = null;
        }

        return b;
    }

    private static string ResolveInstallCommandLine(IntuneAppConfig cfg, string setupFileName)
    {
        if (!string.IsNullOrWhiteSpace(cfg.InstallCommandLine))
            return cfg.InstallCommandLine;

        if (string.Equals(cfg.AppType, "PS1", StringComparison.OrdinalIgnoreCase))
        {
            var userInstall = cfg.InstallExperience.Equals("user", StringComparison.OrdinalIgnoreCase)
                ? " -userInstall"
                : string.Empty;
            return $"powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\\{cfg.PackageName}.ps1 -Install{userInstall}";
        }

        // Safe non-empty fallback for EXE-style packages when command lines are not explicitly provided.
        return $".\\{setupFileName}";
    }

    private static string ResolveUninstallCommandLine(IntuneAppConfig cfg, string setupFileName)
    {
        if (!string.IsNullOrWhiteSpace(cfg.UninstallCommandLine))
            return cfg.UninstallCommandLine;

        if (string.Equals(cfg.AppType, "PS1", StringComparison.OrdinalIgnoreCase))
        {
            var userInstall = cfg.InstallExperience.Equals("user", StringComparison.OrdinalIgnoreCase)
                ? " -userInstall"
                : string.Empty;
            return $"powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\\{cfg.PackageName}.ps1 -UnInstall{userInstall}";
        }

        // Safe non-empty fallback for EXE-style packages when command lines are not explicitly provided.
        return $".\\{setupFileName}";
    }

    private static IEnumerable<JsonNode> DefaultReturnCodesAsNodes()
    {
        foreach (var rc in DefaultReturnCodes.Get())
        {
            var n = System.Text.Json.JsonSerializer.SerializeToNode(rc, JsonHelpers.Options);
            if (n is not null) yield return n;
        }
    }

    private async Task<JsonNode> WaitForFileStateAsync(string fileRelative, string stage, CancellationToken ct)
    {
        const int attempts = 600;
        var success = stage + "Success";
        var pending = stage + "Pending";
        for (int i = 0; i < attempts; i++)
        {
            var file = await _graph.GetAsync(fileRelative, beta: true, ct);
            var state = file?["uploadState"]?.GetValue<string>();
            if (string.Equals(state, success, StringComparison.OrdinalIgnoreCase)) return file!;
            if (!string.Equals(state, pending, StringComparison.OrdinalIgnoreCase))
                throw new SecKeyException($"File upload state is not successful: {state}");
            await Task.Delay(TimeSpan.FromSeconds(10), ct);
        }
        throw new SecKeyException("File request did not complete in the allotted time");
    }

    private async Task UploadFileToAzureStorageAsync(string sasUri, string filePath, string fileUri,
        IProgress<UploadProgress>? progress, CancellationToken ct)
    {
        var chunkSize = 1024L * 1024L * ChunkSizeMb;
        var fileSize = new FileInfo(filePath).Length;
        var chunks = (int)Math.Ceiling((double)fileSize / chunkSize);

        await using var fs = File.OpenRead(filePath);
        var ids = new List<string>(chunks);
        var sasTimer = System.Diagnostics.Stopwatch.StartNew();

        var buf = new byte[chunkSize];
        for (int i = 0; i < chunks; i++)
        {
            var id = Convert.ToBase64String(Encoding.ASCII.GetBytes(i.ToString("D4")));
            ids.Add(id);

            var len = (int)Math.Min(chunkSize, fileSize - fs.Position);
            await fs.ReadExactlyAsync(buf.AsMemory(0, len), ct);

            await PutBlockAsync(sasUri, id, buf, len, ct);

            if (i + 1 < chunks && sasTimer.ElapsedMilliseconds >= SasRenewalThresholdMs)
            {
                await _graph.PostAsync($"{fileUri}/renewUpload", new JsonObject(), beta: true, ct);
                sasTimer.Restart();
            }

            var pct = 0.20 + (0.65 * (i + 1) / chunks);
            progress?.Report(new(UploadStage.Uploading, pct, $"Chunk {i + 1}/{chunks}"));
        }

        await PutBlockListAsync(sasUri, ids, ct);
    }

    private async Task PutBlockAsync(string sasUri, string blockId, byte[] data, int length, CancellationToken ct)
    {
        var url = $"{sasUri}&comp=block&blockid={Uri.EscapeDataString(blockId)}";
        using var req = new HttpRequestMessage(HttpMethod.Put, url)
        {
            Content = new ByteArrayContent(data, 0, length)
        };
        req.Headers.Add("x-ms-blob-type", "BlockBlob");
        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            throw new SecKeyException($"Azure block PUT failed ({(int)resp.StatusCode}): {body}");
        }
    }

    private async Task PutBlockListAsync(string sasUri, IReadOnlyList<string> ids, CancellationToken ct)
    {
        var sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>");
        foreach (var id in ids) sb.Append($"<Latest>{id}</Latest>");
        sb.Append("</BlockList>");

        using var req = new HttpRequestMessage(HttpMethod.Put, sasUri + "&comp=blocklist")
        {
            Content = new StringContent(sb.ToString(), Encoding.UTF8, "application/xml")
        };
        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            throw new SecKeyException($"Azure block list PUT failed ({(int)resp.StatusCode}): {body}");
        }
    }
}

public enum UploadStage { CreatingApp, CreatingContentVersion, CreatingFileEntry, WaitingForSasUri, Uploading, Committing, Completed }

public sealed record UploadProgress(UploadStage Stage, double Fraction, string? Message = null);
