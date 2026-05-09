using System.IO.Compression;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SecKey.Graph.Services.EntraID;
using SecKey.Graph.Services.Intune;

namespace SecKey.Graph.Services;

public sealed class SettingsImportSummary
{
    public int CreatedCount { get; set; }
    public int SkippedCount { get; set; }
    public int ScannedFiles { get; set; }
    public List<string> Notes { get; } = new();

    public string ToStatusText()
        => $"Imported {CreatedCount} items, skipped {SkippedCount}, scanned {ScannedFiles} files.";
}

public sealed class SettingsImportService
{
    private readonly GraphHttpClient _client;
    private readonly ILoggerFactory _loggerFactory;

    public SettingsImportService(GraphHttpClient client, ILoggerFactory? loggerFactory = null)
    {
        _client = client;
        _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
    }

    public async Task<SettingsImportSummary> ImportSecurityBaselineAsync(
        string? baselineZipPath,
        string repoRoot,
        CancellationToken ct = default)
    {
        var summary = new SettingsImportSummary();

        // Microsoft security baseline ZIPs are GPO-centric. If no JSON payload exists,
        // fall back to importing the repo's curated Intune baseline JSON.
        if (!string.IsNullOrWhiteSpace(baselineZipPath) && File.Exists(baselineZipPath))
        {
            if (ZipContainsJson(baselineZipPath))
            {
                var fromZip = await ImportExportedSettingsAsync(baselineZipPath, ct);
                Merge(summary, fromZip);
                summary.Notes.Add("Imported JSON payload from baseline ZIP.");
                return summary;
            }

            summary.Notes.Add("Baseline ZIP contains GPO artifacts; applying curated Intune baseline from repository JSON.");
        }

        var curated = await ImportDefaultRepositoryBaselineAsync(repoRoot, ct);
        Merge(summary, curated);
        return summary;
    }

    public async Task<SettingsImportSummary> ImportExportedSettingsAsync(string pathOrZip, CancellationToken ct = default)
    {
        var summary = new SettingsImportSummary();
        var workDir = pathOrZip;
        var tempDir = string.Empty;

        if (File.Exists(pathOrZip) &&
            Path.GetExtension(pathOrZip).Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            tempDir = Path.Combine(Path.GetTempPath(), "seckey-import-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            ZipFile.ExtractToDirectory(pathOrZip, tempDir);
            workDir = tempDir;
        }

        try
        {
            if (!Directory.Exists(workDir))
            {
                summary.Notes.Add($"Import path not found: {workDir}");
                return summary;
            }

            var files = Directory.EnumerateFiles(workDir, "*.json", SearchOption.AllDirectories).ToArray();
            summary.ScannedFiles += files.Length;

            var complianceFiles = new List<string>();
            var configFiles = new List<string>();
            var settingsCatalogFiles = new List<string>();
            var caFiles = new List<string>();
            var namedLocationFiles = new List<string>();
            var endpointFiles = new List<string>();

            foreach (var file in files)
            {
                var key = file.Replace('\\', '/').ToLowerInvariant();
                if (key.Contains("conditionalaccess") && key.Contains("namedlocation"))
                    namedLocationFiles.Add(file);
                else if (key.Contains("conditionalaccess"))
                    caFiles.Add(file);
                else if (key.Contains("devicecompliance"))
                    complianceFiles.Add(file);
                else if (key.Contains("devicesettingscatalog") || key.Contains("configurationpolicies"))
                    settingsCatalogFiles.Add(file);
                else if (key.Contains("endpointsecurity") || key.Contains("/intents/"))
                    endpointFiles.Add(file);
                else if (key.Contains("deviceconfiguration"))
                    configFiles.Add(file);
                else
                    summary.SkippedCount++;
            }

            await ImportWithPolicyImporterAsync(new DeviceCompliancePolicyService(_client), complianceFiles, summary, ct);
            await ImportWithPolicyImporterAsync(new DeviceConfigurationService(_client), configFiles, summary, ct);
            await ImportWithPolicyImporterAsync(new DeviceSettingsCatalogService(_client), settingsCatalogFiles, summary, ct);
            await ImportWithPolicyImporterAsync(new ConditionalAccessPolicyService(_client), caFiles, summary, ct);
            await ImportWithPolicyImporterAsync(new NamedLocationService(_client), namedLocationFiles, summary, ct);

            if (endpointFiles.Count > 0)
            {
                var endpointImporter = new EndpointSecurityImporter(
                    new EndpointSecurityPolicyService(_client),
                    new EntraIdGroupService(_client),
                    _loggerFactory.CreateLogger<EndpointSecurityImporter>());
                var created = await endpointImporter.ImportAsync(endpointFiles, ct);
                summary.CreatedCount += created.Count(n => n is not null);
                summary.SkippedCount += Math.Max(0, endpointFiles.Count - created.Count);
            }
        }
        finally
        {
            if (!string.IsNullOrEmpty(tempDir) && Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }

        return summary;
    }

    public async Task<SettingsImportSummary> ImportDefaultRepositoryBaselineAsync(string repoRoot, CancellationToken ct = default)
    {
        var summary = new SettingsImportSummary();
        var jsonRoot = Path.Combine(repoRoot, "JSON");
        if (!Directory.Exists(jsonRoot))
        {
            summary.Notes.Add($"Repository JSON folder not found: {jsonRoot}");
            return summary;
        }

        var complianceFiles = FindCsmFiles(Path.Combine(jsonRoot, "DeviceCompliancePolicies"));
        var configFiles = FindCsmFiles(Path.Combine(jsonRoot, "DeviceConfiguration"));
        var settingsCatalogFiles = FindCsmFiles(Path.Combine(jsonRoot, "DeviceSettingsCatalog"));
        var caFiles = FindCsmFiles(Path.Combine(jsonRoot, "ConditionalAccessPolicy"))
            .Where(f => !Path.GetFileName(f).Contains("namedLocation", StringComparison.OrdinalIgnoreCase)).ToList();
        var namedLocationFiles = FindCsmFiles(Path.Combine(jsonRoot, "ConditionalAccessPolicy"))
            .Where(f => Path.GetFileName(f).Contains("namedLocation", StringComparison.OrdinalIgnoreCase)).ToList();
        var endpointFiles = FindCsmFiles(Path.Combine(jsonRoot, "EndpointSecurity"));

        summary.ScannedFiles += complianceFiles.Count + configFiles.Count + settingsCatalogFiles.Count +
                                caFiles.Count + namedLocationFiles.Count + endpointFiles.Count;

        await ImportWithPolicyImporterAsync(new DeviceCompliancePolicyService(_client), complianceFiles, summary, ct);
        await ImportWithPolicyImporterAsync(new DeviceConfigurationService(_client), configFiles, summary, ct);
        await ImportWithPolicyImporterAsync(new DeviceSettingsCatalogService(_client), settingsCatalogFiles, summary, ct);
        await ImportWithPolicyImporterAsync(new ConditionalAccessPolicyService(_client), caFiles, summary, ct);
        await ImportWithPolicyImporterAsync(new NamedLocationService(_client), namedLocationFiles, summary, ct);

        if (endpointFiles.Count > 0)
        {
            var endpointImporter = new EndpointSecurityImporter(
                new EndpointSecurityPolicyService(_client),
                new EntraIdGroupService(_client),
                _loggerFactory.CreateLogger<EndpointSecurityImporter>());
            var created = await endpointImporter.ImportAsync(endpointFiles, ct);
            summary.CreatedCount += created.Count(n => n is not null);
            summary.SkippedCount += Math.Max(0, endpointFiles.Count - created.Count);
        }

        return summary;
    }

    private async Task ImportWithPolicyImporterAsync(
        GraphServiceBase service,
        IReadOnlyList<string> files,
        SettingsImportSummary summary,
        CancellationToken ct)
    {
        if (files.Count == 0) return;
        var importer = new PolicyImporter(_loggerFactory.CreateLogger<PolicyImporter>());
        var created = await importer.ImportAsync(service, files, ct: ct);
        summary.CreatedCount += created.Count;
        summary.SkippedCount += Math.Max(0, files.Count - created.Count);
    }

    private static List<string> FindCsmFiles(string dir)
    {
        if (!Directory.Exists(dir)) return new List<string>();
        return Directory.EnumerateFiles(dir, "*.json", SearchOption.TopDirectoryOnly)
            .Where(f => Path.GetFileName(f).StartsWith("csm", StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private static bool ZipContainsJson(string zipPath)
    {
        using var zip = ZipFile.OpenRead(zipPath);
        return zip.Entries.Any(e => e.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase));
    }

    private static void Merge(SettingsImportSummary target, SettingsImportSummary source)
    {
        target.CreatedCount += source.CreatedCount;
        target.SkippedCount += source.SkippedCount;
        target.ScannedFiles += source.ScannedFiles;
        foreach (var n in source.Notes) target.Notes.Add(n);
    }
}
