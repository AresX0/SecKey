using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SecKey.Core.Services;

/// <summary>
/// Service for backing up and restoring Intune configurations.
/// </summary>
public class IntuneBackupService
{
    private const string SettingsSnapshotFolderName = "SettingsSnapshot";
    private readonly string _backupBasePath;
    private readonly string _workspaceRoot;

    public string BackupBasePath => _backupBasePath;
    public string WorkspaceRoot => _workspaceRoot;

    public IntuneBackupService(string backupBasePath = "", string workspaceRoot = "")
    {
        _backupBasePath = string.IsNullOrEmpty(backupBasePath)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "IntuneBackups")
            : backupBasePath;

        _workspaceRoot = string.IsNullOrWhiteSpace(workspaceRoot)
            ? ResolveWorkspaceRoot()
            : Path.GetFullPath(workspaceRoot);

        Directory.CreateDirectory(_backupBasePath);
    }

    /// <summary>
    /// Creates a backup of Intune configurations.
    /// </summary>
    public async Task<IntuneBackupResult> CreateBackupAsync(
        string backupName = "",
        string tenantId = "",
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        var result = new IntuneBackupResult
        {
            BackupName = string.IsNullOrEmpty(backupName) 
                ? $"IntuneBackup_{DateTime.Now:yyyyMMdd_HHmmss}"
                : backupName,
            CreatedAt = DateTime.Now,
            TenantId = string.IsNullOrWhiteSpace(tenantId) ? "common" : tenantId
        };

        var backupPath = Path.Combine(_backupBasePath, result.BackupName);
        Directory.CreateDirectory(backupPath);

        try
        {
            progress?.Report("Creating Intune configuration backup...");

            var segmentResults = new List<BackupSegmentResult>();
            foreach (var segment in GetDefaultSegments())
            {
                var destinationPath = Path.Combine(backupPath, segment.Name);
                if (Directory.Exists(destinationPath)) Directory.Delete(destinationPath, true);
                Directory.CreateDirectory(destinationPath);

                progress?.Report($"Backing up {segment.DisplayName}...");
                var copiedCount = await BackupDirectoryAsync(segment.SourceRelativePath, destinationPath, progress, ct);
                segmentResults.Add(new BackupSegmentResult(segment.Name, segment.SourceRelativePath, copiedCount));
            }

            var settingsSnapshotPath = Path.Combine(backupPath, SettingsSnapshotFolderName);
            if (Directory.Exists(settingsSnapshotPath)) Directory.Delete(settingsSnapshotPath, true);
            Directory.CreateDirectory(settingsSnapshotPath);

            progress?.Report("Backing up workspace settings snapshot...");
            var settingsSnapshotCount = await BackupWorkspaceSettingsSnapshotAsync(settingsSnapshotPath, progress, ct);

            var intuneAppsCount = segmentResults.FirstOrDefault(s => s.Name == "IntuneApps")?.FileCount ?? 0;
            var jsonCount = segmentResults.FirstOrDefault(s => s.Name == "JSON")?.FileCount ?? 0;
            var remediationCount = segmentResults.FirstOrDefault(s => s.Name == "RemediationScripts")?.FileCount ?? 0;

            var totalBackedUp = segmentResults.Sum(s => s.FileCount) + settingsSnapshotCount;
            if (totalBackedUp == 0)
            {
                throw new InvalidOperationException(
                    $"No files were backed up. Workspace root resolved to '{_workspaceRoot}'. " +
                    "Expected settings folders were not found.");
            }

            // Create metadata file
            var metadataFile = Path.Combine(backupPath, "backup_metadata.json");
            var metadata = new
            {
                result.BackupName,
                result.CreatedAt,
                result.TenantId,
                Version = "2.0",
                WorkspaceRoot = _workspaceRoot,
                Contents = new
                {
                    IntuneAppsCount = intuneAppsCount,
                    JsonConfigCount = jsonCount,
                    RemediationScriptsCount = remediationCount,
                    SettingsSnapshotCount = settingsSnapshotCount,
                    SegmentCounts = segmentResults
                }
            };

            await File.WriteAllTextAsync(metadataFile, JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true }), ct);

            result.Success = true;
            result.BackupPath = backupPath;
            result.Message = $"Backup created successfully at {backupPath}";
            progress?.Report(result.Message);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"Backup failed: {ex.Message}";
            progress?.Report(result.Message);

            try { Directory.Delete(backupPath, true); }
            catch { /* Ignore cleanup errors */ }
        }

        return result;
    }

    /// <summary>
    /// Lists all available backups.
    /// </summary>
    public List<IntuneBackupInfo> ListBackups()
    {
        var backups = new List<IntuneBackupInfo>();

        try
        {
            if (!Directory.Exists(_backupBasePath))
                return backups;

            foreach (var dir in Directory.GetDirectories(_backupBasePath))
            {
                var metadataFile = Path.Combine(dir, "backup_metadata.json");
                if (File.Exists(metadataFile))
                {
                    try
                    {
                        var metadata = ReadMetadata(metadataFile);

                        backups.Add(new IntuneBackupInfo
                        {
                            BackupName = metadata.BackupName,
                            CreatedAt = metadata.CreatedAt,
                            TenantId = metadata.TenantId,
                            BackupPath = dir,
                            Size = GetDirectorySize(dir)
                        });
                    }
                    catch { /* Ignore malformed backups */ }
                }
            }
        }
        catch { /* Ignore access errors */ }

        return backups.OrderByDescending(b => b.CreatedAt).ToList();
    }

    /// <summary>
    /// Deletes a backup by name.
    /// </summary>
    public async Task<bool> DeleteBackupAsync(string backupName)
    {
        return await Task.Run(() =>
        {
            try
            {
                var backupPath = Path.Combine(_backupBasePath, backupName);
                if (Directory.Exists(backupPath))
                {
                    Directory.Delete(backupPath, true);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        });
    }

    /// <summary>
    /// Restores a backup to workspace folders.
    /// </summary>
    public async Task<IntuneRestoreResult> RestoreBackupAsync(
        string backupName,
        IntuneRestoreOptions? options = null,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        options ??= new IntuneRestoreOptions();

        var result = new IntuneRestoreResult
        {
            BackupName = backupName,
            StartedAt = DateTime.Now
        };

        var backupPath = Path.Combine(_backupBasePath, backupName);
        if (!Directory.Exists(backupPath))
        {
            result.Success = false;
            result.Message = $"Backup not found: {backupPath}";
            return result;
        }

        try
        {
            progress?.Report($"Restoring backup: {backupName}");

            if (options.RestoreIntuneApps)
            {
                var count = await RestoreDirectoryAsync(
                    Path.Combine(backupPath, "IntuneApps"),
                    ResolveRestoreTargetPath("IntuneApps"),
                    options.OverwriteExisting,
                    progress,
                    ct);
                result.IntuneAppsFilesRestored = count;
            }

            if (options.RestoreJson)
            {
                var count = await RestoreDirectoryAsync(
                    Path.Combine(backupPath, "JSON"),
                    ResolveRestoreTargetPath("JSON"),
                    options.OverwriteExisting,
                    progress,
                    ct);
                result.JsonFilesRestored = count;
            }

            if (options.RestoreRemediationScripts)
            {
                var count = await RestoreDirectoryAsync(
                    Path.Combine(backupPath, "RemediationScripts"),
                    ResolveRestoreTargetPath("RemediationScripts"),
                    options.OverwriteExisting,
                    progress,
                    ct);
                result.RemediationFilesRestored = count;
            }

            if (options.RestoreSettingsSnapshot)
            {
                var count = await RestoreSettingsSnapshotAsync(
                    Path.Combine(backupPath, SettingsSnapshotFolderName),
                    options.OverwriteExisting,
                    progress,
                    ct);
                result.SettingsSnapshotFilesRestored = count;
            }

            result.Success = true;
            result.CompletedAt = DateTime.Now;
            result.Message =
                $"Restore complete. IntuneApps={result.IntuneAppsFilesRestored}, JSON={result.JsonFilesRestored}, RemediationScripts={result.RemediationFilesRestored}, SettingsSnapshot={result.SettingsSnapshotFilesRestored}";
            progress?.Report(result.Message);
        }
        catch (OperationCanceledException)
        {
            result.Success = false;
            result.CompletedAt = DateTime.Now;
            result.Message = "Restore cancelled.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.CompletedAt = DateTime.Now;
            result.Message = $"Restore failed: {ex.Message}";
        }

        return result;
    }

    public IntuneBackupDetails GetBackupDetails(string backupName)
    {
        var backupPath = Path.Combine(_backupBasePath, backupName);
        var details = new IntuneBackupDetails
        {
            BackupName = backupName,
            BackupPath = backupPath,
            Exists = Directory.Exists(backupPath)
        };

        if (!details.Exists)
        {
            return details;
        }

        var metadataFile = Path.Combine(backupPath, "backup_metadata.json");
        details.HasMetadata = File.Exists(metadataFile);

        if (details.HasMetadata)
        {
            try
            {
                var metadata = ReadMetadata(metadataFile);
                details.CreatedAt = metadata.CreatedAt;
                details.TenantId = metadata.TenantId;
                details.IntuneAppsCount = metadata.IntuneAppsCount;
                details.JsonConfigCount = metadata.JsonConfigCount;
                details.RemediationScriptsCount = metadata.RemediationScriptsCount;
                details.SettingsSnapshotCount = metadata.SettingsSnapshotCount;
                details.SegmentSummaries = metadata.SegmentCounts;
            }
            catch
            {
                // Fall back to file-system counts.
            }
        }

        if (details.IntuneAppsCount == 0)
            details.IntuneAppsCount = SafeCountFiles(Path.Combine(backupPath, "IntuneApps"), "*.*");
        if (details.JsonConfigCount == 0)
            details.JsonConfigCount = SafeCountFiles(Path.Combine(backupPath, "JSON"), "*.json");
        if (details.RemediationScriptsCount == 0)
            details.RemediationScriptsCount = SafeCountFiles(Path.Combine(backupPath, "RemediationScripts"), "*.*");
        if (details.SettingsSnapshotCount == 0)
            details.SettingsSnapshotCount = SafeCountFiles(Path.Combine(backupPath, SettingsSnapshotFolderName), "*.*");

        details.TotalSize = GetDirectorySize(backupPath);
        return details;
    }

    private static BackupMetadata ReadMetadata(string metadataFile)
    {
        var json = File.ReadAllText(metadataFile);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        return new BackupMetadata
        {
            BackupName = ReadString(root, "BackupName", "backupName") ?? string.Empty,
            CreatedAt = ReadDateTime(root, "CreatedAt", "createdAt") ?? DateTime.MinValue,
            TenantId = ReadString(root, "TenantId", "tenantId") ?? string.Empty,
            IntuneAppsCount = ReadInt(root, "Contents", "IntuneAppsCount", "intuneAppsCount"),
            JsonConfigCount = ReadInt(root, "Contents", "JsonConfigCount", "jsonConfigCount"),
            RemediationScriptsCount = ReadInt(root, "Contents", "RemediationScriptsCount", "remediationScriptsCount"),
            SettingsSnapshotCount = ReadInt(root, "Contents", "SettingsSnapshotCount", "settingsSnapshotCount"),
            SegmentCounts = ReadSegmentCounts(root)
        };
    }

    private static string? ReadString(JsonElement root, string primaryName, string fallbackName)
    {
        if (root.TryGetProperty(primaryName, out var primary) && primary.ValueKind == JsonValueKind.String)
            return primary.GetString();

        if (root.TryGetProperty(fallbackName, out var fallback) && fallback.ValueKind == JsonValueKind.String)
            return fallback.GetString();

        return null;
    }

    private static DateTime? ReadDateTime(JsonElement root, string primaryName, string fallbackName)
    {
        var value = ReadString(root, primaryName, fallbackName);
        if (DateTime.TryParse(value, out var parsed))
            return parsed;

        return null;
    }

    private static int ReadInt(JsonElement root, string parentName, string primaryName, string fallbackName)
    {
        JsonElement parent;
        if (!string.IsNullOrWhiteSpace(parentName))
        {
            if (!root.TryGetProperty(parentName, out parent) || parent.ValueKind != JsonValueKind.Object)
                return 0;
        }
        else
        {
            parent = root;
        }

        if (parent.TryGetProperty(primaryName, out var primary) && primary.TryGetInt32(out var primaryValue))
            return primaryValue;

        if (parent.TryGetProperty(fallbackName, out var fallback) && fallback.TryGetInt32(out var fallbackValue))
            return fallbackValue;

        return 0;
    }

    private sealed class BackupMetadata
    {
        public string BackupName { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public string TenantId { get; set; } = string.Empty;
        public int IntuneAppsCount { get; set; }
        public int JsonConfigCount { get; set; }
        public int RemediationScriptsCount { get; set; }
        public int SettingsSnapshotCount { get; set; }
        public List<BackupSegmentResult> SegmentCounts { get; set; } = new();
    }

    private static List<BackupSegmentResult> ReadSegmentCounts(JsonElement root)
    {
        var results = new List<BackupSegmentResult>();
        if (!root.TryGetProperty("Contents", out var contents) || contents.ValueKind != JsonValueKind.Object)
            return results;

        if (!contents.TryGetProperty("SegmentCounts", out var segmentCounts) || segmentCounts.ValueKind != JsonValueKind.Array)
            return results;

        foreach (var item in segmentCounts.EnumerateArray())
        {
            var name = ReadString(item, "Name", "name") ?? string.Empty;
            var source = ReadString(item, "SourceRelativePath", "sourceRelativePath") ?? string.Empty;
            var fileCount = ReadInt(item, string.Empty, "FileCount", "fileCount");
            if (string.IsNullOrWhiteSpace(name))
                continue;
            results.Add(new BackupSegmentResult(name, source, fileCount));
        }

        return results;
    }

    private async Task<int> BackupDirectoryAsync(
        string sourceRelativePath,
        string destinationPath,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        return await Task.Run(() =>
        {
            var copied = 0;
            try
            {
                var sourcePath = FindExistingSourceDirectory(sourceRelativePath);
                if (sourcePath == null)
                {
                    progress?.Report($"Skipped missing source folder: {sourceRelativePath}");
                    return 0;
                }

                var files = Directory.GetFiles(sourcePath, "*.*", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();

                    var relativePath = Path.GetRelativePath(sourcePath, file);
                    var destFile = Path.Combine(destinationPath, relativePath);
                    var destDir = Path.GetDirectoryName(destFile);

                    if (!string.IsNullOrEmpty(destDir))
                        Directory.CreateDirectory(destDir);

                    File.Copy(file, destFile, overwrite: true);
                    copied++;
                }

                progress?.Report($"Backed up {copied} files from {sourcePath}");
            }
            catch (Exception ex)
            {
                // Log but don't fail the entire backup for a single directory
                System.Diagnostics.Debug.WriteLine($"Warning: Could not backup {sourceRelativePath}: {ex.Message}");
            }

            return copied;
        }, ct);
    }

    private async Task<int> RestoreDirectoryAsync(
        string backupSourcePath,
        string restoreTargetPath,
        bool overwriteExisting,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        if (!Directory.Exists(backupSourcePath))
        {
            progress?.Report($"Skipped missing backup segment: {backupSourcePath}");
            return 0;
        }

        return await Task.Run(() =>
        {
            if (overwriteExisting && Directory.Exists(restoreTargetPath))
            {
                Directory.Delete(restoreTargetPath, true);
            }

            Directory.CreateDirectory(restoreTargetPath);

            var files = Directory.GetFiles(backupSourcePath, "*.*", SearchOption.AllDirectories);
            var restored = 0;
            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();

                var relativePath = Path.GetRelativePath(backupSourcePath, file);
                var destinationFile = Path.Combine(restoreTargetPath, relativePath);
                var destinationDir = Path.GetDirectoryName(destinationFile);
                if (!string.IsNullOrEmpty(destinationDir))
                {
                    Directory.CreateDirectory(destinationDir);
                }

                File.Copy(file, destinationFile, overwrite: true);
                restored++;
            }

            progress?.Report($"Restored {restored} files to {restoreTargetPath}");
            return restored;
        }, ct);
    }

    private async Task<int> BackupWorkspaceSettingsSnapshotAsync(
        string destinationPath,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        return await Task.Run(() =>
        {
            var copied = 0;
            var sourceRoot = ResolveWorkspaceRoot();
            if (!Directory.Exists(sourceRoot))
                return 0;

            var excludedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".git", ".vs", "bin", "obj", "node_modules"
            };

            foreach (var file in EnumerateSettingsFiles(sourceRoot, excludedDirs))
            {
                ct.ThrowIfCancellationRequested();

                var relativePath = Path.GetRelativePath(sourceRoot, file);
                var destinationFile = Path.Combine(destinationPath, relativePath);
                var destinationDir = Path.GetDirectoryName(destinationFile);
                if (!string.IsNullOrEmpty(destinationDir))
                    Directory.CreateDirectory(destinationDir);

                File.Copy(file, destinationFile, overwrite: true);
                copied++;
            }

            progress?.Report($"Backed up {copied} settings snapshot files from workspace root {sourceRoot}");
            return copied;
        }, ct);
    }

    private async Task<int> RestoreSettingsSnapshotAsync(
        string backupSnapshotPath,
        bool overwriteExisting,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        if (!Directory.Exists(backupSnapshotPath))
        {
            progress?.Report($"Skipped missing backup segment: {backupSnapshotPath}");
            return 0;
        }

        return await Task.Run(() =>
        {
            var restored = 0;
            var files = Directory.GetFiles(backupSnapshotPath, "*.*", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();

                var relativePath = Path.GetRelativePath(backupSnapshotPath, file);
                var targetFile = Path.Combine(_workspaceRoot, relativePath);
                var targetDir = Path.GetDirectoryName(targetFile);
                if (!string.IsNullOrWhiteSpace(targetDir))
                    Directory.CreateDirectory(targetDir);

                if (!overwriteExisting && File.Exists(targetFile))
                    continue;

                File.Copy(file, targetFile, overwrite: true);
                restored++;
            }

            progress?.Report($"Restored {restored} settings snapshot files to {_workspaceRoot}");
            return restored;
        }, ct);
    }

    private static IEnumerable<string> EnumerateSettingsFiles(string sourceRoot, HashSet<string> excludedDirs)
    {
        var allowedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".json", ".jsonc", ".xml", ".ps1", ".psm1", ".psd1", ".ps1xml", ".tf", ".bicep", ".ini", ".cfg", ".config"
        };

        var stack = new Stack<string>();
        stack.Push(sourceRoot);

        while (stack.Count > 0)
        {
            var current = stack.Pop();

            IEnumerable<string> childDirs;
            try { childDirs = Directory.EnumerateDirectories(current); }
            catch { continue; }

            foreach (var child in childDirs)
            {
                var dirName = Path.GetFileName(child);
                if (excludedDirs.Contains(dirName))
                    continue;
                stack.Push(child);
            }

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(current); }
            catch { continue; }

            foreach (var file in files)
            {
                var extension = Path.GetExtension(file);
                if (!allowedExtensions.Contains(extension))
                    continue;
                yield return file;
            }
        }
    }

    private static IReadOnlyList<BackupSegmentDefinition> GetDefaultSegments()
    {
        return new[]
        {
            new BackupSegmentDefinition("IntuneApps", "IntuneApps", "Intune app templates and package definitions"),
            new BackupSegmentDefinition("JSON", "JSON", "Intune/Entra deployment manifests and settings exports"),
            new BackupSegmentDefinition("RemediationScripts", "RemediationScripts", "Proactive remediation script definitions"),
            new BackupSegmentDefinition("ArchivePAWCSM", Path.Combine("archive", "newPaw", "PAWCSM"), "Archived PAW CSM content"),
            new BackupSegmentDefinition("ArchiveSecKeyPowerShell", Path.Combine("archive", "SecKey-PowerShell"), "Archived SecKey PowerShell module")
        };
    }

    private string ResolveRestoreTargetPath(string relativePath)
    {
        var candidates = new[]
        {
            Path.Combine(_workspaceRoot, relativePath),
            Path.Combine(_workspaceRoot, "source", relativePath),
            Path.GetFullPath(relativePath)
        };

        foreach (var candidate in candidates)
        {
            if (Directory.Exists(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }

        return Path.GetFullPath(relativePath);
    }

    private string? FindExistingSourceDirectory(string sourceRelativePath)
    {
        var candidates = new[]
        {
            Path.Combine(_workspaceRoot, sourceRelativePath),
            Path.Combine(_workspaceRoot, "source", sourceRelativePath),
            Path.GetFullPath(sourceRelativePath),
            Path.GetFullPath(Path.Combine("source", sourceRelativePath))
        };

        foreach (var candidate in candidates)
        {
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static string ResolveWorkspaceRoot()
    {
        var probes = new List<string>
        {
            Directory.GetCurrentDirectory(),
            AppContext.BaseDirectory,
            Environment.CurrentDirectory
        };

        foreach (var probe in probes.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var dir = new DirectoryInfo(probe);
            while (dir != null)
            {
                var hasTopLevelFolders =
                    Directory.Exists(Path.Combine(dir.FullName, "IntuneApps")) ||
                    Directory.Exists(Path.Combine(dir.FullName, "JSON")) ||
                    Directory.Exists(Path.Combine(dir.FullName, "RemediationScripts"));

                var hasRepoMarkers =
                    File.Exists(Path.Combine(dir.FullName, "README.md")) &&
                    Directory.Exists(Path.Combine(dir.FullName, "source"));

                if (hasTopLevelFolders || hasRepoMarkers)
                {
                    return dir.FullName;
                }

                dir = dir.Parent;
            }
        }

        return Directory.GetCurrentDirectory();
    }

    private static int SafeCountFiles(string path, string pattern)
    {
        try
        {
            return Directory.Exists(path)
                ? Directory.GetFiles(path, pattern, SearchOption.AllDirectories).Length
                : 0;
        }
        catch
        {
            return 0;
        }
    }

    private long GetDirectorySize(string path)
    {
        try
        {
            return Directory.GetFiles(path, "*.*", SearchOption.AllDirectories)
                .AsParallel()
                .Sum(f => new FileInfo(f).Length);
        }
        catch
        {
            return 0;
        }
    }
}

public class IntuneBackupResult
{
    public string BackupName { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public string TenantId { get; set; } = "";
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public string BackupPath { get; set; } = "";
}

public class IntuneBackupInfo
{
    public string BackupName { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public string TenantId { get; set; } = "";
    public string BackupPath { get; set; } = "";
    public long Size { get; set; }

    public string SizeFormatted => FormatSize(Size);
    public string CreatedAtFormatted => CreatedAt.ToString("g");

    private static string FormatSize(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:0.##} {sizes[order]}";
    }
}

public class IntuneRestoreOptions
{
    public bool RestoreIntuneApps { get; set; } = true;
    public bool RestoreJson { get; set; } = true;
    public bool RestoreRemediationScripts { get; set; } = true;
    public bool RestoreSettingsSnapshot { get; set; } = true;
    public bool OverwriteExisting { get; set; } = true;
}

public class IntuneRestoreResult
{
    public string BackupName { get; set; } = "";
    public DateTime StartedAt { get; set; }
    public DateTime CompletedAt { get; set; }
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public int IntuneAppsFilesRestored { get; set; }
    public int JsonFilesRestored { get; set; }
    public int RemediationFilesRestored { get; set; }
    public int SettingsSnapshotFilesRestored { get; set; }
}

public sealed record BackupSegmentDefinition(string Name, string SourceRelativePath, string DisplayName);

public sealed record BackupSegmentResult(string Name, string SourceRelativePath, int FileCount);

public class IntuneBackupDetails
{
    public string BackupName { get; set; } = "";
    public string TenantId { get; set; } = "";
    public string BackupPath { get; set; } = "";
    public bool Exists { get; set; }
    public bool HasMetadata { get; set; }
    public DateTime CreatedAt { get; set; }
    public int IntuneAppsCount { get; set; }
    public int JsonConfigCount { get; set; }
    public int RemediationScriptsCount { get; set; }
    public int SettingsSnapshotCount { get; set; }
    public List<BackupSegmentResult> SegmentSummaries { get; set; } = new();
    public long TotalSize { get; set; }

    public string Summary =>
        $"Backup: {BackupName}\nTenant: {(string.IsNullOrWhiteSpace(TenantId) ? "(not set)" : TenantId)}\nPath: {BackupPath}\nCreated: {CreatedAt:g}\nIntuneApps files: {IntuneAppsCount}\nJSON files: {JsonConfigCount}\nRemediation files: {RemediationScriptsCount}\nSettings snapshot files: {SettingsSnapshotCount}\nSegments: {(SegmentSummaries.Count == 0 ? "(none)" : string.Join(", ", SegmentSummaries.Select(s => $"{s.Name}={s.FileCount}")))}\nTotal size: {FormatSize(TotalSize)}\nMetadata: {(HasMetadata ? "present" : "missing")}";

    private static string FormatSize(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:0.##} {sizes[order]}";
    }
}
