using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SecKey.App.Services;
using SecKey.Core.Services;
using System.Windows;

namespace SecKey.App.ViewModels;

public partial class IntuneBackupViewModel : ObservableObject
{
    private IntuneBackupService _service;
    private string _backupBasePath = string.Empty;
    private CancellationTokenSource? _cts;

    [ObservableProperty]
    private bool isRunning;

    [ObservableProperty]
    private string statusMessage = "Ready";

    [ObservableProperty]
    private string backupName = $"IntuneBackup_{DateTime.Now:yyyyMMdd_HHmmss}";

    [ObservableProperty]
    private string projectRootPath = string.Empty;

    [ObservableProperty]
    private string tenantId = EntraConfigService.Instance.GetTenantId();

    [ObservableProperty]
    private ObservableCollection<IntuneBackupInfo> availableBackups = new();

    [ObservableProperty]
    private IntuneBackupInfo? selectedBackup;

    [ObservableProperty]
    private IntuneBackupInfo? compareBackup;

    [ObservableProperty]
    private bool restoreIntuneApps = true;

    [ObservableProperty]
    private bool restoreJson = true;

    [ObservableProperty]
    private bool restoreRemediationScripts = true;

    [ObservableProperty]
    private bool restoreSettingsSnapshot = true;

    [ObservableProperty]
    private bool overwriteExisting = true;

    [ObservableProperty]
    private string selectedBackupDetails = "Select a backup to view details.";

    [ObservableProperty]
    private string compareSummary = "Select primary and comparison backups to compute drift.";

    [ObservableProperty]
    private string compareFolderA = string.Empty;

    [ObservableProperty]
    private string compareFolderB = string.Empty;

    [ObservableProperty]
    private string baselineFolder = string.Empty;

    [ObservableProperty]
    private string sourceExportFolder = string.Empty;

    [ObservableProperty]
    private string targetExportFolder = string.Empty;

    [ObservableProperty]
    private string compareReportPath = string.Empty;

    public IntuneBackupViewModel()
    {
        _service = new IntuneBackupService();
        _backupBasePath = _service.BackupBasePath;
        ProjectRootPath = _service.WorkspaceRoot;
        _ = RefreshBackupList();
    }

    partial void OnProjectRootPathChanged(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        _service = new IntuneBackupService(_backupBasePath, value);
        _ = RefreshBackupList();
    }

    partial void OnSelectedBackupChanged(IntuneBackupInfo? value)
    {
        if (value == null)
        {
            SelectedBackupDetails = "Select a backup to view details.";
            return;
        }

        try
        {
            var details = _service.GetBackupDetails(value.BackupName);
            SelectedBackupDetails = details.Summary;
        }
        catch (Exception ex)
        {
            SelectedBackupDetails = $"Failed to load backup details: {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task CreateBackup()
    {
        if (IsRunning) return;

        IsRunning = true;
        _cts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<string>(msg => StatusMessage = msg);
            StatusMessage = string.IsNullOrWhiteSpace(TenantId)
                ? "Creating Intune backup..."
                : $"Creating Intune backup for tenant {TenantId}...";

            var result = await _service.CreateBackupAsync(BackupName, TenantId, progress, _cts.Token);

            if (result.Success)
            {
                StatusMessage = result.Message;
                await RefreshBackupList();
                BackupName = $"IntuneBackup_{DateTime.Now:yyyyMMdd_HHmmss}";
            }
            else
            {
                StatusMessage = $"Backup failed: {result.Message}";
            }
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Backup cancelled";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
        finally
        {
            IsRunning = false;
            _cts?.Dispose();
        }
    }

    [RelayCommand]
    public async Task RefreshBackupList()
    {
        try
        {
            AvailableBackups.Clear();
            var backups = await Task.Run(() => _service.ListBackups());

            foreach (var backup in backups)
                AvailableBackups.Add(backup);

            StatusMessage = $"Found {backups.Count} backups";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error loading backups: {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task DeleteBackup(IntuneBackupInfo? backup)
    {
        if (backup == null) return;

        var confirm = MessageBox.Show(
            $"Delete backup '{backup.BackupName}'?",
            "Confirm Delete",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        try
        {
            StatusMessage = $"Deleting backup: {backup.BackupName}...";
            var success = await _service.DeleteBackupAsync(backup.BackupName);

            if (success)
            {
                AvailableBackups.Remove(backup);
                StatusMessage = "Backup deleted successfully";
            }
            else
            {
                StatusMessage = "Failed to delete backup";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task LoadBackupList()
    {
        await RefreshBackupList();
    }

    [RelayCommand]
    public void CompareSelectedBackups()
    {
        if (SelectedBackup is null || CompareBackup is null)
        {
            CompareSummary = "Select both Primary and Compare backups first.";
            return;
        }

        try
        {
            var primary = _service.GetBackupDetails(SelectedBackup.BackupName);
            var compare = _service.GetBackupDetails(CompareBackup.BackupName);
            CompareSummary =
                $"Primary: {primary.BackupName}\n" +
                $"Compare: {compare.BackupName}\n\n" +
                $"Intune Apps: {primary.IntuneAppsCount} vs {compare.IntuneAppsCount} (Δ {primary.IntuneAppsCount - compare.IntuneAppsCount})\n" +
                $"JSON Config: {primary.JsonConfigCount} vs {compare.JsonConfigCount} (Δ {primary.JsonConfigCount - compare.JsonConfigCount})\n" +
                $"Remediation: {primary.RemediationScriptsCount} vs {compare.RemediationScriptsCount} (Δ {primary.RemediationScriptsCount - compare.RemediationScriptsCount})\n" +
                $"Settings Snapshot: {primary.SettingsSnapshotCount} vs {compare.SettingsSnapshotCount} (Δ {primary.SettingsSnapshotCount - compare.SettingsSnapshotCount})\n" +
                $"Size: {primary.TotalSize:N0} vs {compare.TotalSize:N0} bytes";
        }
        catch (Exception ex)
        {
            CompareSummary = $"Backup compare failed: {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task ExportBackupInventoryAsync()
    {
        try
        {
            var reportDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Reports");
            Directory.CreateDirectory(reportDir);
            var file = Path.Combine(reportDir, $"intune-backups-{DateTime.Now:yyyyMMdd-HHmmss}.csv");

            var sb = new StringBuilder();
            sb.AppendLine("BackupName,TenantId,CreatedAt,Size,Path");
            foreach (var backup in AvailableBackups)
            {
                sb.AppendLine($"\"{backup.BackupName}\",\"{backup.TenantId}\",\"{backup.CreatedAt:yyyy-MM-dd HH:mm:ss}\",{backup.Size},\"{backup.BackupPath.Replace("\"", "''")}\"");
            }

            await File.WriteAllTextAsync(file, sb.ToString());
            CompareReportPath = file;
            StatusMessage = $"Inventory exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Export failed: {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task RunBaselineCompareAsync()
    {
        var left = !string.IsNullOrWhiteSpace(CompareFolderA) ? CompareFolderA : SelectedBackup?.BackupPath;
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(BaselineFolder))
        {
            CompareSummary = "Set Primary folder (or select backup) and Baseline folder.";
            return;
        }

        await RunDirectoryCompareAsync(left, BaselineFolder, "baseline-compare");
    }

    [RelayCommand]
    public async Task RunCrossTenantCompareAsync()
    {
        if (string.IsNullOrWhiteSpace(SourceExportFolder) || string.IsNullOrWhiteSpace(TargetExportFolder))
        {
            CompareSummary = "Set Source Export Folder and Target Export Folder.";
            return;
        }

        await RunDirectoryCompareAsync(SourceExportFolder, TargetExportFolder, "cross-tenant-compare");
    }

    [RelayCommand]
    public async Task RunCompareFoldersAsync()
    {
        if (string.IsNullOrWhiteSpace(CompareFolderA) || string.IsNullOrWhiteSpace(CompareFolderB))
        {
            CompareSummary = "Set Compare Folder A and Compare Folder B.";
            return;
        }

        await RunDirectoryCompareAsync(CompareFolderA, CompareFolderB, "compare-exports");
    }

    [RelayCommand]
    public async Task GenerateCrossTenantImportPlanAsync()
    {
        if (string.IsNullOrWhiteSpace(SourceExportFolder) || string.IsNullOrWhiteSpace(TargetExportFolder))
        {
            CompareSummary = "Set Source Export Folder and Target Export Folder.";
            return;
        }

        try
        {
            var src = Path.GetFullPath(SourceExportFolder);
            var dst = Path.GetFullPath(TargetExportFolder);
            if (!Directory.Exists(src) || !Directory.Exists(dst))
            {
                CompareSummary = "Source/Target folder not found.";
                return;
            }

            var sourceFiles = Directory.GetFiles(src, "*.*", SearchOption.AllDirectories)
                .Select(f => Path.GetRelativePath(src, f))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var targetFiles = Directory.GetFiles(dst, "*.*", SearchOption.AllDirectories)
                .Select(f => Path.GetRelativePath(dst, f))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var missing = sourceFiles.Where(f => !targetFiles.Contains(f)).OrderBy(f => f).ToList();

            var reports = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Reports");
            Directory.CreateDirectory(reports);
            var planPath = Path.Combine(reports, $"cross-tenant-import-plan-{DateTime.Now:yyyyMMdd-HHmmss}.ps1");
            using var sw = new StreamWriter(planPath);
            sw.WriteLine("# Generated by SecKey - review before execution");
            sw.WriteLine("param(");
            sw.WriteLine("  [string]$SourceRoot = '" + src.Replace("'", "''") + "',");
            sw.WriteLine("  [string]$TargetRoot = '" + dst.Replace("'", "''") + "'");
            sw.WriteLine(")");
            sw.WriteLine();
            foreach (var rel in missing)
            {
                var escaped = rel.Replace("'", "''");
                sw.WriteLine("$src = Join-Path $SourceRoot '" + escaped + "'");
                sw.WriteLine("$dst = Join-Path $TargetRoot '" + escaped + "'");
                sw.WriteLine("New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null");
                sw.WriteLine("Copy-Item $src $dst -Force");
                sw.WriteLine();
            }

            CompareReportPath = planPath;
            CompareSummary = $"Cross-tenant import plan generated with {missing.Count} missing file(s).\n{planPath}";
            StatusMessage = CompareSummary;
        }
        catch (Exception ex)
        {
            CompareSummary = $"Import plan generation failed: {ex.Message}";
            StatusMessage = CompareSummary;
        }

        await Task.CompletedTask;
    }

    private async Task RunDirectoryCompareAsync(string folderA, string folderB, string reportPrefix)
    {
        try
        {
            var left = Path.GetFullPath(folderA);
            var right = Path.GetFullPath(folderB);
            if (!Directory.Exists(left) || !Directory.Exists(right))
            {
                CompareSummary = $"Compare failed: folder missing. A={left}, B={right}";
                return;
            }

            var leftFiles = Directory.GetFiles(left, "*.*", SearchOption.AllDirectories);
            var rightFiles = Directory.GetFiles(right, "*.*", SearchOption.AllDirectories);

            var leftMap = leftFiles.ToDictionary(f => Path.GetRelativePath(left, f), f => f, StringComparer.OrdinalIgnoreCase);
            var rightMap = rightFiles.ToDictionary(f => Path.GetRelativePath(right, f), f => f, StringComparer.OrdinalIgnoreCase);

            var onlyLeft = leftMap.Keys.Where(k => !rightMap.ContainsKey(k)).OrderBy(k => k).ToList();
            var onlyRight = rightMap.Keys.Where(k => !leftMap.ContainsKey(k)).OrderBy(k => k).ToList();
            var common = leftMap.Keys.Where(k => rightMap.ContainsKey(k)).ToList();

            var changed = new List<string>();
            foreach (var key in common)
            {
                var li = new FileInfo(leftMap[key]);
                var ri = new FileInfo(rightMap[key]);
                if (li.Length != ri.Length)
                {
                    changed.Add(key + " (size)");
                    continue;
                }

                var lh = await ComputeHashAsync(leftMap[key]);
                var rh = await ComputeHashAsync(rightMap[key]);
                if (!string.Equals(lh, rh, StringComparison.OrdinalIgnoreCase))
                    changed.Add(key + " (hash)");
            }

            var reports = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Reports");
            Directory.CreateDirectory(reports);
            var report = Path.Combine(reports, $"{reportPrefix}-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            using (var sw = new StreamWriter(report))
            {
                sw.WriteLine($"Compare A: {left}");
                sw.WriteLine($"Compare B: {right}");
                sw.WriteLine();
                sw.WriteLine($"Only in A: {onlyLeft.Count}");
                foreach (var item in onlyLeft.Take(500)) sw.WriteLine("  + " + item);
                sw.WriteLine();
                sw.WriteLine($"Only in B: {onlyRight.Count}");
                foreach (var item in onlyRight.Take(500)) sw.WriteLine("  - " + item);
                sw.WriteLine();
                sw.WriteLine($"Changed: {changed.Count}");
                foreach (var item in changed.Take(500)) sw.WriteLine("  * " + item);
            }

            CompareReportPath = report;
            CompareSummary =
                $"Compared:\nA={left}\nB={right}\n\n" +
                $"Only in A: {onlyLeft.Count}\nOnly in B: {onlyRight.Count}\nChanged: {changed.Count}\n\nReport: {report}";
            StatusMessage = "Compare complete.";
        }
        catch (Exception ex)
        {
            CompareSummary = $"Compare failed: {ex.Message}";
            StatusMessage = CompareSummary;
        }
    }

    private static async Task<string> ComputeHashAsync(string path)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream);
        return Convert.ToHexString(hash);
    }

    [RelayCommand]
    public async Task RestoreSelectedBackup()
    {
        if (SelectedBackup == null || IsRunning) return;

        if (!RestoreIntuneApps && !RestoreJson && !RestoreRemediationScripts && !RestoreSettingsSnapshot)
        {
            StatusMessage = "Select at least one restore scope (IntuneApps, JSON, Remediation Scripts, or Settings Snapshot).";
            return;
        }

        var confirm = MessageBox.Show(
            $"Restore backup '{SelectedBackup.BackupName}' to workspace folders?",
            "Confirm Restore",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        IsRunning = true;
        _cts = new CancellationTokenSource();

        try
        {
            var options = new IntuneRestoreOptions
            {
                RestoreIntuneApps = RestoreIntuneApps,
                RestoreJson = RestoreJson,
                RestoreRemediationScripts = RestoreRemediationScripts,
                RestoreSettingsSnapshot = RestoreSettingsSnapshot,
                OverwriteExisting = OverwriteExisting
            };

            var progress = new Progress<string>(msg => StatusMessage = msg);
            var result = await _service.RestoreBackupAsync(SelectedBackup.BackupName, options, progress, _cts.Token);
            StatusMessage = result.Message;
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Restore cancelled.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Restore failed: {ex.Message}";
        }
        finally
        {
            IsRunning = false;
            _cts?.Dispose();
        }
    }

    [RelayCommand]
    public void OpenSelectedBackupFolder()
    {
        if (SelectedBackup == null)
        {
            StatusMessage = "Select a backup first.";
            return;
        }

        if (!System.IO.Directory.Exists(SelectedBackup.BackupPath))
        {
            StatusMessage = $"Backup path not found: {SelectedBackup.BackupPath}";
            return;
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = SelectedBackup.BackupPath,
            UseShellExecute = true
        });
    }

    [RelayCommand]
    public void OpenBackupRoot()
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = _service.BackupBasePath,
            UseShellExecute = true
        });
    }

    [RelayCommand]
    public void Cancel()
    {
        _cts?.Cancel();
    }

    [RelayCommand]
    public void BrowseCompareFolderA()
    {
        var dlg = new OpenFolderDialog { Title = "Select primary compare folder" };
        if (dlg.ShowDialog() == true)
            CompareFolderA = dlg.FolderName;
    }

    [RelayCommand]
    public void BrowseBaselineFolder()
    {
        var dlg = new OpenFolderDialog { Title = "Select baseline folder" };
        if (dlg.ShowDialog() == true)
            BaselineFolder = dlg.FolderName;
    }

    [RelayCommand]
    public void BrowseSourceExportFolder()
    {
        var dlg = new OpenFolderDialog { Title = "Select source export folder" };
        if (dlg.ShowDialog() == true)
            SourceExportFolder = dlg.FolderName;
    }

    [RelayCommand]
    public void BrowseTargetExportFolder()
    {
        var dlg = new OpenFolderDialog { Title = "Select target export folder" };
        if (dlg.ShowDialog() == true)
            TargetExportFolder = dlg.FolderName;
    }
}
