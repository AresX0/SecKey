using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SecKey.Core.Services;

namespace SecKey.App.ViewModels;

public partial class FileIntegrityViewModel : ObservableObject
{
    private readonly FileIntegrityService _service;
    private CancellationTokenSource? _cts;
    private FileIntegrityBaseline? _currentBaseline;

    [ObservableProperty]
    private bool isRunning;

    [ObservableProperty]
    private string statusMessage = "Ready";

    [ObservableProperty]
    private string selectedDirectory = "";

    [ObservableProperty]
    private string baselineDisplayName = "No baseline loaded";

    [ObservableProperty]
    private int totalBaselineFiles;

    [ObservableProperty]
    private ObservableCollection<FileChangeInfo> addedFiles = new();

    [ObservableProperty]
    private ObservableCollection<FileChangeInfo> modifiedFiles = new();

    [ObservableProperty]
    private ObservableCollection<FileChangeInfo> deletedFiles = new();

    [ObservableProperty]
    private int totalChanges;

    [ObservableProperty]
    private string baselineFilePath = string.Empty;

    public FileIntegrityViewModel()
    {
        _service = new FileIntegrityService();
    }

    [RelayCommand]
    public async Task CreateBaseline(string? directoryPath = null)
    {
        directoryPath ??= SelectedDirectory;
        if (IsRunning || string.IsNullOrWhiteSpace(directoryPath) || !Directory.Exists(directoryPath))
        {
            StatusMessage = "Enter a valid directory path before creating a baseline.";
            return;
        }

        IsRunning = true;
        SelectedDirectory = directoryPath;
        _cts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<FileIntegrityProgress>(p =>
                StatusMessage = $"Scanning: {Path.GetFileName(p.CurrentFile)} ({p.Percent:F0}%)");

            StatusMessage = "Creating file integrity baseline...";
            _currentBaseline = await _service.CreateBaselineAsync(directoryPath, progress: progress, ct: _cts.Token);

            TotalBaselineFiles = _currentBaseline.Entries.Count;
            BaselineDisplayName = $"Baseline: {Path.GetFileName(directoryPath)} ({TotalBaselineFiles} files)";
            StatusMessage = $"Baseline created: {TotalBaselineFiles} files scanned";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Baseline creation cancelled";
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
    public async Task CompareWithBaseline()
    {
        if (IsRunning || _currentBaseline == null) return;

        IsRunning = true;
        AddedFiles.Clear();
        ModifiedFiles.Clear();
        DeletedFiles.Clear();
        _cts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<FileIntegrityProgress>(p =>
                StatusMessage = $"Comparing: {Path.GetFileName(p.CurrentFile)} ({p.Percent:F0}%)");

            StatusMessage = "Comparing files against baseline...";
            var report = await _service.CompareWithBaselineAsync(_currentBaseline, progress, _cts.Token);

            foreach (var file in report.Added)
                AddedFiles.Add(file);

            foreach (var file in report.Modified)
                ModifiedFiles.Add(file);

            foreach (var file in report.Deleted)
                DeletedFiles.Add(file);

            TotalChanges = report.TotalChanges;
            StatusMessage = $"Comparison complete: {report.Added.Count} added, {report.Modified.Count} modified, {report.Deleted.Count} deleted";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Comparison cancelled";
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
    public void Cancel()
    {
        _cts?.Cancel();
    }

    [RelayCommand]
    public void BrowseDirectory()
    {
        var dlg = new OpenFolderDialog { Title = "Select directory to baseline" };
        if (dlg.ShowDialog() == true)
        {
            SelectedDirectory = dlg.FolderName;
        }
    }

    [RelayCommand]
    public async Task SaveBaseline()
    {
        if (_currentBaseline == null)
        {
            StatusMessage = "Create or load a baseline first.";
            return;
        }

        var dlg = new SaveFileDialog
        {
            Title = "Save baseline",
            Filter = "Baseline JSON (*.json)|*.json",
            FileName = $"FIM-Baseline-{DateTime.Now:yyyyMMdd_HHmmss}.json"
        };
        if (dlg.ShowDialog() != true) return;

        await _service.SaveBaselineAsync(_currentBaseline, dlg.FileName);
        BaselineFilePath = dlg.FileName;
        StatusMessage = $"Baseline saved: {dlg.FileName}";
    }

    [RelayCommand]
    public async Task LoadBaseline()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Load baseline",
            Filter = "Baseline JSON (*.json)|*.json|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;

        _currentBaseline = await _service.LoadBaselineAsync(dlg.FileName);
        BaselineFilePath = dlg.FileName;
        SelectedDirectory = _currentBaseline.DirectoryPath;
        TotalBaselineFiles = _currentBaseline.Entries.Count;
        BaselineDisplayName = $"Baseline: {Path.GetFileName(_currentBaseline.DirectoryPath)} ({TotalBaselineFiles} files)";
        StatusMessage = "Baseline loaded.";
    }
}
