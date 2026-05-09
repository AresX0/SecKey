using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using SecKey.App.Services;
using SecKey.Graph;
using SecKey.Graph.Services;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;

namespace SecKey.App.ViewModels;

public sealed partial class InfrastructureViewModel : GraphPageViewModel
{
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string _baselineZipPath =
        Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, "..", "Windows 11 v25H2 Security Baseline.zip"));
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string? _exportPath;
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string? _additionalBreakGlassAccounts;
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string _deploymentStatus = "Idle.";
    public ObservableCollection<DeploymentHistoryEntry> DeploymentHistory { get; } = new();
    public ObservableCollection<OptionalFeatureSelectionViewModel> OptionalFeatures { get; } = new();

    public InfrastructureViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp)
    {
        foreach (var feature in SecKeyManifestDeploymentService.OptionalFeatures)
            OptionalFeatures.Add(new OptionalFeatureSelectionViewModel(feature));
    }

    protected override async IAsyncEnumerable<EntityRow> LoadAsync()
    {
        // Infrastructure tab does not list entities
        await Task.CompletedTask;
        yield break;
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task ApplyFullEnvironmentAsync()
    {
        Busy = true;
        SetDeploymentStatus("Deploying full SecKey environment (all manifest steps).");
        AddHistory("Infrastructure", "Start", "Full manifest deployment started.", false);
        try
        {
            var client = BuildClient();
            var deployment = new SecKeyManifestDeploymentService(client);
            var result = await deployment.DeployCsmAsync(DeploymentPageHelpers.ResolveRepoRoot(), BuildDeploymentOptions());
            StatusMessage = result.ToStatusText() + (result.Notes.Count > 0 ? $" Notes: {string.Join(" | ", result.Notes)}" : string.Empty);
            SetDeploymentStatus($"Full deployment complete. {StatusMessage}");
            AddHistory("Infrastructure", "Complete", StatusMessage, false);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Full deployment failed. {StatusMessage}");
            AddHistory("Infrastructure", "Failed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task UndoFullEnvironmentAsync()
    {
        Busy = true;
        SetDeploymentStatus("Undoing full SecKey environment (removing deployed manifest artifacts).");
        AddHistory("Infrastructure", "UndoStart", "Full manifest rollback started.", false);
        try
        {
            var client = BuildClient();
            var deployment = new SecKeyManifestDeploymentService(client);
            var result = await deployment.UndoCsmAsync(DeploymentPageHelpers.ResolveRepoRoot(), BuildDeploymentOptions());
            StatusMessage = result.ToStatusText() + (result.Notes.Count > 0 ? $" Notes: {string.Join(" | ", result.Notes)}" : string.Empty);
            SetDeploymentStatus($"Full rollback complete. {StatusMessage}");
            AddHistory("Infrastructure", "UndoComplete", StatusMessage, false);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Full rollback failed. {StatusMessage}");
            AddHistory("Infrastructure", "UndoFailed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task ApplyOptionalFeaturesAsync()
    {
        var selectedCommands = OptionalFeatures.Where(feature => feature.IsSelected).Select(feature => feature.Command).ToList();
        if (selectedCommands.Count == 0)
        {
            StatusMessage = "Select at least one optional feature bundle first.";
            SetDeploymentStatus(StatusMessage);
            return;
        }

        Busy = true;
        SetDeploymentStatus($"Deploying optional feature bundle(s): {string.Join(", ", OptionalFeatures.Where(feature => feature.IsSelected).Select(feature => feature.DisplayName))}");
        AddHistory("Infrastructure", "OptionalStart", "Optional feature deployment started.", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var result = await deployment.DeployOptionalFeaturesAsync(DeploymentPageHelpers.ResolveRepoRoot(), selectedCommands, BuildDeploymentOptions());
            StatusMessage = result.ToStatusText() + (result.Notes.Count > 0 ? $" Notes: {string.Join(" | ", result.Notes)}" : string.Empty);
            SetDeploymentStatus($"Optional feature deployment complete. {StatusMessage}");
            AddHistory("Infrastructure", "OptionalComplete", StatusMessage, result.Notes.Any(note => note.Contains("[ERROR]")));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Optional feature deployment failed. {StatusMessage}");
            AddHistory("Infrastructure", "OptionalFailed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task UndoOptionalFeaturesAsync()
    {
        var selectedCommands = OptionalFeatures.Where(feature => feature.IsSelected).Select(feature => feature.Command).ToList();
        if (selectedCommands.Count == 0)
        {
            StatusMessage = "Select at least one optional feature bundle first.";
            SetDeploymentStatus(StatusMessage);
            return;
        }

        Busy = true;
        SetDeploymentStatus($"Undoing optional feature bundle(s): {string.Join(", ", OptionalFeatures.Where(feature => feature.IsSelected).Select(feature => feature.DisplayName))}");
        AddHistory("Infrastructure", "OptionalUndoStart", "Optional feature rollback started.", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var result = await deployment.UndoOptionalFeaturesAsync(DeploymentPageHelpers.ResolveRepoRoot(), selectedCommands, BuildDeploymentOptions());
            StatusMessage = result.ToStatusText() + (result.Notes.Count > 0 ? $" Notes: {string.Join(" | ", result.Notes)}" : string.Empty);
            SetDeploymentStatus($"Optional feature rollback complete. {StatusMessage}");
            AddHistory("Infrastructure", "OptionalUndoComplete", StatusMessage, result.Notes.Any(note => note.Contains("[UNDO ERROR]")));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Optional feature rollback failed. {StatusMessage}");
            AddHistory("Infrastructure", "OptionalUndoFailed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task ImportExportedSettingsAsync()
    {
        if (string.IsNullOrWhiteSpace(ExportPath))
        {
            StatusMessage = "Provide a folder or zip path to import exported settings.";
            SetDeploymentStatus(StatusMessage);
            return;
        }

        Busy = true;
        SetDeploymentStatus($"Importing exported settings from: {ExportPath}");
        AddHistory("Infrastructure", "Start", $"Export import started: {ExportPath}", false);
        try
        {
            var client = BuildClient();
            var importer = new SettingsImportService(client);
            var result = await importer.ImportExportedSettingsAsync(ExportPath);
            StatusMessage = result.ToStatusText();
            SetDeploymentStatus($"Export import complete. {StatusMessage}");
            AddHistory("Infrastructure", "Complete", StatusMessage, false);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Export import failed. {StatusMessage}");
            AddHistory("Infrastructure", "Failed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    private SecKeyManifestDeploymentOptions BuildDeploymentOptions()
    {
        var parsed = (AdditionalBreakGlassAccounts ?? string.Empty)
            .Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToArray();

        return new SecKeyManifestDeploymentOptions
        {
            AdditionalBreakGlassAccounts = parsed,
            Progress = OnDeploymentProgress
        };
    }

    private void OnDeploymentProgress(DeploymentProgressEvent evt)
    {
        var dispatcher = Application.Current?.Dispatcher;
        void apply()
        {
            AddHistory("Infrastructure", evt.Stage, $"{evt.Command}: {evt.Message}", evt.IsError);
            SetDeploymentStatus($"{evt.Stage} {evt.Command}: {evt.Message}");
        }

        if (dispatcher is null || dispatcher.CheckAccess())
            apply();
        else
            dispatcher.Invoke(apply);
    }

    private void SetDeploymentStatus(string message)
        => DeploymentStatus = $"{DateTime.Now:HH:mm:ss} - {message}";

    private void AddHistory(string scope, string stage, string message, bool isError)
        => DeploymentPageHelpers.AddHistory(DeploymentHistory, scope, stage, message, isError);
}
