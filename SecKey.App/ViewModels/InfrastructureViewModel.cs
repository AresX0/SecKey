using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Microsoft.Extensions.DependencyInjection;
using SecKey.App.Services;
using SecKey.Graph;
using SecKey.Graph.Services;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Windows;

namespace SecKey.App.ViewModels;

public sealed partial class InfrastructureViewModel : GraphPageViewModel
{
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string _baselineZipPath =
        Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, "..", "Windows 11 v25H2 Security Baseline.zip"));
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string? _exportPath;
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string? _additionalBreakGlassAccounts;
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private ManifestCommandOption? _selectedManifestCommand;
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string _deploymentStatus = "Idle.";
    public ObservableCollection<DeploymentHistoryEntry> DeploymentHistory { get; } = new();
    public ObservableCollection<OptionalFeatureSelectionViewModel> OptionalFeatures { get; } = new();
    public ObservableCollection<ManifestCommandOption> ManifestCommands { get; } = new();

    public InfrastructureViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp)
    {
        InitializeSettingsInventory("Infrastructure");

        foreach (var feature in SecKeyManifestDeploymentService.OptionalFeatures)
            OptionalFeatures.Add(new OptionalFeatureSelectionViewModel(feature));

        LoadManifestCommands();
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
    private async Task ApplySelectedManifestStepAsync()
    {
        if (SelectedManifestCommand is null)
        {
            StatusMessage = "Select a manifest command first.";
            SetDeploymentStatus(StatusMessage);
            return;
        }

        Busy = true;
        SetDeploymentStatus($"Deploying manifest command: {SelectedManifestCommand.Command}");
        AddHistory("Infrastructure", "CommandStart", $"Deploy command started: {SelectedManifestCommand.Command}", false);

        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            SecKeyManifestDeploymentSummary result;

            if (SelectedManifestCommand.Source == "Optional")
            {
                result = await deployment.DeployOptionalFeaturesAsync(
                    DeploymentPageHelpers.ResolveRepoRoot(),
                    new[] { SelectedManifestCommand.Command },
                    BuildDeploymentOptions());
            }
            else
            {
                result = await deployment.DeployCsmCommandAsync(
                    DeploymentPageHelpers.ResolveRepoRoot(),
                    SelectedManifestCommand.Command,
                    BuildDeploymentOptions());
            }

            StatusMessage = result.ToStatusText() +
                            (result.Notes.Count > 0 ? $" Notes: {string.Join(" | ", result.Notes)}" : string.Empty);
            SetDeploymentStatus($"Deploy command complete. {StatusMessage}");
            AddHistory("Infrastructure", "CommandComplete", StatusMessage, result.Notes.Any(note => note.Contains("[ERROR]")));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Deploy command failed. {StatusMessage}");
            AddHistory("Infrastructure", "CommandFailed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task UndoSelectedManifestStepAsync()
    {
        if (SelectedManifestCommand is null)
        {
            StatusMessage = "Select a manifest command first.";
            SetDeploymentStatus(StatusMessage);
            return;
        }

        Busy = true;
        SetDeploymentStatus($"Undoing manifest command: {SelectedManifestCommand.Command}");
        AddHistory("Infrastructure", "CommandUndoStart", $"Undo command started: {SelectedManifestCommand.Command}", false);

        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            SecKeyManifestDeploymentSummary result;

            if (SelectedManifestCommand.Source == "Optional")
            {
                result = await deployment.UndoOptionalFeaturesAsync(
                    DeploymentPageHelpers.ResolveRepoRoot(),
                    new[] { SelectedManifestCommand.Command },
                    BuildDeploymentOptions());
            }
            else
            {
                result = await deployment.UndoCsmCommandAsync(
                    DeploymentPageHelpers.ResolveRepoRoot(),
                    SelectedManifestCommand.Command,
                    BuildDeploymentOptions());
            }

            StatusMessage = result.ToStatusText() +
                            (result.Notes.Count > 0 ? $" Notes: {string.Join(" | ", result.Notes)}" : string.Empty);
            SetDeploymentStatus($"Undo command complete. {StatusMessage}");
            AddHistory("Infrastructure", "CommandUndoComplete", StatusMessage, result.Notes.Any(note => note.Contains("[UNDO ERROR]")));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Undo command failed. {StatusMessage}");
            AddHistory("Infrastructure", "CommandUndoFailed", StatusMessage, true);
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

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task DeployWdacAndGsaBaselineAsync()
    {
        Busy = true;
        SetDeploymentStatus("Deploying WDAC/AppLocker + Global Secure Access baseline commands.");
        AddHistory("Infrastructure", "Start", "WDAC/GSA baseline deployment started.", false);
        try
        {
            var repoRoot = DeploymentPageHelpers.ResolveRepoRoot();
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = BuildDeploymentOptions();

            var deviceConfig = await deployment.DeployCsmCommandAsync(repoRoot, "Import-DeviceConfigurationList", options);
            AddHistory("Infrastructure", "Complete", "Import-DeviceConfigurationList: " + deviceConfig.ToStatusText(), deviceConfig.Notes.Any(n => n.Contains("[ERROR]")));

            var endpointSecurity = await deployment.DeployCsmCommandAsync(repoRoot, "Import-EndpointSecurityPolicyList", options);
            AddHistory("Infrastructure", "Complete", "Import-EndpointSecurityPolicyList: " + endpointSecurity.ToStatusText(), endpointSecurity.Notes.Any(n => n.Contains("[ERROR]")));

            StatusMessage = $"WDAC/GSA baseline deploy complete. {deviceConfig.ToStatusText()} | {endpointSecurity.ToStatusText()}";
            SetDeploymentStatus(StatusMessage);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"WDAC/GSA deployment failed. {StatusMessage}");
            AddHistory("Infrastructure", "Failed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task UndoWdacAndGsaBaselineAsync()
    {
        Busy = true;
        SetDeploymentStatus("Undoing WDAC/AppLocker + Global Secure Access baseline commands.");
        AddHistory("Infrastructure", "UndoStart", "WDAC/GSA baseline rollback started.", false);
        try
        {
            var repoRoot = DeploymentPageHelpers.ResolveRepoRoot();
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = BuildDeploymentOptions();

            var endpointSecurity = await deployment.UndoCsmCommandAsync(repoRoot, "Import-EndpointSecurityPolicyList", options);
            AddHistory("Infrastructure", "UndoComplete", "Import-EndpointSecurityPolicyList: " + endpointSecurity.ToStatusText(), endpointSecurity.Notes.Any(n => n.Contains("[UNDO ERROR]")));

            var deviceConfig = await deployment.UndoCsmCommandAsync(repoRoot, "Import-DeviceConfigurationList", options);
            AddHistory("Infrastructure", "UndoComplete", "Import-DeviceConfigurationList: " + deviceConfig.ToStatusText(), deviceConfig.Notes.Any(n => n.Contains("[UNDO ERROR]")));

            StatusMessage = $"WDAC/GSA baseline rollback complete. {endpointSecurity.ToStatusText()} | {deviceConfig.ToStatusText()}";
            SetDeploymentStatus(StatusMessage);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"WDAC/GSA rollback failed. {StatusMessage}");
            AddHistory("Infrastructure", "UndoFailed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private void BrowseExportPath()
    {
        var fileDialog = new OpenFileDialog
        {
            Title = "Select Exported Settings Zip (or Cancel to pick a folder)",
            Filter = "Zip archive (*.zip)|*.zip|JSON file (*.json)|*.json|All files (*.*)|*.*"
        };

        if (fileDialog.ShowDialog() == true)
        {
            ExportPath = fileDialog.FileName;
            return;
        }

        var folderDialog = new OpenFolderDialog { Title = "Select exported settings folder" };
        if (folderDialog.ShowDialog() == true)
            ExportPath = folderDialog.FolderName;
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

    private void LoadManifestCommands()
    {
        var repoRoot = DeploymentPageHelpers.ResolveRepoRoot();
        var commandMap = new Dictionary<string, ManifestCommandOption>(StringComparer.OrdinalIgnoreCase);

        AddManifestCommands(Path.Combine(repoRoot, "JSON", "seckey.deploy.json"), "CSM", commandMap);
        AddManifestCommands(Path.Combine(repoRoot, "JSON", "seckey.optional.deploy.json"), "Optional", commandMap);

        foreach (var command in commandMap.Values.OrderBy(item => item.Command))
            ManifestCommands.Add(command);

        SelectedManifestCommand = ManifestCommands.FirstOrDefault();
    }

    private static void AddManifestCommands(string manifestPath, string source, IDictionary<string, ManifestCommandOption> target)
    {
        if (!File.Exists(manifestPath))
            return;

        try
        {
            var manifest = JsonNode.Parse(File.ReadAllText(manifestPath)) as JsonObject;
            var commandList = manifest?["commandList"] as JsonArray;
            if (commandList is null)
                return;

            foreach (var commandNode in commandList.OfType<JsonObject>())
            {
                var command = commandNode["command"]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(command))
                    continue;

                // Keep the first source encountered so CSM takes precedence over optional duplicates.
                if (!target.ContainsKey(command))
                    target[command] = new ManifestCommandOption(command, source);
            }
        }
        catch
        {
            // Ignore malformed manifest files; the UI will still function with remaining entries.
        }
    }
}

public sealed record ManifestCommandOption(string Command, string Source)
{
    public string Display => $"{Command} ({Source})";
}
