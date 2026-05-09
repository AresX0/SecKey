using SecKey.App.Services;
using SecKey.Graph;
using SecKey.Graph.Services;
using SecKey.Graph.Services.EntraID;
using SecKey.Graph.Services.Intune;
using System;
using System.Collections.ObjectModel;
using System.IO;

namespace SecKey.App.ViewModels;

public sealed record DeploymentHistoryEntry(string Timestamp, string Scope, string Stage, string Message, bool IsError);

public sealed partial class OptionalFeatureSelectionViewModel : CommunityToolkit.Mvvm.ComponentModel.ObservableObject
{
    public string Id { get; }
    public string DisplayName { get; }
    public string Description { get; }
    public string Command { get; }

    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private bool _isSelected;

    public OptionalFeatureSelectionViewModel(SecKeyOptionalFeatureDefinition definition)
    {
        Id = definition.Id;
        DisplayName = definition.DisplayName;
        Description = definition.Description;
        Command = definition.Command;
    }
}

public sealed partial class DashboardViewModel : GraphPageViewModel
{
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string _deploymentStatus = "Idle.";
    public ObservableCollection<DeploymentHistoryEntry> DeploymentHistory { get; } = new();

    public DashboardViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp) { }
    protected override async IAsyncEnumerable<EntityRow> LoadAsync()
    {
        var c = BuildClient();
        yield return new(null, "Apps", (await new IntuneApplicationService(c).ListAsync()).Count + " items");
        yield return new(null, "Compliance", (await new DeviceCompliancePolicyService(c).ListAsync()).Count + " items");
        yield return new(null, "Configuration", (await new DeviceConfigurationService(c).ListAsync()).Count + " items");
        yield return new(null, "Settings Catalog", (await new DeviceSettingsCatalogService(c).ListAsync()).Count + " items");
        yield return new(null, "Groups", (await new EntraIdGroupService(c).ListAsync()).Count + " items");
        yield return new(null, "Conditional Access", (await new ConditionalAccessPolicyService(c).ListAsync()).Count + " items");
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task ApplyFullEnvironmentAsync()
    {
        Busy = true;
        SetDeploymentStatus("Deploying full SecKey environment.");
        AddHistory("Dashboard", "Start", "Full environment deployment started.", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = DeploymentPageHelpers.BuildOptions(DeploymentHistory, "Dashboard");
            var result = await deployment.DeployCsmAsync(DeploymentPageHelpers.ResolveRepoRoot(), options);
            StatusMessage = DeploymentPageHelpers.FormatDeploymentResult(result);
            SetDeploymentStatus($"Full deployment complete. {StatusMessage}");
            var hasErrors = result.Notes.Any(n => n.Contains("[ERROR]"));
            AddHistory("Dashboard", "Complete", StatusMessage, hasErrors);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Full deployment failed. {StatusMessage}");
            AddHistory("Dashboard", "Failed", StatusMessage, true);
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
        AddHistory("Dashboard", "UndoStart", "Full manifest rollback started.", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = DeploymentPageHelpers.BuildOptions(DeploymentHistory, "Dashboard");
            var result = await deployment.UndoCsmAsync(DeploymentPageHelpers.ResolveRepoRoot(), options);
            StatusMessage = DeploymentPageHelpers.FormatDeploymentResult(result);
            SetDeploymentStatus($"Full rollback complete. {StatusMessage}");
            var hasErrors = result.Notes.Any(n => n.Contains("[UNDO ERROR]"));
            AddHistory("Dashboard", "UndoComplete", StatusMessage, hasErrors);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Full rollback failed. {StatusMessage}");
            AddHistory("Dashboard", "UndoFailed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task DeployGroupsAsync()
    {
        Busy = true;
        SetDeploymentStatus("Deploying groups and users.");
        AddHistory("Dashboard", "Start", "Group deployment started (users, then groups).", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = DeploymentPageHelpers.BuildOptions(DeploymentHistory, "Dashboard");
            await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-EntraUserList", options);
            var result = await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-EntraGroupList", options);
            StatusMessage = result.ToStatusText();
            SetDeploymentStatus($"Groups deployment complete. {StatusMessage}");
            AddHistory("Dashboard", "Complete", StatusMessage, false);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Groups deployment failed. {StatusMessage}");
            AddHistory("Dashboard", "Failed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task DeployConditionalAccessAsync()
    {
        Busy = true;
        SetDeploymentStatus("Deploying named locations and Conditional Access policies.");
        AddHistory("Dashboard", "Start", "Conditional Access deployment started.", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = DeploymentPageHelpers.BuildOptions(DeploymentHistory, "Dashboard");
            await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-NamedLocationList", options);
            var result = await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-ConditionalAccessPolicyList", options);
            StatusMessage = result.ToStatusText();
            SetDeploymentStatus($"Conditional Access deployment complete. {StatusMessage}");
            AddHistory("Dashboard", "Complete", StatusMessage, false);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Conditional Access deployment failed. {StatusMessage}");
            AddHistory("Dashboard", "Failed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task DeployIntuneAppsAsync()
    {
        Busy = true;
        SetDeploymentStatus("Deploying Intune applications and assignments.");
        AddHistory("Dashboard", "Start", "Intune app deployment started.", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = DeploymentPageHelpers.BuildOptions(DeploymentHistory, "Dashboard");
            await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-IntuneApplicationList", options);
            var result = await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-StoreAppsEntraGroupAssignmentList", options);
            StatusMessage = result.ToStatusText();
            SetDeploymentStatus($"Intune app deployment complete. {StatusMessage}");
            AddHistory("Dashboard", "Complete", StatusMessage, false);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Intune app deployment failed. {StatusMessage}");
            AddHistory("Dashboard", "Failed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    private void SetDeploymentStatus(string message)
        => DeploymentStatus = DeploymentPageHelpers.WithTimestamp(message);

    private void AddHistory(string scope, string stage, string message, bool isError)
        => DeploymentPageHelpers.AddHistory(DeploymentHistory, scope, stage, message, isError);
}

public sealed partial class IntuneAppsViewModel : GraphPageViewModel
{
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string _deploymentStatus = "Idle.";
    public ObservableCollection<DeploymentHistoryEntry> DeploymentHistory { get; } = new();

    public IntuneAppsViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp) { }
    protected override IAsyncEnumerable<EntityRow> LoadAsync()
        => GraphPageHelpers.ListAsRowsAsync(new IntuneApplicationService(BuildClient()));

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task DeployIntuneAppsAsync()
    {
        Busy = true;
        SetDeploymentStatus("Deploying Intune applications.");
        AddHistory("Intune Apps", "Start", "Intune application deployment started.", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = DeploymentPageHelpers.BuildOptions(DeploymentHistory, "Intune Apps");
            var result = await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-IntuneApplicationList", options);
            StatusMessage = result.ToStatusText();
            SetDeploymentStatus($"Intune application deployment complete. {StatusMessage}");
            AddHistory("Intune Apps", "Complete", StatusMessage, false);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Intune application deployment failed. {StatusMessage}");
            AddHistory("Intune Apps", "Failed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task DeployStoreAssignmentsAsync()
    {
        Busy = true;
        SetDeploymentStatus("Deploying store app assignments.");
        AddHistory("Intune Apps", "Start", "Store assignment deployment started.", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = DeploymentPageHelpers.BuildOptions(DeploymentHistory, "Intune Apps");
            var result = await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-StoreAppsEntraGroupAssignmentList", options);
            StatusMessage = result.ToStatusText();
            SetDeploymentStatus($"Store app assignment deployment complete. {StatusMessage}");
            AddHistory("Intune Apps", "Complete", StatusMessage, false);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Store app assignment deployment failed. {StatusMessage}");
            AddHistory("Intune Apps", "Failed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    private void SetDeploymentStatus(string message)
        => DeploymentStatus = DeploymentPageHelpers.WithTimestamp(message);

    private void AddHistory(string scope, string stage, string message, bool isError)
        => DeploymentPageHelpers.AddHistory(DeploymentHistory, scope, stage, message, isError);
}

public sealed partial class PoliciesViewModel : GraphPageViewModel
{
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string _selectedDeploymentCommand = "Import-ConditionalAccessPolicyList";
    public ObservableCollection<DeploymentHistoryEntry> DeploymentHistory { get; } = new();

    public IReadOnlyList<string> DeploymentCommands { get; } = new[]
    {
        "Import-EntraUserList",
        "Import-EntraGroupList",
        "Import-IntuneRoleScopeTagList",
        "Import-NamedLocationList",
        "Import-ConditionalAccessPolicyList",
        "Import-DeviceEnrollmentRestrictionList",
        "Import-DeviceConfigurationList",
        "Import-DeviceConfigurationADMXList",
        "Import-DeviceCompliancePolicyList",
        "Import-DeviceSettingsCatalog",
        "Import-StoreAppsEntraGroupAssignmentList",
        "Import-IntuneApplicationList",
        "Import-AutoPilotPolicyList",
        "Import-EnrollmentStatusPageList",
        "Import-EndpointSecurityPolicyList",
        "Import-ProactiveRemediationScripts"
    };

    public PoliciesViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp) { }

    protected override async IAsyncEnumerable<EntityRow> LoadAsync()
    {
        var c = BuildClient();
        await foreach (var r in GraphPageHelpers.ListAsRowsAsync(new DeviceCompliancePolicyService(c)))
            yield return r with { Description = "Compliance" };
        await foreach (var r in GraphPageHelpers.ListAsRowsAsync(new DeviceConfigurationService(c)))
            yield return r with { Description = "Configuration" };
        await foreach (var r in GraphPageHelpers.ListAsRowsAsync(new DeviceSettingsCatalogService(c)))
            yield return r with { Description = "Settings Catalog" };
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task ApplySelectedDeploymentStepAsync()
    {
        if (string.IsNullOrWhiteSpace(SelectedDeploymentCommand))
        {
            StatusMessage = "Choose a deployment step first.";
            return;
        }

        Busy = true;
        AddHistory("Policies", "Start", $"Step deployment started: {SelectedDeploymentCommand}", false);
        try
        {
            var client = BuildClient();
            var deployment = new SecKeyManifestDeploymentService(client);
            var options = DeploymentPageHelpers.BuildOptions(DeploymentHistory, "Policies");
            var result = await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), SelectedDeploymentCommand, options);
            StatusMessage = result.ToStatusText() + (result.Notes.Count > 0 ? $" Notes: {string.Join(" | ", result.Notes)}" : string.Empty);
            AddHistory("Policies", "Complete", $"{SelectedDeploymentCommand}: {StatusMessage}", false);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            AddHistory("Policies", "Failed", $"{SelectedDeploymentCommand}: {StatusMessage}", true);
        }
        finally
        {
            Busy = false;
        }
    }

    private void AddHistory(string scope, string stage, string message, bool isError)
        => DeploymentPageHelpers.AddHistory(DeploymentHistory, scope, stage, message, isError);
}

public sealed partial class GroupsViewModel : GraphPageViewModel
{
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string _deploymentStatus = "Idle.";
    public ObservableCollection<DeploymentHistoryEntry> DeploymentHistory { get; } = new();

    public GroupsViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp) { }
    protected override IAsyncEnumerable<EntityRow> LoadAsync()
        => GraphPageHelpers.ListAsRowsAsync(new EntraIdGroupService(BuildClient()));

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task DeployGroupsAsync()
    {
        Busy = true;
        SetDeploymentStatus("Deploying groups and users.");
        AddHistory("Groups", "Start", "Users + groups deployment started.", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = DeploymentPageHelpers.BuildOptions(DeploymentHistory, "Groups");
            await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-EntraUserList", options);
            var result = await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-EntraGroupList", options);
            StatusMessage = result.ToStatusText();
            SetDeploymentStatus($"Group deployment complete. {StatusMessage}");
            AddHistory("Groups", "Complete", StatusMessage, false);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Group deployment failed. {StatusMessage}");
            AddHistory("Groups", "Failed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    private void SetDeploymentStatus(string message)
        => DeploymentStatus = DeploymentPageHelpers.WithTimestamp(message);

    private void AddHistory(string scope, string stage, string message, bool isError)
        => DeploymentPageHelpers.AddHistory(DeploymentHistory, scope, stage, message, isError);
}

public sealed partial class ConditionalAccessViewModel : GraphPageViewModel
{
    [CommunityToolkit.Mvvm.ComponentModel.ObservableProperty] private string _deploymentStatus = "Idle.";
    public ObservableCollection<DeploymentHistoryEntry> DeploymentHistory { get; } = new();

    public ConditionalAccessViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp) { }
    protected override IAsyncEnumerable<EntityRow> LoadAsync()
        => GraphPageHelpers.ListAsRowsAsync(new ConditionalAccessPolicyService(BuildClient()));

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private async Task DeployConditionalAccessAsync()
    {
        Busy = true;
        SetDeploymentStatus("Deploying named locations and Conditional Access policies.");
        AddHistory("Conditional Access", "Start", "Named locations + CA deployment started.", false);
        try
        {
            var deployment = new SecKeyManifestDeploymentService(BuildClient());
            var options = DeploymentPageHelpers.BuildOptions(DeploymentHistory, "Conditional Access");
            await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-NamedLocationList", options);
            var result = await deployment.DeployCsmCommandAsync(DeploymentPageHelpers.ResolveRepoRoot(), "Import-ConditionalAccessPolicyList", options);
            StatusMessage = result.ToStatusText();
            SetDeploymentStatus($"Conditional Access deployment complete. {StatusMessage}");
            AddHistory("Conditional Access", "Complete", StatusMessage, false);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            SetDeploymentStatus($"Conditional Access deployment failed. {StatusMessage}");
            AddHistory("Conditional Access", "Failed", StatusMessage, true);
        }
        finally
        {
            Busy = false;
        }
    }

    private void SetDeploymentStatus(string message)
        => DeploymentStatus = DeploymentPageHelpers.WithTimestamp(message);

    private void AddHistory(string scope, string stage, string message, bool isError)
        => DeploymentPageHelpers.AddHistory(DeploymentHistory, scope, stage, message, isError);
}

internal static class DeploymentPageHelpers
{
    public static string ResolveRepoRoot()
    {
        var dir = new DirectoryInfo(Environment.CurrentDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "JSON")) &&
                Directory.Exists(Path.Combine(dir.FullName, "source")))
                return dir.FullName;
            dir = dir.Parent;
        }

        return Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, ".."));
    }

    public static string WithTimestamp(string message) => $"{DateTime.Now:HH:mm:ss} - {message}";

    public static void AddHistory(ObservableCollection<DeploymentHistoryEntry> history, string scope, string stage, string message, bool isError)
    {
        history.Insert(0, new DeploymentHistoryEntry(DateTime.Now.ToString("HH:mm:ss"), scope, stage, message, isError));
        while (history.Count > 50)
            history.RemoveAt(history.Count - 1);
    }

    public static string FormatDeploymentResult(SecKey.Graph.Services.SecKeyManifestDeploymentSummary result)
    {
        var baseText = result.ToStatusText();
        if (result.Notes.Count == 0)
            return baseText;

        var errorLines = result.Notes.Where(n => n.Contains("[ERROR]") || n.Contains("[UNDO ERROR]")).ToList();
        var summaryLines = result.Notes.Where(n => n.Contains("[DEPLOYMENT SUMMARY]") || n.Contains("[UNDO SUMMARY]")).ToList();

        if (errorLines.Count == 0 && summaryLines.Count == 0)
            return baseText + $" | {string.Join(" | ", result.Notes)}";

        var message = baseText;
        if (summaryLines.Count > 0)
        {
            message += $" | {summaryLines[0]}";
        }
        else if (errorLines.Count > 0)
        {
            message += $" | {errorLines.Count} error(s) during deployment";
        }

        return message;
    }

    public static SecKeyManifestDeploymentOptions BuildOptions(
        ObservableCollection<DeploymentHistoryEntry> history,
        string scope,
        IEnumerable<string>? additionalBreakGlass = null)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        return new SecKeyManifestDeploymentOptions
        {
            AdditionalBreakGlassAccounts = (additionalBreakGlass ?? Array.Empty<string>()).ToArray(),
            Progress = evt =>
            {
                void apply() => AddHistory(history, scope, evt.Stage, $"{evt.Command}: {evt.Message}", evt.IsError);
                if (dispatcher is null || dispatcher.CheckAccess()) apply();
                else dispatcher.Invoke(apply);
            }
        };
    }
}
