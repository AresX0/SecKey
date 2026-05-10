using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SecKey.App.ViewModels;

public sealed partial class SshKeyManagerViewModel : ObservableObject
{
    private readonly string _sshDir;

    [ObservableProperty] private string statusMessage = "Ready";
    [ObservableProperty] private string keyName = "id_ed25519";
    [ObservableProperty] private string publicKey = string.Empty;
    [ObservableProperty] private string privateKeyPath = string.Empty;
    [ObservableProperty] private string passphrase = string.Empty;
    [ObservableProperty] private string? selectedKey;
    public ObservableCollection<string> ExistingKeys { get; } = new();

    public SshKeyManagerViewModel()
    {
        _sshDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
        Directory.CreateDirectory(_sshDir);
        RefreshKeys();
    }

    [RelayCommand]
    private void RefreshKeys()
    {
        ExistingKeys.Clear();
        foreach (var key in Directory.GetFiles(_sshDir, "*.pub").Select(Path.GetFileName).OrderBy(x => x))
            ExistingKeys.Add(key ?? string.Empty);
        StatusMessage = $"Found {ExistingKeys.Count} public keys.";
    }

    [RelayCommand]
    private void GenerateKey()
    {
        try
        {
            var keyPath = Path.Combine(_sshDir, KeyName);
            var psi = new ProcessStartInfo
            {
                FileName = "ssh-keygen",
                Arguments = $"-t ed25519 -f \"{keyPath}\" -N \"{Passphrase}\" -C \"SecKey@{Environment.MachineName}\"",
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p is null)
            {
                StatusMessage = "Failed to start ssh-keygen.";
                return;
            }
            p.WaitForExit();
            if (p.ExitCode != 0)
            {
                StatusMessage = p.StandardError.ReadToEnd();
                return;
            }

            PrivateKeyPath = keyPath;
            var pubPath = keyPath + ".pub";
            PublicKey = File.Exists(pubPath) ? File.ReadAllText(pubPath) : string.Empty;
            RefreshKeys();
            StatusMessage = "SSH key created.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Generate failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private void LoadSelectedKey(string? publicFileName)
    {
        if (string.IsNullOrWhiteSpace(publicFileName)) return;
        var pubPath = Path.Combine(_sshDir, publicFileName);
        if (!File.Exists(pubPath)) return;
        PublicKey = File.ReadAllText(pubPath);
        PrivateKeyPath = Path.Combine(_sshDir, Path.GetFileNameWithoutExtension(publicFileName));
        StatusMessage = "Loaded selected key.";
    }

    [RelayCommand]
    private void CopyPublicKey()
    {
        if (!string.IsNullOrWhiteSpace(PublicKey))
            System.Windows.Clipboard.SetText(PublicKey);
        StatusMessage = "Public key copied.";
    }
}
