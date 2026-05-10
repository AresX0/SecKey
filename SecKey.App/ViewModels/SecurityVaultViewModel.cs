using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using SecKey.App.Services;

namespace SecKey.App.ViewModels;

public sealed class SecurityVaultViewModel : BindableBase
{
    private readonly NativeSecurityPortService _service = new();
    private readonly List<VaultSecretItem> _encryptedItems = [];
    private readonly string _masterHashPath;

    private string _name = string.Empty;
    private string _username = string.Empty;
    private string _secret = string.Empty;
    private string _notes = string.Empty;
    private string _statusMessage = "Ready";
    private VaultSecretPlain? _selectedItem;
    private string _masterPasswordInput = string.Empty;
    private bool _isUnlocked;

    public SecurityVaultViewModel()
    {
        _masterHashPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "NativePort", "vault.master.hash");

        AddOrUpdateCommand = new RelayCommand(_ => AddOrUpdate());
        RemoveSelectedCommand = new RelayCommand(_ => RemoveSelected(), _ => SelectedItem is not null);
        LoadSecretCommand = new RelayCommand(_ => LoadSelectedSecret(), _ => SelectedItem is not null);
        ClearEditorCommand = new RelayCommand(_ => ClearEditor());
        RefreshCommand = new RelayCommand(_ => LoadVault(), _ => IsUnlocked);
        UnlockVaultCommand = new RelayCommand(_ => UnlockVault());
        LockVaultCommand = new RelayCommand(_ => LockVault(), _ => IsUnlocked);
        StatusMessage = "Vault locked. Enter master password.";
    }

    public ObservableCollection<VaultSecretPlain> Items { get; } = [];

    public string Name { get => _name; set => SetProperty(ref _name, value); }
    public string Username { get => _username; set => SetProperty(ref _username, value); }
    public string Secret { get => _secret; set => SetProperty(ref _secret, value); }
    public string Notes { get => _notes; set => SetProperty(ref _notes, value); }
    public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }
    public string MasterPasswordInput { get => _masterPasswordInput; set => SetProperty(ref _masterPasswordInput, value); }
    public bool IsUnlocked { get => _isUnlocked; set => SetProperty(ref _isUnlocked, value); }

    public VaultSecretPlain? SelectedItem
    {
        get => _selectedItem;
        set
        {
            if (SetProperty(ref _selectedItem, value))
            {
                ((RelayCommand)RemoveSelectedCommand).RaiseCanExecuteChanged();
                ((RelayCommand)LoadSecretCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public System.Windows.Input.ICommand AddOrUpdateCommand { get; }
    public System.Windows.Input.ICommand RemoveSelectedCommand { get; }
    public System.Windows.Input.ICommand LoadSecretCommand { get; }
    public System.Windows.Input.ICommand ClearEditorCommand { get; }
    public System.Windows.Input.ICommand RefreshCommand { get; }
    public System.Windows.Input.ICommand UnlockVaultCommand { get; }
    public System.Windows.Input.ICommand LockVaultCommand { get; }

    private void LoadVault()
    {
        if (!IsUnlocked)
        {
            StatusMessage = "Vault is locked.";
            return;
        }

        try
        {
            _encryptedItems.Clear();
            _encryptedItems.AddRange(_service.LoadVault());

            Items.Clear();
            foreach (var encrypted in _encryptedItems.OrderByDescending(x => x.UpdatedAtUtc))
            {
                try
                {
                    var plain = _service.UnprotectSecret(encrypted);
                    Items.Add(plain);
                }
                catch
                {
                    // Skip items that cannot be decrypted for this user context.
                }
            }

            StatusMessage = $"Loaded {Items.Count} vault entries.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Vault load failed: {ex.Message}";
        }
    }

    private void AddOrUpdate()
    {
        if (!IsUnlocked)
        {
            StatusMessage = "Unlock vault first.";
            return;
        }

        if (string.IsNullOrWhiteSpace(Name) || string.IsNullOrWhiteSpace(Secret))
        {
            StatusMessage = "Name and Secret are required.";
            return;
        }

        try
        {
            var id = SelectedItem?.Id ?? string.Empty;
            var protectedItem = _service.ProtectSecret(id, Name.Trim(), Username.Trim(), Secret, Notes.Trim());

            var existingIndex = _encryptedItems.FindIndex(x => x.Id == protectedItem.Id);
            if (existingIndex >= 0)
            {
                _encryptedItems[existingIndex] = protectedItem;
            }
            else
            {
                _encryptedItems.Add(protectedItem);
            }

            _service.SaveVault(_encryptedItems);
            LoadVault();
            StatusMessage = "Vault entry saved.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Save failed: {ex.Message}";
        }
    }

    private void RemoveSelected()
    {
        if (!IsUnlocked)
        {
            StatusMessage = "Unlock vault first.";
            return;
        }

        if (SelectedItem is null)
        {
            return;
        }

        var idx = _encryptedItems.FindIndex(x => x.Id == SelectedItem.Id);
        if (idx < 0)
        {
            return;
        }

        _encryptedItems.RemoveAt(idx);
        _service.SaveVault(_encryptedItems);
        LoadVault();
        ClearEditor();
        StatusMessage = "Vault entry removed.";
    }

    private void LoadSelectedSecret()
    {
        if (!IsUnlocked)
        {
            StatusMessage = "Unlock vault first.";
            return;
        }

        if (SelectedItem is null)
        {
            return;
        }

        Name = SelectedItem.Name;
        Username = SelectedItem.Username;
        Secret = SelectedItem.Secret;
        Notes = SelectedItem.Notes;
        StatusMessage = "Loaded selected secret into editor.";
    }

    private void ClearEditor()
    {
        Name = string.Empty;
        Username = string.Empty;
        Secret = string.Empty;
        Notes = string.Empty;
        SelectedItem = null;
        StatusMessage = "Editor cleared.";
    }

    private void UnlockVault()
    {
        if (string.IsNullOrWhiteSpace(MasterPasswordInput))
        {
            StatusMessage = "Master password is required.";
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(_masterHashPath)!);
        var hash = ComputeHash(MasterPasswordInput);

        if (File.Exists(_masterHashPath))
        {
            var existing = File.ReadAllText(_masterHashPath).Trim();
            if (!string.Equals(existing, hash, StringComparison.Ordinal))
            {
                StatusMessage = "Invalid master password.";
                return;
            }
        }
        else
        {
            File.WriteAllText(_masterHashPath, hash);
        }

        IsUnlocked = true;
        MasterPasswordInput = string.Empty;
        LoadVault();
        ((RelayCommand)RefreshCommand).RaiseCanExecuteChanged();
        ((RelayCommand)LockVaultCommand).RaiseCanExecuteChanged();
        StatusMessage = "Vault unlocked.";
    }

    private void LockVault()
    {
        IsUnlocked = false;
        Items.Clear();
        _encryptedItems.Clear();
        ClearEditor();
        ((RelayCommand)RefreshCommand).RaiseCanExecuteChanged();
        ((RelayCommand)LockVaultCommand).RaiseCanExecuteChanged();
        StatusMessage = "Vault locked.";
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }
}
