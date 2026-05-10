using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using SecKey.Core.Services;

namespace SecKey.App.ViewModels
{
    /// <summary>
    /// Represents a wipe level option for the UI.
    /// </summary>
    public class WipeLevelOption
    {
        public SecureWipeLevel Level { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int PassCount { get; set; }
        public string Icon { get; set; } = "🔒";
    }

    /// <summary>
    /// ViewModel for the Secure Data Wipe view.
    /// </summary>
    public class SecureWipeViewModel : BindableBase
    {
        private readonly SecureWipeService _service;
        private CancellationTokenSource? _cts;

        public SecureWipeViewModel()
        {
            _service = new SecureWipeService();
            InitializeWipeLevels();

            // Commands
            BrowseFileCommand = new RelayCommand(_ => BrowseFile());
            BrowseFolderCommand = new RelayCommand(_ => BrowseFolder());
            WipeCommand = new RelayCommand(async _ => await ExecuteWipeAsync(), _ => CanExecuteWipe());
            CancelCommand = new RelayCommand(_ => CancelWipe(), _ => IsWiping);
            WipeFreeSpaceCommand = new RelayCommand(async _ => await WipeFreeSpaceAsync(), _ => !IsWiping);
            ClearLogCommand = new RelayCommand(_ => WipeLog.Clear());

            // Set default
            SelectedWipeLevel = WipeLevels[2]; // DoD 5220.22-M as default
        }

        private void InitializeWipeLevels()
        {
            WipeLevels = new ObservableCollection<WipeLevelOption>
            {
                new() { Level = SecureWipeLevel.SinglePassZero, Name = "Quick Erase (Zeros)", 
                    Description = "Single pass with zeros - Fast, suitable for non-sensitive data", PassCount = 1, Icon = "⚡" },
                new() { Level = SecureWipeLevel.SinglePassRandom, Name = "Random Overwrite", 
                    Description = "Single pass with cryptographically random data", PassCount = 1, Icon = "🎲" },
                new() { Level = SecureWipeLevel.DoD522022M, Name = "DoD 5220.22-M (Standard)", 
                    Description = "U.S. Department of Defense standard - 3 passes (zeros, ones, random) + verification", PassCount = 3, Icon = "🛡️" },
                new() { Level = SecureWipeLevel.DoD522022M_ECE, Name = "DoD 5220.22-M ECE (Enhanced)", 
                    Description = "Enhanced DoD standard - 7 passes for higher security", PassCount = 7, Icon = "🔐" },
                new() { Level = SecureWipeLevel.NIST80088Clear, Name = "NIST 800-88 Clear", 
                    Description = "NIST standard for sanitizing media - Single verified pass", PassCount = 1, Icon = "📋" },
                new() { Level = SecureWipeLevel.NIST80088Purge, Name = "NIST 800-88 Purge", 
                    Description = "NIST enhanced sanitization - Multiple verified passes", PassCount = 3, Icon = "🧹" },
                new() { Level = SecureWipeLevel.Gutmann35Pass, Name = "Gutmann 35-Pass (Maximum)", 
                    Description = "Peter Gutmann's method - 35 passes with specific patterns. Very slow but maximum security.", PassCount = 35, Icon = "🔥" },
                new() { Level = SecureWipeLevel.CustomPasses, Name = "Custom Passes", 
                    Description = "Specify your own number of overwrite passes", PassCount = 0, Icon = "⚙️" }
            };
        }

        #region Properties

        public ObservableCollection<WipeLevelOption> WipeLevels { get; private set; } = new();

        private WipeLevelOption? _selectedWipeLevel;
        public WipeLevelOption? SelectedWipeLevel
        {
            get => _selectedWipeLevel;
            set
            {
                if (SetProperty(ref _selectedWipeLevel, value))
                {
                    OnPropertyChanged(nameof(IsCustomPasses));
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        public bool IsCustomPasses => SelectedWipeLevel?.Level == SecureWipeLevel.CustomPasses;

        private int _customPassCount = 3;
        public int CustomPassCount
        {
            get => _customPassCount;
            set => SetProperty(ref _customPassCount, Math.Clamp(value, 1, 100));
        }

        private string _targetPath = string.Empty;
        public string TargetPath
        {
            get => _targetPath;
            set
            {
                if (SetProperty(ref _targetPath, value))
                {
                    UpdateTargetInfo();
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        private bool _isFile;
        public bool IsFile
        {
            get => _isFile;
            set => SetProperty(ref _isFile, value);
        }

        private string _targetInfo = string.Empty;
        public string TargetInfo
        {
            get => _targetInfo;
            set => SetProperty(ref _targetInfo, value);
        }

        private bool _isWiping;
        public bool IsWiping
        {
            get => _isWiping;
            set
            {
                if (SetProperty(ref _isWiping, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        private double _progress;
        public double Progress
        {
            get => _progress;
            set => SetProperty(ref _progress, value);
        }

        private string _statusMessage = "Ready. Select a file or folder to wipe.";
        public string StatusMessage
        {
            get => _statusMessage;
            set => SetProperty(ref _statusMessage, value);
        }

        private string _currentOperation = string.Empty;
        public string CurrentOperation
        {
            get => _currentOperation;
            set => SetProperty(ref _currentOperation, value);
        }

        private int _currentPass;
        public int CurrentPass
        {
            get => _currentPass;
            set => SetProperty(ref _currentPass, value);
        }

        private int _totalPasses;
        public int TotalPasses
        {
            get => _totalPasses;
            set => SetProperty(ref _totalPasses, value);
        }

        private bool _confirmBeforeWipe = true;
        public bool ConfirmBeforeWipe
        {
            get => _confirmBeforeWipe;
            set => SetProperty(ref _confirmBeforeWipe, value);
        }

        private bool _renameBeforeDelete = true;
        public bool RenameBeforeDelete
        {
            get => _renameBeforeDelete;
            set => SetProperty(ref _renameBeforeDelete, value);
        }

        private bool _wipeFreeSpaceAfter;
        public bool WipeFreeSpaceAfter
        {
            get => _wipeFreeSpaceAfter;
            set => SetProperty(ref _wipeFreeSpaceAfter, value);
        }

        public ObservableCollection<string> WipeLog { get; } = new();

        // Available drives for free space wipe
        public ObservableCollection<DriveInfo> AvailableDrives { get; } = new();

        private DriveInfo? _selectedDrive;
        public DriveInfo? SelectedDrive
        {
            get => _selectedDrive;
            set => SetProperty(ref _selectedDrive, value);
        }

        #endregion

        #region Commands

        public ICommand BrowseFileCommand { get; }
        public ICommand BrowseFolderCommand { get; }
        public ICommand WipeCommand { get; }
        public ICommand CancelCommand { get; }
        public ICommand WipeFreeSpaceCommand { get; }
        public ICommand ClearLogCommand { get; }

        #endregion

        #region Methods

        private void BrowseFile()
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Select File to Securely Wipe",
                Filter = "All Files (*.*)|*.*",
                Multiselect = false
            };

            if (dialog.ShowDialog() == true)
            {
                TargetPath = dialog.FileName;
                IsFile = true;
            }
        }

        private void BrowseFolder()
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Select Folder to Securely Wipe (ALL CONTENTS WILL BE DESTROYED)"
            };

            if (dialog.ShowDialog() == true)
            {
                TargetPath = dialog.FolderName;
                IsFile = false;
            }
        }

        private void UpdateTargetInfo()
        {
            if (string.IsNullOrWhiteSpace(TargetPath))
            {
                TargetInfo = string.Empty;
                return;
            }

            try
            {
                if (File.Exists(TargetPath))
                {
                    IsFile = true;
                    var fi = new FileInfo(TargetPath);
                    TargetInfo = $"File: {fi.Name} ({FormatBytes(fi.Length)})";
                }
                else if (Directory.Exists(TargetPath))
                {
                    IsFile = false;
                    var files = Directory.GetFiles(TargetPath, "*", SearchOption.AllDirectories);
                    var dirs = Directory.GetDirectories(TargetPath, "*", SearchOption.AllDirectories);
                    long totalSize = 0;
                    foreach (var f in files)
                    {
                        try { totalSize += new FileInfo(f).Length; } catch { }
                    }
                    TargetInfo = $"Folder: {files.Length} files, {dirs.Length} subfolders ({FormatBytes(totalSize)})";
                }
                else
                {
                    TargetInfo = "Path does not exist";
                }
            }
            catch (Exception ex)
            {
                TargetInfo = $"Error: {ex.Message}";
            }
        }

        private bool CanExecuteWipe()
        {
            return !IsWiping &&
                   SelectedWipeLevel != null &&
                   !string.IsNullOrWhiteSpace(TargetPath) &&
                   (File.Exists(TargetPath) || Directory.Exists(TargetPath));
        }

        private async Task ExecuteWipeAsync()
        {
            if (SelectedWipeLevel == null || string.IsNullOrWhiteSpace(TargetPath))
                return;

            // Confirm with user
            if (ConfirmBeforeWipe)
            {
                var typeStr = IsFile ? "file" : "folder and ALL its contents";
                var result = MessageBox.Show(
                    $"⚠️ WARNING: This will PERMANENTLY and IRREVERSIBLY destroy the {typeStr}:\n\n" +
                    $"{TargetPath}\n\n" +
                    $"Wipe Level: {SelectedWipeLevel.Name}\n" +
                    $"Passes: {(IsCustomPasses ? CustomPassCount : SelectedWipeLevel.PassCount)}\n\n" +
                    "THIS ACTION CANNOT BE UNDONE!\n\n" +
                    "Are you absolutely sure you want to proceed?",
                    "Confirm Secure Wipe",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.No);

                if (result != MessageBoxResult.Yes)
                    return;

                // Double confirmation for folders
                if (!IsFile)
                {
                    result = MessageBox.Show(
                        "FINAL WARNING: You are about to wipe an entire folder.\n\n" +
                        "Type 'DELETE' mentally and click Yes to confirm.",
                        "Final Confirmation",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Stop,
                        MessageBoxResult.No);

                    if (result != MessageBoxResult.Yes)
                        return;
                }
            }

            _cts?.Cancel();
            _cts = new CancellationTokenSource();

            IsWiping = true;
            Progress = 0;
            TotalPasses = IsCustomPasses ? CustomPassCount : SelectedWipeLevel.PassCount;

            var progress = new Progress<SecureWipeProgress>(p =>
            {
                CurrentPass = p.CurrentPass;
                Progress = p.OverallPercentage;
                CurrentOperation = p.StatusMessage;
                StatusMessage = $"Wiping: {Path.GetFileName(p.CurrentFile)} - Pass {p.CurrentPass}/{p.TotalPasses}";
            });

            try
            {
                Log($"Starting secure wipe: {TargetPath}");
                Log($"Wipe level: {SelectedWipeLevel.Name} ({TotalPasses} passes)");

                SecureWipeResult result;

                if (IsFile)
                {
                    result = await _service.WipeFileAsync(
                        TargetPath,
                        SelectedWipeLevel.Level,
                        progress,
                        _cts.Token,
                        CustomPassCount);
                }
                else
                {
                    result = await _service.WipeDirectoryAsync(
                        TargetPath,
                        SelectedWipeLevel.Level,
                        progress,
                        _cts.Token,
                        CustomPassCount);
                }

                if (result.Success)
                {
                    Log($"✅ Wipe completed successfully!");
                    Log($"   Files wiped: {result.FilesWiped}");
                    Log($"   Folders removed: {result.FoldersRemoved}");
                    Log($"   Data destroyed: {FormatBytes(result.BytesWiped)}");
                    Log($"   Duration: {result.Duration:mm\\:ss}");

                    StatusMessage = $"Wipe completed: {result.FilesWiped} files, {FormatBytes(result.BytesWiped)} destroyed";
                    Progress = 100;

                    // Wipe free space if requested
                    if (WipeFreeSpaceAfter && !string.IsNullOrEmpty(TargetPath))
                    {
                        await WipeFreeSpaceAsync();
                    }

                    MessageBox.Show(
                        $"Secure wipe completed successfully!\n\n" +
                        $"Files wiped: {result.FilesWiped}\n" +
                        $"Folders removed: {result.FoldersRemoved}\n" +
                        $"Data destroyed: {FormatBytes(result.BytesWiped)}\n" +
                        $"Duration: {result.Duration:mm\\:ss}",
                        "Wipe Complete",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                else
                {
                    Log($"❌ Wipe failed: {result.ErrorMessage}");
                    foreach (var error in result.Errors)
                    {
                        Log($"   Error: {error}");
                    }
                    StatusMessage = $"Wipe failed: {result.ErrorMessage}";

                    MessageBox.Show(
                        $"Secure wipe encountered errors:\n\n{result.ErrorMessage}",
                        "Wipe Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }

                TargetPath = string.Empty;
            }
            catch (OperationCanceledException)
            {
                Log("⚠️ Wipe operation cancelled by user");
                StatusMessage = "Wipe cancelled";
            }
            catch (Exception ex)
            {
                Log($"❌ Error: {ex.Message}");
                StatusMessage = $"Error: {ex.Message}";
                MessageBox.Show($"Error during wipe:\n\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsWiping = false;
                CurrentOperation = string.Empty;
            }
        }

        private void CancelWipe()
        {
            _cts?.Cancel();
            StatusMessage = "Cancelling...";
            Log("Cancellation requested...");
        }

        private async Task WipeFreeSpaceAsync()
        {
            // Refresh drives
            AvailableDrives.Clear();
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                {
                    AvailableDrives.Add(drive);
                }
            }

            if (SelectedDrive == null && AvailableDrives.Count > 0)
            {
                SelectedDrive = AvailableDrives[0];
            }

            if (SelectedDrive == null)
            {
                MessageBox.Show("No drive selected for free space wipe.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var result = MessageBox.Show(
                $"This will wipe free space on drive {SelectedDrive.Name}\n\n" +
                $"Free space: {FormatBytes(SelectedDrive.AvailableFreeSpace)}\n\n" +
                "This may take a very long time. Continue?",
                "Wipe Free Space",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes)
                return;

            _cts?.Cancel();
            _cts = new CancellationTokenSource();

            IsWiping = true;
            Progress = 0;

            var progress = new Progress<SecureWipeProgress>(p =>
            {
                Progress = p.OverallPercentage;
                StatusMessage = p.StatusMessage;
            });

            try
            {
                Log($"Starting free space wipe on {SelectedDrive.Name}");

                var wipeResult = await _service.WipeFreeSpaceAsync(
                    SelectedDrive.RootDirectory.FullName,
                    SelectedWipeLevel?.Level ?? SecureWipeLevel.SinglePassZero,
                    progress,
                    _cts.Token,
                    CustomPassCount);

                if (wipeResult.Success)
                {
                    Log($"✅ Free space wipe completed: {FormatBytes(wipeResult.BytesWiped)}");
                    StatusMessage = "Free space wipe completed";
                }
                else
                {
                    Log($"❌ Free space wipe failed: {wipeResult.ErrorMessage}");
                }
            }
            catch (OperationCanceledException)
            {
                Log("Free space wipe cancelled");
            }
            catch (Exception ex)
            {
                Log($"Error: {ex.Message}");
            }
            finally
            {
                IsWiping = false;
            }
        }

        private void Log(string message)
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            _ = Application.Current.Dispatcher.InvokeAsync(() =>
            {
                WipeLog.Add($"[{timestamp}] {message}");
            });
        }

        private static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;
            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }
            return $"{size:0.##} {sizes[order]}";
        }

        #endregion
    }
}
