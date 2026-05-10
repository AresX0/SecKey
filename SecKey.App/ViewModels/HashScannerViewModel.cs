using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using Microsoft.VisualBasic;
using SecKey.Core.Services;

namespace SecKey.App.ViewModels;

/// <summary>
/// ViewModel for the Hash Scanner tool - calculates file hashes (MD5, SHA1, SHA256, SHA512)
/// </summary>
public class HashScannerViewModel : BindableBase
{
    private string _selectedFile = string.Empty;
    private string _md5Hash = string.Empty;
    private string _sha1Hash = string.Empty;
    private string _sha256Hash = string.Empty;
    private string _sha512Hash = string.Empty;
    private string _crc32Hash = string.Empty;
    private string _statusMessage = "Ready - Select a file or drop files to calculate hashes";
    private bool _isCalculating;
    private bool _useUppercase = true;
    private long _fileSize;
    private string _fileName = string.Empty;
    private DateTime _fileModified;
    private CancellationTokenSource? _cancellationTokenSource;
    private double _progress;

    public HashScannerViewModel()
    {
        BrowseFileCommand = new RelayCommand(_ => BrowseFile());
        CalculateHashesCommand = new AsyncRelayCommand(CalculateHashesAsync, () => !string.IsNullOrEmpty(SelectedFile) && File.Exists(SelectedFile) && !IsCalculating);
        CancelCommand = new RelayCommand(_ => Cancel(), _ => IsCalculating);
        CopyMD5Command = new RelayCommand(_ => CopyToClipboard(MD5Hash), _ => !string.IsNullOrEmpty(MD5Hash));
        CopySHA1Command = new RelayCommand(_ => CopyToClipboard(SHA1Hash), _ => !string.IsNullOrEmpty(SHA1Hash));
        CopySHA256Command = new RelayCommand(_ => CopyToClipboard(SHA256Hash), _ => !string.IsNullOrEmpty(SHA256Hash));
        CopySHA512Command = new RelayCommand(_ => CopyToClipboard(SHA512Hash), _ => !string.IsNullOrEmpty(SHA512Hash));
        CopyCRC32Command = new RelayCommand(_ => CopyToClipboard(CRC32Hash), _ => !string.IsNullOrEmpty(CRC32Hash));
        CopyAllCommand = new RelayCommand(_ => CopyAllHashes(), _ => !string.IsNullOrEmpty(SHA256Hash));
        ClearCommand = new RelayCommand(_ => ClearAll());
        VerifyHashCommand = new RelayCommand(_ => VerifyHash());
        OpenInExplorerCommand = new RelayCommand(_ => OpenInExplorer(), _ => !string.IsNullOrEmpty(SelectedFile) && File.Exists(SelectedFile));
    }

    #region Properties

    public string SelectedFile
    {
        get => _selectedFile;
        set
        {
            _selectedFile = value;
            RaisePropertyChanged();
            ((AsyncRelayCommand)CalculateHashesCommand).RaiseCanExecuteChanged();
            ((RelayCommand)OpenInExplorerCommand).RaiseCanExecuteChanged();
            
            if (File.Exists(value))
            {
                var fi = new FileInfo(value);
                FileName = fi.Name;
                FileSize = fi.Length;
                FileModified = fi.LastWriteTime;
            }
        }
    }

    public string FileName
    {
        get => _fileName;
        set { _fileName = value; RaisePropertyChanged(); }
    }

    public long FileSize
    {
        get => _fileSize;
        set { _fileSize = value; RaisePropertyChanged(); RaisePropertyChanged(nameof(FileSizeFormatted)); }
    }

    public string FileSizeFormatted => FormatFileSize(FileSize);

    public DateTime FileModified
    {
        get => _fileModified;
        set { _fileModified = value; RaisePropertyChanged(); }
    }

    public string MD5Hash
    {
        get => _md5Hash;
        set { _md5Hash = value; RaisePropertyChanged(); ((RelayCommand)CopyMD5Command).RaiseCanExecuteChanged(); }
    }

    public string SHA1Hash
    {
        get => _sha1Hash;
        set { _sha1Hash = value; RaisePropertyChanged(); ((RelayCommand)CopySHA1Command).RaiseCanExecuteChanged(); }
    }

    public string SHA256Hash
    {
        get => _sha256Hash;
        set { _sha256Hash = value; RaisePropertyChanged(); ((RelayCommand)CopySHA256Command).RaiseCanExecuteChanged(); ((RelayCommand)CopyAllCommand).RaiseCanExecuteChanged(); }
    }

    public string SHA512Hash
    {
        get => _sha512Hash;
        set { _sha512Hash = value; RaisePropertyChanged(); ((RelayCommand)CopySHA512Command).RaiseCanExecuteChanged(); }
    }

    public string CRC32Hash
    {
        get => _crc32Hash;
        set { _crc32Hash = value; RaisePropertyChanged(); ((RelayCommand)CopyCRC32Command).RaiseCanExecuteChanged(); }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; RaisePropertyChanged(); }
    }

    public bool IsCalculating
    {
        get => _isCalculating;
        private set
        {
            _isCalculating = value;
            RaisePropertyChanged();
            ((AsyncRelayCommand)CalculateHashesCommand).RaiseCanExecuteChanged();
            ((RelayCommand)CancelCommand).RaiseCanExecuteChanged();
        }
    }

    public bool UseUppercase
    {
        get => _useUppercase;
        set
        {
            _useUppercase = value;
            RaisePropertyChanged();
            // Re-format existing hashes
            if (!string.IsNullOrEmpty(MD5Hash))
                MD5Hash = value ? MD5Hash.ToUpperInvariant() : MD5Hash.ToLowerInvariant();
            if (!string.IsNullOrEmpty(SHA1Hash))
                SHA1Hash = value ? SHA1Hash.ToUpperInvariant() : SHA1Hash.ToLowerInvariant();
            if (!string.IsNullOrEmpty(SHA256Hash))
                SHA256Hash = value ? SHA256Hash.ToUpperInvariant() : SHA256Hash.ToLowerInvariant();
            if (!string.IsNullOrEmpty(SHA512Hash))
                SHA512Hash = value ? SHA512Hash.ToUpperInvariant() : SHA512Hash.ToLowerInvariant();
            if (!string.IsNullOrEmpty(CRC32Hash))
                CRC32Hash = value ? CRC32Hash.ToUpperInvariant() : CRC32Hash.ToLowerInvariant();
        }
    }

    public double Progress
    {
        get => _progress;
        set { _progress = value; RaisePropertyChanged(); }
    }

    public ObservableCollection<HashResult> HashHistory { get; } = new();

    #endregion

    #region Commands

    public ICommand BrowseFileCommand { get; }
    public ICommand CalculateHashesCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand CopyMD5Command { get; }
    public ICommand CopySHA1Command { get; }
    public ICommand CopySHA256Command { get; }
    public ICommand CopySHA512Command { get; }
    public ICommand CopyCRC32Command { get; }
    public ICommand CopyAllCommand { get; }
    public ICommand ClearCommand { get; }
    public ICommand VerifyHashCommand { get; }
    public ICommand OpenInExplorerCommand { get; }

    #endregion

    #region Methods

    private void BrowseFile()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select File to Hash",
            Filter = "All Files|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            SelectedFile = dialog.FileName;
            _ = CalculateHashesAsync();
        }
    }

    public async Task CalculateHashesAsync()
    {
        if (string.IsNullOrEmpty(SelectedFile) || !File.Exists(SelectedFile))
        {
            StatusMessage = "File not found";
            return;
        }

        IsCalculating = true;
        _cancellationTokenSource = new CancellationTokenSource();
        Progress = 0;

        // Clear previous hashes
        MD5Hash = string.Empty;
        SHA1Hash = string.Empty;
        SHA256Hash = string.Empty;
        SHA512Hash = string.Empty;
        CRC32Hash = string.Empty;

        try
        {
            var fileInfo = new FileInfo(SelectedFile);
            StatusMessage = $"Calculating hashes for {fileInfo.Name} ({FormatFileSize(fileInfo.Length)})...";

            var stopwatch = Stopwatch.StartNew();

            // Calculate all hashes in parallel
            var md5Task = CalculateHashAsync<MD5>(SelectedFile, _cancellationTokenSource.Token);
            var sha1Task = CalculateHashAsync<SHA1>(SelectedFile, _cancellationTokenSource.Token);
            var sha256Task = CalculateHashAsync<SHA256>(SelectedFile, _cancellationTokenSource.Token);
            var sha512Task = CalculateHashAsync<SHA512>(SelectedFile, _cancellationTokenSource.Token);
            var crc32Task = CalculateCRC32Async(SelectedFile, _cancellationTokenSource.Token);

            // Update progress as each completes
            var tasks = new[] { md5Task, sha1Task, sha256Task, sha512Task, crc32Task };
            int completed = 0;

            foreach (var task in tasks)
            {
                await task;
                completed++;
                Progress = (double)completed / tasks.Length * 100;
            }

            MD5Hash = FormatHash(await md5Task);
            SHA1Hash = FormatHash(await sha1Task);
            SHA256Hash = FormatHash(await sha256Task);
            SHA512Hash = FormatHash(await sha512Task);
            CRC32Hash = FormatHash(await crc32Task);

            stopwatch.Stop();
            StatusMessage = $"Hashes calculated in {stopwatch.ElapsedMilliseconds}ms";

            // Add to history
            HashHistory.Insert(0, new HashResult
            {
                FileName = fileInfo.Name,
                FilePath = SelectedFile,
                FileSize = fileInfo.Length,
                SHA256 = SHA256Hash,
                MD5 = MD5Hash,
                CalculatedAt = DateTime.Now
            });

            // Keep history limited
            while (HashHistory.Count > 50)
                HashHistory.RemoveAt(HashHistory.Count - 1);
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Hash calculation cancelled";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
        finally
        {
            IsCalculating = false;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
        }
    }

    private async Task<byte[]> CalculateHashAsync<T>(string filePath, CancellationToken cancellationToken) where T : HashAlgorithm
    {
        using var algorithm = typeof(T).Name switch
        {
            "MD5" => (HashAlgorithm)System.Security.Cryptography.MD5.Create(),
            "SHA1" => System.Security.Cryptography.SHA1.Create(),
            "SHA256" => System.Security.Cryptography.SHA256.Create(),
            "SHA512" => System.Security.Cryptography.SHA512.Create(),
            _ => throw new NotSupportedException($"Algorithm {typeof(T).Name} not supported")
        };

        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        return await algorithm.ComputeHashAsync(stream, cancellationToken);
    }

    private async Task<byte[]> CalculateCRC32Async(string filePath, CancellationToken cancellationToken)
    {
        return await Task.Run(() =>
        {
            uint crc = 0xFFFFFFFF;
            var buffer = new byte[81920];

            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            int bytesRead;
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                for (int i = 0; i < bytesRead; i++)
                {
                    crc = (crc >> 8) ^ Crc32Table[(crc ^ buffer[i]) & 0xFF];
                }
            }

            crc ^= 0xFFFFFFFF;
            return BitConverter.GetBytes(crc).Reverse().ToArray();
        }, cancellationToken);
    }

    private static readonly uint[] Crc32Table = GenerateCrc32Table();

    private static uint[] GenerateCrc32Table()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int j = 0; j < 8; j++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
            }
            table[i] = crc;
        }
        return table;
    }

    private string FormatHash(byte[] hash)
    {
        var hex = BitConverter.ToString(hash).Replace("-", "");
        return UseUppercase ? hex : hex.ToLowerInvariant();
    }

    private void Cancel()
    {
        _cancellationTokenSource?.Cancel();
    }

    private void CopyToClipboard(string text)
    {
        if (!string.IsNullOrEmpty(text))
        {
            System.Windows.Clipboard.SetText(text);
            StatusMessage = "Hash copied to clipboard";
        }
    }

    private void CopyAllHashes()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"File: {SelectedFile}");
        sb.AppendLine($"Size: {FileSizeFormatted}");
        sb.AppendLine($"Modified: {FileModified:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();
        if (!string.IsNullOrEmpty(MD5Hash)) sb.AppendLine($"MD5:    {MD5Hash}");
        if (!string.IsNullOrEmpty(SHA1Hash)) sb.AppendLine($"SHA1:   {SHA1Hash}");
        if (!string.IsNullOrEmpty(SHA256Hash)) sb.AppendLine($"SHA256: {SHA256Hash}");
        if (!string.IsNullOrEmpty(SHA512Hash)) sb.AppendLine($"SHA512: {SHA512Hash}");
        if (!string.IsNullOrEmpty(CRC32Hash)) sb.AppendLine($"CRC32:  {CRC32Hash}");

        System.Windows.Clipboard.SetText(sb.ToString());
        StatusMessage = "All hashes copied to clipboard";
    }

    private void ClearAll()
    {
        SelectedFile = string.Empty;
        FileName = string.Empty;
        FileSize = 0;
        FileModified = default;
        MD5Hash = string.Empty;
        SHA1Hash = string.Empty;
        SHA256Hash = string.Empty;
        SHA512Hash = string.Empty;
        CRC32Hash = string.Empty;
        Progress = 0;
        StatusMessage = "Ready - Select a file or drop files to calculate hashes";
    }

    private void VerifyHash()
    {
        var entered = Interaction.InputBox("Enter the expected hash value to verify:", "Verify Hash", "");
        if (!string.IsNullOrWhiteSpace(entered))
        {
            var inputHash = entered.Trim().ToUpperInvariant().Replace(" ", "").Replace("-", "");
            
            bool match = false;
            string matchType = "";

            if (inputHash.Equals(MD5Hash.ToUpperInvariant()))
            {
                match = true;
                matchType = "MD5";
            }
            else if (inputHash.Equals(SHA1Hash.ToUpperInvariant()))
            {
                match = true;
                matchType = "SHA1";
            }
            else if (inputHash.Equals(SHA256Hash.ToUpperInvariant()))
            {
                match = true;
                matchType = "SHA256";
            }
            else if (inputHash.Equals(SHA512Hash.ToUpperInvariant()))
            {
                match = true;
                matchType = "SHA512";
            }
            else if (inputHash.Equals(CRC32Hash.ToUpperInvariant()))
            {
                match = true;
                matchType = "CRC32";
            }

            if (match)
            {
                StatusMessage = $"✓ Hash MATCHES ({matchType})";
                System.Windows.MessageBox.Show($"✓ Hash verification PASSED!\n\nThe provided hash matches the {matchType} hash of the file.", 
                    "Hash Verified", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                StatusMessage = "✗ Hash does NOT match any calculated hash";
                System.Windows.MessageBox.Show("✗ Hash verification FAILED!\n\nThe provided hash does not match any of the calculated hashes.", 
                    "Hash Mismatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    private void OpenInExplorer()
    {
        if (File.Exists(SelectedFile))
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"/select,\"{SelectedFile}\"",
                UseShellExecute = true
            });
        }
    }

    private static string FormatFileSize(long bytes)
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

    /// <summary>
    /// Handle file drop from UI
    /// </summary>
    public void HandleFileDrop(string[] files)
    {
        if (files != null && files.Length > 0)
        {
            SelectedFile = files[0];
            _ = CalculateHashesAsync();
        }
    }

    #endregion
}

/// <summary>
/// Represents a hash calculation result for history tracking
/// </summary>
public class HashResult
{
    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public string SHA256 { get; set; } = string.Empty;
    public string MD5 { get; set; } = string.Empty;
    public DateTime CalculatedAt { get; set; }

    public string FileSizeFormatted
    {
        get
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = FileSize;
            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }
            return $"{size:0.##} {sizes[order]}";
        }
    }
}
