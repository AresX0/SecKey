using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SecKey.Core.Services
{
    /// <summary>
    /// File Integrity Monitor (FIM) - creates baselines of file hashes and detects changes.
    /// </summary>
    public class FileIntegrityService
    {
        /// <summary>
        /// Creates a baseline snapshot of all files in the specified directory.
        /// </summary>
        public async Task<FileIntegrityBaseline> CreateBaselineAsync(string directoryPath,
            string hashAlgorithm = "SHA256", bool recursive = true,
            IProgress<FileIntegrityProgress>? progress = null,
            CancellationToken ct = default)
        {
            var baseline = new FileIntegrityBaseline
            {
                DirectoryPath = directoryPath,
                HashAlgorithm = hashAlgorithm,
                CreatedUtc = DateTime.UtcNow
            };

            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = Directory.GetFiles(directoryPath, "*", searchOption);
            int total = files.Length;
            int processed = 0;

            await Task.Run(() =>
            {
                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        var fi = new FileInfo(file);
                        var hash = ComputeFileHash(file, hashAlgorithm);
                        var relativePath = Path.GetRelativePath(directoryPath, file);

                        baseline.Entries.Add(new FileIntegrityEntry
                        {
                            RelativePath = relativePath,
                            Hash = hash,
                            SizeBytes = fi.Length,
                            LastModifiedUtc = fi.LastWriteTimeUtc,
                            CreatedUtc = fi.CreationTimeUtc
                        });
                    }
                    catch (Exception ex)
                    {
                        baseline.Errors.Add($"{file}: {ex.Message}");
                    }

                    processed++;
                    progress?.Report(new FileIntegrityProgress
                    {
                        Current = processed,
                        Total = total,
                        CurrentFile = file
                    });
                }
            }, ct);

            return baseline;
        }

        /// <summary>
        /// Compares current files against a baseline to detect changes.
        /// </summary>
        public async Task<FileIntegrityReport> CompareWithBaselineAsync(FileIntegrityBaseline baseline,
            IProgress<FileIntegrityProgress>? progress = null,
            CancellationToken ct = default)
        {
            var report = new FileIntegrityReport
            {
                BaselineCreatedUtc = baseline.CreatedUtc,
                CheckedUtc = DateTime.UtcNow,
                DirectoryPath = baseline.DirectoryPath
            };

            var baselineMap = baseline.Entries.ToDictionary(e => e.RelativePath, StringComparer.OrdinalIgnoreCase);
            var searchOption = SearchOption.AllDirectories;
            
            string[] currentFiles;
            try
            {
                currentFiles = Directory.GetFiles(baseline.DirectoryPath, "*", searchOption);
            }
            catch (Exception ex)
            {
                report.Errors.Add($"Cannot access directory: {ex.Message}");
                return report;
            }

            var currentRelativePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int total = currentFiles.Length + baseline.Entries.Count;
            int processed = 0;

            await Task.Run(() =>
            {
                // Check current files against baseline
                foreach (var file in currentFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var relativePath = Path.GetRelativePath(baseline.DirectoryPath, file);
                    currentRelativePaths.Add(relativePath);

                    try
                    {
                        if (!baselineMap.TryGetValue(relativePath, out var baselineEntry))
                        {
                            // New file
                            var fi = new FileInfo(file);
                            report.Added.Add(new FileChangeInfo
                            {
                                RelativePath = relativePath,
                                ChangeType = "Added",
                                CurrentSize = fi.Length,
                                CurrentModified = fi.LastWriteTimeUtc
                            });
                        }
                        else
                        {
                            // Existing file - check for modifications
                            var fi = new FileInfo(file);
                            if (fi.Length != baselineEntry.SizeBytes || fi.LastWriteTimeUtc != baselineEntry.LastModifiedUtc)
                            {
                                // Size or date changed - verify hash
                                var currentHash = ComputeFileHash(file, baseline.HashAlgorithm);
                                if (!string.Equals(currentHash, baselineEntry.Hash, StringComparison.OrdinalIgnoreCase))
                                {
                                    report.Modified.Add(new FileChangeInfo
                                    {
                                        RelativePath = relativePath,
                                        ChangeType = "Modified",
                                        OriginalHash = baselineEntry.Hash,
                                        CurrentHash = currentHash,
                                        OriginalSize = baselineEntry.SizeBytes,
                                        CurrentSize = fi.Length,
                                        OriginalModified = baselineEntry.LastModifiedUtc,
                                        CurrentModified = fi.LastWriteTimeUtc
                                    });
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        report.Errors.Add($"{relativePath}: {ex.Message}");
                    }

                    processed++;
                    progress?.Report(new FileIntegrityProgress
                    {
                        Current = processed,
                        Total = total,
                        CurrentFile = file
                    });
                }

                // Check for deleted files
                foreach (var entry in baseline.Entries)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!currentRelativePaths.Contains(entry.RelativePath))
                    {
                        report.Deleted.Add(new FileChangeInfo
                        {
                            RelativePath = entry.RelativePath,
                            ChangeType = "Deleted",
                            OriginalHash = entry.Hash,
                            OriginalSize = entry.SizeBytes,
                            OriginalModified = entry.LastModifiedUtc
                        });
                    }
                    processed++;
                }
            }, ct);

            return report;
        }

        /// <summary>
        /// Saves a baseline to a JSON file.
        /// </summary>
        public async Task SaveBaselineAsync(FileIntegrityBaseline baseline, string filePath)
        {
            var json = JsonSerializer.Serialize(baseline, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(filePath, json);
        }

        /// <summary>
        /// Loads a baseline from a JSON file.
        /// </summary>
        public async Task<FileIntegrityBaseline> LoadBaselineAsync(string filePath)
        {
            var json = await File.ReadAllTextAsync(filePath);
            return JsonSerializer.Deserialize<FileIntegrityBaseline>(json) 
                ?? throw new InvalidOperationException("Invalid baseline file.");
        }

        private static string ComputeFileHash(string filePath, string algorithm)
        {
            using var stream = File.OpenRead(filePath);
            using var hasher = algorithm.ToUpperInvariant() switch
            {
                "MD5" => (HashAlgorithm)MD5.Create(),
                "SHA1" => SHA1.Create(),
                "SHA256" => SHA256.Create(),
                "SHA384" => SHA384.Create(),
                "SHA512" => SHA512.Create(),
                _ => SHA256.Create()
            };
            var hashBytes = hasher.ComputeHash(stream);
            return Convert.ToHexString(hashBytes);
        }
    }

    public class FileIntegrityBaseline
    {
        public string DirectoryPath { get; set; } = "";
        public string HashAlgorithm { get; set; } = "SHA256";
        public DateTime CreatedUtc { get; set; }
        public List<FileIntegrityEntry> Entries { get; set; } = new();
        public List<string> Errors { get; set; } = new();
    }

    public class FileIntegrityEntry
    {
        public string RelativePath { get; set; } = "";
        public string Hash { get; set; } = "";
        public long SizeBytes { get; set; }
        public DateTime LastModifiedUtc { get; set; }
        public DateTime CreatedUtc { get; set; }
    }

    public class FileIntegrityReport
    {
        public string DirectoryPath { get; set; } = "";
        public DateTime BaselineCreatedUtc { get; set; }
        public DateTime CheckedUtc { get; set; }
        public List<FileChangeInfo> Added { get; set; } = new();
        public List<FileChangeInfo> Modified { get; set; } = new();
        public List<FileChangeInfo> Deleted { get; set; } = new();
        public List<string> Errors { get; set; } = new();

        public int TotalChanges => Added.Count + Modified.Count + Deleted.Count;
        public bool HasChanges => TotalChanges > 0;
    }

    public class FileChangeInfo
    {
        public string RelativePath { get; set; } = "";
        public string ChangeType { get; set; } = "";
        public string? OriginalHash { get; set; }
        public string? CurrentHash { get; set; }
        public long OriginalSize { get; set; }
        public long CurrentSize { get; set; }
        public DateTime? OriginalModified { get; set; }
        public DateTime? CurrentModified { get; set; }

        public string ChangeIcon => ChangeType switch
        {
            "Added" => "🟢",
            "Modified" => "🟡",
            "Deleted" => "🔴",
            _ => "⚪"
        };
    }

    public class FileIntegrityProgress
    {
        public int Current { get; set; }
        public int Total { get; set; }
        public string CurrentFile { get; set; } = "";
        public double Percent => Total > 0 ? (Current * 100.0 / Total) : 0;
    }
}
