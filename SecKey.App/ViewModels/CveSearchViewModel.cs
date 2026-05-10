using System.Collections.ObjectModel;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using SecKey.App.Services;

namespace SecKey.App.ViewModels;

public sealed class CveSearchViewModel : BindableBase
{
    private readonly NativeSecurityPortService _service = new();
    private static readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(30) };
    private CancellationTokenSource? _searchCts;

    private string _query = string.Empty;
    private string _statusMessage = "Ready. Enter a CVE ID (e.g., CVE-2024-1234) or keyword to search.";
    private bool _isSearching;
    private int _selectedSearchType = 0; // 0 = CVE ID, 1 = Keyword
    private string _selectedDetails = string.Empty;

    public CveSearchViewModel()
    {
        SearchCommand = new AsyncRelayCommand(SearchAsync, () => !IsSearching && !string.IsNullOrWhiteSpace(Query));
        OpenSelectedCommand = new RelayCommand(_ => OpenSelected(), _ => Selected is not null);
        ExportResultsCommand = new AsyncRelayCommand(ExportResultsAsync, () => Results.Count > 0);
        CopySelectedIdCommand = new RelayCommand(_ => CopySelectedId(), _ => Selected is not null);
        CopyDescriptionCommand = new RelayCommand(_ => CopyDescription(), _ => Selected is not null);
        OpenReferenceCommand = new RelayCommand(_ => OpenReference(), _ => Selected is not null);
        CancelCommand = new RelayCommand(_ => CancelSearch(), _ => IsSearching);
    }

    public ObservableCollection<CveEntry> Results { get; } = [];
    public ObservableCollection<string> SearchTypes { get; } = ["CVE ID", "Keyword"];

    public CveEntry? Selected
    {
        get => _selected;
        set
        {
            if (SetProperty(ref _selected, value))
            {
                SelectedDetails = value is null ? string.Empty :
                    $"ID: {value.Id}\nSeverity: {value.Severity}\nBase Score: {value.BaseScore}\nPublished: {value.PublishedUtc:yyyy-MM-dd}\nModified: {value.LastModified:yyyy-MM-dd}\nKEV: {(value.IsKev ? "YES (Known Exploited)" : "No")}\n\nDescription:\n{value.Summary}\n\nReferences:\n{string.Join("\n", value.References)}\n\nAffected:\n{string.Join("\n", value.AffectedProducts)}";
                ((RelayCommand)OpenSelectedCommand).RaiseCanExecuteChanged();
                ((RelayCommand)CopySelectedIdCommand).RaiseCanExecuteChanged();
                ((RelayCommand)CopyDescriptionCommand).RaiseCanExecuteChanged();
                ((RelayCommand)OpenReferenceCommand).RaiseCanExecuteChanged();
            }
        }
    }
    private CveEntry? _selected;

    public string SelectedDetails { get => _selectedDetails; set => SetProperty(ref _selectedDetails, value); }

    public string Query
    {
        get => _query;
        set
        {
            if (SetProperty(ref _query, value))
            {
                // Auto-detect CVE ID pattern
                if (!string.IsNullOrWhiteSpace(value) && value.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
                    SelectedSearchType = 0;
                ((AsyncRelayCommand)SearchCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public int SelectedSearchType
    {
        get => _selectedSearchType;
        set => SetProperty(ref _selectedSearchType, value);
    }

    public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }

    public bool IsSearching
    {
        get => _isSearching;
        set
        {
            if (SetProperty(ref _isSearching, value))
            {
                ((AsyncRelayCommand)SearchCommand).RaiseCanExecuteChanged();
                ((RelayCommand)CancelCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public System.Windows.Input.ICommand SearchCommand { get; }
    public System.Windows.Input.ICommand OpenSelectedCommand { get; }
    public System.Windows.Input.ICommand ExportResultsCommand { get; }
    public System.Windows.Input.ICommand CopySelectedIdCommand { get; }
    public System.Windows.Input.ICommand CopyDescriptionCommand { get; }
    public System.Windows.Input.ICommand OpenReferenceCommand { get; }
    public System.Windows.Input.ICommand CancelCommand { get; }

    private async Task SearchAsync()
    {
        _searchCts?.Cancel();
        _searchCts = new CancellationTokenSource();
        var ct = _searchCts.Token;

        IsSearching = true;
        Results.Clear();

        try
        {
            if (SelectedSearchType == 0)
            {
                await SearchByCveIdAsync(Query.Trim(), ct);
            }
            else
            {
                await SearchByKeywordAsync(Query.Trim(), ct);
            }

            StatusMessage = Results.Count == 0 ? "No results found." : $"Found {Results.Count} CVE result(s).";

            // Enrich with CISA KEV badges (best-effort)
            _ = EnrichWithKevAsync(ct).ConfigureAwait(false);

            ((AsyncRelayCommand)ExportResultsCommand).RaiseCanExecuteChanged();
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Search cancelled.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Search failed: {ex.Message}";
        }
        finally
        {
            IsSearching = false;
        }
    }

    private async Task SearchByCveIdAsync(string cveId, CancellationToken ct)
    {
        cveId = cveId.Trim().ToUpperInvariant();
        if (!cveId.StartsWith("CVE-")) cveId = "CVE-" + cveId;

        StatusMessage = $"Looking up {cveId} via MITRE API...";

        try
        {
            var url = $"https://cveawg.mitre.org/api/cve/{cveId}";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Accept", "application/json");
            using var response = await _httpClient.SendAsync(request, ct);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                StatusMessage = $"{cveId} not found in MITRE database.";
                return;
            }

            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync(ct);
            var doc = JsonDocument.Parse(json);
            var result = ParseMitreCveRecord(doc.RootElement);
            if (result != null)
                Results.Add(result);
        }
        catch (Exception ex)
        {
            StatusMessage = $"MITRE lookup failed: {ex.Message}";
        }
    }

    private async Task SearchByKeywordAsync(string keyword, CancellationToken ct)
    {
        StatusMessage = $"Searching NVD for '{keyword}'...";

        try
        {
            var url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={Uri.EscapeDataString(keyword)}&resultsPerPage=50";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Accept", "application/json");
            using var response = await _httpClient.SendAsync(request, ct);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(ct);
            var doc = JsonDocument.Parse(json);

            if (doc.RootElement.TryGetProperty("vulnerabilities", out var vulns))
            {
                foreach (var vuln in vulns.EnumerateArray())
                {
                    if (ct.IsCancellationRequested) break;
                    if (vuln.TryGetProperty("cve", out var cve))
                    {
                        var result = ParseNvdCveRecord(cve);
                        if (result != null)
                            Results.Add(result);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"NVD search failed: {ex.Message}";
        }
    }

    private async Task EnrichWithKevAsync(CancellationToken ct)
    {
        try
        {
            var url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
            using var response = await _httpClient.GetAsync(url, ct);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync(ct);
            var doc = JsonDocument.Parse(json);

            if (doc.RootElement.TryGetProperty("vulnerabilities", out var kev_vulns))
            {
                foreach (var vuln in kev_vulns.EnumerateArray())
                {
                    if (vuln.TryGetProperty("cveID", out var cveId) && vuln.TryGetProperty("dateAdded", out var dateAdded))
                    {
                        var kevId = cveId.GetString();
                        var kevDate = dateAdded.GetString();
                        var matching = Results.FirstOrDefault(r => r.Id == kevId);
                        if (matching != null)
                        {
                            matching.MarkKev(kevDate ?? string.Empty);
                        }
                    }
                }
            }
        }
        catch
        {
            // Non-fatal, best-effort enrichment
        }
    }

    private CveEntry? ParseMitreCveRecord(JsonElement cveElement)
    {
        try
        {
            var id = cveElement.GetProperty("ID").GetString() ?? string.Empty;
            var state = cveElement.TryGetProperty("State", out var s) ? s.GetString() ?? "UNKNOWN" : "UNKNOWN";
            var summary = cveElement.TryGetProperty("Description", out var desc) ? desc.EnumerateArray().FirstOrDefault().GetProperty("value").GetString() ?? string.Empty : string.Empty;

            var entry = new CveEntry
            {
                Id = id,
                Summary = summary,
                PublishedUtc = DateTime.Now,
                LastModified = DateTime.Now,
                SourceUrl = $"https://cve.mitre.org/cgi-bin/cvename.cgi?name={id}"
            };

            return entry;
        }
        catch
        {
            return null;
        }
    }

    private CveEntry? ParseNvdCveRecord(JsonElement cveElement)
    {
        try
        {
            var id = cveElement.GetProperty("id").GetString() ?? string.Empty;
            var metricsExists = cveElement.TryGetProperty("metrics", out var metrics);
            double? baseScore = null;
            string severity = "UNKNOWN";

            if (metricsExists && metrics.TryGetProperty("cvssV3_1", out var cvss31))
            {
                if (cvss31.TryGetProperty("cvssData", out var cvssData))
                {
                    if (cvssData.TryGetProperty("baseScore", out var score))
                        baseScore = score.GetDouble();
                    if (cvssData.TryGetProperty("baseSeverity", out var sev))
                        severity = sev.GetString() ?? "UNKNOWN";
                }
            }

            var descVal = cveElement.GetProperty("descriptions").EnumerateArray()
                .FirstOrDefault(d => d.GetProperty("lang").GetString() == "en")
                .GetProperty("value").GetString() ?? string.Empty;

            return new CveEntry
            {
                Id = id,
                Severity = severity,
                BaseScore = baseScore,
                Summary = descVal,
                PublishedUtc = DateTime.Parse(cveElement.GetProperty("published").GetString() ?? DateTime.Now.ToString()),
                LastModified = DateTime.Parse(cveElement.GetProperty("lastModified").GetString() ?? DateTime.Now.ToString()),
                SourceUrl = $"https://nvd.nist.gov/vuln/detail/{id}"
            };
        }
        catch
        {
            return null;
        }
    }

    private void OpenSelected()
    {
        if (Selected is null || string.IsNullOrWhiteSpace(Selected.SourceUrl)) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = Selected.SourceUrl, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open URL: {ex.Message}";
        }
    }

    private void OpenReference()
    {
        if (Selected is null || Selected.References.Count == 0) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = Selected.References[0], UseShellExecute = true });
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open reference: {ex.Message}";
        }
    }

    private void CopySelectedId()
    {
        if (Selected is null) return;
        try
        {
            System.Windows.Clipboard.SetText(Selected.Id);
            StatusMessage = $"Copied {Selected.Id} to clipboard";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Copy failed: {ex.Message}";
        }
    }

    private void CopyDescription()
    {
        if (Selected is null) return;
        try
        {
            System.Windows.Clipboard.SetText(Selected.Summary);
            StatusMessage = "Copied description to clipboard";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Copy failed: {ex.Message}";
        }
    }

    private void CancelSearch()
    {
        _searchCts?.Cancel();
        StatusMessage = "Search cancelled.";
    }

    private async Task ExportResultsAsync()
    {
        try
        {
            var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Reports");
            Directory.CreateDirectory(folder);
            var path = Path.Combine(folder, $"cve-results-{DateTime.Now:yyyyMMdd-HHmmss}.csv");

            var sb = new StringBuilder();
            sb.AppendLine("Id,Severity,BaseScore,Published,LastModified,KEV,Summary,References");
            foreach (var cve in Results)
            {
                var refs = string.Join("; ", cve.References);
                sb.AppendLine($"\"{Csv(cve.Id)}\",\"{Csv(cve.Severity)}\",\"{cve.BaseScore}\",\"{cve.PublishedUtc:yyyy-MM-dd}\",\"{cve.LastModified:yyyy-MM-dd}\",\"{(cve.IsKev ? "YES" : "No")}\",\"{Csv(cve.Summary)}\",\"{Csv(refs)}\"");
            }

            await File.WriteAllTextAsync(path, sb.ToString());
            StatusMessage = $"Exported {Results.Count} CVE(s) to {path}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Export failed: {ex.Message}";
        }
    }

    private static string Csv(string s) => (s ?? string.Empty).Replace("\"", "\"\"");
}

public sealed record CveEntry
{
    public string Id { get; set; } = string.Empty;
    public string Severity { get; set; } = "UNKNOWN";
    public double? BaseScore { get; set; }
    public string Summary { get; set; } = string.Empty;
    public DateTime PublishedUtc { get; set; }
    public DateTime LastModified { get; set; }
    public string SourceUrl { get; set; } = string.Empty;
    public List<string> References { get; set; } = [];
    public List<string> AffectedProducts { get; set; } = [];
    public bool IsKev { get; set; }

    public void MarkKev(string dateAdded)
    {
        IsKev = true;
    }
};
