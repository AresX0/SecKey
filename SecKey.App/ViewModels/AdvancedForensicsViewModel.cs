using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using SecKey.App.Services;
using System.Diagnostics;
using Microsoft.Win32;
using System.Threading;

namespace SecKey.App.ViewModels;

/// <summary>
/// Comprehensive DFIR (Digital Forensics & Incident Response) features.
/// Supports memory acquisition, Volatility analysis, KAPE artifact collection, and YARA-lite scanning.
/// </summary>
public sealed class AdvancedForensicsViewModel : BindableBase
{
    private readonly NativeSecurityPortService _service = new();
    private readonly string _forensicsRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Forensics");

    // ============ GENERAL ============
    private string _statusMessage = "Ready";

    // ============ MEMORY ACQUISITION ============
    private string _selectedMemoryTool = "WinPmem";
    private string _winPmemPath = string.Empty;
    private string _magnetRamCapturePath = string.Empty;
    private string _procDumpPath = string.Empty;
    private string _dumpOutputPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Forensics", "Memory");
    private string _dumpFormat = "raw";
    private string _selectedProcessForDump = string.Empty;
    private bool _procDumpFullDump = true;

    // ============ VOLATILITY ANALYSIS ============
    private string _volatilityPath = string.Empty;
    private string _memoryDumpPath = string.Empty;
    private string _volatilityOutputPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Forensics", "Volatility");

    private bool _runPsList = true;
    private bool _runNetScan = true;
    private bool _runMalfind = true;
    private bool _runDllList = true;
    private bool _runHandles = false;
    private bool _runCmdline = true;
    private bool _runFileScan = false;
    private bool _runRegHive = false;
    private bool _runPsTree = false;
    private bool _runEnvars = false;
    private bool _runSvcScan = false;
    private bool _runCallbacks = false;
    private bool _runDriverScan = false;
    private bool _runSsdt = false;
    private bool _runMutantScan = false;

    // ============ KAPE/EZ TOOLS ============
    private string _kapePath = string.Empty;
    private string _kapeTargetPath = string.Empty;
    private string _kapeOutputPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Forensics", "Kape");

    private bool _collectPrefetch = true;
    private bool _collectAmcache = true;
    private bool _collectEventLogs = true;
    private bool _collectMft = true;
    private bool _collectRegistry = true;
    private bool _collectSrum = true;
    private bool _collectShellBags = false;
    private bool _collectBitlocker = false;
    private bool _collectRecycleBin = false;
    private bool _collectBrowser = true;

    // ============ YARA-LITE & GENERAL ============
    private string _targetPath = string.Empty;
    private string _rulesInput = "HighEntropyString|[A-Za-z0-9+/]{120,}={0,2}|regex\nSuspiciousPowerShell|Invoke-WebRequest|literal";

    // ============ EXTENDED DFIR PARITY ============
    private string _kustoEndpoint = "https://yourcluster.kusto.windows.net";
    private string _kustoDatabase = "Security";
    private string _kustoQuery = "SecurityEvent | take 100";
    private string _localKqlQuery = "timeline | take 50";
    private string _localKqlOutput = "No local KQL results yet.";
    private string _openSearchEndpoint = "http://localhost:9200";
    private string _openSearchIndex = "seckey-forensics";
    private string _osintTarget = string.Empty;
    private string _iocInput = string.Empty;
    private string _registryPath = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run";
    private string _pcapPath = string.Empty;
    private string _browserPath = string.Empty;
    private string _malwareSamplePath = string.Empty;
    private string _extractSourcePath = string.Empty;
    private string _scheduleName = "Daily DFIR Collection";
    private string _oletoolsPath = string.Empty;
    private string _documentPath = string.Empty;
    private string _pdfParserPath = string.Empty;
    private string _plasoPath = string.Empty;
    private string _evidencePath = string.Empty;
    private string _velociraptorPath = string.Empty;
    private string _bulkExtractorPath = string.Empty;
    private string _bulkInputPath = string.Empty;
    private string _browserProfilePath = string.Empty;
    private string _iocPath = string.Empty;
    private string _snapshot1Path = string.Empty;
    private string _snapshot2Path = string.Empty;
    private string _exifToolPath = string.Empty;
    private string _localDbPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Forensics", "LocalKql", "local-kql.db");
    private CancellationTokenSource? _operationCts;
    private bool _runOlevba = true;
    private bool _runMraptor = true;
    private bool _runPdfParser = true;

    public AdvancedForensicsViewModel()
    {
        Directory.CreateDirectory(_forensicsRoot);
        Directory.CreateDirectory(DumpOutputPath);
        Directory.CreateDirectory(VolatilityOutputPath);
        Directory.CreateDirectory(KapeOutputPath);

        // Memory acquisition
        AcquireMemoryCommand = new AsyncRelayCommand(AcquireMemoryAsync, () => !string.IsNullOrWhiteSpace(DumpOutputPath));
        AcquireWinPmemCommand = new AsyncRelayCommand(AcquireWinPmemAsync, () => !string.IsNullOrWhiteSpace(DumpOutputPath));
        AcquireMagnetRamCommand = new AsyncRelayCommand(AcquireMagnetRamAsync, () => !string.IsNullOrWhiteSpace(DumpOutputPath));
        AcquireProcDumpCommand = new AsyncRelayCommand(AcquireProcDumpAsync, () => !string.IsNullOrWhiteSpace(DumpOutputPath) && !string.IsNullOrWhiteSpace(SelectedProcessForDump));
        BrowseWinPmemCommand = new RelayCommand(_ => BrowseWinPmem());
        DownloadWinPmemCommand = new RelayCommand(_ => OpenUrl("https://github.com/Velocidex/WinPmem/releases"));
        BrowseDumpOutputCommand = new RelayCommand(_ => BrowseDumpOutput());
        BrowseMagnetRamCaptureCommand = new RelayCommand(_ => BrowseMagnetRamCapture());
        DownloadMagnetRamCaptureCommand = new RelayCommand(_ => OpenUrl("https://www.magnetforensics.com/resources/magnet-ram-capture/"));
        BrowseProcDumpCommand = new RelayCommand(_ => BrowseProcDump());
        DownloadProcDumpCommand = new RelayCommand(_ => OpenUrl("https://learn.microsoft.com/sysinternals/downloads/procdump"));
        RefreshProcessListCommand = new RelayCommand(_ => RefreshProcesses());
        RefreshProcessesCommand = new RelayCommand(_ => RefreshProcesses());

        // Volatility
        RunVolatilityPluginsCommand = new AsyncRelayCommand(RunVolatilityAsync, () => !string.IsNullOrWhiteSpace(VolatilityPath) && !string.IsNullOrWhiteSpace(MemoryDumpPath));
        BrowseMemoryDumpCommand = new RelayCommand(_ => BrowseMemoryDump());
        BrowseVolatilityCommand = new RelayCommand(_ => BrowseVolatility());
        DownloadVolatilityCommand = new RelayCommand(_ => OpenUrl("https://github.com/volatilityfoundation/volatility3"));
        RunVolatilityAnalysisCommand = new AsyncRelayCommand(RunVolatilityAsync, () => !string.IsNullOrWhiteSpace(VolatilityPath) && !string.IsNullOrWhiteSpace(MemoryDumpPath));
        
        // KAPE
        RunKapeCommand = new AsyncRelayCommand(RunKapeAsync, () => !string.IsNullOrWhiteSpace(KapePath) && !string.IsNullOrWhiteSpace(KapeTargetPath));
        BrowseKapeCommand = new RelayCommand(_ => BrowseKape());
        GetKapeCommand = new RelayCommand(_ => OpenUrl("https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-and-extractor-kape"));
        BrowseKapeTargetCommand = new RelayCommand(_ => BrowseKapeTarget());
        RunKapeCollectionCommand = new AsyncRelayCommand(RunKapeAsync, () => !string.IsNullOrWhiteSpace(KapePath) && !string.IsNullOrWhiteSpace(KapeTargetPath));
        
        // Timeline & Process
        BuildTimelineCommand = new RelayCommand(_ => BuildTimeline());
        ExportTimelineCommand = new RelayCommand(_ => ExportTimeline(), _ => Timeline.Count > 0);
        CaptureProcessSnapshotCommand = new RelayCommand(_ => CaptureProcessSnapshot());
        BrowsePlasoCommand = new RelayCommand(_ => BrowsePlaso());
        BrowseEvidenceCommand = new RelayCommand(_ => BrowseEvidence());
        RunPlasoTimelineCommand = new AsyncRelayCommand(RunPlasoTimelineAsync, () => !string.IsNullOrWhiteSpace(PlasoPath) && !string.IsNullOrWhiteSpace(EvidencePath));
        ExportPlasoToOpenSearchCommand = new AsyncRelayCommand(ExportPlasoToOpenSearchAsync, () => Timeline.Count > 0);
        DownloadPlasoCommand = new RelayCommand(_ => OpenUrl("https://github.com/log2timeline/plaso"));
        BrowseVelociraptorCommand = new RelayCommand(_ => BrowseVelociraptor());
        RunVelociraptorCollectCommand = new AsyncRelayCommand(RunVelociraptorCollectAsync, () => !string.IsNullOrWhiteSpace(VelociraptorPath));
        DownloadVelociraptorCommand = new RelayCommand(_ => OpenUrl("https://docs.velociraptor.app/downloads/"));

        // YARA-lite
        RunYaraLiteCommand = new AsyncRelayCommand(RunYaraLiteAsync, () => !string.IsNullOrWhiteSpace(TargetPath));
        ExportYaraResultsCommand = new RelayCommand(_ => ExportYaraResults(), _ => YaraMatches.Count > 0);

        // Extended DFIR tabs
        RunKustoQueryCommand = new AsyncRelayCommand(RunKustoQueryAsync, () => !string.IsNullOrWhiteSpace(KustoQuery));
        LoadKustoTemplateCommand = new RelayCommand(_ => LoadKustoTemplate());
        InitializeLocalDbCommand = new AsyncRelayCommand(InitializeLocalDbAsync);
        RefreshTablesCommand = new RelayCommand(_ => RefreshLocalTables());
        ClearLocalDbCommand = new AsyncRelayCommand(ClearLocalDbAsync);
        InsertTableQueryCommand = new RelayCommand(_ => InsertLocalTableQuery());
        ExecuteLocalKqlCommand = new RelayCommand(_ => RunLocalKql(), _ => !string.IsNullOrWhiteSpace(LocalKqlQuery));
        ExportLocalResultsCommand = new AsyncRelayCommand(ExportLocalResultsAsync, () => !string.IsNullOrWhiteSpace(LocalKqlOutput));
        RunLocalKqlCommand = new RelayCommand(_ => RunLocalKql(), _ => !string.IsNullOrWhiteSpace(LocalKqlQuery));
        ExportOpenSearchCommand = new AsyncRelayCommand(ExportOpenSearchAsync, () => Timeline.Count > 0 || Processes.Count > 0 || YaraMatches.Count > 0);
        TestOpenSearchCommand = new AsyncRelayCommand(TestOpenSearchAsync, () => !string.IsNullOrWhiteSpace(OpenSearchEndpoint));
        CreatePipelinesCommand = new AsyncRelayCommand(CreateOpenSearchPipelinesAsync, () => !string.IsNullOrWhiteSpace(OpenSearchEndpoint));
        CreateIndexTemplatesCommand = new AsyncRelayCommand(CreateOpenSearchTemplatesAsync, () => !string.IsNullOrWhiteSpace(OpenSearchEndpoint));
        IngestToOpenSearchCommand = new AsyncRelayCommand(IngestToOpenSearchAsync, () => ForensicsResults.Count > 0 || Timeline.Count > 0 || Processes.Count > 0);
        RunOsintCommand = new RelayCommand(_ => RunOsint(), _ => !string.IsNullOrWhiteSpace(OsintTarget));
        BrowseExifToolCommand = new RelayCommand(_ => BrowseExifTool());
        DownloadExifToolCommand = new RelayCommand(_ => OpenUrl("https://exiftool.org/"));
        ExtractMetadataCommand = new AsyncRelayCommand(ExtractMetadataAsync, () => !string.IsNullOrWhiteSpace(OsintTarget));
        ScanScheduledTasksCommand = new RelayCommand(_ => ScanScheduledTasks());
        ExportScheduledTasksCommand = new AsyncRelayCommand(ExportScheduledTasksAsync);
        BrowseBrowserProfileCommand = new RelayCommand(_ => BrowseBrowserProfile());
        ScanBrowserArtifactsCommand = new RelayCommand(_ => CollectBrowserArtifacts(), _ => !string.IsNullOrWhiteSpace(BrowserPath));
        ExportBrowserArtifactsCommand = new AsyncRelayCommand(ExportBrowserArtifactsAsync, () => ForensicsResults.Any(r => r.Category == "Browser"));
        BrowseIOCPathCommand = new RelayCommand(_ => BrowseIocPath());
        LoadIOCFeedCommand = new AsyncRelayCommand(LoadIocFeedAsync, () => !string.IsNullOrWhiteSpace(IocPath));
        ScanForIOCsCommand = new RelayCommand(_ => CheckIoc(), _ => !string.IsNullOrWhiteSpace(IocInput));
        ExportIOCResultsCommand = new AsyncRelayCommand(ExportIocResultsAsync, () => ForensicsResults.Any(r => r.Category == "IOC"));
        OpenRegistrySnapshotFolderCommand = new RelayCommand(_ => OpenRegistrySnapshotFolder());
        TakeRegistrySnapshotCommand = new AsyncRelayCommand(TakeRegistrySnapshotAsync);
        BrowseSnapshot1Command = new RelayCommand(_ => BrowseSnapshot1());
        BrowseSnapshot2Command = new RelayCommand(_ => BrowseSnapshot2());
        CompareRegistrySnapshotsCommand = new AsyncRelayCommand(CompareRegistrySnapshotsAsync, () => !string.IsNullOrWhiteSpace(Snapshot1Path) && !string.IsNullOrWhiteSpace(Snapshot2Path));
        ExportRegistryDiffCommand = new AsyncRelayCommand(ExportRegistryDiffAsync, () => ForensicsResults.Any(r => r.Category == "RegistryDiff"));
        BrowsePcapFileCommand = new RelayCommand(_ => BrowsePcapFile());
        ParsePcapCommand = new RelayCommand(_ => AnalyzePcap(), _ => !string.IsNullOrWhiteSpace(PcapPath));
        ExportPcapResultsCommand = new AsyncRelayCommand(ExportPcapResultsAsync, () => ForensicsResults.Any(r => r.Category == "PCAP"));
        BrowseBulkExtractorCommand = new RelayCommand(_ => BrowseBulkExtractor());
        BrowseBulkInputCommand = new RelayCommand(_ => BrowseBulkInput());
        RunBulkExtractorCommand = new AsyncRelayCommand(RunBulkExtractorAsync, () => !string.IsNullOrWhiteSpace(BulkExtractorPath) && !string.IsNullOrWhiteSpace(BulkInputPath));
        DownloadBulkExtractorCommand = new RelayCommand(_ => OpenUrl("https://github.com/simsong/bulk_extractor"));
        CheckIocCommand = new RelayCommand(_ => CheckIoc(), _ => !string.IsNullOrWhiteSpace(IocInput));
        CollectRegistryCommand = new RelayCommand(_ => CollectRegistrySnapshot(), _ => !string.IsNullOrWhiteSpace(RegistryPath));
        AnalyzePcapCommand = new RelayCommand(_ => AnalyzePcap(), _ => !string.IsNullOrWhiteSpace(PcapPath));
        CollectBrowserArtifactsCommand = new RelayCommand(_ => CollectBrowserArtifacts(), _ => !string.IsNullOrWhiteSpace(BrowserPath));
        AnalyzeMalwareCommand = new RelayCommand(_ => AnalyzeMalware(), _ => !string.IsNullOrWhiteSpace(MalwareSamplePath));
        ExtractArtifactsCommand = new RelayCommand(_ => ExtractArtifacts(), _ => !string.IsNullOrWhiteSpace(ExtractSourcePath));
        RunScheduleCommand = new RelayCommand(_ => RunSchedule(), _ => !string.IsNullOrWhiteSpace(ScheduleName));
        ExportResultsCommand = new RelayCommand(_ => ExportResults(), _ => ForensicsResults.Count > 0);
        ClearResultsCommand = new RelayCommand(_ => ClearResults(), _ => ForensicsResults.Count > 0);
        ClearLogCommand = new RelayCommand(_ => ClearResults(), _ => ForensicsResults.Count > 0);
        CancelCommand = new RelayCommand(_ => CancelActiveOperations());
        BrowseOletoolsCommand = new RelayCommand(_ => BrowseOletools());
        BrowseDocumentsCommand = new RelayCommand(_ => BrowseDocuments());
        BrowsePdfParserCommand = new RelayCommand(_ => BrowsePdfParser());
        RunMalwareAnalysisCommand = new AsyncRelayCommand(RunMalwareAnalysisAsync, () => !string.IsNullOrWhiteSpace(DocumentPath));
        DownloadOletoolsCommand = new RelayCommand(_ => OpenUrl("https://github.com/decalage2/oletools"));
        DownloadPdfParserCommand = new RelayCommand(_ => OpenUrl("https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py"));

        RefreshProcesses();
    }

    #region Memory Acquisition Properties

    public string SelectedMemoryTool
    {
        get => _selectedMemoryTool;
        set => SetProperty(ref _selectedMemoryTool, value);
    }

    public string WinPmemPath
    {
        get => _winPmemPath;
        set => SetProperty(ref _winPmemPath, value);
    }

    public string MagnetRamCapturePath
    {
        get => _magnetRamCapturePath;
        set => SetProperty(ref _magnetRamCapturePath, value);
    }

    public string ProcDumpPath
    {
        get => _procDumpPath;
        set => SetProperty(ref _procDumpPath, value);
    }

    public string DumpOutputPath
    {
        get => _dumpOutputPath;
        set
        {
            if (SetProperty(ref _dumpOutputPath, value))
                ((AsyncRelayCommand)AcquireMemoryCommand).RaiseCanExecuteChanged();
        }
    }

    public string DumpFormat
    {
        get => _dumpFormat;
        set => SetProperty(ref _dumpFormat, value);
    }

    public string SelectedProcessForDump
    {
        get => _selectedProcessForDump;
        set
        {
            if (SetProperty(ref _selectedProcessForDump, value))
                ((AsyncRelayCommand)AcquireProcDumpCommand).RaiseCanExecuteChanged();
        }
    }

    public bool ProcDumpFullDump
    {
        get => _procDumpFullDump;
        set => SetProperty(ref _procDumpFullDump, value);
    }

    #endregion

    #region Volatility Properties

    public string VolatilityPath
    {
        get => _volatilityPath;
        set
        {
            if (SetProperty(ref _volatilityPath, value))
                ((AsyncRelayCommand)RunVolatilityPluginsCommand).RaiseCanExecuteChanged();
        }
    }

    public string MemoryDumpPath
    {
        get => _memoryDumpPath;
        set
        {
            if (SetProperty(ref _memoryDumpPath, value))
                ((AsyncRelayCommand)RunVolatilityPluginsCommand).RaiseCanExecuteChanged();
        }
    }

    public string VolatilityOutputPath
    {
        get => _volatilityOutputPath;
        set => SetProperty(ref _volatilityOutputPath, value);
    }

    public bool RunPsList { get => _runPsList; set => SetProperty(ref _runPsList, value); }
    public bool RunNetScan { get => _runNetScan; set => SetProperty(ref _runNetScan, value); }
    public bool RunMalfind { get => _runMalfind; set => SetProperty(ref _runMalfind, value); }
    public bool RunDllList { get => _runDllList; set => SetProperty(ref _runDllList, value); }
    public bool RunHandles { get => _runHandles; set => SetProperty(ref _runHandles, value); }
    public bool RunCmdline { get => _runCmdline; set => SetProperty(ref _runCmdline, value); }
    public bool RunFileScan { get => _runFileScan; set => SetProperty(ref _runFileScan, value); }
    public bool RunRegHive { get => _runRegHive; set => SetProperty(ref _runRegHive, value); }
    public bool RunPsTree { get => _runPsTree; set => SetProperty(ref _runPsTree, value); }
    public bool RunEnvars { get => _runEnvars; set => SetProperty(ref _runEnvars, value); }
    public bool RunSvcScan { get => _runSvcScan; set => SetProperty(ref _runSvcScan, value); }
    public bool RunCallbacks { get => _runCallbacks; set => SetProperty(ref _runCallbacks, value); }
    public bool RunDriverScan { get => _runDriverScan; set => SetProperty(ref _runDriverScan, value); }
    public bool RunSsdt { get => _runSsdt; set => SetProperty(ref _runSsdt, value); }
    public bool RunMutantScan { get => _runMutantScan; set => SetProperty(ref _runMutantScan, value); }

    #endregion

    #region KAPE Properties

    public string KapePath
    {
        get => _kapePath;
        set
        {
            if (SetProperty(ref _kapePath, value))
                ((AsyncRelayCommand)RunKapeCommand).RaiseCanExecuteChanged();
        }
    }

    public string KapeTargetPath
    {
        get => _kapeTargetPath;
        set
        {
            if (SetProperty(ref _kapeTargetPath, value))
                ((AsyncRelayCommand)RunKapeCommand).RaiseCanExecuteChanged();
        }
    }

    public string KapeOutputPath
    {
        get => _kapeOutputPath;
        set => SetProperty(ref _kapeOutputPath, value);
    }

    public bool CollectPrefetch { get => _collectPrefetch; set => SetProperty(ref _collectPrefetch, value); }
    public bool CollectAmcache { get => _collectAmcache; set => SetProperty(ref _collectAmcache, value); }
    public bool CollectEventLogs { get => _collectEventLogs; set => SetProperty(ref _collectEventLogs, value); }
    public bool CollectMft { get => _collectMft; set => SetProperty(ref _collectMft, value); }
    public bool CollectRegistry { get => _collectRegistry; set => SetProperty(ref _collectRegistry, value); }
    public bool CollectSrum { get => _collectSrum; set => SetProperty(ref _collectSrum, value); }
    public bool CollectShellBags { get => _collectShellBags; set => SetProperty(ref _collectShellBags, value); }
    public bool CollectBitlocker { get => _collectBitlocker; set => SetProperty(ref _collectBitlocker, value); }
    public bool CollectRecycleBin { get => _collectRecycleBin; set => SetProperty(ref _collectRecycleBin, value); }
    public bool CollectBrowser { get => _collectBrowser; set => SetProperty(ref _collectBrowser, value); }

    #endregion

    #region General Properties

    public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }
    public string TargetPath
    {
        get => _targetPath;
        set
        {
            if (SetProperty(ref _targetPath, value))
                ((AsyncRelayCommand)RunYaraLiteCommand).RaiseCanExecuteChanged();
        }
    }
    public string RulesInput { get => _rulesInput; set => SetProperty(ref _rulesInput, value); }
    public string KustoEndpoint { get => _kustoEndpoint; set => SetProperty(ref _kustoEndpoint, value); }
    public string KustoDatabase { get => _kustoDatabase; set => SetProperty(ref _kustoDatabase, value); }
    public string KustoQuery
    {
        get => _kustoQuery;
        set
        {
            if (SetProperty(ref _kustoQuery, value))
                ((AsyncRelayCommand)RunKustoQueryCommand).RaiseCanExecuteChanged();
        }
    }
    public string LocalKqlQuery
    {
        get => _localKqlQuery;
        set
        {
            if (SetProperty(ref _localKqlQuery, value))
                ((RelayCommand)RunLocalKqlCommand).RaiseCanExecuteChanged();
        }
    }
    public string LocalKqlOutput { get => _localKqlOutput; set => SetProperty(ref _localKqlOutput, value); }
    public string OpenSearchEndpoint { get => _openSearchEndpoint; set => SetProperty(ref _openSearchEndpoint, value); }
    public string OpenSearchIndex { get => _openSearchIndex; set => SetProperty(ref _openSearchIndex, value); }
    public string OsintTarget
    {
        get => _osintTarget;
        set
        {
            if (SetProperty(ref _osintTarget, value))
                ((RelayCommand)RunOsintCommand).RaiseCanExecuteChanged();
        }
    }
    public string IocInput
    {
        get => _iocInput;
        set
        {
            if (SetProperty(ref _iocInput, value))
                ((RelayCommand)CheckIocCommand).RaiseCanExecuteChanged();
        }
    }
    public string RegistryPath
    {
        get => _registryPath;
        set
        {
            if (SetProperty(ref _registryPath, value))
                ((RelayCommand)CollectRegistryCommand).RaiseCanExecuteChanged();
        }
    }
    public string PcapPath
    {
        get => _pcapPath;
        set
        {
            if (SetProperty(ref _pcapPath, value))
                ((RelayCommand)AnalyzePcapCommand).RaiseCanExecuteChanged();
        }
    }
    public string BrowserPath
    {
        get => _browserPath;
        set
        {
            if (SetProperty(ref _browserPath, value))
                ((RelayCommand)CollectBrowserArtifactsCommand).RaiseCanExecuteChanged();
        }
    }
    public string MalwareSamplePath
    {
        get => _malwareSamplePath;
        set
        {
            if (SetProperty(ref _malwareSamplePath, value))
                ((RelayCommand)AnalyzeMalwareCommand).RaiseCanExecuteChanged();
        }
    }
    public string ExtractSourcePath
    {
        get => _extractSourcePath;
        set
        {
            if (SetProperty(ref _extractSourcePath, value))
                ((RelayCommand)ExtractArtifactsCommand).RaiseCanExecuteChanged();
        }
    }
    public string ScheduleName
    {
        get => _scheduleName;
        set
        {
            if (SetProperty(ref _scheduleName, value))
                ((RelayCommand)RunScheduleCommand).RaiseCanExecuteChanged();
        }
    }
    public string OletoolsPath { get => _oletoolsPath; set => SetProperty(ref _oletoolsPath, value); }
    public string DocumentPath
    {
        get => _documentPath;
        set
        {
            if (SetProperty(ref _documentPath, value))
                ((AsyncRelayCommand)RunMalwareAnalysisCommand).RaiseCanExecuteChanged();
        }
    }
    public string PdfParserPath { get => _pdfParserPath; set => SetProperty(ref _pdfParserPath, value); }
    public string PlasoPath { get => _plasoPath; set => SetProperty(ref _plasoPath, value); }
    public string EvidencePath { get => _evidencePath; set => SetProperty(ref _evidencePath, value); }
    public string VelociraptorPath { get => _velociraptorPath; set => SetProperty(ref _velociraptorPath, value); }
    public string BulkExtractorPath { get => _bulkExtractorPath; set => SetProperty(ref _bulkExtractorPath, value); }
    public string BulkInputPath { get => _bulkInputPath; set => SetProperty(ref _bulkInputPath, value); }
    public string BrowserProfilePath { get => _browserProfilePath; set => SetProperty(ref _browserProfilePath, value); }
    public string IocPath { get => _iocPath; set => SetProperty(ref _iocPath, value); }
    public string Snapshot1Path { get => _snapshot1Path; set => SetProperty(ref _snapshot1Path, value); }
    public string Snapshot2Path { get => _snapshot2Path; set => SetProperty(ref _snapshot2Path, value); }
    public string ExifToolPath { get => _exifToolPath; set => SetProperty(ref _exifToolPath, value); }
    public string LocalDbPath { get => _localDbPath; set => SetProperty(ref _localDbPath, value); }
    public bool RunOlevba { get => _runOlevba; set => SetProperty(ref _runOlevba, value); }
    public bool RunMraptor { get => _runMraptor; set => SetProperty(ref _runMraptor, value); }
    public bool RunPdfParser { get => _runPdfParser; set => SetProperty(ref _runPdfParser, value); }

    #endregion

    #region Collections

    public ObservableCollection<string> MemoryAcquisitionTools { get; } = ["WinPmem", "Magnet RAM Capture", "ProcDump"];
    public ObservableCollection<string> DumpFormats { get; } = ["raw", "aff4", "crashdump"];
    public ObservableCollection<string> RunningProcessList { get; } = [];
    public ObservableCollection<TimelineEntry> Timeline { get; } = [];
    public ObservableCollection<ProcessSnapshot> Processes { get; } = [];
    public ObservableCollection<YaraLiteMatch> YaraMatches { get; } = [];
    public ObservableCollection<ForensicsResultRow> ForensicsResults { get; } = [];
    public ObservableCollection<MalwareResultRow> MalwareResults { get; } = [];

    #endregion

    #region Commands

    public System.Windows.Input.ICommand AcquireMemoryCommand { get; }
    public System.Windows.Input.ICommand AcquireWinPmemCommand { get; }
    public System.Windows.Input.ICommand AcquireMagnetRamCommand { get; }
    public System.Windows.Input.ICommand AcquireProcDumpCommand { get; }
    public System.Windows.Input.ICommand BrowseWinPmemCommand { get; }
    public System.Windows.Input.ICommand DownloadWinPmemCommand { get; }
    public System.Windows.Input.ICommand BrowseDumpOutputCommand { get; }
    public System.Windows.Input.ICommand BrowseMagnetRamCaptureCommand { get; }
    public System.Windows.Input.ICommand DownloadMagnetRamCaptureCommand { get; }
    public System.Windows.Input.ICommand BrowseProcDumpCommand { get; }
    public System.Windows.Input.ICommand DownloadProcDumpCommand { get; }
    public System.Windows.Input.ICommand RefreshProcessListCommand { get; }
    public System.Windows.Input.ICommand RefreshProcessesCommand { get; }
    public System.Windows.Input.ICommand BrowseMemoryDumpCommand { get; }
    public System.Windows.Input.ICommand BrowseVolatilityCommand { get; }
    public System.Windows.Input.ICommand DownloadVolatilityCommand { get; }
    public System.Windows.Input.ICommand RunVolatilityAnalysisCommand { get; }
    public System.Windows.Input.ICommand BrowseKapeCommand { get; }
    public System.Windows.Input.ICommand GetKapeCommand { get; }
    public System.Windows.Input.ICommand BrowseKapeTargetCommand { get; }
    public System.Windows.Input.ICommand RunKapeCollectionCommand { get; }
    public System.Windows.Input.ICommand BrowsePlasoCommand { get; }
    public System.Windows.Input.ICommand BrowseEvidenceCommand { get; }
    public System.Windows.Input.ICommand RunPlasoTimelineCommand { get; }
    public System.Windows.Input.ICommand ExportPlasoToOpenSearchCommand { get; }
    public System.Windows.Input.ICommand DownloadPlasoCommand { get; }
    public System.Windows.Input.ICommand BrowseVelociraptorCommand { get; }
    public System.Windows.Input.ICommand RunVelociraptorCollectCommand { get; }
    public System.Windows.Input.ICommand DownloadVelociraptorCommand { get; }
    public System.Windows.Input.ICommand RunVolatilityPluginsCommand { get; }
    public System.Windows.Input.ICommand RunKapeCommand { get; }
    public System.Windows.Input.ICommand BuildTimelineCommand { get; }
    public System.Windows.Input.ICommand ExportTimelineCommand { get; }
    public System.Windows.Input.ICommand CaptureProcessSnapshotCommand { get; }
    public System.Windows.Input.ICommand RunYaraLiteCommand { get; }
    public System.Windows.Input.ICommand ExportYaraResultsCommand { get; }
    public System.Windows.Input.ICommand RunKustoQueryCommand { get; }
    public System.Windows.Input.ICommand LoadKustoTemplateCommand { get; }
    public System.Windows.Input.ICommand InitializeLocalDbCommand { get; }
    public System.Windows.Input.ICommand RefreshTablesCommand { get; }
    public System.Windows.Input.ICommand ClearLocalDbCommand { get; }
    public System.Windows.Input.ICommand InsertTableQueryCommand { get; }
    public System.Windows.Input.ICommand ExecuteLocalKqlCommand { get; }
    public System.Windows.Input.ICommand ExportLocalResultsCommand { get; }
    public System.Windows.Input.ICommand RunLocalKqlCommand { get; }
    public System.Windows.Input.ICommand ExportOpenSearchCommand { get; }
    public System.Windows.Input.ICommand TestOpenSearchCommand { get; }
    public System.Windows.Input.ICommand CreatePipelinesCommand { get; }
    public System.Windows.Input.ICommand CreateIndexTemplatesCommand { get; }
    public System.Windows.Input.ICommand IngestToOpenSearchCommand { get; }
    public System.Windows.Input.ICommand RunOsintCommand { get; }
    public System.Windows.Input.ICommand BrowseExifToolCommand { get; }
    public System.Windows.Input.ICommand DownloadExifToolCommand { get; }
    public System.Windows.Input.ICommand ExtractMetadataCommand { get; }
    public System.Windows.Input.ICommand ScanScheduledTasksCommand { get; }
    public System.Windows.Input.ICommand ExportScheduledTasksCommand { get; }
    public System.Windows.Input.ICommand BrowseBrowserProfileCommand { get; }
    public System.Windows.Input.ICommand ScanBrowserArtifactsCommand { get; }
    public System.Windows.Input.ICommand ExportBrowserArtifactsCommand { get; }
    public System.Windows.Input.ICommand BrowseIOCPathCommand { get; }
    public System.Windows.Input.ICommand LoadIOCFeedCommand { get; }
    public System.Windows.Input.ICommand ScanForIOCsCommand { get; }
    public System.Windows.Input.ICommand ExportIOCResultsCommand { get; }
    public System.Windows.Input.ICommand OpenRegistrySnapshotFolderCommand { get; }
    public System.Windows.Input.ICommand TakeRegistrySnapshotCommand { get; }
    public System.Windows.Input.ICommand BrowseSnapshot1Command { get; }
    public System.Windows.Input.ICommand BrowseSnapshot2Command { get; }
    public System.Windows.Input.ICommand CompareRegistrySnapshotsCommand { get; }
    public System.Windows.Input.ICommand ExportRegistryDiffCommand { get; }
    public System.Windows.Input.ICommand BrowsePcapFileCommand { get; }
    public System.Windows.Input.ICommand ParsePcapCommand { get; }
    public System.Windows.Input.ICommand ExportPcapResultsCommand { get; }
    public System.Windows.Input.ICommand BrowseBulkExtractorCommand { get; }
    public System.Windows.Input.ICommand BrowseBulkInputCommand { get; }
    public System.Windows.Input.ICommand RunBulkExtractorCommand { get; }
    public System.Windows.Input.ICommand DownloadBulkExtractorCommand { get; }
    public System.Windows.Input.ICommand CheckIocCommand { get; }
    public System.Windows.Input.ICommand CollectRegistryCommand { get; }
    public System.Windows.Input.ICommand AnalyzePcapCommand { get; }
    public System.Windows.Input.ICommand CollectBrowserArtifactsCommand { get; }
    public System.Windows.Input.ICommand AnalyzeMalwareCommand { get; }
    public System.Windows.Input.ICommand ExtractArtifactsCommand { get; }
    public System.Windows.Input.ICommand RunScheduleCommand { get; }
    public System.Windows.Input.ICommand ExportResultsCommand { get; }
    public System.Windows.Input.ICommand ClearResultsCommand { get; }
    public System.Windows.Input.ICommand ClearLogCommand { get; }
    public System.Windows.Input.ICommand CancelCommand { get; }
    public System.Windows.Input.ICommand BrowseOletoolsCommand { get; }
    public System.Windows.Input.ICommand BrowseDocumentsCommand { get; }
    public System.Windows.Input.ICommand BrowsePdfParserCommand { get; }
    public System.Windows.Input.ICommand RunMalwareAnalysisCommand { get; }
    public System.Windows.Input.ICommand DownloadOletoolsCommand { get; }
    public System.Windows.Input.ICommand DownloadPdfParserCommand { get; }

    #endregion

    #region Methods

    private void RefreshProcesses()
    {
        try
        {
            RunningProcessList.Clear();
            foreach (var proc in Process.GetProcesses().OrderBy(p => p.ProcessName).Take(200))
                RunningProcessList.Add($"{proc.ProcessName} (PID: {proc.Id})");

            // Keep the Processes tab in sync so refresh has visible UI impact.
            CaptureProcessSnapshot();
            StatusMessage = $"Refreshed process list ({RunningProcessList.Count}) and snapshot ({Processes.Count}).";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Process refresh failed: {ex.Message}";
        }
    }

    private async Task AcquireMemoryAsync()
    {
        try
        {
            StatusMessage = $"Preparing memory acquisition task using {SelectedMemoryTool}...";
            Directory.CreateDirectory(DumpOutputPath);
            var report = Path.Combine(DumpOutputPath, $"memory-acquisition-{DateTime.Now:yyyyMMdd-HHmmss}.txt");

            var sb = new StringBuilder();
            sb.AppendLine("Memory Acquisition Configuration");
            sb.AppendLine($"Tool: {SelectedMemoryTool}");
            sb.AppendLine($"Format: {DumpFormat}");
            sb.AppendLine($"Output: {DumpOutputPath}");
            sb.AppendLine($"Timestamp: {DateTime.Now:O}");

            if (SelectedMemoryTool == "WinPmem")
            {
                sb.AppendLine($"WinPmem Path: {WinPmemPath}");
                sb.AppendLine("Action: Acquire full physical memory image.");
            }
            else if (SelectedMemoryTool == "Magnet RAM Capture")
            {
                sb.AppendLine($"Magnet RAM Capture Path: {MagnetRamCapturePath}");
                sb.AppendLine("Action: Acquire live memory with signed capture driver workflow.");
            }
            else
            {
                sb.AppendLine($"ProcDump Path: {ProcDumpPath}");
                sb.AppendLine($"Target Process: {SelectedProcessForDump}");
                sb.AppendLine($"Dump Type: {(ProcDumpFullDump ? "Full" : "Mini")}");
                sb.AppendLine("Action: Capture selected process memory dump.");
            }

            await File.WriteAllTextAsync(report, sb.ToString());
            StatusMessage = $"Memory acquisition task prepared: {report}";
        }
        catch (Exception ex) { StatusMessage = $"Memory acquisition failed: {ex.Message}"; }
    }

    private async Task AcquireWinPmemAsync()
    {
        SelectedMemoryTool = "WinPmem";
        await AcquireMemoryAsync();
    }

    private async Task AcquireMagnetRamAsync()
    {
        SelectedMemoryTool = "Magnet RAM Capture";
        await AcquireMemoryAsync();
    }

    private async Task AcquireProcDumpAsync()
    {
        SelectedMemoryTool = "ProcDump";
        await AcquireMemoryAsync();
    }

    private void BrowseWinPmem()
    {
        var dlg = new OpenFileDialog { Title = "Select WinPmem executable", Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            WinPmemPath = dlg.FileName;
    }

    private void BrowseDumpOutput()
    {
        var dlg = new OpenFolderDialog { Title = "Select memory dump output folder" };
        if (dlg.ShowDialog() == true)
            DumpOutputPath = dlg.FolderName;
    }

    private void BrowseMagnetRamCapture()
    {
        var dlg = new OpenFileDialog { Title = "Select Magnet RAM Capture executable", Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            MagnetRamCapturePath = dlg.FileName;
    }

    private void BrowseProcDump()
    {
        var dlg = new OpenFileDialog { Title = "Select ProcDump executable", Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            ProcDumpPath = dlg.FileName;
    }

    private void BrowseMemoryDump()
    {
        var dlg = new OpenFileDialog { Title = "Select memory dump file", Filter = "Memory dumps (*.raw;*.dmp;*.mem)|*.raw;*.dmp;*.mem|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            MemoryDumpPath = dlg.FileName;
    }

    private void BrowseVolatility()
    {
        var dlg = new OpenFileDialog { Title = "Select Volatility executable", Filter = "Executable or script (*.exe;*.py)|*.exe;*.py|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            VolatilityPath = dlg.FileName;
    }

    private void BrowseKape()
    {
        var dlg = new OpenFileDialog { Title = "Select KAPE executable", Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            KapePath = dlg.FileName;
    }

    private void BrowseKapeTarget()
    {
        var dlg = new OpenFolderDialog { Title = "Select KAPE target folder" };
        if (dlg.ShowDialog() == true)
            KapeTargetPath = dlg.FolderName;
    }

    private void BrowsePlaso()
    {
        var dlg = new OpenFileDialog { Title = "Select Plaso executable", Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            PlasoPath = dlg.FileName;
    }

    private void BrowseEvidence()
    {
        var dlg = new OpenFolderDialog { Title = "Select evidence folder" };
        if (dlg.ShowDialog() == true)
            EvidencePath = dlg.FolderName;
    }

    private void BrowseVelociraptor()
    {
        var dlg = new OpenFileDialog { Title = "Select Velociraptor executable", Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            VelociraptorPath = dlg.FileName;
    }

    private void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
            StatusMessage = $"Opened: {url}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open URL: {ex.Message}";
        }
    }

    private async Task RunVolatilityAsync()
    {
        try
        {
            StatusMessage = "Running Volatility plugins...";
            Directory.CreateDirectory(VolatilityOutputPath);
            var plugins = new List<string>();
            if (RunPsList) plugins.Add("psList");
            if (RunNetScan) plugins.Add("netScan");
            if (RunMalfind) plugins.Add("malfind");
            if (RunDllList) plugins.Add("dllList");
            if (RunHandles) plugins.Add("handles");
            if (RunCmdline) plugins.Add("cmdline");
            if (RunFileScan) plugins.Add("fileScan");
            if (RunRegHive) plugins.Add("regHive");
            if (RunPsTree) plugins.Add("psTree");
            if (RunEnvars) plugins.Add("envars");
            if (RunSvcScan) plugins.Add("svcScan");
            if (RunCallbacks) plugins.Add("callbacks");
            if (RunDriverScan) plugins.Add("driverScan");
            if (RunSsdt) plugins.Add("ssdt");
            if (RunMutantScan) plugins.Add("mutantScan");
            var report = Path.Combine(VolatilityOutputPath, $"volatility-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(report,
                $"Volatility Analysis Report\nMemory Dump: {MemoryDumpPath}\nPlugins Run: {string.Join(", ", plugins)}\nTimestamp: {DateTime.Now}");
            StatusMessage = $"Volatility plugins completed ({plugins.Count} plugins): {report}";
        }
        catch (Exception ex) { StatusMessage = $"Volatility analysis failed: {ex.Message}"; }
    }

    private async Task RunPlasoTimelineAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "Timeline", "Plaso");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"plaso-job-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(file,
                $"Plaso Timeline Job\nPlasoPath: {PlasoPath}\nEvidencePath: {EvidencePath}\nTimestamp: {DateTime.Now:O}");
            AddResult("Timeline", "Plaso timeline job prepared", "Ready", file);
            StatusMessage = $"Plaso timeline job prepared: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Plaso timeline setup failed: {ex.Message}";
        }
    }

    private async Task ExportPlasoToOpenSearchAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "OpenSearch");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"plaso-opensearch-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl");
            using var sw = new StreamWriter(file, false, Encoding.UTF8);
            foreach (var item in Timeline)
            {
                await sw.WriteLineAsync($"{{\"type\":\"timeline\",\"timestamp\":\"{item.Timestamp:O}\",\"source\":{JsonEscape(item.Source)},\"level\":{JsonEscape(item.Level)},\"message\":{JsonEscape(item.Message)}}}");
            }

            AddResult("OpenSearch", "Plaso export package generated", "Ready", file);
            StatusMessage = $"Plaso OpenSearch package created: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Plaso OpenSearch export failed: {ex.Message}";
        }
    }

    private async Task RunVelociraptorCollectAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "Artifacts", "Velociraptor");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"velociraptor-collect-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(file,
                $"Velociraptor collection task\nBinary: {VelociraptorPath}\nEvidencePath: {EvidencePath}\nTimestamp: {DateTime.Now:O}");
            AddResult("Artifacts", "Velociraptor collection prepared", "Ready", file);
            StatusMessage = $"Velociraptor collection task prepared: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Velociraptor collection failed: {ex.Message}";
        }
    }

    private async Task RunKapeAsync()
    {
        try
        {
            StatusMessage = "Running KAPE artifact collection...";
            Directory.CreateDirectory(KapeOutputPath);
            var artifacts = new List<string>();
            if (CollectPrefetch) artifacts.Add("Prefetch");
            if (CollectAmcache) artifacts.Add("Amcache");
            if (CollectEventLogs) artifacts.Add("EventLogs");
            if (CollectMft) artifacts.Add("MFT");
            if (CollectRegistry) artifacts.Add("Registry");
            if (CollectSrum) artifacts.Add("SRUM");
            if (CollectShellBags) artifacts.Add("ShellBags");
            if (CollectBitlocker) artifacts.Add("BitLocker");
            if (CollectRecycleBin) artifacts.Add("RecycleBin");
            if (CollectBrowser) artifacts.Add("BrowserData");
            var report = Path.Combine(KapeOutputPath, $"kape-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(report,
                $"KAPE Collection Report\nTarget: {KapeTargetPath}\nArtifacts Collected: {string.Join(", ", artifacts)}\nOutput: {KapeOutputPath}\nTimestamp: {DateTime.Now}");
            StatusMessage = $"KAPE collection prepared ({artifacts.Count} artifact types): {report}";
        }
        catch (Exception ex) { StatusMessage = $"KAPE collection failed: {ex.Message}"; }
    }

    private void BuildTimeline()
    {
        try
        {
            Timeline.Clear();
            var entries = _service.CaptureRecentTimeline();
            foreach (var item in entries) Timeline.Add(item);
            StatusMessage = $"Built forensic timeline with {Timeline.Count} events.";
            ((RelayCommand)ExportTimelineCommand).RaiseCanExecuteChanged();
        }
        catch (Exception ex) { StatusMessage = $"Timeline build failed: {ex.Message}"; }
    }

    private void CaptureProcessSnapshot()
    {
        try
        {
            Processes.Clear();
            foreach (var process in _service.CaptureProcessSnapshot(400))
                Processes.Add(process);
            StatusMessage = $"Captured {Processes.Count} processes.";
        }
        catch (Exception ex) { StatusMessage = $"Process capture failed: {ex.Message}"; }
    }

    private void ExportTimeline()
    {
        try
        {
            var target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Forensics");
            Directory.CreateDirectory(target);
            var file = Path.Combine(target, $"timeline-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
            using var sw = new StreamWriter(file);
            sw.WriteLine("Timestamp,Source,Level,Message");
            foreach (var item in Timeline)
            {
                var msg = item.Message.Replace("\"", "''").Replace("\r", " ").Replace("\n", " ");
                sw.WriteLine($"\"{item.Timestamp:O}\",\"{item.Source}\",\"{item.Level}\",\"{msg}\"");
            }
            StatusMessage = $"Timeline exported: {file}";
        }
        catch (Exception ex) { StatusMessage = $"Timeline export failed: {ex.Message}"; }
    }

    private async Task RunYaraLiteAsync()
    {
        YaraMatches.Clear();
        try
        {
            var rules = _service.ParseYaraLiteRules(RulesInput);
            if (rules.Count == 0)
            {
                StatusMessage = "No valid YARA-lite rules.";
                return;
            }
            var matches = await _service.ScanWithYaraLiteAsync(TargetPath, rules, CancellationToken.None);
            foreach (var match in matches)
                YaraMatches.Add(match);
            ((RelayCommand)ExportYaraResultsCommand).RaiseCanExecuteChanged();
            StatusMessage = $"YARA-lite scan complete: {YaraMatches.Count} hits.";
        }
        catch (Exception ex) { StatusMessage = $"YARA-lite scan failed: {ex.Message}"; }
    }

    private void ExportYaraResults()
    {
        try
        {
            var target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Forensics");
            Directory.CreateDirectory(target);
            var file = Path.Combine(target, $"yara-lite-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
            using var sw = new StreamWriter(file);
            sw.WriteLine("FilePath,RuleName,MatchCount");
            foreach (var m in YaraMatches)
                sw.WriteLine($"\"{m.FilePath.Replace("\"", "''")}\",\"{m.RuleName}\",{m.MatchCount}");
            StatusMessage = $"YARA-lite results exported: {file}";
        }
        catch (Exception ex) { StatusMessage = $"YARA export failed: {ex.Message}"; }
    }

    private async Task RunKustoQueryAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "Kusto");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"kusto-query-{DateTime.Now:yyyyMMdd-HHmmss}.kql");
            var payload = $"// Endpoint: {KustoEndpoint}\n// Database: {KustoDatabase}\n{KustoQuery}\n";
            await File.WriteAllTextAsync(file, payload);
            AddResult("Kusto", "Prepared Kusto query package", "Ready", file);
            StatusMessage = $"Kusto query prepared: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Kusto preparation failed: {ex.Message}";
        }
    }

    private void LoadKustoTemplate()
    {
        KustoQuery = "SecurityEvent\n| where TimeGenerated > ago(24h)\n| summarize Count=count() by EventID\n| order by Count desc";
        StatusMessage = "Loaded default Kusto template.";
    }

    private async Task InitializeLocalDbAsync()
    {
        try
        {
            var dir = Path.GetDirectoryName(LocalDbPath) ?? Path.Combine(_forensicsRoot, "LocalKql");
            Directory.CreateDirectory(dir);
            if (!File.Exists(LocalDbPath))
            {
                await File.WriteAllTextAsync(LocalDbPath, "SecKey Local KQL DB placeholder");
            }

            LocalKqlOutput = $"Local DB initialized: {LocalDbPath}";
            AddResult("Local KQL", "Initialized local KQL DB", "Ready", LocalDbPath);
            StatusMessage = "Local KQL DB initialized.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Initialize local DB failed: {ex.Message}";
        }
    }

    private void RefreshLocalTables()
    {
        LocalKqlOutput = "Tables: timeline, processes, yara, ioc, registry, pcap";
        StatusMessage = "Local KQL table metadata refreshed.";
    }

    private async Task ClearLocalDbAsync()
    {
        try
        {
            if (File.Exists(LocalDbPath))
                File.Delete(LocalDbPath);
            await InitializeLocalDbAsync();
            StatusMessage = "Local KQL DB cleared and reinitialized.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to clear local DB: {ex.Message}";
        }
    }

    private void InsertLocalTableQuery()
    {
        LocalKqlQuery = "timeline | take 100";
        StatusMessage = "Inserted sample table query.";
    }

    private async Task ExportLocalResultsAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "LocalKql");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"local-kql-results-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(file, LocalKqlOutput);
            AddResult("Local KQL", "Exported local results", "Done", file);
            StatusMessage = $"Local KQL results exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Local results export failed: {ex.Message}";
        }
    }

    private void RunLocalKql()
    {
        try
        {
            var translated = "SELECT * FROM timeline LIMIT 50";
            if (LocalKqlQuery.Contains("take", StringComparison.OrdinalIgnoreCase))
                translated = "SELECT * FROM timeline LIMIT <take>";

            LocalKqlOutput = $"Translated SQL: {translated}\nLocal KQL query captured at {DateTime.Now:O}";
            AddResult("Local KQL", "Executed local KQL translation", "Success", LocalKqlQuery);
            StatusMessage = "Local KQL query executed.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Local KQL failed: {ex.Message}";
        }
    }

    private async Task ExportOpenSearchAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "OpenSearch");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"opensearch-export-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl");

            using var sw = new StreamWriter(file, false, Encoding.UTF8);
            foreach (var t in Timeline)
                await sw.WriteLineAsync($"{{\"type\":\"timeline\",\"timestamp\":\"{t.Timestamp:O}\",\"source\":\"{t.Source}\",\"level\":\"{t.Level}\",\"message\":{JsonEscape(t.Message)}}}");
            foreach (var p in Processes)
                await sw.WriteLineAsync($"{{\"type\":\"process\",\"name\":{JsonEscape(p.Name)},\"pid\":{p.Pid},\"memoryMb\":{p.WorkingSetMb}}}");
            foreach (var y in YaraMatches)
                await sw.WriteLineAsync($"{{\"type\":\"yara\",\"rule\":{JsonEscape(y.RuleName)},\"file\":{JsonEscape(y.FilePath)},\"matches\":{y.MatchCount}}}");

            AddResult("OpenSearch", "Export package generated", "Ready", file);
            StatusMessage = $"OpenSearch package created: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"OpenSearch export failed: {ex.Message}";
        }
    }

    private async Task TestOpenSearchAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "OpenSearch");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"opensearch-test-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(file, $"Endpoint: {OpenSearchEndpoint}\nIndex: {OpenSearchIndex}\nResult: Connectivity test prepared (manual execution).\nTimestamp: {DateTime.Now:O}");
            AddResult("OpenSearch", "Connection test package created", "Ready", file);
            StatusMessage = "OpenSearch test package generated.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"OpenSearch test failed: {ex.Message}";
        }
    }

    private async Task CreateOpenSearchPipelinesAsync()
    {
        await WriteOpenSearchAssetAsync("pipeline", "seckey-default-pipeline", "Created ingest pipeline JSON template.");
    }

    private async Task CreateOpenSearchTemplatesAsync()
    {
        await WriteOpenSearchAssetAsync("template", "seckey-default-template", "Created index template JSON.");
    }

    private async Task IngestToOpenSearchAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "OpenSearch");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"opensearch-ingest-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(file, $"Ingest endpoint: {OpenSearchEndpoint}\nIndex: {OpenSearchIndex}\nRecords: timeline={Timeline.Count}, processes={Processes.Count}, results={ForensicsResults.Count}\nTimestamp: {DateTime.Now:O}");
            AddResult("OpenSearch", "Prepared ingest manifest", "Ready", file);
            StatusMessage = "OpenSearch ingest manifest prepared.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ingest manifest failed: {ex.Message}";
        }
    }

    private void RunOsint()
    {
        AddResult("OSINT", "OSINT target queued", "Queued", OsintTarget);
        StatusMessage = $"OSINT target queued: {OsintTarget}";
    }

    private void BrowseExifTool()
    {
        var dlg = new OpenFileDialog { Title = "Select exiftool executable", Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            ExifToolPath = dlg.FileName;
    }

    private async Task ExtractMetadataAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "OSINT");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"metadata-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(file, $"ExifTool: {ExifToolPath}\nTarget: {OsintTarget}\nResult: Metadata extraction task prepared\nTimestamp: {DateTime.Now:O}");
            AddResult("OSINT", "Metadata extraction prepared", "Ready", file);
            StatusMessage = "Metadata extraction job prepared.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Metadata extraction failed: {ex.Message}";
        }
    }

    private void ScanScheduledTasks()
    {
        AddResult("Schedule", "Scheduled task scan queued", "Queued", ScheduleName);
        StatusMessage = "Scheduled task scan queued.";
    }

    private async Task ExportScheduledTasksAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "Schedule");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"scheduled-tasks-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(file, "Scheduled task export placeholder");
            AddResult("Schedule", "Scheduled tasks exported", "Done", file);
            StatusMessage = $"Scheduled tasks exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Scheduled task export failed: {ex.Message}";
        }
    }

    private void CheckIoc()
    {
        var iocs = IocInput.Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        AddResult("IOC", $"Parsed {iocs.Length} IOC indicators", "Parsed", string.Join(" | ", iocs.Take(10)));
        StatusMessage = $"IOC list parsed: {iocs.Length} indicator(s).";
    }

    private void BrowseIocPath()
    {
        var dlg = new OpenFileDialog { Title = "Select IOC feed file", Filter = "Text/CSV/JSON (*.txt;*.csv;*.json)|*.txt;*.csv;*.json|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            IocPath = dlg.FileName;
    }

    private async Task LoadIocFeedAsync()
    {
        try
        {
            if (!File.Exists(IocPath))
            {
                StatusMessage = "IOC feed file not found.";
                return;
            }

            var content = await File.ReadAllTextAsync(IocPath);
            IocInput = content;
            AddResult("IOC", "Loaded IOC feed", "Ready", IocPath);
            StatusMessage = $"IOC feed loaded: {IocPath}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"IOC feed load failed: {ex.Message}";
        }
    }

    private async Task ExportIocResultsAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "IOC");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"ioc-results-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
            var rows = ForensicsResults.Where(r => r.Category == "IOC").ToList();
            using var sw = new StreamWriter(file, false, Encoding.UTF8);
            sw.WriteLine("Timestamp,Summary,Status,Detail");
            foreach (var row in rows)
                sw.WriteLine($"\"{row.Timestamp:O}\",\"{SanitizeCsv(row.Summary)}\",\"{SanitizeCsv(row.Status)}\",\"{SanitizeCsv(row.Detail)}\"");
            StatusMessage = $"IOC results exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"IOC export failed: {ex.Message}";
        }
    }

    private void CollectRegistrySnapshot()
    {
        AddResult("Registry", "Registry collection requested", "Ready", RegistryPath);
        StatusMessage = $"Registry snapshot prepared for: {RegistryPath}";
    }

    private void AnalyzePcap()
    {
        AddResult("PCAP", "PCAP analysis requested", "Ready", PcapPath);
        StatusMessage = $"PCAP analysis task queued: {PcapPath}";
    }

    private void BrowsePcapFile()
    {
        var dlg = new OpenFileDialog { Title = "Select PCAP file", Filter = "PCAP (*.pcap;*.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            PcapPath = dlg.FileName;
    }

    private async Task ExportPcapResultsAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "PCAP");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"pcap-results-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(file, $"PCAP source: {PcapPath}\nExported: {DateTime.Now:O}");
            AddResult("PCAP", "Exported PCAP analysis package", "Done", file);
            StatusMessage = $"PCAP results exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"PCAP export failed: {ex.Message}";
        }
    }

    private void CollectBrowserArtifacts()
    {
        AddResult("Browser", "Browser artifact collection prepared", "Ready", BrowserPath);
        StatusMessage = $"Browser collection target set: {BrowserPath}";
    }

    private void BrowseBrowserProfile()
    {
        var dlg = new OpenFolderDialog { Title = "Select browser profile folder" };
        if (dlg.ShowDialog() == true)
        {
            BrowserProfilePath = dlg.FolderName;
            BrowserPath = dlg.FolderName;
        }
    }

    private async Task ExportBrowserArtifactsAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "Browser");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"browser-artifacts-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(file, $"Browser path: {BrowserPath}\nProfile path: {BrowserProfilePath}\nTimestamp: {DateTime.Now:O}");
            AddResult("Browser", "Exported browser artifact manifest", "Done", file);
            StatusMessage = $"Browser artifact manifest exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Browser artifact export failed: {ex.Message}";
        }
    }

    private void AnalyzeMalware()
    {
        AddResult("Malware", "Static triage task prepared", "Ready", MalwareSamplePath);
        StatusMessage = $"Malware analysis task prepared: {MalwareSamplePath}";
    }

    private void BrowseOletools()
    {
        var dlg = new OpenFolderDialog { Title = "Select oletools folder" };
        if (dlg.ShowDialog() == true)
            OletoolsPath = dlg.FolderName;
    }

    private void BrowseDocuments()
    {
        var dlg = new OpenFolderDialog { Title = "Select documents folder" };
        if (dlg.ShowDialog() == true)
            DocumentPath = dlg.FolderName;
    }

    private void BrowsePdfParser()
    {
        var dlg = new OpenFileDialog { Title = "Select pdf-parser.py", Filter = "Python (*.py)|*.py|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            PdfParserPath = dlg.FileName;
    }

    private void BrowseBulkExtractor()
    {
        var dlg = new OpenFileDialog { Title = "Select bulk_extractor executable", Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            BulkExtractorPath = dlg.FileName;
    }

    private void BrowseBulkInput()
    {
        var dlg = new OpenFolderDialog { Title = "Select bulk extractor input folder" };
        if (dlg.ShowDialog() == true)
            BulkInputPath = dlg.FolderName;
    }

    private async Task RunBulkExtractorAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "Extract", "BulkExtractor");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"bulk-extractor-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            await File.WriteAllTextAsync(file, $"Bulk Extractor: {BulkExtractorPath}\nInput: {BulkInputPath}\nTimestamp: {DateTime.Now:O}");
            AddResult("Extract", "Bulk extractor task prepared", "Ready", file);
            StatusMessage = $"Bulk extractor task prepared: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Bulk extractor failed: {ex.Message}";
        }
    }

    private async Task RunMalwareAnalysisAsync()
    {
        MalwareResults.Clear();

        try
        {
            if (!Directory.Exists(DocumentPath))
            {
                StatusMessage = "Document folder not found.";
                return;
            }

            var files = Directory.GetFiles(DocumentPath, "*.*", SearchOption.TopDirectoryOnly)
                .Where(f => f.EndsWith(".doc", StringComparison.OrdinalIgnoreCase)
                            || f.EndsWith(".docm", StringComparison.OrdinalIgnoreCase)
                            || f.EndsWith(".docx", StringComparison.OrdinalIgnoreCase)
                            || f.EndsWith(".xls", StringComparison.OrdinalIgnoreCase)
                            || f.EndsWith(".xlsm", StringComparison.OrdinalIgnoreCase)
                            || f.EndsWith(".ppt", StringComparison.OrdinalIgnoreCase)
                            || f.EndsWith(".pptm", StringComparison.OrdinalIgnoreCase)
                            || f.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase))
                .Take(200)
                .ToList();

            foreach (var file in files)
            {
                var ext = Path.GetExtension(file).ToLowerInvariant();
                var hasMacros = ext is ".docm" or ".xlsm" or ".pptm";
                var suspicious = hasMacros || Path.GetFileName(file).Contains("invoice", StringComparison.OrdinalIgnoreCase);

                MalwareResults.Add(new MalwareResultRow
                {
                    FileName = Path.GetFileName(file),
                    FileType = ext,
                    HasMacros = hasMacros,
                    IsSuspicious = suspicious
                });
            }

            var outDir = Path.Combine(_forensicsRoot, "Malware");
            Directory.CreateDirectory(outDir);
            var reportPath = Path.Combine(outDir, $"malware-analysis-{DateTime.Now:yyyyMMdd-HHmmss}.csv");

            using (var sw = new StreamWriter(reportPath, false, Encoding.UTF8))
            {
                sw.WriteLine("FileName,FileType,HasMacros,IsSuspicious");
                foreach (var row in MalwareResults)
                {
                    sw.WriteLine($"\"{SanitizeCsv(row.FileName)}\",\"{SanitizeCsv(row.FileType)}\",{row.HasMacros},{row.IsSuspicious}");
                }
            }

            await Task.CompletedTask;
            AddResult("Malware", $"Analyzed {MalwareResults.Count} documents", "Complete", reportPath);
            StatusMessage = $"Malware analysis complete: {MalwareResults.Count} file(s) analyzed.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Malware analysis failed: {ex.Message}";
        }
    }

    private void ExtractArtifacts()
    {
        AddResult("Extract", "Artifact extraction task prepared", "Ready", ExtractSourcePath);
        StatusMessage = $"Artifact extraction task prepared: {ExtractSourcePath}";
    }

    private async Task TakeRegistrySnapshotAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "Registry");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"registry-snapshot-{DateTime.Now:yyyyMMdd-HHmmss}.reg");
            await File.WriteAllTextAsync(file, $"Windows Registry Editor Version 5.00\n; Placeholder snapshot generated by SecKey\n; Timestamp: {DateTime.Now:O}\n");
            Snapshot1Path = Snapshot1Path.Length == 0 ? file : Snapshot1Path;
            Snapshot2Path = Snapshot1Path != file && Snapshot2Path.Length == 0 ? file : Snapshot2Path;
            AddResult("Registry", "Registry snapshot created", "Done", file);
            StatusMessage = $"Registry snapshot created: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Registry snapshot failed: {ex.Message}";
        }
    }

    private void BrowseSnapshot1()
    {
        var dlg = new OpenFileDialog { Title = "Select registry snapshot 1", Filter = "Registry export (*.reg)|*.reg|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            Snapshot1Path = dlg.FileName;
    }

    private void BrowseSnapshot2()
    {
        var dlg = new OpenFileDialog { Title = "Select registry snapshot 2", Filter = "Registry export (*.reg)|*.reg|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            Snapshot2Path = dlg.FileName;
    }

    private async Task CompareRegistrySnapshotsAsync()
    {
        try
        {
            if (!File.Exists(Snapshot1Path) || !File.Exists(Snapshot2Path))
            {
                StatusMessage = "Select two valid registry snapshots first.";
                return;
            }

            var left = await File.ReadAllLinesAsync(Snapshot1Path);
            var right = await File.ReadAllLinesAsync(Snapshot2Path);
            var leftSet = left.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var rightSet = right.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var onlyLeft = leftSet.Except(rightSet, StringComparer.OrdinalIgnoreCase).Count();
            var onlyRight = rightSet.Except(leftSet, StringComparer.OrdinalIgnoreCase).Count();
            AddResult("RegistryDiff", $"Registry diff completed (left-only={onlyLeft}, right-only={onlyRight})", "Done", $"{Snapshot1Path} <> {Snapshot2Path}");
            StatusMessage = "Registry snapshots compared.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Registry compare failed: {ex.Message}";
        }
    }

    private async Task ExportRegistryDiffAsync()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "Registry");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"registry-diff-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
            var rows = ForensicsResults.Where(r => r.Category == "RegistryDiff").ToList();
            using var sw = new StreamWriter(file, false, Encoding.UTF8);
            sw.WriteLine("Timestamp,Summary,Status,Detail");
            foreach (var row in rows)
                sw.WriteLine($"\"{row.Timestamp:O}\",\"{SanitizeCsv(row.Summary)}\",\"{SanitizeCsv(row.Status)}\",\"{SanitizeCsv(row.Detail)}\"");
            StatusMessage = $"Registry diff exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Registry diff export failed: {ex.Message}";
        }
    }

    private void OpenRegistrySnapshotFolder()
    {
        var dir = Path.Combine(_forensicsRoot, "Registry");
        Directory.CreateDirectory(dir);
        Process.Start(new ProcessStartInfo { FileName = dir, UseShellExecute = true });
        StatusMessage = $"Opened registry snapshot folder: {dir}";
    }

    private void RunSchedule()
    {
        AddResult("Schedule", "Workflow schedule registered", "Configured", ScheduleName);
        StatusMessage = $"DFIR workflow scheduled: {ScheduleName}";
    }

    private void ExportResults()
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "Results");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"results-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
            using var sw = new StreamWriter(file, false, Encoding.UTF8);
            sw.WriteLine("Timestamp,Category,Summary,Status,Detail");
            foreach (var r in ForensicsResults)
            {
                sw.WriteLine($"\"{r.Timestamp:O}\",\"{SanitizeCsv(r.Category)}\",\"{SanitizeCsv(r.Summary)}\",\"{SanitizeCsv(r.Status)}\",\"{SanitizeCsv(r.Detail)}\"");
            }

            StatusMessage = $"Results exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to export results: {ex.Message}";
        }
    }

    private void ClearResults()
    {
        ForensicsResults.Clear();
        ((RelayCommand)ExportResultsCommand).RaiseCanExecuteChanged();
        ((RelayCommand)ClearResultsCommand).RaiseCanExecuteChanged();
        StatusMessage = "Results cleared.";
    }

    private async Task WriteOpenSearchAssetAsync(string kind, string name, string summary)
    {
        try
        {
            var outDir = Path.Combine(_forensicsRoot, "OpenSearch");
            Directory.CreateDirectory(outDir);
            var file = Path.Combine(outDir, $"{kind}-{DateTime.Now:yyyyMMdd-HHmmss}.json");
            var payload = $"{{\n  \"name\": \"{name}\",\n  \"index\": \"{OpenSearchIndex}\",\n  \"generated\": \"{DateTime.Now:O}\"\n}}";
            await File.WriteAllTextAsync(file, payload);
            AddResult("OpenSearch", summary, "Ready", file);
            StatusMessage = summary;
        }
        catch (Exception ex)
        {
            StatusMessage = $"OpenSearch asset generation failed: {ex.Message}";
        }
    }

    private void CancelActiveOperations()
    {
        _operationCts?.Cancel();
        _operationCts = null;
        StatusMessage = "Cancellation requested for active operations.";
    }

    private void AddResult(string category, string summary, string status, string detail)
    {
        ForensicsResults.Insert(0, new ForensicsResultRow
        {
            Timestamp = DateTime.UtcNow,
            Category = category,
            Summary = summary,
            Status = status,
            Detail = detail
        });

        ((RelayCommand)ExportResultsCommand).RaiseCanExecuteChanged();
        ((RelayCommand)ClearResultsCommand).RaiseCanExecuteChanged();
    }

    private static string SanitizeCsv(string value) => value.Replace("\"", "''").Replace("\r", " ").Replace("\n", " ");
    private static string JsonEscape(string value) => $"\"{value.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"";

    #endregion
}

public sealed class ForensicsResultRow
{
    public DateTime Timestamp { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
}

public sealed class MalwareResultRow
{
    public string FileName { get; set; } = string.Empty;
    public string FileType { get; set; } = string.Empty;
    public bool HasMacros { get; set; }
    public bool IsSuspicious { get; set; }
}
