using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using SecKey.Core.Models;
using SecKey.Core.Services;
using SecKey.Graph.Services;
using SecKey.App.Services;

namespace SecKey.App.ViewModels
{
    /// <summary>
    /// ViewModel for the AD Security Analyzer view (PLATYPUS-style functionality).
    /// Provides Active Directory and Entra ID security analysis capabilities.
    /// </summary>
    public class SecurityAnalyzerViewModel : BindableBase
    {
        private readonly AdSecurityAnalysisService _analysisService;
        private readonly AdSecurityDatabaseService _databaseService;
        private readonly EntraIdSecurityService _entraIdService;
        private CancellationTokenSource? _cts;

        public SecurityAnalyzerViewModel()
        {
            _analysisService = new AdSecurityAnalysisService(new Progress<string>(msg => AppendLog(msg)));
            _databaseService = new AdSecurityDatabaseService();
            _entraIdService = new EntraIdSecurityService(
                new Progress<string>(msg => AppendLog(msg)),
                EntraConfigService.Instance.GetGraphClientId());

            // Initialize collections
            PrivilegedMembers = new ObservableCollection<AdPrivilegedMember>();
            RiskyAcls = new ObservableCollection<AdRiskyAcl>();
            RiskyGpos = new ObservableCollection<AdRiskyGpo>();
            SysvolFiles = new ObservableCollection<SysvolRiskyFile>();
            KerberosDelegations = new ObservableCollection<AdKerberosDelegation>();
            AdminCountAnomalies = new ObservableCollection<AdAdminCountAnomaly>();
            AnalysisHistory = new ObservableCollection<StoredAnalysisRun>();
            LogMessages = new ObservableCollection<string>();
            DeploymentResults = new ObservableCollection<AdObjectCreationResult>();
            SecurityFindings = new ObservableCollection<SecurityFinding>();
            StaleUsers = new ObservableCollection<StaleAccountInfo>();
            StaleComputers = new ObservableCollection<StaleAccountInfo>();
            ComputersWithoutLaps = new ObservableCollection<ComputerLapsStatus>();
            
            // Entra ID collections
            EntraPrivilegedRoles = new ObservableCollection<EntraIdPrivilegedRole>();
            EntraRiskyApps = new ObservableCollection<EntraIdRiskyApp>();
            EntraConditionalAccessPolicies = new ObservableCollection<EntraIdConditionalAccessPolicy>();
            EntraPimViolations = new ObservableCollection<EntraIdPimViolation>();
            EntraPimViolations = new ObservableCollection<EntraIdPimViolation>();
            EntraPimAssignments = new ObservableCollection<EntraIdPimAssignment>();

            // Initialize commands
            DiscoverDomainCommand = new AsaRelayCommand(async _ => await DiscoverDomainAsync(), _ => !IsAnalyzing);
            RunFullAnalysisCommand = new AsaRelayCommand(async _ => await RunFullAnalysisAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            RunPrivilegedAnalysisCommand = new AsaRelayCommand(async _ => await RunPrivilegedAnalysisAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            RunAclAnalysisCommand = new AsaRelayCommand(async _ => await RunAclAnalysisAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            RunDelegationAnalysisCommand = new AsaRelayCommand(async _ => await RunDelegationAnalysisAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            RunSysvolAnalysisCommand = new AsaRelayCommand(async _ => await RunSysvolAnalysisAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            CancelAnalysisCommand = new AsaRelayCommand(_ => CancelAnalysis(), _ => IsAnalyzing);
            
            ExportToCsvCommand = new AsaRelayCommand(async _ => await ExportToCsvAsync(), _ => HasResults);
            ExportSelectedRunCommand = new AsaRelayCommand(async _ => await ExportSelectedRunAsync(), _ => SelectedHistoryRun != null);
            LoadHistoryCommand = new AsaRelayCommand(async _ => await LoadHistoryAsync());
            LoadSelectedRunCommand = new AsaRelayCommand(async _ => await LoadSelectedRunAsync(), _ => SelectedHistoryRun != null);
            DeleteSelectedRunCommand = new AsaRelayCommand(async _ => await DeleteSelectedRunAsync(), _ => SelectedHistoryRun != null);
            ClearHistoryCommand = new AsaRelayCommand(async _ => await ClearHistoryAsync(), _ => AnalysisHistory.Count > 0);
            ClearLogCommand = new AsaRelayCommand(_ => LogMessages.Clear());
            OpenDatabaseFolderCommand = new AsaRelayCommand(_ => OpenDatabaseFolder());

            // Deployment commands
            DeployTieredOusCommand = new AsaRelayCommand(async _ => await DeployTieredOusAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            DeployBaselineGposCommand = new AsaRelayCommand(async _ => await DeployBaselineGposAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            PreviewDeploymentCommand = new AsaRelayCommand(_ => PreviewDeployment(), _ => IsDomainDiscovered);
            ClearDeploymentResultsCommand = new AsaRelayCommand(_ => DeploymentResults.Clear(), _ => DeploymentResults.Count > 0);

            // MDE/MDI Proxy in a Box commands
            GenerateProxyScriptCommand = new AsaRelayCommand(_ => GenerateProxyScript());
            CopyProxyScriptCommand = new AsaRelayCommand(_ => CopyProxyScriptToClipboard(), _ => !string.IsNullOrEmpty(ProxyGeneratedScript));
            SaveProxyScriptCommand = new AsaRelayCommand(_ => SaveProxyScriptToFile(), _ => !string.IsNullOrEmpty(ProxyGeneratedScript));

            // Entra ID commands
            ConnectEntraIdCommand = new AsaRelayCommand(async _ => await ConnectEntraIdAsync(), _ => !IsAnalyzing && !string.IsNullOrWhiteSpace(EntraTenantId));
            DisconnectEntraIdCommand = new AsaRelayCommand(_ => DisconnectEntraId(), _ => IsEntraConnected);
            RunEntraAnalysisCommand = new AsaRelayCommand(async _ => await RunEntraAnalysisAsync(), _ => !IsAnalyzing && IsEntraConnected);
            GetEntraPrivilegedRolesCommand = new AsaRelayCommand(async _ => await GetEntraPrivilegedRolesAsync(), _ => !IsAnalyzing && IsEntraConnected);
            GetEntraRiskyAppsCommand = new AsaRelayCommand(async _ => await GetEntraRiskyAppsAsync(), _ => !IsAnalyzing && IsEntraConnected);
            GetEntraCaPoliciesCommand = new AsaRelayCommand(async _ => await GetEntraCaPoliciesAsync(), _ => !IsAnalyzing && IsEntraConnected);
            GetEntraPimViolationsCommand = new AsaRelayCommand(async _ => await GetEntraPimViolationsAsync(), _ => !IsAnalyzing && IsEntraConnected);

            // Remediation commands - PLATYPUS IR Operations
            TakebackTenantCommand = new AsaRelayCommand(async _ => await TakebackTenantAsync(), _ => !IsAnalyzing && IsEntraConnected);
            MassPasswordResetCommand = new AsaRelayCommand(async _ => await MassPasswordResetAsync(), _ => !IsAnalyzing && IsEntraConnected);
            RevokeAllTokensCommand = new AsaRelayCommand(async _ => await RevokeAllTokensAsync(), _ => !IsAnalyzing && IsEntraConnected);
            RemovePrivRoleMembersCommand = new AsaRelayCommand(async _ => await RemovePrivRoleMembersAsync(), _ => !IsAnalyzing && IsEntraConnected);
            RemoveAdminCountCommand = new AsaRelayCommand(async _ => await RemoveAdminCountAsync(), _ => !IsAnalyzing && IsDomainDiscovered);

            // Additional Entra IR commands
            RemoveAppOwnersCommand = new AsaRelayCommand(async _ => await RemoveAppOwnersAsync(), _ => !IsAnalyzing && IsEntraConnected);
            DisableCaPoliciesCommand = new AsaRelayCommand(async _ => await DisableCaPoliciesAsync(), _ => !IsAnalyzing && IsEntraConnected);
            DeployIrCaPoliciesCommand = new AsaRelayCommand(async _ => await DeployIrCaPoliciesAsync(), _ => !IsAnalyzing && IsEntraConnected);
            ExportSyncedUsersCommand = new AsaRelayCommand(async _ => await ExportSyncedUsersAsync(), _ => !IsAnalyzing && IsEntraConnected);

            // Attack Path Detection commands
            RunAttackPathScanCommand = new AsaRelayCommand(async _ => await RunAttackPathScanAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            AuditLapsCommand = new AsaRelayCommand(async _ => await AuditLapsAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            FindGppPasswordsCommand = new AsaRelayCommand(async _ => await FindGppPasswordsAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            FindStaleAccountsCommand = new AsaRelayCommand(async _ => await FindStaleAccountsAsync(), _ => !IsAnalyzing && IsDomainDiscovered);

            // Security GPO Deployment commands
            DeployPrintNightmareGpoCommand = new AsaRelayCommand(async _ => await DeploySecurityGpoAsync("PrintNightmare"), _ => !IsAnalyzing && IsDomainDiscovered);
            DeployLlmnrDisableGpoCommand = new AsaRelayCommand(async _ => await DeploySecurityGpoAsync("LlmnrNbtns"), _ => !IsAnalyzing && IsDomainDiscovered);
            DeploySmbSigningGpoCommand = new AsaRelayCommand(async _ => await DeploySecurityGpoAsync("SmbSigning"), _ => !IsAnalyzing && IsDomainDiscovered);
            DeployCredentialGuardGpoCommand = new AsaRelayCommand(async _ => await DeploySecurityGpoAsync("CredentialGuard"), _ => !IsAnalyzing && IsDomainDiscovered);

            // AD Operations commands - Krbtgt, Replication, LAPS, SYSVOL
            ResetKrbtgtCommand = new AsaRelayCommand(async _ => await ResetKrbtgtAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            ForceReplicationCommand = new AsaRelayCommand(async _ => await ForceReplicationAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            ImplementLapsCommand = new AsaRelayCommand(async _ => await ImplementLapsAsync(), _ => !IsAnalyzing && IsDomainDiscovered);
            AuthoritativeSysvolRestoreCommand = new AsaRelayCommand(async _ => await AuthoritativeSysvolRestoreAsync(), _ => !IsAnalyzing && IsDomainDiscovered);

            // Initialize
            _ = InitializeAsync();
                    AuthoritativeSysvolRestoreCommand = new AsaRelayCommand(async _ => await AuthoritativeSysvolRestoreAsync(), _ => !IsAnalyzing && IsDomainDiscovered);

                    // PIM Assignment Management commands
                    GetPimAssignmentsCommand = new AsaRelayCommand(async _ => await GetPimAssignmentsAsync(), _ => !IsAnalyzing && IsEntraConnected);
                    CreatePimAssignmentCommand = new AsaRelayCommand(async _ => await CreatePimAssignmentAsync(), _ => !IsAnalyzing && IsEntraConnected && !string.IsNullOrWhiteSpace(PimNewPrincipalUpn) && !string.IsNullOrWhiteSpace(PimNewRoleName));

                    // App Registration command
                    CreateAppRegistrationCommand = new AsaRelayCommand(async _ => await CreateAppRegistrationAsync(), _ => !IsAnalyzing && IsEntraConnected && !string.IsNullOrWhiteSpace(AppRegistrationName));

                    // Initialize
                    _ = InitializeAsync();
        }

        #region Properties

        // Analysis State
        private bool _isAnalyzing;
        public bool IsAnalyzing
        {
            get => _isAnalyzing;
            set
            {
                if (SetProperty(ref _isAnalyzing, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        private bool _isDomainDiscovered;
        public bool IsDomainDiscovered
        {
            get => _isDomainDiscovered;
            set
            {
                if (SetProperty(ref _isDomainDiscovered, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        private string _status = "Ready. Click 'Discover Domain' to begin.";
        public string Status
        {
            get => _status;
            set => SetProperty(ref _status, value);
        }

        private double _progress;
        public double Progress
        {
            get => _progress;
            set => SetProperty(ref _progress, value);
        }

        private bool _isIndeterminate = true;
        public bool IsIndeterminate
        {
            get => _isIndeterminate;
            set => SetProperty(ref _isIndeterminate, value);
        }

        // Domain Info
        private string _targetDomain = string.Empty;
        public string TargetDomain
        {
            get => _targetDomain;
            set => SetProperty(ref _targetDomain, value);
        }

        private string _targetDc = string.Empty;
        public string TargetDc
        {
            get => _targetDc;
            set => SetProperty(ref _targetDc, value);
        }

        private AdDomainInfo? _domainInfo;
        public AdDomainInfo? DomainInfo
        {
            get => _domainInfo;
            set => SetProperty(ref _domainInfo, value);
        }

        // Analysis Options
        private bool _analyzePrivilegedGroups = true;
        public bool AnalyzePrivilegedGroups
        {
            get => _analyzePrivilegedGroups;
            set => SetProperty(ref _analyzePrivilegedGroups, value);
        }

        private bool _analyzeRiskyAcls = true;
        public bool AnalyzeRiskyAcls
        {
            get => _analyzeRiskyAcls;
            set => SetProperty(ref _analyzeRiskyAcls, value);
        }

        private bool _analyzeGpos = true;
        public bool AnalyzeGpos
        {
            get => _analyzeGpos;
            set => SetProperty(ref _analyzeGpos, value);
        }

        private bool _analyzeSysvol = true;
        public bool AnalyzeSysvol
        {
            get => _analyzeSysvol;
            set => SetProperty(ref _analyzeSysvol, value);
        }

        private bool _analyzeKerberosDelegation = true;
        public bool AnalyzeKerberosDelegation
        {
            get => _analyzeKerberosDelegation;
            set => SetProperty(ref _analyzeKerberosDelegation, value);
        }

        private bool _analyzeAdminCount = true;
        public bool AnalyzeAdminCount
        {
            get => _analyzeAdminCount;
            set => SetProperty(ref _analyzeAdminCount, value);
        }

        private bool _filterSafeIdentities = true;
        public bool FilterSafeIdentities
        {
            get => _filterSafeIdentities;
            set => SetProperty(ref _filterSafeIdentities, value);
        }

        private bool _includeForestMode;
        public bool IncludeForestMode
        {
            get => _includeForestMode;
            set => SetProperty(ref _includeForestMode, value);
        }

        // Deployment Options (BILL Model)
        private string _deploymentBaseName = "Admin";
        public string DeploymentBaseName
        {
            get => _deploymentBaseName;
            set => SetProperty(ref _deploymentBaseName, value);
        }

        private string _tier0Name = "Tier0";
        public string Tier0Name
        {
            get => _tier0Name;
            set => SetProperty(ref _tier0Name, value);
        }

        private string _tier1Name = "Tier1";
        public string Tier1Name
        {
            get => _tier1Name;
            set => SetProperty(ref _tier1Name, value);
        }

        private string _tier2Name = "Tier2";
        public string Tier2Name
        {
            get => _tier2Name;
            set => SetProperty(ref _tier2Name, value);
        }

        private bool _createPawOus = true;
        public bool CreatePawOus
        {
            get => _createPawOus;
            set => SetProperty(ref _createPawOus, value);
        }

        private bool _createServiceAccountOus = true;
        public bool CreateServiceAccountOus
        {
            get => _createServiceAccountOus;
            set => SetProperty(ref _createServiceAccountOus, value);
        }

        private bool _createGroupsOus = true;
        public bool CreateGroupsOus
        {
            get => _createGroupsOus;
            set => SetProperty(ref _createGroupsOus, value);
        }

        private bool _createUsersOus = true;
        public bool CreateUsersOus
        {
            get => _createUsersOus;
            set => SetProperty(ref _createUsersOus, value);
        }

        private bool _createDevicesOus = true;
        public bool CreateDevicesOus
        {
            get => _createDevicesOus;
            set => SetProperty(ref _createDevicesOus, value);
        }

        private bool _protectOusFromDeletion = true;
        public bool ProtectOusFromDeletion
        {
            get => _protectOusFromDeletion;
            set => SetProperty(ref _protectOusFromDeletion, value);
        }

        private bool _deployPasswordPolicyGpo = true;
        public bool DeployPasswordPolicyGpo
        {
            get => _deployPasswordPolicyGpo;
            set => SetProperty(ref _deployPasswordPolicyGpo, value);
        }

        private bool _deployAuditPolicyGpo = true;
        public bool DeployAuditPolicyGpo
        {
            get => _deployAuditPolicyGpo;
            set => SetProperty(ref _deployAuditPolicyGpo, value);
        }

        private bool _deploySecurityBaselineGpo = true;
        public bool DeploySecurityBaselineGpo
        {
            get => _deploySecurityBaselineGpo;
            set => SetProperty(ref _deploySecurityBaselineGpo, value);
        }

        private bool _deployPawGpo = true;
        public bool DeployPawGpo
        {
            get => _deployPawGpo;
            set => SetProperty(ref _deployPawGpo, value);
        }

        // === PLATYPUS/BILL Tiered GPO Properties ===

        // Tier 0 GPOs
        private bool _deployT0BaselineAudit;
        public bool DeployT0BaselineAudit
        {
            get => _deployT0BaselineAudit;
            set => SetProperty(ref _deployT0BaselineAudit, value);
        }

        private bool _deployT0DisallowDsrm;
        public bool DeployT0DisallowDsrm
        {
            get => _deployT0DisallowDsrm;
            set => SetProperty(ref _deployT0DisallowDsrm, value);
        }

        private bool _deployT0DomainBlock;
        public bool DeployT0DomainBlock
        {
            get => _deployT0DomainBlock;
            set => SetProperty(ref _deployT0DomainBlock, value);
        }

        private bool _deployT0DomainControllers;
        public bool DeployT0DomainControllers
        {
            get => _deployT0DomainControllers;
            set => SetProperty(ref _deployT0DomainControllers, value);
        }

        private bool _deployT0EsxAdmins;
        public bool DeployT0EsxAdmins
        {
            get => _deployT0EsxAdmins;
            set => SetProperty(ref _deployT0EsxAdmins, value);
        }

        private bool _deployT0UserRights;
        public bool DeployT0UserRights
        {
            get => _deployT0UserRights;
            set => SetProperty(ref _deployT0UserRights, value);
        }

        private bool _deployT0RestrictedGroups;
        public bool DeployT0RestrictedGroups
        {
            get => _deployT0RestrictedGroups;
            set => SetProperty(ref _deployT0RestrictedGroups, value);
        }

        // Tier 1 GPOs
        private bool _deployT1LocalAdmin;
        public bool DeployT1LocalAdmin
        {
            get => _deployT1LocalAdmin;
            set => SetProperty(ref _deployT1LocalAdmin, value);
        }

        private bool _deployT1UserRights;
        public bool DeployT1UserRights
        {
            get => _deployT1UserRights;
            set => SetProperty(ref _deployT1UserRights, value);
        }

        private bool _deployT1RestrictedGroups;
        public bool DeployT1RestrictedGroups
        {
            get => _deployT1RestrictedGroups;
            set => SetProperty(ref _deployT1RestrictedGroups, value);
        }

        // Tier 2 GPOs
        private bool _deployT2LocalAdmin;
        public bool DeployT2LocalAdmin
        {
            get => _deployT2LocalAdmin;
            set => SetProperty(ref _deployT2LocalAdmin, value);
        }

        private bool _deployT2UserRights;
        public bool DeployT2UserRights
        {
            get => _deployT2UserRights;
            set => SetProperty(ref _deployT2UserRights, value);
        }

        private bool _deployT2RestrictedGroups;
        public bool DeployT2RestrictedGroups
        {
            get => _deployT2RestrictedGroups;
            set => SetProperty(ref _deployT2RestrictedGroups, value);
        }

        // Cross-Tier GPOs
        private bool _deployDisableSmb1;
        public bool DeployDisableSmb1
        {
            get => _deployDisableSmb1;
            set => SetProperty(ref _deployDisableSmb1, value);
        }

        private bool _deployDisableWDigest;
        public bool DeployDisableWDigest
        {
            get => _deployDisableWDigest;
            set => SetProperty(ref _deployDisableWDigest, value);
        }

        private bool _deployResetMachinePassword;
        public bool DeployResetMachinePassword
        {
            get => _deployResetMachinePassword;
            set => SetProperty(ref _deployResetMachinePassword, value);
        }

        private bool _createTierGroups = true;
        public bool CreateTierGroups
        {
            get => _createTierGroups;
            set => SetProperty(ref _createTierGroups, value);
        }

        private bool _linkGposToOus;
        public bool LinkGposToOus
        {
            get => _linkGposToOus;
            set => SetProperty(ref _linkGposToOus, value);
        }

        // === MDE/MDI Proxy in a Box Properties ===
        private string _proxyTargetServer = string.Empty;
        public string ProxyTargetServer
        {
            get => _proxyTargetServer;
            set => SetProperty(ref _proxyTargetServer, value);
        }

        private string _proxyPort = "3128";
        public string ProxyPort
        {
            get => _proxyPort;
            set => SetProperty(ref _proxyPort, value);
        }

        private bool _proxyAllowSsh = true;
        public bool ProxyAllowSsh
        {
            get => _proxyAllowSsh;
            set => SetProperty(ref _proxyAllowSsh, value);
        }

        private bool _proxyIncludeMde = true;
        public bool ProxyIncludeMde
        {
            get => _proxyIncludeMde;
            set => SetProperty(ref _proxyIncludeMde, value);
        }

        private bool _proxyIncludeMdi = true;
        public bool ProxyIncludeMdi
        {
            get => _proxyIncludeMdi;
            set => SetProperty(ref _proxyIncludeMdi, value);
        }

        private string _proxyGeneratedScript = string.Empty;
        public string ProxyGeneratedScript
        {
            get => _proxyGeneratedScript;
            set => SetProperty(ref _proxyGeneratedScript, value);
        }

        private string _deploymentPreview = string.Empty;
        public string DeploymentPreview
        {
            get => _deploymentPreview;
            set => SetProperty(ref _deploymentPreview, value);
        }

        // Results
        private bool _hasResults;
        public bool HasResults
        {
            get => _hasResults;
            set
            {
                if (SetProperty(ref _hasResults, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        private int _totalFindings;
        public int TotalFindings
        {
            get => _totalFindings;
            set => SetProperty(ref _totalFindings, value);
        }

        private int _criticalFindings;
        public int CriticalFindings
        {
            get => _criticalFindings;
            set => SetProperty(ref _criticalFindings, value);
        }

        private int _highFindings;
        public int HighFindings
        {
            get => _highFindings;
            set => SetProperty(ref _highFindings, value);
        }

        private int _mediumFindings;
        public int MediumFindings
        {
            get => _mediumFindings;
            set => SetProperty(ref _mediumFindings, value);
        }

        private int _lowFindings;
        public int LowFindings
        {
            get => _lowFindings;
            set => SetProperty(ref _lowFindings, value);
        }

        private TimeSpan _analysisDuration;
        public TimeSpan AnalysisDuration
        {
            get => _analysisDuration;
            set => SetProperty(ref _analysisDuration, value);
        }

        private long? _currentRunId;
        public long? CurrentRunId
        {
            get => _currentRunId;
            set => SetProperty(ref _currentRunId, value);
        }

        // Collections
        public ObservableCollection<AdPrivilegedMember> PrivilegedMembers { get; }
        public ObservableCollection<AdRiskyAcl> RiskyAcls { get; }
        public ObservableCollection<AdRiskyGpo> RiskyGpos { get; }
        public ObservableCollection<SysvolRiskyFile> SysvolFiles { get; }
        public ObservableCollection<AdKerberosDelegation> KerberosDelegations { get; }
        public ObservableCollection<AdAdminCountAnomaly> AdminCountAnomalies { get; }
        public ObservableCollection<StoredAnalysisRun> AnalysisHistory { get; }
        public ObservableCollection<string> LogMessages { get; }
        public ObservableCollection<AdObjectCreationResult> DeploymentResults { get; }

        // Attack Path / Security Findings Collections
        public ObservableCollection<SecurityFinding> SecurityFindings { get; }
        public ObservableCollection<StaleAccountInfo> StaleUsers { get; }
        public ObservableCollection<StaleAccountInfo> StaleComputers { get; }
        public ObservableCollection<ComputerLapsStatus> ComputersWithoutLaps { get; }
        
        // Entra ID Collections
        public ObservableCollection<EntraIdPrivilegedRole> EntraPrivilegedRoles { get; }
        public ObservableCollection<EntraIdRiskyApp> EntraRiskyApps { get; }
        public ObservableCollection<EntraIdConditionalAccessPolicy> EntraConditionalAccessPolicies { get; }
        public ObservableCollection<EntraIdPimViolation> EntraPimViolations { get; }
        public ObservableCollection<EntraIdPimAssignment> EntraPimAssignments { get; }

        // Entra ID Properties
        private string _entraTenantId = string.Empty;
        public string EntraTenantId
        {
            get => _entraTenantId;
            set
            {
                if (SetProperty(ref _entraTenantId, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        private bool _isEntraConnected;
        public bool IsEntraConnected
        {
            get => _isEntraConnected;
            set
            {
                if (SetProperty(ref _isEntraConnected, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        private EntraIdTenant? _entraTenant;
        public EntraIdTenant? EntraTenant
        {
            get => _entraTenant;
            set => SetProperty(ref _entraTenant, value);
        }

        private bool _entraUsersOnly = false;
        public bool EntraUsersOnly
        {
            get => _entraUsersOnly;
            set => SetProperty(ref _entraUsersOnly, value);
        }

        private int _entraPrivilegedUserCount;
        public int EntraPrivilegedUserCount
        {
            get => _entraPrivilegedUserCount;
            set => SetProperty(ref _entraPrivilegedUserCount, value);
        }

        private int _entraRiskyAppCount;
        public int EntraRiskyAppCount
        {
            get => _entraRiskyAppCount;
            set => SetProperty(ref _entraRiskyAppCount, value);
        }

        private int _entraCaPolicyCount;
        public int EntraCaPolicyCount
        {
            get => _entraCaPolicyCount;
            set => SetProperty(ref _entraCaPolicyCount, value);
        }

        private int _entraPimViolationCount;
        public int EntraPimViolationCount
        {
            get => _entraPimViolationCount;
            set => SetProperty(ref _entraPimViolationCount, value);
        }

        // PIM Assignment Management properties
        private string _pimNewPrincipalUpn = string.Empty;
        public string PimNewPrincipalUpn
        {
            get => _pimNewPrincipalUpn;
            set
            {
                if (SetProperty(ref _pimNewPrincipalUpn, value))
                    CommandManager.InvalidateRequerySuggested();
            }
        }

        private string _pimNewRoleName = string.Empty;
        public string PimNewRoleName
        {
            get => _pimNewRoleName;
            set
            {
                if (SetProperty(ref _pimNewRoleName, value))
                    CommandManager.InvalidateRequerySuggested();
            }
        }

        private string _pimNewJustification = string.Empty;
        public string PimNewJustification
        {
            get => _pimNewJustification;
            set => SetProperty(ref _pimNewJustification, value);
        }

        private int _pimNewDurationDays = 365;
        public int PimNewDurationDays
        {
            get => _pimNewDurationDays;
            set => SetProperty(ref _pimNewDurationDays, value);
        }

        private string _pimAssignmentFilter = "All";
        public string PimAssignmentFilter
        {
            get => _pimAssignmentFilter;
            set => SetProperty(ref _pimAssignmentFilter, value);
        }

        // App Registration properties
        private string _appRegistrationName = "SecKey CSM PowerShell Tool";
        public string AppRegistrationName
        {
            get => _appRegistrationName;
            set
            {
                if (SetProperty(ref _appRegistrationName, value))
                    CommandManager.InvalidateRequerySuggested();
            }
        }

        private string _appRegistrationResultText = string.Empty;
        public string AppRegistrationResultText
        {
            get => _appRegistrationResultText;
            set => SetProperty(ref _appRegistrationResultText, value);
        }

        private bool _appRegistrationSuccess;
        public bool AppRegistrationSuccess
        {
            get => _appRegistrationSuccess;
            set => SetProperty(ref _appRegistrationSuccess, value);
        }

        private StoredAnalysisRun? _selectedHistoryRun;
        public StoredAnalysisRun? SelectedHistoryRun
        {
            get => _selectedHistoryRun;
            set
            {
                if (SetProperty(ref _selectedHistoryRun, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        // Selected Items for Detail View
        private AdPrivilegedMember? _selectedPrivilegedMember;
        public AdPrivilegedMember? SelectedPrivilegedMember
        {
            get => _selectedPrivilegedMember;
            set => SetProperty(ref _selectedPrivilegedMember, value);
        }

        private AdRiskyAcl? _selectedRiskyAcl;
        public AdRiskyAcl? SelectedRiskyAcl
        {
            get => _selectedRiskyAcl;
            set => SetProperty(ref _selectedRiskyAcl, value);
        }

        private AdKerberosDelegation? _selectedDelegation;
        public AdKerberosDelegation? SelectedDelegation
        {
            get => _selectedDelegation;
            set => SetProperty(ref _selectedDelegation, value);
        }

        #endregion

        #region Commands

        public ICommand DiscoverDomainCommand { get; }
        public ICommand RunFullAnalysisCommand { get; }
        public ICommand RunPrivilegedAnalysisCommand { get; }
        public ICommand RunAclAnalysisCommand { get; }
        public ICommand RunDelegationAnalysisCommand { get; }
        public ICommand RunSysvolAnalysisCommand { get; }
        public ICommand CancelAnalysisCommand { get; }
        public ICommand ExportToCsvCommand { get; }
        public ICommand ExportSelectedRunCommand { get; }
        public ICommand LoadHistoryCommand { get; }
        public ICommand LoadSelectedRunCommand { get; }
        public ICommand DeleteSelectedRunCommand { get; }
        public ICommand ClearHistoryCommand { get; }
        public ICommand ClearLogCommand { get; }
        public ICommand OpenDatabaseFolderCommand { get; }

        // Deployment Commands
        public ICommand DeployTieredOusCommand { get; }
        public ICommand DeployBaselineGposCommand { get; }
        public ICommand PreviewDeploymentCommand { get; }
        public ICommand ClearDeploymentResultsCommand { get; }

        // MDE/MDI Proxy in a Box Commands
        public ICommand GenerateProxyScriptCommand { get; }
        public ICommand CopyProxyScriptCommand { get; }
        public ICommand SaveProxyScriptCommand { get; }

        // Entra ID (Azure AD) Commands - PLATYPUS Azure Analysis
        public ICommand ConnectEntraIdCommand { get; }
        public ICommand DisconnectEntraIdCommand { get; }
        public ICommand RunEntraAnalysisCommand { get; }
        public ICommand GetEntraPrivilegedRolesCommand { get; }
        public ICommand GetEntraRiskyAppsCommand { get; }
        public ICommand GetEntraCaPoliciesCommand { get; }
        public ICommand GetEntraPimViolationsCommand { get; }

        // Remediation / Takeback Commands - PLATYPUS IR Operations
        public ICommand TakebackTenantCommand { get; }
        public ICommand MassPasswordResetCommand { get; }
        public ICommand RevokeAllTokensCommand { get; }
        public ICommand RemovePrivRoleMembersCommand { get; }
        public ICommand RemoveAdminCountCommand { get; }

        // Additional Entra IR Commands
        public ICommand RemoveAppOwnersCommand { get; }
        public ICommand DisableCaPoliciesCommand { get; }
        public ICommand DeployIrCaPoliciesCommand { get; }
        public ICommand ExportSyncedUsersCommand { get; }

        // Attack Path Detection Commands
        public ICommand RunAttackPathScanCommand { get; }
        public ICommand AuditLapsCommand { get; }
        public ICommand FindGppPasswordsCommand { get; }
        public ICommand FindStaleAccountsCommand { get; }

        // Security GPO Deployment Commands
        public ICommand DeployPrintNightmareGpoCommand { get; }
        public ICommand DeployLlmnrDisableGpoCommand { get; }
        public ICommand DeploySmbSigningGpoCommand { get; }
        public ICommand DeployCredentialGuardGpoCommand { get; }

        // AD Operations Commands - Krbtgt, Replication, LAPS, SYSVOL
        public ICommand ResetKrbtgtCommand { get; }
        public ICommand ForceReplicationCommand { get; }
        public ICommand ImplementLapsCommand { get; }
        public ICommand AuthoritativeSysvolRestoreCommand { get; }

        // PIM Assignment Management Commands
        public ICommand GetPimAssignmentsCommand { get; }
        public ICommand CreatePimAssignmentCommand { get; }

        // App Registration Command
        public ICommand CreateAppRegistrationCommand { get; }

        #endregion

        #region Initialization

        private async Task InitializeAsync()
        {
            try
            {
                await _databaseService.InitializeAsync();
                AppendLog($"Database initialized: {_databaseService.DatabasePath}");
                await LoadHistoryAsync();
            }
            catch (Exception ex)
            {
                AppendLog($"Error initializing database: {ex.Message}");
            }
        }

        #endregion

        #region Domain Discovery

        private async Task DiscoverDomainAsync()
        {
            IsAnalyzing = true;
            Status = "Discovering Active Directory domain...";
            ClearResults();

            try
            {
                _cts = new CancellationTokenSource();

                DomainInfo = await _analysisService.DiscoverDomainAsync(
                    string.IsNullOrWhiteSpace(TargetDomain) ? null : TargetDomain,
                    string.IsNullOrWhiteSpace(TargetDc) ? null : TargetDc,
                    _cts.Token);

                if (!string.IsNullOrEmpty(DomainInfo?.ChosenDc))
                {
                    IsDomainDiscovered = true;
                    Status = $"Connected to {DomainInfo.DomainFqdn} via {DomainInfo.ChosenDc}";
                    AppendLog($"Domain: {DomainInfo.DomainFqdn}");
                    AppendLog($"Domain Controller: {DomainInfo.ChosenDc}");
                    AppendLog($"PDC Emulator: {DomainInfo.PdcEmulator}");
                    AppendLog($"AD Recycle Bin: {(DomainInfo.IsAdRecycleBinEnabled ? "Enabled" : "Disabled")}");
                    AppendLog($"SYSVOL: {DomainInfo.SysvolReplicationInfo}");
                }
                else
                {
                    IsDomainDiscovered = false;
                    Status = "Could not connect to domain. Check domain name and credentials.";
                }
            }
            catch (OperationCanceledException)
            {
                Status = "Discovery cancelled.";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        #endregion

        #region Analysis Methods

        private async Task RunFullAnalysisAsync()
        {
            IsAnalyzing = true;
            Status = "Running full security analysis...";
            ClearResults();

            try
            {
                _cts = new CancellationTokenSource();

                var options = new AdSecurityAnalysisOptions
                {
                    AnalyzePrivilegedGroups = AnalyzePrivilegedGroups,
                    AnalyzeRiskyAcls = AnalyzeRiskyAcls,
                    AnalyzeGpos = AnalyzeGpos,
                    AnalyzeSysvol = AnalyzeSysvol,
                    AnalyzeKerberosDelegation = AnalyzeKerberosDelegation,
                    AnalyzeAdminCount = AnalyzeAdminCount,
                    FilterSafeIdentities = FilterSafeIdentities,
                    IncludeForestMode = IncludeForestMode,
                    TargetDomain = string.IsNullOrWhiteSpace(TargetDomain) ? null : TargetDomain,
                    TargetDc = string.IsNullOrWhiteSpace(TargetDc) ? null : TargetDc
                };

                var result = await _analysisService.RunFullAnalysisAsync(options, _cts.Token);
                
                // Update UI
                await Application.Current.Dispatcher.InvokeAsync(() => PopulateResults(result));

                // Save to database
                CurrentRunId = await _databaseService.SaveAnalysisAsync(result);
                AppendLog($"Analysis saved to database (Run ID: {CurrentRunId})");

                // Refresh history
                await LoadHistoryAsync();

                Status = $"Analysis complete. Found {result.TotalFindings} findings in {result.Duration.TotalSeconds:F1}s";
            }
            catch (OperationCanceledException)
            {
                Status = "Analysis cancelled.";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        private async Task RunPrivilegedAnalysisAsync()
        {
            IsAnalyzing = true;
            Status = "Analyzing privileged group memberships...";

            try
            {
                _cts = new CancellationTokenSource();
                var members = await _analysisService.GetPrivilegedMembersAsync(IncludeForestMode, _cts.Token);

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    PrivilegedMembers.Clear();
                    foreach (var m in members)
                    {
                        PrivilegedMembers.Add(m);
                    }
                    HasResults = members.Count > 0;
                });

                Status = $"Found {members.Count} privileged accounts";
                AppendLog($"Privileged members: {members.Count}");
            }
            catch (OperationCanceledException)
            {
                Status = "Analysis cancelled.";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        private async Task RunAclAnalysisAsync()
        {
            IsAnalyzing = true;
            Status = "Analyzing ACLs on sensitive objects...";

            try
            {
                _cts = new CancellationTokenSource();
                var acls = await _analysisService.GetRiskyAclsAsync(FilterSafeIdentities, null, _cts.Token);

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    RiskyAcls.Clear();
                    foreach (var a in acls)
                    {
                        RiskyAcls.Add(a);
                    }
                    HasResults = acls.Count > 0;
                });

                Status = $"Found {acls.Count} ACLs of interest";
                AppendLog($"ACLs of Interest: {acls.Count}");
            }
            catch (OperationCanceledException)
            {
                Status = "Analysis cancelled.";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        private async Task RunDelegationAnalysisAsync()
        {
            IsAnalyzing = true;
            Status = "Analyzing Kerberos delegation...";

            try
            {
                _cts = new CancellationTokenSource();
                var delegations = await _analysisService.GetKerberosDelegationsAsync(_cts.Token);

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    KerberosDelegations.Clear();
                    foreach (var d in delegations)
                    {
                        KerberosDelegations.Add(d);
                    }
                    HasResults = delegations.Count > 0;
                });

                Status = $"Found {delegations.Count} accounts with delegation";
                AppendLog($"Kerberos delegations: {delegations.Count}");
            }
            catch (OperationCanceledException)
            {
                Status = "Analysis cancelled.";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        private async Task RunSysvolAnalysisAsync()
        {
            IsAnalyzing = true;
            Status = "Scanning SYSVOL for risky files...";

            try
            {
                _cts = new CancellationTokenSource();
                var files = await _analysisService.ScanSysvolAsync(_cts.Token);

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    SysvolFiles.Clear();
                    foreach (var f in files)
                    {
                        SysvolFiles.Add(f);
                    }
                    HasResults = files.Count > 0;
                });

                Status = $"Found {files.Count} risky files in SYSVOL";
                AppendLog($"SYSVOL files: {files.Count}");
            }
            catch (OperationCanceledException)
            {
                Status = "Analysis cancelled.";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        private void CancelAnalysis()
        {
            _cts?.Cancel();
            Status = "Cancelling...";
        }

        #endregion

        #region Results Management

        private void PopulateResults(AdSecurityAnalysisResult result)
        {
            DomainInfo = result.DomainInfo;

            PrivilegedMembers.Clear();
            foreach (var m in result.PrivilegedMembers)
                PrivilegedMembers.Add(m);

            RiskyAcls.Clear();
            foreach (var a in result.RiskyAcls)
                RiskyAcls.Add(a);

            RiskyGpos.Clear();
            foreach (var g in result.RiskyGpos)
                RiskyGpos.Add(g);

            SysvolFiles.Clear();
            foreach (var f in result.SysvolRiskyFiles)
                SysvolFiles.Add(f);

            KerberosDelegations.Clear();
            foreach (var d in result.KerberosDelegations)
                KerberosDelegations.Add(d);

            AdminCountAnomalies.Clear();
            foreach (var a in result.AdminCountAnomalies)
                AdminCountAnomalies.Add(a);

            TotalFindings = result.TotalFindings;
            CriticalFindings = result.CriticalCount;
            HighFindings = result.HighCount;
            MediumFindings = result.MediumCount;
            LowFindings = result.LowCount;
            AnalysisDuration = result.Duration;
            HasResults = result.TotalFindings > 0;
        }

        private void ClearResults()
        {
            PrivilegedMembers.Clear();
            RiskyAcls.Clear();
            RiskyGpos.Clear();
            SysvolFiles.Clear();
            KerberosDelegations.Clear();
            AdminCountAnomalies.Clear();
            TotalFindings = 0;
            CriticalFindings = 0;
            HighFindings = 0;
            MediumFindings = 0;
            LowFindings = 0;
            HasResults = false;
            CurrentRunId = null;
        }

        #endregion

        #region Export Methods

        private async Task ExportToCsvAsync()
        {
            if (!CurrentRunId.HasValue)
            {
                MessageBox.Show("No analysis to export. Run an analysis first.", "Export", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dialog = new OpenFolderDialog
            {
                Title = "Select folder for CSV export"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    await _databaseService.ExportToCsvAsync(CurrentRunId.Value, dialog.FolderName);
                    Status = $"Exported to {dialog.FolderName}";
                    AppendLog($"Export complete: {dialog.FolderName}");

                    // Open folder
                    Process.Start("explorer.exe", dialog.FolderName);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async Task ExportSelectedRunAsync()
        {
            if (SelectedHistoryRun == null) return;

            var dialog = new OpenFolderDialog
            {
                Title = "Select folder for CSV export"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    await _databaseService.ExportToCsvAsync(SelectedHistoryRun.Id, dialog.FolderName);
                    Status = $"Exported run {SelectedHistoryRun.Id} to {dialog.FolderName}";
                    AppendLog($"Export complete: {dialog.FolderName}");

                    Process.Start("explorer.exe", dialog.FolderName);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        #endregion

        #region History Management

        private async Task LoadHistoryAsync()
        {
            try
            {
                var history = await _databaseService.GetAnalysisHistoryAsync();
                
                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    AnalysisHistory.Clear();
                    foreach (var run in history)
                    {
                        AnalysisHistory.Add(run);
                    }
                });
            }
            catch (Exception ex)
            {
                AppendLog($"Error loading history: {ex.Message}");
            }
        }

        private async Task LoadSelectedRunAsync()
        {
            if (SelectedHistoryRun == null) return;

            try
            {
                Status = $"Loading analysis run {SelectedHistoryRun.Id}...";
                var result = await _databaseService.GetAnalysisResultAsync(SelectedHistoryRun.Id);

                if (result != null)
                {
                    await Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        PopulateResults(result);
                        CurrentRunId = SelectedHistoryRun.Id;
                        IsDomainDiscovered = true;
                    });

                    Status = $"Loaded analysis from {SelectedHistoryRun.RunTime:g}";
                }
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error loading run: {ex.Message}");
            }
        }

        private async Task DeleteSelectedRunAsync()
        {
            if (SelectedHistoryRun == null) return;

            var result = MessageBox.Show(
                $"Delete analysis run from {SelectedHistoryRun.RunTime:g}?",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    await _databaseService.DeleteAnalysisRunAsync(SelectedHistoryRun.Id);
                    await LoadHistoryAsync();
                    Status = "Analysis run deleted.";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Delete failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async Task ClearHistoryAsync()
        {
            var result = MessageBox.Show(
                "Delete ALL analysis history? This cannot be undone.",
                "Confirm Clear History",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    await _databaseService.ClearAllHistoryAsync();
                    await LoadHistoryAsync();
                    ClearResults();
                    Status = "All history cleared.";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Clear failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void OpenDatabaseFolder()
        {
            var folder = Path.GetDirectoryName(_databaseService.DatabasePath);
            if (!string.IsNullOrEmpty(folder) && Directory.Exists(folder))
            {
                Process.Start("explorer.exe", folder);
            }
        }

        #endregion

        #region Logging

        private void AppendLog(string message)
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            var entry = $"[{timestamp}] {message}";

            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                LogMessages.Add(entry);
                
                // Keep log size manageable
                while (LogMessages.Count > 1000)
                {
                    LogMessages.RemoveAt(0);
                }
            });
        }

        #endregion

        #region Deployment Methods

        private void PreviewDeployment()
        {
            var preview = new System.Text.StringBuilder();
            preview.AppendLine("=== OU Structure Preview ===");
            preview.AppendLine();
            
            if (DomainInfo != null)
            {
                preview.AppendLine($"Target Domain: {DomainInfo.DomainFqdn}");
                preview.AppendLine($"Domain DN: {DomainInfo.DomainDn}");
                preview.AppendLine();
            }

            preview.AppendLine($"OU={DeploymentBaseName},{DomainInfo?.DomainDn ?? "DC=domain,DC=local"}");
            preview.AppendLine($"  ├── OU={Tier0Name}");
            if (CreatePawOus) preview.AppendLine($"  │   ├── OU=SecureKeyboard");
            if (CreateServiceAccountOus) preview.AppendLine($"  │   ├── OU=ServiceAccounts");
            if (CreateGroupsOus) preview.AppendLine($"  │   ├── OU=Groups");
            if (CreateUsersOus) preview.AppendLine($"  │   └── OU=Users");
            
            preview.AppendLine($"  ├── OU={Tier1Name}");
            if (CreatePawOus) preview.AppendLine($"  │   ├── OU=SecureKeyboard");
            if (CreateServiceAccountOus) preview.AppendLine($"  │   ├── OU=ServiceAccounts");
            if (CreateGroupsOus) preview.AppendLine($"  │   ├── OU=Groups");
            if (CreateUsersOus) preview.AppendLine($"  │   ├── OU=Users");
            if (CreateDevicesOus) preview.AppendLine($"  │   └── OU=Servers");
            
            preview.AppendLine($"  └── OU={Tier2Name}");
            if (CreatePawOus) preview.AppendLine($"      ├── OU=SecureKeyboard");
            if (CreateServiceAccountOus) preview.AppendLine($"      ├── OU=ServiceAccounts");
            if (CreateGroupsOus) preview.AppendLine($"      ├── OU=Groups");
            if (CreateUsersOus) preview.AppendLine($"      ├── OU=Users");
            if (CreateDevicesOus) preview.AppendLine($"      └── OU=Workstations");

            preview.AppendLine();
            preview.AppendLine("=== GPO Preview ===");
            preview.AppendLine();

            // Quick Deploy GPOs
            if (DeployPasswordPolicyGpo || DeployAuditPolicyGpo || DeploySecurityBaselineGpo || DeployPawGpo)
            {
                preview.AppendLine("[Quick Deploy GPOs]");
                if (DeployPasswordPolicyGpo) preview.AppendLine("  • Password Policy GPO (linked to domain)");
                if (DeployAuditPolicyGpo) preview.AppendLine("  • Advanced Audit Policy GPO (linked to domain)");
                if (DeploySecurityBaselineGpo) preview.AppendLine("  • Security Baseline GPO (linked to each tier)");
                if (DeployPawGpo) preview.AppendLine("  • SecureKeyboard Security GPO (linked to SecureKeyboard OUs)");
                preview.AppendLine();
            }

            // Tier 0 GPOs
            if (DeployT0BaselineAudit || DeployT0DisallowDsrm || DeployT0DomainBlock || 
                DeployT0DomainControllers || DeployT0EsxAdmins || DeployT0UserRights || DeployT0RestrictedGroups)
            {
                preview.AppendLine("[Tier 0 GPOs - Domain Controllers / Critical Servers]");
                if (DeployT0BaselineAudit) preview.AppendLine("  • Tier 0 - Baseline Audit Policies - Tier 0 Servers");
                if (DeployT0DisallowDsrm) preview.AppendLine("  • Tier 0 - Disallow DSRM Login - DC ONLY");
                if (DeployT0DomainBlock) preview.AppendLine("  • Tier 0 - Admin Block - Top Level");
                if (DeployT0DomainControllers) preview.AppendLine("  • Tier 0 - Domain Controllers - DC Only");
                if (DeployT0EsxAdmins) preview.AppendLine("  • Tier 0 - ESX Admins Restricted Group - DC Only");
                if (DeployT0UserRights) preview.AppendLine("  • Tier 0 - User Rights Assignments - Tier 0 Servers");
                if (DeployT0RestrictedGroups) preview.AppendLine("  • Tier 0 - Restricted Groups - Tier 0 Servers");
                preview.AppendLine();
            }

            // Tier 1 GPOs
            if (DeployT1LocalAdmin || DeployT1UserRights || DeployT1RestrictedGroups)
            {
                preview.AppendLine("[Tier 1 GPOs - Servers]");
                if (DeployT1LocalAdmin) preview.AppendLine("  • Tier 1 - Tier 1 Operators in Local Admin - Tier 1 Servers");
                if (DeployT1UserRights) preview.AppendLine("  • Tier 1 - User Rights Assignments - Tier 1 Servers");
                if (DeployT1RestrictedGroups) preview.AppendLine("  • Tier 1 - Restricted Groups - Tier 1 Servers");
                preview.AppendLine();
            }

            // Tier 2 GPOs
            if (DeployT2LocalAdmin || DeployT2UserRights || DeployT2RestrictedGroups)
            {
                preview.AppendLine("[Tier 2 GPOs - Workstations]");
                if (DeployT2LocalAdmin) preview.AppendLine("  • Tier 2 - Tier 2 Operators in Local Admin - Tier 2 Devices");
                if (DeployT2UserRights) preview.AppendLine("  • Tier 2 - User Rights Assignments - Tier 2 Devices");
                if (DeployT2RestrictedGroups) preview.AppendLine("  • Tier 2 - Restricted Groups - Tier 2 Devices");
                preview.AppendLine();
            }

            // Cross-Tier GPOs
            if (DeployDisableSmb1 || DeployDisableWDigest || DeployResetMachinePassword)
            {
                preview.AppendLine("[Cross-Tier GPOs - All Devices]");
                if (DeployDisableSmb1) preview.AppendLine("  • Tier ALL - Disable SMBv1 - Top Level");
                if (DeployDisableWDigest) preview.AppendLine("  • Tier ALL - Disable WDigest - Top Level");
                if (DeployResetMachinePassword) preview.AppendLine("  • PLATYPUS - Reset Machine Account Password");
                preview.AppendLine();
            }

            // Security Groups
            if (CreateTierGroups)
            {
                preview.AppendLine("[Security Groups]");
                preview.AppendLine("  Tier 0:");
                preview.AppendLine("    • Tier 0 - Operators");
                preview.AppendLine("    • Tier 0 - PAW Users");
                preview.AppendLine("    • Tier 0 - Service Accounts");
                preview.AppendLine("    • IR - Emergency Access");
                preview.AppendLine("    • DVRL - Deny Logon All Tiers");
                preview.AppendLine("  Tier 1:");
                preview.AppendLine("    • Tier 1 - Operators");
                preview.AppendLine("    • Tier 1 - PAW Users");
                preview.AppendLine("    • Tier 1 - Service Accounts");
                preview.AppendLine("    • Tier 1 - Server Local Admins");
                preview.AppendLine("  Tier 2:");
                preview.AppendLine("    • Tier 2 - Operators");
                preview.AppendLine("    • Tier 2 - PAW Users");
                preview.AppendLine("    • Tier 2 - Service Accounts");
                preview.AppendLine("    • Tier 2 - Workstation Local Admins");
                preview.AppendLine();
            }

            preview.AppendLine($"Protection from deletion: {(ProtectOusFromDeletion ? "Enabled" : "Disabled")}");
            preview.AppendLine($"Link GPOs to OUs: {(LinkGposToOus ? "Enabled" : "Disabled")}");

            DeploymentPreview = preview.ToString();
        }

        #endregion

        #region MDE/MDI Proxy in a Box Methods

        private void GenerateProxyScript()
        {
            var script = new System.Text.StringBuilder();
            var port = string.IsNullOrWhiteSpace(ProxyPort) ? "3128" : ProxyPort.Trim();

            script.AppendLine("#!/bin/bash");
            script.AppendLine();
            script.AppendLine("###############################################################################");
            script.AppendLine("# MDE/MDI Proxy in a Box - Squid Proxy Setup");
            script.AppendLine("# Generated by PlatypusTools");
            script.AppendLine("# Based on: https://github.com/mswillsykes/squidmdemdi");
            script.AppendLine("#");
            script.AppendLine("# Purpose: Deploy a Squid proxy for Microsoft Defender for Endpoint (MDE)");
            script.AppendLine("#          and Microsoft Defender for Identity (MDI) in air-gapped environments");
            script.AppendLine("###############################################################################");
            script.AppendLine();
            script.AppendLine("set -e");
            script.AppendLine();
            script.AppendLine("# Install Squid");
            script.AppendLine("echo \"[+] Installing Squid proxy...\"");
            script.AppendLine("sudo apt update");
            script.AppendLine("sudo apt install -y squid");
            script.AppendLine();
            script.AppendLine("# Configure UFW firewall");
            script.AppendLine("echo \"[+] Configuring firewall...\"");
            
            if (ProxyAllowSsh)
            {
                script.AppendLine("sudo ufw allow 22/tcp      # SSH");
            }
            
            script.AppendLine($"sudo ufw allow {port}/tcp   # Squid Proxy");
            script.AppendLine("sudo ufw --force enable");
            script.AppendLine();
            
            script.AppendLine("# Create MDE/MDI endpoint whitelist configuration");
            script.AppendLine("echo \"[+] Creating endpoint whitelist...\"");
            script.AppendLine("sudo tee /etc/squid/mdemdi.conf > /dev/null << 'ENDPOINTS'");
            
            // MDE Endpoints
            if (ProxyIncludeMde)
            {
                script.AppendLine("# Microsoft Defender for Endpoint (MDE) URLs");
                script.AppendLine(".wdcp.microsoft.com");
                script.AppendLine(".wdcpalt.microsoft.com");
                script.AppendLine(".wd.microsoft.com");
                script.AppendLine(".update.microsoft.com");
                script.AppendLine(".download.microsoft.com");
                script.AppendLine(".download.windowsupdate.com");
                script.AppendLine(".security.microsoft.com");
                script.AppendLine(".securitycenter.windows.com");
                script.AppendLine(".securitycenter.microsoft.com");
                script.AppendLine(".blob.core.windows.net");
                script.AppendLine(".events.data.microsoft.com");
                script.AppendLine(".windowsupdate.com");
                script.AppendLine(".go.microsoft.com");
                script.AppendLine(".channel.api.security.microsoft.com");
                script.AppendLine(".data.microsoft.com");
            }
            
            // MDI Endpoints
            if (ProxyIncludeMdi)
            {
                script.AppendLine("# Microsoft Defender for Identity (MDI) URLs");
                script.AppendLine(".atp.azure.com");
                script.AppendLine(".login.microsoftonline.com");
                script.AppendLine(".login.windows.net");
                script.AppendLine(".aadrm.com");
                script.AppendLine(".aadcdn.msftauth.net");
                script.AppendLine(".aadcdn.msftauthimages.net");
                script.AppendLine(".aadcdn.msauthimages.net");
                script.AppendLine(".microsoft.com");
                script.AppendLine(".ods.opinsights.azure.com");
                script.AppendLine(".oms.opinsights.azure.com");
                script.AppendLine(".azure-automation.net");
                script.AppendLine(".dc.services.visualstudio.com");
            }
            
            script.AppendLine("ENDPOINTS");
            script.AppendLine();
            
            script.AppendLine("# Create Squid configuration");
            script.AppendLine("echo \"[+] Configuring Squid...\"");
            script.AppendLine("sudo tee /etc/squid/squid.conf > /dev/null << 'SQUIDCONF'");
            script.AppendLine("# MDE/MDI Proxy Configuration - Generated by PlatypusTools");
            script.AppendLine();
            script.AppendLine("# ACL definitions for RFC 1918 private networks (internal clients)");
            script.AppendLine("acl localnet src 10.0.0.0/8");
            script.AppendLine("acl localnet src 172.16.0.0/12");
            script.AppendLine("acl localnet src 192.168.0.0/16");
            script.AppendLine("acl localnet src fc00::/7");
            script.AppendLine("acl localnet src fe80::/10");
            script.AppendLine();
            script.AppendLine("# ACL for SSL ports");
            script.AppendLine("acl SSL_ports port 443");
            script.AppendLine("acl Safe_ports port 80");
            script.AppendLine("acl Safe_ports port 443");
            script.AppendLine("acl Safe_ports port 1025-65535");
            script.AppendLine("acl CONNECT method CONNECT");
            script.AppendLine();
            script.AppendLine("# MDE/MDI whitelist");
            script.AppendLine("acl mdemdi dstdomain \"/etc/squid/mdemdi.conf\"");
            script.AppendLine();
            script.AppendLine("# Deny access to non-safe ports");
            script.AppendLine("http_access deny !Safe_ports");
            script.AppendLine("http_access deny CONNECT !SSL_ports");
            script.AppendLine();
            script.AppendLine("# Only allow internal networks to whitelisted endpoints");
            script.AppendLine("http_access allow localnet mdemdi");
            script.AppendLine("http_access allow localhost mdemdi");
            script.AppendLine();
            script.AppendLine("# Deny everything else");
            script.AppendLine("http_access deny all");
            script.AppendLine();
            script.AppendLine($"# Listen on port {port}");
            script.AppendLine($"http_port {port}");
            script.AppendLine();
            script.AppendLine("# Performance tuning");
            script.AppendLine("cache_mem 256 MB");
            script.AppendLine("maximum_object_size_in_memory 512 KB");
            script.AppendLine("cache_dir ufs /var/spool/squid 100 16 256");
            script.AppendLine();
            script.AppendLine("# Logging");
            script.AppendLine("access_log /var/log/squid/access.log squid");
            script.AppendLine("cache_log /var/log/squid/cache.log");
            script.AppendLine();
            script.AppendLine("# Disable via header for privacy");
            script.AppendLine("via off");
            script.AppendLine("forwarded_for off");
            script.AppendLine("SQUIDCONF");
            script.AppendLine();
            
            script.AppendLine("# Restart Squid to apply configuration");
            script.AppendLine("echo \"[+] Restarting Squid service...\"");
            script.AppendLine("sudo systemctl restart squid");
            script.AppendLine("sudo systemctl enable squid");
            script.AppendLine();
            script.AppendLine("# Verify Squid is running");
            script.AppendLine("echo \"[+] Verifying Squid status...\"");
            script.AppendLine("sudo systemctl status squid --no-pager");
            script.AppendLine();
            script.AppendLine("echo \"\"");
            script.AppendLine("echo \"###############################################################################\"");
            script.AppendLine("echo \"# MDE/MDI Proxy Setup Complete!\"");
            script.AppendLine($"echo \"# Proxy is listening on port {port}\"");
            script.AppendLine("echo \"#\"");
            script.AppendLine("echo \"# Configure clients to use this proxy:\"");
            script.AppendLine("echo \"#   Windows: Set proxy in IE settings or via GPO\"");
            script.AppendLine("echo \"#   Linux:   export https_proxy=http://<proxy-ip>:" + port + "\"");
            script.AppendLine("echo \"###############################################################################\"");
            
            ProxyGeneratedScript = script.ToString();
            CommandManager.InvalidateRequerySuggested();
            
            AppendLog($"Generated MDE/MDI proxy script (Port: {port}, MDE: {ProxyIncludeMde}, MDI: {ProxyIncludeMdi})");
        }

        private void CopyProxyScriptToClipboard()
        {
            if (string.IsNullOrEmpty(ProxyGeneratedScript))
            {
                MessageBox.Show("No script generated yet. Click 'Generate Script' first.", "No Script", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                Clipboard.SetText(ProxyGeneratedScript);
                MessageBox.Show("Script copied to clipboard!", "Copied", MessageBoxButton.OK, MessageBoxImage.Information);
                AppendLog("Proxy script copied to clipboard.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to copy to clipboard: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveProxyScriptToFile()
        {
            if (string.IsNullOrEmpty(ProxyGeneratedScript))
            {
                MessageBox.Show("No script generated yet. Click 'Generate Script' first.", "No Script", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var saveDialog = new SaveFileDialog
            {
                Filter = "Shell Script (*.sh)|*.sh|All Files (*.*)|*.*",
                DefaultExt = ".sh",
                FileName = "setup-mdemdi-proxy.sh",
                Title = "Save Proxy Setup Script"
            };

            if (saveDialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllText(saveDialog.FileName, ProxyGeneratedScript);
                    MessageBox.Show($"Script saved to:\n{saveDialog.FileName}", "Saved", MessageBoxButton.OK, MessageBoxImage.Information);
                    AppendLog($"Proxy script saved to: {saveDialog.FileName}");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to save script: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        #endregion

        #region OU Deployment Methods

        private async Task DeployTieredOusAsync()
        {
            if (DomainInfo == null)
            {
                MessageBox.Show("Please discover the domain first.", "Domain Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var confirm = MessageBox.Show(
                $"Create tiered admin OU structure in {DomainInfo.DomainFqdn}?\n\n" +
                "This will create:\n" +
                $"• {DeploymentBaseName} (base OU)\n" +
                $"• {Tier0Name}, {Tier1Name}, {Tier2Name} (tier OUs)\n" +
                "• Sub-OUs for PAW, ServiceAccounts, Groups, Users, Devices\n\n" +
                "Continue?",
                "Confirm OU Deployment",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (confirm != MessageBoxResult.Yes) return;

            IsAnalyzing = true;
            Status = "Deploying tiered OU structure...";

            try
            {
                _cts = new CancellationTokenSource();
                DeploymentResults.Clear();

                var template = new BillOuTemplate
                {
                    BaseName = DeploymentBaseName,
                    Tier0Name = Tier0Name,
                    Tier1Name = Tier1Name,
                    Tier2Name = Tier2Name,
                    CreatePawOus = CreatePawOus,
                    CreateServiceAccountOus = CreateServiceAccountOus,
                    CreateGroupsOus = CreateGroupsOus
                };

                var results = await _analysisService.DeployTieredOuStructureAsync(
                    template, 
                    ProtectOusFromDeletion,
                    CreateUsersOus,
                    CreateDevicesOus,
                    _cts.Token);

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    foreach (var r in results)
                    {
                        DeploymentResults.Add(r);
                        AppendLog($"{(r.Success ? "✓" : "✗")} {r.ObjectType}: {r.ObjectName} - {r.Message}");
                    }
                });

                var successCount = results.Count(r => r.Success);
                var failCount = results.Count(r => !r.Success);
                Status = $"Deployment complete: {successCount} succeeded, {failCount} failed";
            }
            catch (OperationCanceledException)
            {
                Status = "Deployment cancelled.";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Deployment error: {ex.Message}");
                MessageBox.Show($"Deployment failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        private async Task DeployBaselineGposAsync()
        {
            if (DomainInfo == null)
            {
                MessageBox.Show("Please discover the domain first.", "Domain Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var confirm = MessageBox.Show(
                $"Deploy baseline GPOs to {DomainInfo.DomainFqdn}?\n\n" +
                "This will create and link:\n" +
                (DeployPasswordPolicyGpo ? "• Password Policy GPO\n" : "") +
                (DeployAuditPolicyGpo ? "• Advanced Audit Policy GPO\n" : "") +
                (DeploySecurityBaselineGpo ? "• Security Baseline GPO\n" : "") +
                (DeployPawGpo ? "• PAW Security GPO\n" : "") +
                "\nContinue?",
                "Confirm GPO Deployment",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (confirm != MessageBoxResult.Yes) return;

            IsAnalyzing = true;
            Status = "Deploying baseline GPOs...";

            try
            {
                _cts = new CancellationTokenSource();

                var gpoOptions = new GpoDeploymentOptions
                {
                    // Legacy/Quick Deploy GPOs
                    DeployPasswordPolicy = DeployPasswordPolicyGpo,
                    DeployAuditPolicy = DeployAuditPolicyGpo,
                    DeploySecurityBaseline = DeploySecurityBaselineGpo,
                    DeployPawPolicy = DeployPawGpo,
                    TieredOuBaseName = DeploymentBaseName,

                    // Tier 0 GPOs
                    DeployT0BaselineAudit = DeployT0BaselineAudit,
                    DeployT0DisallowDsrm = DeployT0DisallowDsrm,
                    DeployT0DomainBlock = DeployT0DomainBlock,
                    DeployT0DomainControllers = DeployT0DomainControllers,
                    DeployT0EsxAdmins = DeployT0EsxAdmins,
                    DeployT0UserRights = DeployT0UserRights,
                    DeployT0RestrictedGroups = DeployT0RestrictedGroups,

                    // Tier 1 GPOs
                    DeployT1LocalAdmin = DeployT1LocalAdmin,
                    DeployT1UserRights = DeployT1UserRights,
                    DeployT1RestrictedGroups = DeployT1RestrictedGroups,

                    // Tier 2 GPOs
                    DeployT2LocalAdmin = DeployT2LocalAdmin,
                    DeployT2UserRights = DeployT2UserRights,
                    DeployT2RestrictedGroups = DeployT2RestrictedGroups,

                    // Cross-Tier GPOs
                    DeployDisableSmb1 = DeployDisableSmb1,
                    DeployDisableWDigest = DeployDisableWDigest,
                    DeployResetMachinePassword = DeployResetMachinePassword,

                    // Security Groups
                    CreateTierGroups = CreateTierGroups,

                    LinkGposToOus = LinkGposToOus
                };

                var results = await _analysisService.DeployBaselineGposAsync(gpoOptions, _cts.Token);

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    foreach (var r in results)
                    {
                        DeploymentResults.Add(r);
                        AppendLog($"{(r.Success ? "✓" : "✗")} {r.ObjectType}: {r.ObjectName} - {r.Message}");
                    }
                });

                var successCount = results.Count(r => r.Success);
                var failCount = results.Count(r => !r.Success);
                Status = $"GPO deployment complete: {successCount} succeeded, {failCount} failed";
            }
            catch (OperationCanceledException)
            {
                Status = "GPO deployment cancelled.";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"GPO deployment error: {ex.Message}");
                MessageBox.Show($"GPO deployment failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        #endregion

        #region Entra ID (Azure AD) Methods - PLATYPUS Azure Analysis

        /// <summary>
        /// Connect to Entra ID (Azure AD) using interactive browser authentication
        /// </summary>
        private async Task ConnectEntraIdAsync()
        {
            IsAnalyzing = true;
            Status = "Connecting to Entra ID (Azure AD)...";

            try
            {
                _cts = new CancellationTokenSource();
                AppendLog($"Connecting to Entra ID tenant: {EntraTenantId}");

                var success = await _entraIdService.ConnectAsync(EntraTenantId);

                if (success)
                {
                    IsEntraConnected = true;
                    EntraTenant = await _entraIdService.GetTenantInfoAsync();
                    
                    if (EntraTenant != null)
                    {
                        AppendLog($"Connected to tenant: {EntraTenant.DisplayName} ({EntraTenant.TenantId})");
                        AppendLog($"Verified domains: {string.Join(", ", EntraTenant.VerifiedDomains)}");
                    }
                    
                    Status = $"Connected to Entra ID: {EntraTenant?.DisplayName ?? EntraTenantId}";
                }
                else
                {
                    IsEntraConnected = false;
                    Status = "Failed to connect to Entra ID";
                    AppendLog("Authentication failed or was cancelled");
                }
            }
            catch (Exception ex)
            {
                Status = $"Entra ID connection error: {ex.Message}";
                AppendLog($"Error connecting to Entra ID: {ex.Message}");
                IsEntraConnected = false;
            }
            finally
            {
                IsAnalyzing = false;
                CommandManager.InvalidateRequerySuggested();
            }
        }

        /// <summary>
        /// Disconnect from Entra ID
        /// </summary>
        private void DisconnectEntraId()
        {
            _entraIdService.Disconnect();
            IsEntraConnected = false;
            EntraTenant = null;
            EntraPrivilegedRoles.Clear();
            EntraRiskyApps.Clear();
            EntraConditionalAccessPolicies.Clear();
            EntraPimViolations.Clear();
            EntraPrivilegedUserCount = 0;
            EntraRiskyAppCount = 0;
            EntraCaPolicyCount = 0;
            EntraPimViolationCount = 0;
            Status = "Disconnected from Entra ID";
            AppendLog("Disconnected from Entra ID");
            CommandManager.InvalidateRequerySuggested();
        }

        /// <summary>
        /// Run full Entra ID security analysis (equivalent to PLATYPUS Azure checks)
        /// </summary>
        private async Task RunEntraAnalysisAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Running Entra ID security analysis...";
            EntraPrivilegedRoles.Clear();
            EntraRiskyApps.Clear();
            EntraConditionalAccessPolicies.Clear();
            EntraPimViolations.Clear();

            try
            {
                _cts = new CancellationTokenSource();
                AppendLog("Starting full Entra ID security analysis...");

                var result = await _entraIdService.RunFullAnalysisAsync(EntraTenantId, EntraUsersOnly);

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    // Privileged roles
                    foreach (var role in result.PrivilegedRoles)
                    {
                        EntraPrivilegedRoles.Add(role);
                    }
                    EntraPrivilegedUserCount = result.PrivilegedRoles
                        .SelectMany(r => r.Members)
                        .Count(m => m.ObjectType == "User");

                    // Risky apps
                    foreach (var app in result.RiskyApps)
                    {
                        EntraRiskyApps.Add(app);
                    }
                    EntraRiskyAppCount = result.RiskyApps.Count;

                    // Conditional Access policies
                    foreach (var policy in result.ConditionalAccessPolicies)
                    {
                        EntraConditionalAccessPolicies.Add(policy);
                    }
                    EntraCaPolicyCount = result.ConditionalAccessPolicies.Count;

                    EntraPimViolations.Clear();
                    EntraPimViolationCount = 0;
                });

                AppendLog($"Analysis complete: {EntraPrivilegedUserCount} privileged users, {EntraRiskyAppCount} risky apps, {EntraCaPolicyCount} CA policies");
                Status = $"Entra ID analysis complete: {EntraPrivilegedUserCount} privileged users, {EntraRiskyAppCount} risky apps";
            }
            catch (Exception ex)
            {
                Status = $"Entra ID analysis error: {ex.Message}";
                AppendLog($"Error during Entra ID analysis: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Get privileged role assignments (equivalent to Get-AzureAdPrivObjects)
        /// </summary>
        private async Task GetEntraPrivilegedRolesAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Retrieving Entra ID privileged roles...";
            EntraPrivilegedRoles.Clear();

            try
            {
                _cts = new CancellationTokenSource();
                AppendLog("Retrieving privileged role assignments...");

                var roles = await _entraIdService.GetPrivilegedRolesAsync(EntraUsersOnly);

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    foreach (var role in roles)
                    {
                        EntraPrivilegedRoles.Add(role);
                    }
                    EntraPrivilegedUserCount = roles
                        .SelectMany(r => r.Members)
                        .Count(m => m.ObjectType == "User");
                });

                AppendLog($"Found {roles.Count} privileged roles with {EntraPrivilegedUserCount} user assignments");
                Status = $"Found {EntraPrivilegedUserCount} privileged user assignments across {roles.Count} roles";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error retrieving privileged roles: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Get risky applications (equivalent to Get-AzureAdRiskyApps)
        /// </summary>
        private async Task GetEntraRiskyAppsAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Retrieving risky Entra ID applications...";
            EntraRiskyApps.Clear();

            try
            {
                _cts = new CancellationTokenSource();
                AppendLog("Scanning for applications with risky API permissions...");

                var apps = await _entraIdService.GetRiskyAppsAsync();

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    foreach (var app in apps)
                    {
                        EntraRiskyApps.Add(app);
                    }
                    EntraRiskyAppCount = apps.Count;
                });

                var criticalCount = apps.Count(a => a.Severity == "Critical");
                var highCount = apps.Count(a => a.Severity == "High");
                AppendLog($"Found {apps.Count} risky applications: {criticalCount} Critical, {highCount} High");
                Status = $"Found {apps.Count} risky applications ({criticalCount} Critical, {highCount} High)";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error retrieving risky apps: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Get Conditional Access policies (equivalent to Get-AzureAdCAPolicies)
        /// </summary>
        private async Task GetEntraCaPoliciesAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Retrieving Entra ID Conditional Access policies...";
            EntraConditionalAccessPolicies.Clear();

            try
            {
                _cts = new CancellationTokenSource();
                AppendLog("Retrieving Conditional Access policies...");

                var policies = await _entraIdService.GetConditionalAccessPoliciesAsync();

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    foreach (var policy in policies)
                    {
                        EntraConditionalAccessPolicies.Add(policy);
                    }
                    EntraCaPolicyCount = policies.Count;
                });

                var enabledCount = policies.Count(p => p.State == "enabled");
                var reportOnlyCount = policies.Count(p => p.State == "enabledForReportingButNotEnforced");
                AppendLog($"Found {policies.Count} CA policies: {enabledCount} Enabled, {reportOnlyCount} Report-only");
                Status = $"Found {policies.Count} Conditional Access policies ({enabledCount} enabled)";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error retrieving CA policies: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Get PIM policy violations (roles that have permanent assignments where eligible-only is recommended)
        /// </summary>
        private async Task GetEntraPimViolationsAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Retrieving Entra ID PIM violations...";
            EntraPimViolations.Clear();

            try
            {
                _cts = new CancellationTokenSource();
                AppendLog("Analyzing PIM assignments for permanent-role violations...");

                var violations = await _entraIdService.GetPimViolationsAsync();

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    foreach (var violation in violations)
                    {
                        EntraPimViolations.Add(violation);
                    }
                    EntraPimViolationCount = violations.Count;
                });

                var criticalCount = violations.Count(v => v.ViolationType == "Critical");
                var warningCount = violations.Count(v => v.ViolationType == "Warning");
                AppendLog($"Found {violations.Count} PIM violations: {criticalCount} Critical, {warningCount} Warning");
                Status = $"Found {violations.Count} PIM violations ({criticalCount} critical)";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                AppendLog($"Error retrieving PIM violations: {ex.Message}");
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        #endregion

        #region Remediation / Takeback Methods (PLATYPUS IR Operations)

        // Remediation properties
        private string _exemptedUsers = string.Empty;
        public string ExemptedUsers
        {
            get => _exemptedUsers;
            set => SetProperty(ref _exemptedUsers, value);
        }

        private bool _remediationWhatIf = true;
        public bool RemediationWhatIf
        {
            get => _remediationWhatIf;
            set => SetProperty(ref _remediationWhatIf, value);
        }

        private bool _takebackResetPasswords = true;
        public bool TakebackResetPasswords
        {
            get => _takebackResetPasswords;
            set => SetProperty(ref _takebackResetPasswords, value);
        }

        private bool _takebackRevokeSessions = true;
        public bool TakebackRevokeSessions
        {
            get => _takebackRevokeSessions;
            set => SetProperty(ref _takebackRevokeSessions, value);
        }

        private bool _takebackRemoveRoles;
        public bool TakebackRemoveRoles
        {
            get => _takebackRemoveRoles;
            set => SetProperty(ref _takebackRemoveRoles, value);
        }

        // LAPS Implementation properties
        private string _lapsTargetOu = string.Empty;
        public string LapsTargetOu
        {
            get => _lapsTargetOu;
            set => SetProperty(ref _lapsTargetOu, value);
        }

        private string _lapsAdminGroup = "Domain Admins";
        public string LapsAdminGroup
        {
            get => _lapsAdminGroup;
            set => SetProperty(ref _lapsAdminGroup, value);
        }

        /// <summary>
        /// Performs tenant takeback operation
        /// </summary>
        private async Task TakebackTenantAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            if (string.IsNullOrWhiteSpace(ExemptedUsers))
            {
                AppendLog("ERROR: You must specify exempted users to avoid locking yourself out!");
                MessageBox.Show("You must specify exempted users (comma-separated) to avoid locking yourself out!", 
                    "Exempted Users Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!RemediationWhatIf)
            {
                var confirm = MessageBox.Show(
                    "WARNING: This will reset passwords and revoke sessions for ALL privileged users except those exempted.\n\n" +
                    "This is a destructive operation. Are you ABSOLUTELY sure?",
                    "Confirm Tenant Takeback",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (confirm != MessageBoxResult.Yes)
                {
                    AppendLog("Tenant takeback cancelled by user");
                    return;
                }
            }

            IsAnalyzing = true;
            Status = "Executing tenant takeback...";

            try
            {
                var exemptedList = ExemptedUsers.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => u.Trim()).ToList();

                AppendLog($"Starting tenant takeback with {exemptedList.Count} exempted users");
                AppendLog($"WhatIf mode: {RemediationWhatIf}");

                var options = new TenantTakebackOptions
                {
                    TenantId = EntraTenantId,
                    ExemptedUserUpns = exemptedList,
                    ResetPasswords = TakebackResetPasswords,
                    RevokeSessions = TakebackRevokeSessions,
                    RemoveFromRoles = TakebackRemoveRoles,
                    WhatIf = RemediationWhatIf
                };

                var result = await _entraIdService.TakebackTenantAsync(options);

                if (result.Success)
                {
                    AppendLog($"Takeback complete: {result.PasswordsReset} passwords reset, {result.SessionsRevoked} sessions revoked");
                    Status = $"Takeback complete: Processed {result.TotalProcessed} users";
                }
                else
                {
                    AppendLog($"Takeback failed: {string.Join(", ", result.Errors)}");
                    Status = "Takeback failed - check log";
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Error during takeback: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Mass password reset for all users
        /// </summary>
        private async Task MassPasswordResetAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            if (!RemediationWhatIf)
            {
                var confirm = MessageBox.Show(
                    "WARNING: This will reset passwords for ALL users in the tenant except external and exempted users.\n\n" +
                    "This is a very destructive operation. Are you ABSOLUTELY sure?",
                    "Confirm Mass Password Reset",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (confirm != MessageBoxResult.Yes)
                {
                    AppendLog("Mass password reset cancelled by user");
                    return;
                }
            }

            IsAnalyzing = true;
            Status = "Executing mass password reset...";

            try
            {
                var exemptedList = ExemptedUsers.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => u.Trim()).ToList();

                var result = await _entraIdService.MassPasswordResetAsync(exemptedList, false, RemediationWhatIf);

                AppendLog($"Mass password reset complete: {result.ResetCount} reset, {result.SkippedCount} skipped, {result.FailedCount} failed");
                Status = $"Password reset complete: {result.ResetCount} users processed";
            }
            catch (Exception ex)
            {
                AppendLog($"Error during mass password reset: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Revoke all user tokens
        /// </summary>
        private async Task RevokeAllTokensAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Revoking all user tokens...";

            try
            {
                var exemptedList = ExemptedUsers.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => u.Trim()).ToList();

                var count = await _entraIdService.RevokeAllUserTokensAsync(exemptedList, RemediationWhatIf);

                AppendLog($"Revoked tokens for {count} users");
                Status = $"Token revocation complete: {count} users";
            }
            catch (Exception ex)
            {
                AppendLog($"Error revoking tokens: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Remove privileged role members
        /// </summary>
        private async Task RemovePrivRoleMembersAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Removing privileged role members...";

            try
            {
                var exemptedList = ExemptedUsers.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => u.Trim()).ToList();

                var roleNames = new List<string> 
                { 
                    "Global Administrator", 
                    "Privileged Role Administrator",
                    "Privileged Authentication Administrator"
                };

                var count = await _entraIdService.RemovePrivilegedRoleMembersAsync(
                    roleNames, exemptedList, RemediationWhatIf);

                AppendLog($"Removed {count} role assignments");
                Status = $"Role member removal complete: {count} removed";
            }
            catch (Exception ex)
            {
                AppendLog($"Error removing role members: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Remove owners from risky/malicious applications
        /// </summary>
        private async Task RemoveAppOwnersAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Exporting and removing app owners...";

            try
            {
                // First export owners for backup
                var exportDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "PlatypusTools", "EntraExports");
                Directory.CreateDirectory(exportDir);
                var exportPath = Path.Combine(exportDir, $"AppOwners_{DateTime.Now:yyyyMMdd_HHmmss}.json");

                var exportResult = await _entraIdService.ExportAppOwnersAsync(exportPath);
                if (exportResult.Success)
                {
                    AppendLog($"Exported {exportResult.ExportedCount} app/SP owner records to {exportPath}");

                    // Now remove owners
                    var removedCount = await _entraIdService.RemoveAppOwnersFromExportAsync(
                        exportPath, RemediationWhatIf);

                    AppendLog(RemediationWhatIf
                        ? $"[WhatIf] Would remove {removedCount} app owner assignments"
                        : $"Removed {removedCount} app owner assignments");
                    Status = $"App owners: {removedCount} removed, backup at {exportPath}";
                }
                else
                {
                    AppendLog($"Failed to export app owners: {exportResult.ErrorMessage}");
                    Status = "App owners export failed";
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Error removing app owners: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Disable all Conditional Access policies during IR
        /// </summary>
        private async Task DisableCaPoliciesAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Disabling Conditional Access policies...";

            try
            {
                // Exempt any IR policies we deployed
                var exemptIds = new List<string>();

                var count = await _entraIdService.DisableConditionalAccessPoliciesAsync(
                    exemptIds, RemediationWhatIf);

                AppendLog(RemediationWhatIf
                    ? $"[WhatIf] Would disable {count} CA policies"
                    : $"Disabled {count} CA policies");
                Status = $"CA policy disable complete: {count} policies";
            }
            catch (Exception ex)
            {
                AppendLog($"Error disabling CA policies: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Deploy IR Conditional Access policy templates
        /// </summary>
        private async Task DeployIrCaPoliciesAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Deploying IR Conditional Access policies...";

            try
            {
                var exemptedList = ExemptedUsers.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => u.Trim()).ToList();

                var options = new IrCaPolicyDeploymentOptions
                {
                    BreakglassAccountUpns = exemptedList,
                    WhatIf = RemediationWhatIf,
                    EnablePolicies = false // Report-only mode by default
                };

                var results = await _entraIdService.DeployIrCaPoliciesAsync(options);

                foreach (var r in results)
                {
                    AppendLog($"  {r.Status}: {r.TemplateName} — {r.Message}");
                }

                var created = results.Count(r => r.Status == "Created" || r.Status == "WhatIf");
                AppendLog($"IR CA policy deployment complete: {created}/{results.Count} policies");
                Status = $"IR CA policies deployed: {created}/{results.Count}";
            }
            catch (Exception ex)
            {
                AppendLog($"Error deploying IR CA policies: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Export synced users and optionally disable directory sync
        /// </summary>
        private async Task ExportSyncedUsersAsync()
        {
            if (!IsEntraConnected)
            {
                AppendLog("Not connected to Entra ID. Connect first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Exporting synced users...";

            try
            {
                var exportDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "PlatypusTools", "EntraExports");
                Directory.CreateDirectory(exportDir);
                var exportPath = Path.Combine(exportDir, $"SyncedUsers_{DateTime.Now:yyyyMMdd_HHmmss}.csv");

                var result = await _entraIdService.ExportSyncedUsersAsync(
                    exportPath, disableSync: false, whatIf: RemediationWhatIf);

                if (result.Success || result.ExportedSuccessfully)
                {
                    AppendLog($"Exported {result.SyncedUserCount} synced users to {result.ExportFilePath}");
                    Status = $"Synced users exported: {result.SyncedUserCount} users";
                }
                else
                {
                    AppendLog($"Export failed: {result.ErrorMessage}");
                    Status = "Synced users export failed";
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Error exporting synced users: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Remove AdminCount from non-protected accounts
        /// </summary>
        private async Task RemoveAdminCountAsync()
        {
            if (!IsDomainDiscovered)
            {
                AppendLog("Domain not discovered. Discover domain first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Removing AdminCount from orphaned accounts...";

            try
            {
                var results = await _analysisService.RemoveAdminCountAsync(
                    allUsers: true,
                    whatIf: RemediationWhatIf);

                var successCount = results.Count(r => r.Success);
                AppendLog($"AdminCount removal complete: {successCount}/{results.Count} successful");
                Status = $"AdminCount removal: {successCount} accounts fixed";
            }
            catch (Exception ex)
            {
                AppendLog($"Error removing AdminCount: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        #endregion

        #region Attack Path Detection

        /// <summary>
        /// Run complete attack path detection scan
        /// </summary>
        private async Task RunAttackPathScanAsync()
        {
            if (!IsDomainDiscovered)
            {
                AppendLog("Domain not discovered. Discover domain first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Running attack path detection scan...";
            SecurityFindings.Clear();

            try
            {
                _cts = new CancellationTokenSource();
                var result = await _analysisService.RunAttackPathScanAsync(_cts.Token);

                Application.Current.Dispatcher.Invoke(() =>
                {
                    foreach (var finding in result.AllFindings)
                    {
                        SecurityFindings.Add(finding);
                    }
                });

                AppendLog($"Attack path scan complete: {result.TotalFindings} findings ({result.CriticalFindings} critical)");
                Status = $"Attack path scan complete: {result.TotalFindings} findings";
                HasResults = result.TotalFindings > 0;
            }
            catch (OperationCanceledException)
            {
                AppendLog("Attack path scan cancelled.");
                Status = "Scan cancelled";
            }
            catch (Exception ex)
            {
                AppendLog($"Error during attack path scan: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
                _cts?.Dispose();
                _cts = null;
            }
        }

        /// <summary>
        /// Audit LAPS deployment across the domain
        /// </summary>
        private async Task AuditLapsAsync()
        {
            if (!IsDomainDiscovered)
            {
                AppendLog("Domain not discovered. Discover domain first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Auditing LAPS deployment...";
            ComputersWithoutLaps.Clear();

            try
            {
                _cts = new CancellationTokenSource();
                var result = await _analysisService.AuditLapsDeploymentAsync(_cts.Token);

                Application.Current.Dispatcher.Invoke(() =>
                {
                    foreach (var computer in result.ComputersWithoutLaps)
                    {
                        ComputersWithoutLaps.Add(computer);
                        // Also add as SecurityFinding for display in main grid
                        SecurityFindings.Add(new SecurityFinding
                        {
                            Category = "Missing LAPS",
                            Severity = "High",
                            ObjectName = computer.ComputerName,
                            ObjectDn = computer.DistinguishedName,
                            ObjectType = "computer",
                            Description = $"No LAPS password set. OS: {computer.OperatingSystem}",
                            Recommendation = "Deploy LAPS to manage local admin passwords securely."
                        });
                    }
                });

                AppendLog($"LAPS Audit complete: {result.ComputersWithLaps}/{result.TotalComputers} computers have LAPS ({result.CoveragePercent:F1}%)");
                AppendLog($"Legacy LAPS schema: {result.LapsSchemaExtended}, Windows LAPS schema: {result.WindowsLapsSchemaExtended}");
                Status = $"LAPS Coverage: {result.CoveragePercent:F1}% ({result.ComputersWithoutLaps.Count} without LAPS)";
                HasResults = result.ComputersWithoutLaps.Count > 0;
            }
            catch (OperationCanceledException)
            {
                AppendLog("LAPS audit cancelled.");
                Status = "Audit cancelled";
            }
            catch (Exception ex)
            {
                AppendLog($"Error during LAPS audit: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
                _cts?.Dispose();
                _cts = null;
            }
        }

        /// <summary>
        /// Find Group Policy Preferences with embedded passwords
        /// </summary>
        private async Task FindGppPasswordsAsync()
        {
            if (!IsDomainDiscovered)
            {
                AppendLog("Domain not discovered. Discover domain first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Scanning SYSVOL for GPP passwords...";

            try
            {
                _cts = new CancellationTokenSource();
                var findings = await _analysisService.FindGppPasswordsAsync(_cts.Token);

                Application.Current.Dispatcher.Invoke(() =>
                {
                    foreach (var finding in findings)
                    {
                        SecurityFindings.Add(finding);
                    }
                });

                if (findings.Count > 0)
                {
                    AppendLog($"[CRITICAL] Found {findings.Count} GPP passwords in SYSVOL!");
                }
                else
                {
                    AppendLog("No GPP passwords found in SYSVOL.");
                }
                
                Status = findings.Count > 0 ? $"CRITICAL: {findings.Count} GPP passwords found!" : "No GPP passwords found";
                HasResults = findings.Count > 0;
            }
            catch (OperationCanceledException)
            {
                AppendLog("GPP password scan cancelled.");
                Status = "Scan cancelled";
            }
            catch (Exception ex)
            {
                AppendLog($"Error scanning GPP passwords: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
                _cts?.Dispose();
                _cts = null;
            }
        }

        /// <summary>
        /// Find stale/inactive accounts
        /// </summary>
        private async Task FindStaleAccountsAsync()
        {
            if (!IsDomainDiscovered)
            {
                AppendLog("Domain not discovered. Discover domain first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Finding stale accounts...";
            StaleUsers.Clear();
            StaleComputers.Clear();

            try
            {
                _cts = new CancellationTokenSource();
                var result = await _analysisService.FindStaleAccountsAsync(90, _cts.Token);

                Application.Current.Dispatcher.Invoke(() =>
                {
                    foreach (var user in result.StaleUsers)
                    {
                        StaleUsers.Add(user);
                        // Also add as SecurityFinding for display in main grid
                        var severity = user.IsPrivileged ? "Critical" : "Medium";
                        SecurityFindings.Add(new SecurityFinding
                        {
                            Category = "Stale User Account",
                            Severity = severity,
                            ObjectName = user.SamAccountName,
                            ObjectDn = user.DistinguishedName,
                            ObjectType = "user",
                            Description = $"Inactive for {user.DaysSinceLastLogon} days.{(user.IsPrivileged ? " PRIVILEGED ACCOUNT!" : "")}",
                            Recommendation = "Disable or delete stale accounts to reduce attack surface."
                        });
                    }
                    foreach (var computer in result.StaleComputers)
                    {
                        StaleComputers.Add(computer);
                        SecurityFindings.Add(new SecurityFinding
                        {
                            Category = "Stale Computer Account",
                            Severity = "Low",
                            ObjectName = computer.SamAccountName,
                            ObjectDn = computer.DistinguishedName,
                            ObjectType = "computer",
                            Description = $"Inactive for {computer.DaysSinceLastLogon} days. OS: {computer.OperatingSystem}",
                            Recommendation = "Delete stale computer accounts."
                        });
                    }
                });

                AppendLog($"Stale account scan complete: {result.StaleUsers.Count} users, {result.StaleComputers.Count} computers inactive for 90+ days");
                Status = $"Stale accounts: {result.StaleUsers.Count} users, {result.StaleComputers.Count} computers";
                HasResults = result.StaleUsers.Count > 0 || result.StaleComputers.Count > 0;
            }
            catch (OperationCanceledException)
            {
                AppendLog("Stale account scan cancelled.");
                Status = "Scan cancelled";
            }
            catch (Exception ex)
            {
                AppendLog($"Error finding stale accounts: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
                _cts?.Dispose();
                _cts = null;
            }
        }

        #endregion

        #region Security GPO Deployment

        /// <summary>
        /// Deploy a security hardening GPO
        /// </summary>
        private async Task DeploySecurityGpoAsync(string gpoType)
        {
            if (!IsDomainDiscovered)
            {
                AppendLog("Domain not discovered. Discover domain first.");
                return;
            }

            IsAnalyzing = true;
            Status = $"Deploying {gpoType} GPO...";

            try
            {
                _cts = new CancellationTokenSource();
                AdGpoResult result;

                switch (gpoType)
                {
                    case "PrintNightmare":
                        result = await _analysisService.DeployPrintNightmareGpoAsync(RemediationWhatIf, _cts.Token);
                        break;
                    case "LlmnrNbtns":
                        result = await _analysisService.DeployLlmnrDisableGpoAsync(RemediationWhatIf, _cts.Token);
                        break;
                    case "SmbSigning":
                        result = await _analysisService.DeploySmbSigningGpoAsync(RemediationWhatIf, _cts.Token);
                        break;
                    case "CredentialGuard":
                        result = await _analysisService.DeployCredentialGuardGpoAsync(RemediationWhatIf, _cts.Token);
                        break;
                    default:
                        AppendLog($"Unknown GPO type: {gpoType}");
                        return;
                }

                if (result.Success)
                {
                    AppendLog($"[OK] {result.Message}");
                    if (result.GpoGuid != null)
                    {
                        DeploymentResults.Add(new AdObjectCreationResult
                        {
                            Success = true,
                            ObjectType = "GPO",
                            ObjectName = result.GpoName,
                            DistinguishedName = result.GpoDn ?? "",
                            Message = result.Message
                        });
                    }
                    Status = result.Message;
                }
                else
                {
                    AppendLog($"[ERROR] {result.Message}");
                    Status = $"Failed: {result.Message}";
                }
            }
            catch (OperationCanceledException)
            {
                AppendLog("GPO deployment cancelled.");
                Status = "Deployment cancelled";
            }
            catch (Exception ex)
            {
                AppendLog($"Error deploying GPO: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
                _cts?.Dispose();
                _cts = null;
            }
        }

        #endregion

        #region AD Operations - Krbtgt, Replication, LAPS, SYSVOL

        /// <summary>
        /// Resets the krbtgt account password.
        /// </summary>
        private async Task ResetKrbtgtAsync()
        {
            if (!IsDomainDiscovered)
            {
                AppendLog("Domain not discovered. Please discover domain first.");
                return;
            }

            var confirm = MessageBox.Show(
                "This will reset the krbtgt account password.\n\n" +
                "⚠️ IMPORTANT:\n" +
                "• This invalidates ALL Kerberos tickets in the domain\n" +
                "• Reset TWICE with 10+ hours between resets for full rotation\n" +
                "• Wait 10+ hours after second reset for all tickets to expire\n\n" +
                $"WhatIf Mode: {(RemediationWhatIf ? "ON (safe preview)" : "OFF (will execute)")}\n\n" +
                "Continue?",
                "Reset Krbtgt Password",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (confirm != MessageBoxResult.Yes) return;

            IsAnalyzing = true;
            Status = "Resetting krbtgt password...";

            try
            {
                _cts = new CancellationTokenSource();
                var result = await _analysisService.ResetKrbtgtPasswordAsync(RemediationWhatIf, _cts.Token);

                if (result.Success)
                {
                    AppendLog($"[OK] {result.Message}");
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        DeploymentResults.Add(result);
                    });
                }
                else
                {
                    AppendLog($"[ERROR] {result.Message}");
                }

                Status = result.Message;
            }
            catch (Exception ex)
            {
                AppendLog($"Error resetting krbtgt: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Forces AD replication between domain controllers.
        /// </summary>
        private async Task ForceReplicationAsync()
        {
            if (!IsDomainDiscovered)
            {
                AppendLog("Domain not discovered. Please discover domain first.");
                return;
            }

            IsAnalyzing = true;
            Status = "Forcing AD replication...";

            try
            {
                _cts = new CancellationTokenSource();
                var result = await _analysisService.ForceReplicationAsync(null, RemediationWhatIf, _cts.Token);

                if (result.Success)
                {
                    AppendLog($"[OK] {result.Message}");
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        DeploymentResults.Add(result);
                    });
                }
                else
                {
                    AppendLog($"[ERROR] {result.Message}");
                }

                Status = result.Message;
            }
            catch (Exception ex)
            {
                AppendLog($"Error forcing replication: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Implements LAPS by setting up schema and permissions.
        /// </summary>
        private async Task ImplementLapsAsync()
        {
            if (!IsDomainDiscovered)
            {
                AppendLog("Domain not discovered. Please discover domain first.");
                return;
            }

            if (string.IsNullOrWhiteSpace(LapsTargetOu))
            {
                MessageBox.Show(
                    "Please enter a Target OU for LAPS implementation.\n\nExample: OU=Workstations,DC=contoso,DC=com",
                    "LAPS Target OU Required",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            IsAnalyzing = true;
            Status = "Implementing LAPS...";

            try
            {
                _cts = new CancellationTokenSource();
                var results = await _analysisService.ImplementLapsAsync(
                    LapsTargetOu,
                    true,
                    string.IsNullOrWhiteSpace(LapsAdminGroup) ? null : LapsAdminGroup,
                    RemediationWhatIf,
                    _cts.Token);

                foreach (var result in results)
                {
                    if (result.Success)
                    {
                        AppendLog($"[OK] {result.Message}");
                    }
                    else
                    {
                        AppendLog($"[ERROR] {result.Message}");
                    }

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        DeploymentResults.Add(result);
                    });
                }

                Status = $"LAPS implementation complete. {results.Count(r => r.Success)}/{results.Count} steps succeeded.";
            }
            catch (Exception ex)
            {
                AppendLog($"Error implementing LAPS: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        /// <summary>
        /// Performs authoritative SYSVOL restore.
        /// </summary>
        private async Task AuthoritativeSysvolRestoreAsync()
        {
            if (!IsDomainDiscovered)
            {
                AppendLog("Domain not discovered. Please discover domain first.");
                return;
            }

            var confirm = MessageBox.Show(
                "⚠️ AUTHORITATIVE SYSVOL RESTORE ⚠️\n\n" +
                "This will make the current DC's SYSVOL the authoritative source.\n" +
                "All other DCs will OVERWRITE their SYSVOL with this DC's copy!\n\n" +
                "Use this ONLY when:\n" +
                "• SYSVOL replication is broken\n" +
                "• You have verified this DC has the correct SYSVOL content\n" +
                "• You understand this will replace SYSVOL on ALL other DCs\n\n" +
                $"WhatIf Mode: {(RemediationWhatIf ? "ON (safe preview)" : "OFF (will execute)")}\n\n" +
                "Are you SURE you want to continue?",
                "Authoritative SYSVOL Restore",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (confirm != MessageBoxResult.Yes) return;

            IsAnalyzing = true;
            Status = "Initiating authoritative SYSVOL restore...";

            try
            {
                _cts = new CancellationTokenSource();
                var result = await _analysisService.AuthoritativeSysvolRestoreAsync(null, RemediationWhatIf, _cts.Token);

                if (result.Success)
                {
                    AppendLog($"[OK] {result.Message}");
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        DeploymentResults.Add(result);
                    });
                }
                else
                {
                    AppendLog($"[ERROR] {result.Message}");
                }

                Status = result.Message;
            }
            catch (Exception ex)
            {
                AppendLog($"Error during SYSVOL restore: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        #endregion

        #region PIM Assignment Management

        private async Task GetPimAssignmentsAsync()
        {
            if (!IsEntraConnected) return;
            try
            {
                IsAnalyzing = true;
                Status = "Loading PIM assignments...";
                Application.Current.Dispatcher.Invoke(() => EntraPimAssignments.Clear());

                var eligible = await _entraIdService.GetEligiblePimAssignmentsAsync();
                var active = await _entraIdService.GetActivePimAssignmentsAsync();

                Application.Current.Dispatcher.Invoke(() =>
                {
                    foreach (var a in eligible)
                        EntraPimAssignments.Add(a);
                    foreach (var a in active.Where(ac => !eligible.Any(e => e.PrincipalId == ac.PrincipalId && e.RoleId == ac.RoleId)))
                        EntraPimAssignments.Add(a);
                });

                Status = $"Loaded {EntraPimAssignments.Count} PIM assignments ({eligible.Count} eligible, {active.Count} active).";
                AppendLog(Status);
            }
            catch (Exception ex)
            {
                AppendLog($"Error loading PIM assignments: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        private async Task CreatePimAssignmentAsync()
        {
            if (!IsEntraConnected) return;
            if (string.IsNullOrWhiteSpace(PimNewPrincipalUpn) || string.IsNullOrWhiteSpace(PimNewRoleName))
            {
                AppendLog("PIM assignment creation requires a user UPN and role name.");
                return;
            }

            var justification = string.IsNullOrWhiteSpace(PimNewJustification)
                ? "SecKey - PIM eligible assignment"
                : PimNewJustification;

            try
            {
                IsAnalyzing = true;
                Status = $"Creating PIM eligible assignment: {PimNewRoleName} for {PimNewPrincipalUpn}...";

                var (success, message) = await _entraIdService.CreatePimEligibleAssignmentAsync(
                    PimNewPrincipalUpn, PimNewRoleName, justification, PimNewDurationDays);

                AppendLog(message);
                Status = success ? "PIM assignment created successfully." : $"PIM assignment failed: {message}";

                if (success)
                {
                    PimNewPrincipalUpn = string.Empty;
                    PimNewJustification = string.Empty;
                    await GetPimAssignmentsAsync();
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Error creating PIM assignment: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        #endregion

        #region App Registration Management

        private async Task CreateAppRegistrationAsync()
        {
            if (!IsEntraConnected) return;
            if (string.IsNullOrWhiteSpace(AppRegistrationName))
            {
                AppendLog("App registration name is required.");
                return;
            }

            try
            {
                IsAnalyzing = true;
                Status = $"Creating app registration '{AppRegistrationName}'...";
                AppRegistrationResultText = string.Empty;
                AppRegistrationSuccess = false;

                var result = await _entraIdService.CreateAppRegistrationAsync(AppRegistrationName);

                AppRegistrationSuccess = result.Success;
                AppRegistrationResultText = result.Success
                    ? $"Success! AppId: {result.AppId}\nObject ID: {result.ObjectId}\n{(result.AlreadyExisted ? "(App already existed)" : "(Newly created)")}\n\nGrant admin consent in the Azure portal before use."
                    : $"Failed: {result.Message}";

                AppendLog(result.Message);
                Status = result.Success ? $"App registration ready. AppId: {result.AppId}" : $"App registration failed: {result.Message}";
            }
            catch (Exception ex)
            {
                AppRegistrationResultText = $"Error: {ex.Message}";
                AppendLog($"App registration error: {ex.Message}");
                Status = $"Error: {ex.Message}";
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        #endregion
    }
}

