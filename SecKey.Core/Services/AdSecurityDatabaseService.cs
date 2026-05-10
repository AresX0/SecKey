using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using SecKey.Core.Models;

namespace SecKey.Core.Services
{
    /// <summary>
    /// Database service for storing and retrieving AD/Entra ID security analysis results.
    /// Uses SQLite for local storage with export capabilities.
    /// </summary>
    public class AdSecurityDatabaseService : IDisposable
    {
        private readonly string _databasePath;
        private SQLiteConnection? _connection;
        private bool _disposed;

        public string DatabasePath => _databasePath;
        public bool IsInitialized => _connection != null;

        public AdSecurityDatabaseService(string? databasePath = null)
        {
            _databasePath = databasePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecKey", "ad_security_analysis.db");

            var directory = Path.GetDirectoryName(_databasePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }

        #region Initialization

        public async Task InitializeAsync()
        {
            if (_connection != null) return;

            var connectionString = $"Data Source={_databasePath};Version=3;";
            _connection = new SQLiteConnection(connectionString);
            await _connection.OpenAsync();

            await CreateTablesAsync();
        }

        private async Task CreateTablesAsync()
        {
            var createTablesSql = @"
                -- Analysis runs (parent table)
                CREATE TABLE IF NOT EXISTS AnalysisRuns (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    AnalysisType TEXT NOT NULL,
                    RunTime DATETIME DEFAULT CURRENT_TIMESTAMP,
                    TargetDomain TEXT,
                    TargetDc TEXT,
                    TargetTenantId TEXT,
                    TotalFindings INTEGER DEFAULT 0,
                    CriticalCount INTEGER DEFAULT 0,
                    HighCount INTEGER DEFAULT 0,
                    MediumCount INTEGER DEFAULT 0,
                    LowCount INTEGER DEFAULT 0,
                    DurationSeconds REAL DEFAULT 0,
                    IsComplete INTEGER DEFAULT 0,
                    DomainInfoJson TEXT,
                    ErrorsJson TEXT
                );

                -- Privileged Members
                CREATE TABLE IF NOT EXISTS PrivilegedMembers (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId INTEGER NOT NULL,
                    SamAccountName TEXT,
                    DistinguishedName TEXT,
                    ObjectClass TEXT,
                    GroupName TEXT,
                    PasswordLastSet DATETIME,
                    LastLogon DATETIME,
                    PasswordNeverExpires INTEGER DEFAULT 0,
                    TrustedForDelegation INTEGER DEFAULT 0,
                    HasSpn INTEGER DEFAULT 0,
                    IsEnabled INTEGER DEFAULT 1,
                    IsNested INTEGER DEFAULT 0,
                    NestedPath TEXT,
                    RiskyUacFlags TEXT,
                    FOREIGN KEY (RunId) REFERENCES AnalysisRuns(Id) ON DELETE CASCADE
                );

                -- Risky ACLs
                CREATE TABLE IF NOT EXISTS RiskyAcls (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId INTEGER NOT NULL,
                    ObjectDn TEXT,
                    ObjectClass TEXT,
                    IdentityReference TEXT,
                    ActiveDirectoryRights TEXT,
                    AccessControlType TEXT,
                    ObjectType TEXT,
                    ObjectTypeName TEXT,
                    InheritedObjectType TEXT,
                    IsInherited INTEGER DEFAULT 0,
                    Severity TEXT,
                    Description TEXT,
                    FOREIGN KEY (RunId) REFERENCES AnalysisRuns(Id) ON DELETE CASCADE
                );

                -- Risky GPOs
                CREATE TABLE IF NOT EXISTS RiskyGpos (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId INTEGER NOT NULL,
                    GpoName TEXT,
                    GpoGuid TEXT,
                    CreatedTime DATETIME,
                    ModifiedTime DATETIME,
                    RiskySettings TEXT,
                    HasScheduledTasks INTEGER DEFAULT 0,
                    HasRegistryMods INTEGER DEFAULT 0,
                    HasFileOperations INTEGER DEFAULT 0,
                    HasSoftwareInstallation INTEGER DEFAULT 0,
                    HasLocalUserMods INTEGER DEFAULT 0,
                    HasEnvironmentMods INTEGER DEFAULT 0,
                    Severity TEXT,
                    FOREIGN KEY (RunId) REFERENCES AnalysisRuns(Id) ON DELETE CASCADE
                );

                -- SYSVOL Risky Files
                CREATE TABLE IF NOT EXISTS SysvolRiskyFiles (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId INTEGER NOT NULL,
                    FileName TEXT,
                    FilePath TEXT,
                    Extension TEXT,
                    CreationTime DATETIME,
                    LastWriteTime DATETIME,
                    FileSize INTEGER,
                    Sha256Hash TEXT,
                    Severity TEXT,
                    FOREIGN KEY (RunId) REFERENCES AnalysisRuns(Id) ON DELETE CASCADE
                );

                -- Kerberos Delegations
                CREATE TABLE IF NOT EXISTS KerberosDelegations (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId INTEGER NOT NULL,
                    SamAccountName TEXT,
                    DistinguishedName TEXT,
                    ObjectClass TEXT,
                    DelegationType TEXT,
                    AllowedToDelegateTo TEXT,
                    AllowedToActOnBehalfOf TEXT,
                    IsSensitive INTEGER DEFAULT 0,
                    Severity TEXT,
                    Description TEXT,
                    FOREIGN KEY (RunId) REFERENCES AnalysisRuns(Id) ON DELETE CASCADE
                );

                -- AdminCount Anomalies
                CREATE TABLE IF NOT EXISTS AdminCountAnomalies (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId INTEGER NOT NULL,
                    SamAccountName TEXT,
                    DistinguishedName TEXT,
                    ObjectClass TEXT,
                    AdminCount INTEGER,
                    IsCurrentlyPrivileged INTEGER DEFAULT 0,
                    Issue TEXT,
                    FOREIGN KEY (RunId) REFERENCES AnalysisRuns(Id) ON DELETE CASCADE
                );

                -- Entra ID Privileged Roles
                CREATE TABLE IF NOT EXISTS EntraIdPrivilegedRoles (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId INTEGER NOT NULL,
                    RoleId TEXT,
                    RoleDisplayName TEXT,
                    RoleTemplateId TEXT,
                    IsBuiltIn INTEGER DEFAULT 1,
                    MembersJson TEXT,
                    FOREIGN KEY (RunId) REFERENCES AnalysisRuns(Id) ON DELETE CASCADE
                );

                -- Entra ID Risky Apps
                CREATE TABLE IF NOT EXISTS EntraIdRiskyApps (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId INTEGER NOT NULL,
                    AppId TEXT,
                    DisplayName TEXT,
                    ObjectId TEXT,
                    PermissionsJson TEXT,
                    OwnersJson TEXT,
                    CreatedDateTime DATETIME,
                    Severity TEXT,
                    RiskReason TEXT,
                    FOREIGN KEY (RunId) REFERENCES AnalysisRuns(Id) ON DELETE CASCADE
                );

                -- Entra ID Conditional Access Policies
                CREATE TABLE IF NOT EXISTS EntraIdCaPolicies (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId INTEGER NOT NULL,
                    PolicyId TEXT,
                    DisplayName TEXT,
                    State TEXT,
                    CreatedDateTime DATETIME,
                    ModifiedDateTime DATETIME,
                    IncludedUsers TEXT,
                    ExcludedUsers TEXT,
                    IncludedApplications TEXT,
                    GrantControls TEXT,
                    SessionControls TEXT,
                    FOREIGN KEY (RunId) REFERENCES AnalysisRuns(Id) ON DELETE CASCADE
                );

                -- Create indexes for common queries
                CREATE INDEX IF NOT EXISTS idx_analysisruns_runtime ON AnalysisRuns(RunTime);
                CREATE INDEX IF NOT EXISTS idx_analysisruns_domain ON AnalysisRuns(TargetDomain);
                CREATE INDEX IF NOT EXISTS idx_privilegedmembers_runid ON PrivilegedMembers(RunId);
                CREATE INDEX IF NOT EXISTS idx_riskyacls_runid ON RiskyAcls(RunId);
                CREATE INDEX IF NOT EXISTS idx_riskyacls_severity ON RiskyAcls(Severity);
            ";

            using var cmd = new SQLiteCommand(createTablesSql, _connection);
            await cmd.ExecuteNonQueryAsync();
        }

        #endregion

        #region Save Analysis Results

        /// <summary>
        /// Saves an AD security analysis result to the database.
        /// </summary>
        public async Task<long> SaveAnalysisAsync(AdSecurityAnalysisResult result)
        {
            if (_connection == null) await InitializeAsync();

            using var transaction = _connection!.BeginTransaction();

            try
            {
                // Insert main run record
                var runId = await InsertAnalysisRunAsync(result, transaction);

                // Insert child records
                await InsertPrivilegedMembersAsync(runId, result.PrivilegedMembers, transaction);
                await InsertRiskyAclsAsync(runId, result.RiskyAcls, transaction);
                await InsertRiskyGposAsync(runId, result.RiskyGpos, transaction);
                await InsertSysvolFilesAsync(runId, result.SysvolRiskyFiles, transaction);
                await InsertKerberosDelegationsAsync(runId, result.KerberosDelegations, transaction);
                await InsertAdminCountAnomaliesAsync(runId, result.AdminCountAnomalies, transaction);

                transaction.Commit();
                return runId;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }

        private async Task<long> InsertAnalysisRunAsync(AdSecurityAnalysisResult result, SQLiteTransaction transaction)
        {
            var sql = @"
                INSERT INTO AnalysisRuns (
                    AnalysisType, RunTime, TargetDomain, TargetDc, TotalFindings,
                    CriticalCount, HighCount, MediumCount, LowCount, DurationSeconds,
                    IsComplete, DomainInfoJson, ErrorsJson
                ) VALUES (
                    @AnalysisType, @RunTime, @TargetDomain, @TargetDc, @TotalFindings,
                    @CriticalCount, @HighCount, @MediumCount, @LowCount, @DurationSeconds,
                    @IsComplete, @DomainInfoJson, @ErrorsJson
                );
                SELECT last_insert_rowid();";

            using var cmd = new SQLiteCommand(sql, _connection, transaction);
            cmd.Parameters.AddWithValue("@AnalysisType", "AD");
            cmd.Parameters.AddWithValue("@RunTime", result.StartTime);
            cmd.Parameters.AddWithValue("@TargetDomain", result.DomainInfo?.DomainFqdn ?? "");
            cmd.Parameters.AddWithValue("@TargetDc", result.DomainInfo?.ChosenDc ?? "");
            cmd.Parameters.AddWithValue("@TotalFindings", result.TotalFindings);
            cmd.Parameters.AddWithValue("@CriticalCount", result.CriticalCount);
            cmd.Parameters.AddWithValue("@HighCount", result.HighCount);
            cmd.Parameters.AddWithValue("@MediumCount", result.MediumCount);
            cmd.Parameters.AddWithValue("@LowCount", result.LowCount);
            cmd.Parameters.AddWithValue("@DurationSeconds", result.Duration.TotalSeconds);
            cmd.Parameters.AddWithValue("@IsComplete", result.IsComplete ? 1 : 0);
            cmd.Parameters.AddWithValue("@DomainInfoJson", JsonSerializer.Serialize(result.DomainInfo));
            cmd.Parameters.AddWithValue("@ErrorsJson", JsonSerializer.Serialize(result.Errors));

            var id = await cmd.ExecuteScalarAsync();
            return Convert.ToInt64(id);
        }

        private async Task InsertPrivilegedMembersAsync(long runId, List<AdPrivilegedMember> members, SQLiteTransaction transaction)
        {
            if (members.Count == 0) return;

            var sql = @"
                INSERT INTO PrivilegedMembers (
                    RunId, SamAccountName, DistinguishedName, ObjectClass, GroupName,
                    PasswordLastSet, LastLogon, PasswordNeverExpires, TrustedForDelegation,
                    HasSpn, IsEnabled, IsNested, NestedPath, RiskyUacFlags
                ) VALUES (
                    @RunId, @SamAccountName, @DistinguishedName, @ObjectClass, @GroupName,
                    @PasswordLastSet, @LastLogon, @PasswordNeverExpires, @TrustedForDelegation,
                    @HasSpn, @IsEnabled, @IsNested, @NestedPath, @RiskyUacFlags
                )";

            foreach (var member in members)
            {
                using var cmd = new SQLiteCommand(sql, _connection, transaction);
                cmd.Parameters.AddWithValue("@RunId", runId);
                cmd.Parameters.AddWithValue("@SamAccountName", member.SamAccountName);
                cmd.Parameters.AddWithValue("@DistinguishedName", member.DistinguishedName);
                cmd.Parameters.AddWithValue("@ObjectClass", member.ObjectClass);
                cmd.Parameters.AddWithValue("@GroupName", member.GroupName);
                cmd.Parameters.AddWithValue("@PasswordLastSet", (object?)member.PasswordLastSet ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@LastLogon", (object?)member.LastLogon ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@PasswordNeverExpires", member.PasswordNeverExpires ? 1 : 0);
                cmd.Parameters.AddWithValue("@TrustedForDelegation", member.TrustedForDelegation ? 1 : 0);
                cmd.Parameters.AddWithValue("@HasSpn", member.HasSpn ? 1 : 0);
                cmd.Parameters.AddWithValue("@IsEnabled", member.IsEnabled ? 1 : 0);
                cmd.Parameters.AddWithValue("@IsNested", member.IsNested ? 1 : 0);
                cmd.Parameters.AddWithValue("@NestedPath", member.NestedPath);
                cmd.Parameters.AddWithValue("@RiskyUacFlags", string.Join(",", member.RiskyUacFlags));
                await cmd.ExecuteNonQueryAsync();
            }
        }

        private async Task InsertRiskyAclsAsync(long runId, List<AdRiskyAcl> acls, SQLiteTransaction transaction)
        {
            if (acls.Count == 0) return;

            var sql = @"
                INSERT INTO RiskyAcls (
                    RunId, ObjectDn, ObjectClass, IdentityReference, ActiveDirectoryRights,
                    AccessControlType, ObjectType, ObjectTypeName, InheritedObjectType,
                    IsInherited, Severity, Description
                ) VALUES (
                    @RunId, @ObjectDn, @ObjectClass, @IdentityReference, @ActiveDirectoryRights,
                    @AccessControlType, @ObjectType, @ObjectTypeName, @InheritedObjectType,
                    @IsInherited, @Severity, @Description
                )";

            foreach (var acl in acls)
            {
                using var cmd = new SQLiteCommand(sql, _connection, transaction);
                cmd.Parameters.AddWithValue("@RunId", runId);
                cmd.Parameters.AddWithValue("@ObjectDn", acl.ObjectDn);
                cmd.Parameters.AddWithValue("@ObjectClass", acl.ObjectClass);
                cmd.Parameters.AddWithValue("@IdentityReference", acl.IdentityReference);
                cmd.Parameters.AddWithValue("@ActiveDirectoryRights", acl.ActiveDirectoryRights);
                cmd.Parameters.AddWithValue("@AccessControlType", acl.AccessControlType);
                cmd.Parameters.AddWithValue("@ObjectType", acl.ObjectType);
                cmd.Parameters.AddWithValue("@ObjectTypeName", acl.ObjectTypeName);
                cmd.Parameters.AddWithValue("@InheritedObjectType", acl.InheritedObjectType);
                cmd.Parameters.AddWithValue("@IsInherited", acl.IsInherited ? 1 : 0);
                cmd.Parameters.AddWithValue("@Severity", acl.Severity);
                cmd.Parameters.AddWithValue("@Description", acl.Description);
                await cmd.ExecuteNonQueryAsync();
            }
        }

        private async Task InsertRiskyGposAsync(long runId, List<AdRiskyGpo> gpos, SQLiteTransaction transaction)
        {
            if (gpos.Count == 0) return;

            var sql = @"
                INSERT INTO RiskyGpos (
                    RunId, GpoName, GpoGuid, CreatedTime, ModifiedTime, RiskySettings,
                    HasScheduledTasks, HasRegistryMods, HasFileOperations, 
                    HasSoftwareInstallation, HasLocalUserMods, HasEnvironmentMods, Severity
                ) VALUES (
                    @RunId, @GpoName, @GpoGuid, @CreatedTime, @ModifiedTime, @RiskySettings,
                    @HasScheduledTasks, @HasRegistryMods, @HasFileOperations,
                    @HasSoftwareInstallation, @HasLocalUserMods, @HasEnvironmentMods, @Severity
                )";

            foreach (var gpo in gpos)
            {
                using var cmd = new SQLiteCommand(sql, _connection, transaction);
                cmd.Parameters.AddWithValue("@RunId", runId);
                cmd.Parameters.AddWithValue("@GpoName", gpo.GpoName);
                cmd.Parameters.AddWithValue("@GpoGuid", gpo.GpoGuid);
                cmd.Parameters.AddWithValue("@CreatedTime", gpo.CreatedTime);
                cmd.Parameters.AddWithValue("@ModifiedTime", gpo.ModifiedTime);
                cmd.Parameters.AddWithValue("@RiskySettings", string.Join(",", gpo.RiskySettings));
                cmd.Parameters.AddWithValue("@HasScheduledTasks", gpo.HasScheduledTasks ? 1 : 0);
                cmd.Parameters.AddWithValue("@HasRegistryMods", gpo.HasRegistryMods ? 1 : 0);
                cmd.Parameters.AddWithValue("@HasFileOperations", gpo.HasFileOperations ? 1 : 0);
                cmd.Parameters.AddWithValue("@HasSoftwareInstallation", gpo.HasSoftwareInstallation ? 1 : 0);
                cmd.Parameters.AddWithValue("@HasLocalUserMods", gpo.HasLocalUserMods ? 1 : 0);
                cmd.Parameters.AddWithValue("@HasEnvironmentMods", gpo.HasEnvironmentMods ? 1 : 0);
                cmd.Parameters.AddWithValue("@Severity", gpo.Severity);
                await cmd.ExecuteNonQueryAsync();
            }
        }

        private async Task InsertSysvolFilesAsync(long runId, List<SysvolRiskyFile> files, SQLiteTransaction transaction)
        {
            if (files.Count == 0) return;

            var sql = @"
                INSERT INTO SysvolRiskyFiles (
                    RunId, FileName, FilePath, Extension, CreationTime, LastWriteTime,
                    FileSize, Sha256Hash, Severity
                ) VALUES (
                    @RunId, @FileName, @FilePath, @Extension, @CreationTime, @LastWriteTime,
                    @FileSize, @Sha256Hash, @Severity
                )";

            foreach (var file in files)
            {
                using var cmd = new SQLiteCommand(sql, _connection, transaction);
                cmd.Parameters.AddWithValue("@RunId", runId);
                cmd.Parameters.AddWithValue("@FileName", file.FileName);
                cmd.Parameters.AddWithValue("@FilePath", file.FilePath);
                cmd.Parameters.AddWithValue("@Extension", file.Extension);
                cmd.Parameters.AddWithValue("@CreationTime", file.CreationTime);
                cmd.Parameters.AddWithValue("@LastWriteTime", file.LastWriteTime);
                cmd.Parameters.AddWithValue("@FileSize", file.FileSize);
                cmd.Parameters.AddWithValue("@Sha256Hash", file.Sha256Hash);
                cmd.Parameters.AddWithValue("@Severity", file.Severity);
                await cmd.ExecuteNonQueryAsync();
            }
        }

        private async Task InsertKerberosDelegationsAsync(long runId, List<AdKerberosDelegation> delegations, SQLiteTransaction transaction)
        {
            if (delegations.Count == 0) return;

            var sql = @"
                INSERT INTO KerberosDelegations (
                    RunId, SamAccountName, DistinguishedName, ObjectClass, DelegationType,
                    AllowedToDelegateTo, AllowedToActOnBehalfOf, IsSensitive, Severity, Description
                ) VALUES (
                    @RunId, @SamAccountName, @DistinguishedName, @ObjectClass, @DelegationType,
                    @AllowedToDelegateTo, @AllowedToActOnBehalfOf, @IsSensitive, @Severity, @Description
                )";

            foreach (var del in delegations)
            {
                using var cmd = new SQLiteCommand(sql, _connection, transaction);
                cmd.Parameters.AddWithValue("@RunId", runId);
                cmd.Parameters.AddWithValue("@SamAccountName", del.SamAccountName);
                cmd.Parameters.AddWithValue("@DistinguishedName", del.DistinguishedName);
                cmd.Parameters.AddWithValue("@ObjectClass", del.ObjectClass);
                cmd.Parameters.AddWithValue("@DelegationType", del.DelegationType);
                cmd.Parameters.AddWithValue("@AllowedToDelegateTo", string.Join(";", del.AllowedToDelegateTo));
                cmd.Parameters.AddWithValue("@AllowedToActOnBehalfOf", string.Join(";", del.AllowedToActOnBehalfOf));
                cmd.Parameters.AddWithValue("@IsSensitive", del.IsSensitive ? 1 : 0);
                cmd.Parameters.AddWithValue("@Severity", del.Severity);
                cmd.Parameters.AddWithValue("@Description", del.Description);
                await cmd.ExecuteNonQueryAsync();
            }
        }

        private async Task InsertAdminCountAnomaliesAsync(long runId, List<AdAdminCountAnomaly> anomalies, SQLiteTransaction transaction)
        {
            if (anomalies.Count == 0) return;

            var sql = @"
                INSERT INTO AdminCountAnomalies (
                    RunId, SamAccountName, DistinguishedName, ObjectClass, AdminCount,
                    IsCurrentlyPrivileged, Issue
                ) VALUES (
                    @RunId, @SamAccountName, @DistinguishedName, @ObjectClass, @AdminCount,
                    @IsCurrentlyPrivileged, @Issue
                )";

            foreach (var anomaly in anomalies)
            {
                using var cmd = new SQLiteCommand(sql, _connection, transaction);
                cmd.Parameters.AddWithValue("@RunId", runId);
                cmd.Parameters.AddWithValue("@SamAccountName", anomaly.SamAccountName);
                cmd.Parameters.AddWithValue("@DistinguishedName", anomaly.DistinguishedName);
                cmd.Parameters.AddWithValue("@ObjectClass", anomaly.ObjectClass);
                cmd.Parameters.AddWithValue("@AdminCount", anomaly.AdminCount);
                cmd.Parameters.AddWithValue("@IsCurrentlyPrivileged", anomaly.IsCurrentlyPrivileged ? 1 : 0);
                cmd.Parameters.AddWithValue("@Issue", anomaly.Issue);
                await cmd.ExecuteNonQueryAsync();
            }
        }

        #endregion

        #region Query Analysis History

        /// <summary>
        /// Gets all analysis runs from the database.
        /// </summary>
        public async Task<List<StoredAnalysisRun>> GetAnalysisHistoryAsync(int limit = 100)
        {
            if (_connection == null) await InitializeAsync();

            var runs = new List<StoredAnalysisRun>();
            var sql = @"
                SELECT Id, AnalysisType, RunTime, TargetDomain, TargetTenantId,
                       TotalFindings, CriticalCount, HighCount, MediumCount, LowCount,
                       DurationSeconds, IsComplete
                FROM AnalysisRuns
                ORDER BY RunTime DESC
                LIMIT @Limit";

            using var cmd = new SQLiteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@Limit", limit);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                runs.Add(new StoredAnalysisRun
                {
                    Id = reader.GetInt64(0),
                    AnalysisType = reader.GetString(1),
                    RunTime = reader.GetDateTime(2),
                    TargetDomain = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    TargetTenantId = reader.IsDBNull(4) ? "" : reader.GetString(4),
                    TotalFindings = reader.GetInt32(5),
                    CriticalCount = reader.GetInt32(6),
                    HighCount = reader.GetInt32(7),
                    MediumCount = reader.GetInt32(8),
                    LowCount = reader.GetInt32(9),
                    DurationSeconds = reader.GetDouble(10),
                    IsComplete = reader.GetInt32(11) == 1
                });
            }

            return runs;
        }

        /// <summary>
        /// Gets full analysis result by run ID.
        /// </summary>
        public async Task<AdSecurityAnalysisResult?> GetAnalysisResultAsync(long runId)
        {
            if (_connection == null) await InitializeAsync();

            var result = new AdSecurityAnalysisResult();

            // Get main run info
            var runSql = "SELECT * FROM AnalysisRuns WHERE Id = @RunId";
            using (var cmd = new SQLiteCommand(runSql, _connection))
            {
                cmd.Parameters.AddWithValue("@RunId", runId);
                using var reader = await cmd.ExecuteReaderAsync();
                if (!await reader.ReadAsync()) return null;

                result.StartTime = reader.GetDateTime(reader.GetOrdinal("RunTime"));
                var durationSeconds = reader.GetDouble(reader.GetOrdinal("DurationSeconds"));
                result.EndTime = result.StartTime.AddSeconds(durationSeconds);
                result.CriticalCount = reader.GetInt32(reader.GetOrdinal("CriticalCount"));
                result.HighCount = reader.GetInt32(reader.GetOrdinal("HighCount"));
                result.MediumCount = reader.GetInt32(reader.GetOrdinal("MediumCount"));
                result.LowCount = reader.GetInt32(reader.GetOrdinal("LowCount"));
                result.IsComplete = reader.GetInt32(reader.GetOrdinal("IsComplete")) == 1;

                var domainJson = reader.IsDBNull(reader.GetOrdinal("DomainInfoJson")) 
                    ? null : reader.GetString(reader.GetOrdinal("DomainInfoJson"));
                if (!string.IsNullOrEmpty(domainJson))
                {
                    result.DomainInfo = JsonSerializer.Deserialize<AdDomainInfo>(domainJson) ?? new AdDomainInfo();
                }
            }

            // Get child records
            result.PrivilegedMembers = await GetPrivilegedMembersAsync(runId);
            result.RiskyAcls = await GetRiskyAclsAsync(runId);
            result.RiskyGpos = await GetRiskyGposAsync(runId);
            result.SysvolRiskyFiles = await GetSysvolFilesAsync(runId);
            result.KerberosDelegations = await GetKerberosDelegationsAsync(runId);
            result.AdminCountAnomalies = await GetAdminCountAnomaliesAsync(runId);

            return result;
        }

        private async Task<List<AdPrivilegedMember>> GetPrivilegedMembersAsync(long runId)
        {
            var members = new List<AdPrivilegedMember>();
            var sql = "SELECT * FROM PrivilegedMembers WHERE RunId = @RunId";

            using var cmd = new SQLiteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@RunId", runId);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                members.Add(new AdPrivilegedMember
                {
                    SamAccountName = reader.GetString(reader.GetOrdinal("SamAccountName")),
                    DistinguishedName = reader.GetString(reader.GetOrdinal("DistinguishedName")),
                    ObjectClass = reader.GetString(reader.GetOrdinal("ObjectClass")),
                    GroupName = reader.GetString(reader.GetOrdinal("GroupName")),
                    PasswordLastSet = reader.IsDBNull(reader.GetOrdinal("PasswordLastSet")) 
                        ? null : reader.GetDateTime(reader.GetOrdinal("PasswordLastSet")),
                    LastLogon = reader.IsDBNull(reader.GetOrdinal("LastLogon")) 
                        ? null : reader.GetDateTime(reader.GetOrdinal("LastLogon")),
                    PasswordNeverExpires = reader.GetInt32(reader.GetOrdinal("PasswordNeverExpires")) == 1,
                    TrustedForDelegation = reader.GetInt32(reader.GetOrdinal("TrustedForDelegation")) == 1,
                    HasSpn = reader.GetInt32(reader.GetOrdinal("HasSpn")) == 1,
                    IsEnabled = reader.GetInt32(reader.GetOrdinal("IsEnabled")) == 1,
                    IsNested = reader.GetInt32(reader.GetOrdinal("IsNested")) == 1,
                    NestedPath = reader.GetString(reader.GetOrdinal("NestedPath")),
                    RiskyUacFlags = reader.GetString(reader.GetOrdinal("RiskyUacFlags"))
                        .Split(',', StringSplitOptions.RemoveEmptyEntries).ToList()
                });
            }

            return members;
        }

        private async Task<List<AdRiskyAcl>> GetRiskyAclsAsync(long runId)
        {
            var acls = new List<AdRiskyAcl>();
            var sql = "SELECT * FROM RiskyAcls WHERE RunId = @RunId";

            using var cmd = new SQLiteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@RunId", runId);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                acls.Add(new AdRiskyAcl
                {
                    ObjectDn = reader.GetString(reader.GetOrdinal("ObjectDn")),
                    ObjectClass = reader.IsDBNull(reader.GetOrdinal("ObjectClass")) ? "" : reader.GetString(reader.GetOrdinal("ObjectClass")),
                    IdentityReference = reader.GetString(reader.GetOrdinal("IdentityReference")),
                    ActiveDirectoryRights = reader.GetString(reader.GetOrdinal("ActiveDirectoryRights")),
                    AccessControlType = reader.GetString(reader.GetOrdinal("AccessControlType")),
                    ObjectType = reader.GetString(reader.GetOrdinal("ObjectType")),
                    ObjectTypeName = reader.GetString(reader.GetOrdinal("ObjectTypeName")),
                    InheritedObjectType = reader.GetString(reader.GetOrdinal("InheritedObjectType")),
                    IsInherited = reader.GetInt32(reader.GetOrdinal("IsInherited")) == 1,
                    Severity = reader.GetString(reader.GetOrdinal("Severity")),
                    Description = reader.GetString(reader.GetOrdinal("Description"))
                });
            }

            return acls;
        }

        private async Task<List<AdRiskyGpo>> GetRiskyGposAsync(long runId)
        {
            var gpos = new List<AdRiskyGpo>();
            var sql = "SELECT * FROM RiskyGpos WHERE RunId = @RunId";

            using var cmd = new SQLiteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@RunId", runId);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                gpos.Add(new AdRiskyGpo
                {
                    GpoName = reader.GetString(reader.GetOrdinal("GpoName")),
                    GpoGuid = reader.GetString(reader.GetOrdinal("GpoGuid")),
                    CreatedTime = reader.GetDateTime(reader.GetOrdinal("CreatedTime")),
                    ModifiedTime = reader.GetDateTime(reader.GetOrdinal("ModifiedTime")),
                    RiskySettings = reader.GetString(reader.GetOrdinal("RiskySettings"))
                        .Split(',', StringSplitOptions.RemoveEmptyEntries).ToList(),
                    HasScheduledTasks = reader.GetInt32(reader.GetOrdinal("HasScheduledTasks")) == 1,
                    HasRegistryMods = reader.GetInt32(reader.GetOrdinal("HasRegistryMods")) == 1,
                    HasFileOperations = reader.GetInt32(reader.GetOrdinal("HasFileOperations")) == 1,
                    HasSoftwareInstallation = reader.GetInt32(reader.GetOrdinal("HasSoftwareInstallation")) == 1,
                    HasLocalUserMods = reader.GetInt32(reader.GetOrdinal("HasLocalUserMods")) == 1,
                    HasEnvironmentMods = reader.GetInt32(reader.GetOrdinal("HasEnvironmentMods")) == 1,
                    Severity = reader.GetString(reader.GetOrdinal("Severity"))
                });
            }

            return gpos;
        }

        private async Task<List<SysvolRiskyFile>> GetSysvolFilesAsync(long runId)
        {
            var files = new List<SysvolRiskyFile>();
            var sql = "SELECT * FROM SysvolRiskyFiles WHERE RunId = @RunId";

            using var cmd = new SQLiteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@RunId", runId);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                files.Add(new SysvolRiskyFile
                {
                    FileName = reader.GetString(reader.GetOrdinal("FileName")),
                    FilePath = reader.GetString(reader.GetOrdinal("FilePath")),
                    Extension = reader.GetString(reader.GetOrdinal("Extension")),
                    CreationTime = reader.GetDateTime(reader.GetOrdinal("CreationTime")),
                    LastWriteTime = reader.GetDateTime(reader.GetOrdinal("LastWriteTime")),
                    FileSize = reader.GetInt64(reader.GetOrdinal("FileSize")),
                    Sha256Hash = reader.GetString(reader.GetOrdinal("Sha256Hash")),
                    Severity = reader.GetString(reader.GetOrdinal("Severity"))
                });
            }

            return files;
        }

        private async Task<List<AdKerberosDelegation>> GetKerberosDelegationsAsync(long runId)
        {
            var delegations = new List<AdKerberosDelegation>();
            var sql = "SELECT * FROM KerberosDelegations WHERE RunId = @RunId";

            using var cmd = new SQLiteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@RunId", runId);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                delegations.Add(new AdKerberosDelegation
                {
                    SamAccountName = reader.GetString(reader.GetOrdinal("SamAccountName")),
                    DistinguishedName = reader.GetString(reader.GetOrdinal("DistinguishedName")),
                    ObjectClass = reader.GetString(reader.GetOrdinal("ObjectClass")),
                    DelegationType = reader.GetString(reader.GetOrdinal("DelegationType")),
                    AllowedToDelegateTo = reader.GetString(reader.GetOrdinal("AllowedToDelegateTo"))
                        .Split(';', StringSplitOptions.RemoveEmptyEntries).ToList(),
                    AllowedToActOnBehalfOf = reader.GetString(reader.GetOrdinal("AllowedToActOnBehalfOf"))
                        .Split(';', StringSplitOptions.RemoveEmptyEntries).ToList(),
                    IsSensitive = reader.GetInt32(reader.GetOrdinal("IsSensitive")) == 1,
                    Severity = reader.GetString(reader.GetOrdinal("Severity")),
                    Description = reader.GetString(reader.GetOrdinal("Description"))
                });
            }

            return delegations;
        }

        private async Task<List<AdAdminCountAnomaly>> GetAdminCountAnomaliesAsync(long runId)
        {
            var anomalies = new List<AdAdminCountAnomaly>();
            var sql = "SELECT * FROM AdminCountAnomalies WHERE RunId = @RunId";

            using var cmd = new SQLiteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@RunId", runId);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                anomalies.Add(new AdAdminCountAnomaly
                {
                    SamAccountName = reader.GetString(reader.GetOrdinal("SamAccountName")),
                    DistinguishedName = reader.GetString(reader.GetOrdinal("DistinguishedName")),
                    ObjectClass = reader.GetString(reader.GetOrdinal("ObjectClass")),
                    AdminCount = reader.GetInt32(reader.GetOrdinal("AdminCount")),
                    IsCurrentlyPrivileged = reader.GetInt32(reader.GetOrdinal("IsCurrentlyPrivileged")) == 1,
                    Issue = reader.GetString(reader.GetOrdinal("Issue"))
                });
            }

            return anomalies;
        }

        #endregion

        #region Export to Spreadsheet

        /// <summary>
        /// Exports an analysis run to CSV files (one per category).
        /// </summary>
        public async Task ExportToCsvAsync(long runId, string outputFolder)
        {
            if (!Directory.Exists(outputFolder))
                Directory.CreateDirectory(outputFolder);

            var result = await GetAnalysisResultAsync(runId);
            if (result == null) return;

            var timestamp = result.StartTime.ToString("yyyyMMdd_HHmmss");
            var domain = result.DomainInfo?.DomainFqdn ?? "unknown";

            // Export each category
            await ExportPrivilegedMembersToCsvAsync(result.PrivilegedMembers, 
                Path.Combine(outputFolder, $"{domain}_{timestamp}_PrivilegedMembers.csv"));

            await ExportRiskyAclsToCsvAsync(result.RiskyAcls,
                Path.Combine(outputFolder, $"{domain}_{timestamp}_RiskyACLs.csv"));

            await ExportRiskyGposToCsvAsync(result.RiskyGpos,
                Path.Combine(outputFolder, $"{domain}_{timestamp}_RiskyGPOs.csv"));

            await ExportSysvolFilesToCsvAsync(result.SysvolRiskyFiles,
                Path.Combine(outputFolder, $"{domain}_{timestamp}_SysvolFiles.csv"));

            await ExportKerberosDelegationsToCsvAsync(result.KerberosDelegations,
                Path.Combine(outputFolder, $"{domain}_{timestamp}_KerberosDelegation.csv"));

            await ExportAdminCountAnomaliesToCsvAsync(result.AdminCountAnomalies,
                Path.Combine(outputFolder, $"{domain}_{timestamp}_AdminCountAnomalies.csv"));

            // Export summary
            await ExportSummaryToCsvAsync(result,
                Path.Combine(outputFolder, $"{domain}_{timestamp}_Summary.csv"));
        }

        private async Task ExportPrivilegedMembersToCsvAsync(List<AdPrivilegedMember> members, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("SamAccountName,GroupName,ObjectClass,Enabled,PasswordNeverExpires,TrustedForDelegation,HasSPN,Nested,NestedPath,RiskyUACFlags,PasswordLastSet,LastLogon");

            foreach (var m in members)
            {
                sb.AppendLine($"\"{m.SamAccountName}\",\"{m.GroupName}\",\"{m.ObjectClass}\",{m.IsEnabled},{m.PasswordNeverExpires},{m.TrustedForDelegation},{m.HasSpn},{m.IsNested},\"{m.NestedPath}\",\"{string.Join(";", m.RiskyUacFlags)}\",{m.PasswordLastSet:yyyy-MM-dd HH:mm:ss},{m.LastLogon:yyyy-MM-dd HH:mm:ss}");
            }

            await File.WriteAllTextAsync(filePath, sb.ToString());
        }

        private async Task ExportRiskyAclsToCsvAsync(List<AdRiskyAcl> acls, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("ObjectDN,IdentityReference,Rights,ObjectType,ObjectTypeName,Severity,AccessControlType,Description");

            foreach (var a in acls)
            {
                sb.AppendLine($"\"{a.ObjectDn}\",\"{a.IdentityReference}\",\"{a.ActiveDirectoryRights}\",\"{a.ObjectType}\",\"{a.ObjectTypeName}\",{a.Severity},{a.AccessControlType},\"{a.Description}\"");
            }

            await File.WriteAllTextAsync(filePath, sb.ToString());
        }

        private async Task ExportRiskyGposToCsvAsync(List<AdRiskyGpo> gpos, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("GpoName,GpoGuid,Severity,ScheduledTasks,RegistryMods,FileOps,SoftwareInstall,UserMods,EnvMods,CreatedTime,ModifiedTime,RiskySettings");

            foreach (var g in gpos)
            {
                sb.AppendLine($"\"{g.GpoName}\",\"{g.GpoGuid}\",{g.Severity},{g.HasScheduledTasks},{g.HasRegistryMods},{g.HasFileOperations},{g.HasSoftwareInstallation},{g.HasLocalUserMods},{g.HasEnvironmentMods},{g.CreatedTime:yyyy-MM-dd HH:mm:ss},{g.ModifiedTime:yyyy-MM-dd HH:mm:ss},\"{string.Join(";", g.RiskySettings)}\"");
            }

            await File.WriteAllTextAsync(filePath, sb.ToString());
        }

        private async Task ExportSysvolFilesToCsvAsync(List<SysvolRiskyFile> files, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("FileName,FilePath,Extension,Severity,FileSize,SHA256,CreationTime,LastWriteTime");

            foreach (var f in files)
            {
                sb.AppendLine($"\"{f.FileName}\",\"{f.FilePath}\",\"{f.Extension}\",{f.Severity},{f.FileSize},{f.Sha256Hash},{f.CreationTime:yyyy-MM-dd HH:mm:ss},{f.LastWriteTime:yyyy-MM-dd HH:mm:ss}");
            }

            await File.WriteAllTextAsync(filePath, sb.ToString());
        }

        private async Task ExportKerberosDelegationsToCsvAsync(List<AdKerberosDelegation> delegations, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("SamAccountName,ObjectClass,DelegationType,Severity,AllowedToDelegateTo,Description");

            foreach (var d in delegations)
            {
                sb.AppendLine($"\"{d.SamAccountName}\",\"{d.ObjectClass}\",\"{d.DelegationType}\",{d.Severity},\"{string.Join(";", d.AllowedToDelegateTo)}\",\"{d.Description}\"");
            }

            await File.WriteAllTextAsync(filePath, sb.ToString());
        }

        private async Task ExportAdminCountAnomaliesToCsvAsync(List<AdAdminCountAnomaly> anomalies, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("SamAccountName,ObjectClass,AdminCount,IsCurrentlyPrivileged,Issue");

            foreach (var a in anomalies)
            {
                sb.AppendLine($"\"{a.SamAccountName}\",\"{a.ObjectClass}\",{a.AdminCount},{a.IsCurrentlyPrivileged},\"{a.Issue}\"");
            }

            await File.WriteAllTextAsync(filePath, sb.ToString());
        }

        private async Task ExportSummaryToCsvAsync(AdSecurityAnalysisResult result, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Property,Value");
            sb.AppendLine($"Domain,{result.DomainInfo?.DomainFqdn}");
            sb.AppendLine($"DomainController,{result.DomainInfo?.ChosenDc}");
            sb.AppendLine($"AnalysisTime,{result.StartTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Duration,{result.Duration.TotalSeconds:F1} seconds");
            sb.AppendLine($"TotalFindings,{result.TotalFindings}");
            sb.AppendLine($"CriticalFindings,{result.CriticalCount}");
            sb.AppendLine($"HighFindings,{result.HighCount}");
            sb.AppendLine($"MediumFindings,{result.MediumCount}");
            sb.AppendLine($"LowFindings,{result.LowCount}");
            sb.AppendLine($"PrivilegedMembers,{result.PrivilegedMembers.Count}");
            sb.AppendLine($"RiskyACLs,{result.RiskyAcls.Count}");
            sb.AppendLine($"RiskyGPOs,{result.RiskyGpos.Count}");
            sb.AppendLine($"SysvolRiskyFiles,{result.SysvolRiskyFiles.Count}");
            sb.AppendLine($"KerberosDelegations,{result.KerberosDelegations.Count}");
            sb.AppendLine($"AdminCountAnomalies,{result.AdminCountAnomalies.Count}");

            await File.WriteAllTextAsync(filePath, sb.ToString());
        }

        /// <summary>
        /// Deletes an analysis run and all its child records.
        /// </summary>
        public async Task DeleteAnalysisRunAsync(long runId)
        {
            if (_connection == null) await InitializeAsync();

            var sql = "DELETE FROM AnalysisRuns WHERE Id = @RunId";
            using var cmd = new SQLiteCommand(sql, _connection);
            cmd.Parameters.AddWithValue("@RunId", runId);
            await cmd.ExecuteNonQueryAsync();
        }

        /// <summary>
        /// Clears all analysis history.
        /// </summary>
        public async Task ClearAllHistoryAsync()
        {
            if (_connection == null) await InitializeAsync();

            var tables = new[] 
            { 
                "AdminCountAnomalies", "KerberosDelegations", "SysvolRiskyFiles", 
                "RiskyGpos", "RiskyAcls", "PrivilegedMembers", "EntraIdCaPolicies",
                "EntraIdRiskyApps", "EntraIdPrivilegedRoles", "AnalysisRuns" 
            };

            foreach (var table in tables)
            {
                var sql = $"DELETE FROM {table}";
                using var cmd = new SQLiteCommand(sql, _connection);
                await cmd.ExecuteNonQueryAsync();
            }
        }

        #endregion

        #region Dispose

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                _connection?.Close();
                _connection?.Dispose();
            }

            _disposed = true;
        }

        #endregion
    }
}

