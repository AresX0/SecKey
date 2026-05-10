using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;

namespace SecKey.Core.Services
{
    public interface ISystemAuditService
    {
        Task<List<AuditItem>> RunFullAudit();
        Task<List<AuditItem>> AuditFilePermissions(string path);
        Task<List<AuditItem>> AuditFirewall();
        Task<List<AuditItem>> AuditFirewallRules();
        Task<List<AuditItem>> AuditWindowsUpdates();
        Task<List<AuditItem>> AuditInstalledSoftware();
        Task<List<AuditItem>> AuditStartupItems();
        Task<List<AuditItem>> AuditSensitiveDirectoriesAcl();
        Task<List<AuditItem>> AuditAdministrativeAccounts();
        Task<List<AuditItem>> AuditAntivirusStatus();
        Task<List<AuditItem>> ScanElevatedUsers();
        Task<List<AuditItem>> ScanCriticalAcls();
        Task<List<AuditItem>> ScanOutboundTraffic();
        Task<List<AuditItem>> ScanInboundTraffic();
        Task<bool> DisableUser(string username);
        Task<bool> DeleteUser(string username);
        Task<bool> ResetUserPassword(string username, string newPassword);
        Task<bool> FixIssue(AuditItem item);
        void OpenUsersAndGroups();
    }

    public class AuditItem
    {
        public string Category { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public AuditSeverity Severity { get; set; }
        public AuditStatus Status { get; set; }
        public string Details { get; set; } = string.Empty;
        public string? FixAction { get; set; }
        public bool CanAutoFix { get; set; }
    }

    public enum AuditSeverity
    {
        Info,
        Warning,
        Critical
    }

    public enum AuditStatus
    {
        Pass,
        Fail,
        Unknown
    }

    public class SystemAuditService : ISystemAuditService
    {
        public async Task<List<AuditItem>> RunFullAudit()
        {
            var items = new List<AuditItem>();

            try
            {
                items.AddRange(await AuditFirewall());
                items.AddRange(await AuditFirewallRules());
                items.AddRange(await AuditWindowsUpdates());
                items.AddRange(await AuditStartupItems());
                items.AddRange(await AuditSystemSettings());
                items.AddRange(await AuditSensitiveDirectoriesAcl());
                items.AddRange(await AuditAdministrativeAccounts());
                items.AddRange(await AuditAntivirusStatus());
            }
            catch (Exception ex)
            {
                items.Add(new AuditItem
                {
                    Category = "System",
                    Name = "Audit Error",
                    Description = ex.Message,
                    Severity = AuditSeverity.Warning,
                    Status = AuditStatus.Unknown,
                    Details = ex.StackTrace ?? string.Empty
                });
            }

            return items;
        }

        public async Task<List<AuditItem>> AuditFilePermissions(string path)
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    if (!Directory.Exists(path) && !File.Exists(path))
                    {
                        items.Add(new AuditItem
                        {
                            Category = "File Permissions",
                            Name = path,
                            Description = "Path not found",
                            Severity = AuditSeverity.Warning,
                            Status = AuditStatus.Fail
                        });
                        return;
                    }

                    var info = new FileInfo(path);
                    var security = info.GetAccessControl();
                    var rules = security.GetAccessRules(true, true, typeof(NTAccount));

                    foreach (AuthorizationRule rule in rules)
                    {
                        var fsRule = rule as FileSystemAccessRule;
                        if (fsRule != null)
                        {
                            var severity = DeterminePermissionSeverity(fsRule);
                            items.Add(new AuditItem
                            {
                                Category = "File Permissions",
                                Name = fsRule.IdentityReference.Value,
                                Description = $"{fsRule.FileSystemRights} - {fsRule.AccessControlType}",
                                Severity = severity,
                                Status = severity == AuditSeverity.Critical ? AuditStatus.Fail : AuditStatus.Pass,
                                Details = path
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "File Permissions",
                        Name = "Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown
                    });
                }
            });

            return items;
        }

        public async Task<List<AuditItem>> AuditFirewall()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "advfirewall show allprofiles state",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(startInfo);
                    if (process != null)
                    {
                        var output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        var isEnabled = output.Contains("State                                 ON");
                        items.Add(new AuditItem
                        {
                            Category = "Firewall",
                            Name = "Windows Firewall",
                            Description = isEnabled ? "Firewall is enabled" : "Firewall is disabled",
                            Severity = isEnabled ? AuditSeverity.Info : AuditSeverity.Critical,
                            Status = isEnabled ? AuditStatus.Pass : AuditStatus.Fail,
                            CanAutoFix = !isEnabled,
                            FixAction = "netsh advfirewall set allprofiles state on"
                        });
                    }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "Firewall",
                        Name = "Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown
                    });
                }
            });

            return items;
        }

        public async Task<List<AuditItem>> AuditWindowsUpdates()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = "-Command \"Get-HotFix | Select-Object -First 1 -Property InstalledOn | ConvertTo-Json\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(startInfo);
                    if (process != null)
                    {
                        var output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        var hasRecentUpdates = !string.IsNullOrEmpty(output);
                        items.Add(new AuditItem
                        {
                            Category = "Windows Updates",
                            Name = "Update Status",
                            Description = hasRecentUpdates ? "Updates are installed" : "No recent updates found",
                            Severity = hasRecentUpdates ? AuditSeverity.Info : AuditSeverity.Warning,
                            Status = hasRecentUpdates ? AuditStatus.Pass : AuditStatus.Fail,
                            Details = output
                        });
                    }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "Windows Updates",
                        Name = "Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown
                    });
                }
            });

            return items;
        }

        public async Task<List<AuditItem>> AuditInstalledSoftware()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    // Use registry instead of WMI Win32_Product for better performance
                    var uninstallKeys = new[]
                    {
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                    };

                    var count = 0;
                    foreach (var keyPath in uninstallKeys)
                    {
                        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath);
                        if (key != null)
                        {
                            foreach (var subKeyName in key.GetSubKeyNames())
                            {
                                try
                                {
                                    using var subKey = key.OpenSubKey(subKeyName);
                                    if (subKey != null)
                                    {
                                        var displayName = subKey.GetValue("DisplayName")?.ToString();
                                        var displayVersion = subKey.GetValue("DisplayVersion")?.ToString();
                                        
                                        if (!string.IsNullOrEmpty(displayName))
                                        {
                                            items.Add(new AuditItem
                                            {
                                                Category = "Installed Software",
                                                Name = displayName,
                                                Description = $"Version: {displayVersion ?? "Unknown"}",
                                                Severity = AuditSeverity.Info,
                                                Status = AuditStatus.Pass
                                            });
                                            
                                            count++;
                                            if (count >= 100) break; // Limit to first 100
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                        
                        if (count >= 100) break;
                    }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "Installed Software",
                        Name = "Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown
                    });
                }
            });

            return items;
        }

        public async Task<List<AuditItem>> AuditStartupItems()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    // Check registry startup items
                    var startupKeys = new[]
                    {
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                    };

                    foreach (var keyPath in startupKeys)
                    {
                        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath);
                        if (key != null)
                        {
                            foreach (var valueName in key.GetValueNames())
                            {
                                var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                                items.Add(new AuditItem
                                {
                                    Category = "Startup Items",
                                    Name = valueName,
                                    Description = value,
                                    Severity = AuditSeverity.Info,
                                    Status = AuditStatus.Pass,
                                    Details = keyPath
                                });
                            }
                        }
                    }

                    // Check startup folder
                    var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                    if (Directory.Exists(startupFolder))
                    {
                        foreach (var file in Directory.GetFiles(startupFolder))
                        {
                            items.Add(new AuditItem
                            {
                                Category = "Startup Items",
                                Name = Path.GetFileName(file),
                                Description = file,
                                Severity = AuditSeverity.Info,
                                Status = AuditStatus.Pass,
                                Details = "Startup Folder"
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "Startup Items",
                        Name = "Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown
                    });
                }
            });

            return items;
        }

        private async Task<List<AuditItem>> AuditSystemSettings()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                // Check UAC
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                    if (key != null)
                    {
                        var uacEnabled = (int?)key.GetValue("EnableLUA") == 1;
                        items.Add(new AuditItem
                        {
                            Category = "System Settings",
                            Name = "UAC (User Account Control)",
                            Description = uacEnabled ? "UAC is enabled" : "UAC is disabled",
                            Severity = uacEnabled ? AuditSeverity.Info : AuditSeverity.Critical,
                            Status = uacEnabled ? AuditStatus.Pass : AuditStatus.Fail,
                            CanAutoFix = !uacEnabled,
                            FixAction = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f"
                        });
                    }
                }
                catch { }

                // Check Windows Defender
                try
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = "-Command \"Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled | ConvertTo-Json\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(startInfo);
                    if (process != null)
                    {
                        var output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        var defenderEnabled = output.Contains("true");
                        items.Add(new AuditItem
                        {
                            Category = "System Settings",
                            Name = "Windows Defender",
                            Description = defenderEnabled ? "Real-time protection enabled" : "Real-time protection disabled",
                            Severity = defenderEnabled ? AuditSeverity.Info : AuditSeverity.Critical,
                            Status = defenderEnabled ? AuditStatus.Pass : AuditStatus.Fail
                        });
                    }
                }
                catch { }
            });

            return items;
        }

        public async Task<List<AuditItem>> AuditFirewallRules()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    // Get inbound rules
                    var inboundInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "advfirewall firewall show rule name=all dir=in",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var inboundProcess = Process.Start(inboundInfo);
                    if (inboundProcess != null)
                    {
                        var output = inboundProcess.StandardOutput.ReadToEnd();
                        inboundProcess.WaitForExit();

                        var rules = ParseFirewallRules(output, "Inbound");
                        items.AddRange(rules);
                    }

                    // Get outbound rules
                    var outboundInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "advfirewall firewall show rule name=all dir=out",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var outboundProcess = Process.Start(outboundInfo);
                    if (outboundProcess != null)
                    {
                        var output = outboundProcess.StandardOutput.ReadToEnd();
                        outboundProcess.WaitForExit();

                        var rules = ParseFirewallRules(output, "Outbound");
                        items.AddRange(rules);
                    }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "Firewall Rules",
                        Name = "Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown
                    });
                }
            });

            return items;
        }

        public async Task<List<AuditItem>> AuditSensitiveDirectoriesAcl()
        {
            var items = new List<AuditItem>();

            var sensitiveDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "config")
            };

            foreach (var dir in sensitiveDirs)
            {
                if (Directory.Exists(dir))
                {
                    var aclItems = await AuditFilePermissions(dir);
                    items.AddRange(aclItems);
                }
            }

            return items;
        }

        public async Task<List<AuditItem>> AuditAdministrativeAccounts()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = "localgroup Administrators",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(startInfo);
                    if (process != null)
                    {
                        var output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        var inMemberList = false;

                        foreach (var line in lines)
                        {
                            var trimmed = line.Trim();
                            
                            if (trimmed.StartsWith("-----"))
                            {
                                inMemberList = true;
                                continue;
                            }

                            if (inMemberList && !string.IsNullOrWhiteSpace(trimmed) && 
                                !trimmed.StartsWith("The command"))
                            {
                                items.Add(new AuditItem
                                {
                                    Category = "Administrative Accounts",
                                    Name = trimmed,
                                    Description = "Member of Administrators group",
                                    Severity = AuditSeverity.Info,
                                    Status = AuditStatus.Pass,
                                    Details = "Has full administrative control"
                                });
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "Administrative Accounts",
                        Name = "Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown
                    });
                }
            });

            return items;
        }

        public async Task<List<AuditItem>> AuditAntivirusStatus()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    // Check Windows Defender
                    var defenderInfo = new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = "-Command \"Get-MpComputerStatus | ConvertTo-Json\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(defenderInfo);
                    if (process != null)
                    {
                        var output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        var realtimeEnabled = output.Contains("\"RealTimeProtectionEnabled\": true");
                        var antivirusEnabled = output.Contains("\"AntivirusEnabled\": true");
                        var antispywareEnabled = output.Contains("\"AntispywareEnabled\": true");

                        items.Add(new AuditItem
                        {
                            Category = "Antivirus Protection",
                            Name = "Windows Defender - Real-time Protection",
                            Description = realtimeEnabled ? "Enabled" : "Disabled",
                            Severity = realtimeEnabled ? AuditSeverity.Info : AuditSeverity.Critical,
                            Status = realtimeEnabled ? AuditStatus.Pass : AuditStatus.Fail,
                            CanAutoFix = !realtimeEnabled,
                            FixAction = "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $false\""
                        });

                        items.Add(new AuditItem
                        {
                            Category = "Antivirus Protection",
                            Name = "Windows Defender - Antivirus",
                            Description = antivirusEnabled ? "Enabled" : "Disabled",
                            Severity = antivirusEnabled ? AuditSeverity.Info : AuditSeverity.Critical,
                            Status = antivirusEnabled ? AuditStatus.Pass : AuditStatus.Fail,
                            CanAutoFix = !antivirusEnabled,
                            FixAction = "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $false\""
                        });

                        items.Add(new AuditItem
                        {
                            Category = "Antivirus Protection",
                            Name = "Windows Defender - Antispyware",
                            Description = antispywareEnabled ? "Enabled" : "Disabled",
                            Severity = antispywareEnabled ? AuditSeverity.Info : AuditSeverity.Critical,
                            Status = antispywareEnabled ? AuditStatus.Pass : AuditStatus.Fail,
                            CanAutoFix = !antispywareEnabled,
                            FixAction = "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $false\""
                        });

                        // Get signature information
                        if (output.Contains("AntivirusSignatureLastUpdated"))
                        {
                            var lastUpdateMatch = System.Text.RegularExpressions.Regex.Match(
                                output, 
                                @"""AntivirusSignatureLastUpdated"":\s*""([^""]+)"""
                            );
                            
                            if (lastUpdateMatch.Success)
                            {
                                items.Add(new AuditItem
                                {
                                    Category = "Antivirus Protection",
                                    Name = "Signature Last Updated",
                                    Description = lastUpdateMatch.Groups[1].Value,
                                    Severity = AuditSeverity.Info,
                                    Status = AuditStatus.Pass
                                });
                            }
                        }
                    }

                    // Check for other antivirus via WMI
                    try
                    {
                        var wmiInfo = new ProcessStartInfo
                        {
                            FileName = "powershell",
                            Arguments = "-Command \"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName, productState | ConvertTo-Json\"",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        };

                        using var wmiProcess = Process.Start(wmiInfo);
                        if (wmiProcess != null)
                        {
                            var wmiOutput = wmiProcess.StandardOutput.ReadToEnd();
                            wmiProcess.WaitForExit();

                            if (!string.IsNullOrWhiteSpace(wmiOutput) && wmiOutput.Contains("displayName"))
                            {
                                items.Add(new AuditItem
                                {
                                    Category = "Antivirus Protection",
                                    Name = "Installed Antivirus Products",
                                    Description = "See details for list",
                                    Severity = AuditSeverity.Info,
                                    Status = AuditStatus.Pass,
                                    Details = wmiOutput
                                });
                            }
                        }
                    }
                    catch { }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "Antivirus Protection",
                        Name = "Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown
                    });
                }
            });

            return items;
        }

        private List<AuditItem> ParseFirewallRules(string output, string direction)
        {
            var items = new List<AuditItem>();
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            
            string? ruleName = null;
            string? action = null;
            string? profile = null;
            string? localPort = null;
            string? remotePort = null;
            
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                
                if (trimmed.StartsWith("Rule Name:"))
                {
                    // Save previous rule
                    if (ruleName != null)
                    {
                        items.Add(new AuditItem
                        {
                            Category = $"Firewall Rules ({direction})",
                            Name = ruleName,
                            Description = $"{action ?? "Unknown"} - {profile ?? "All Profiles"}",
                            Severity = action == "Block" ? AuditSeverity.Info : AuditSeverity.Info,
                            Status = AuditStatus.Pass,
                            Details = $"Local Port: {localPort ?? "Any"}, Remote Port: {remotePort ?? "Any"}"
                        });
                    }
                    
                    ruleName = trimmed.Substring("Rule Name:".Length).Trim();
                    action = null;
                    profile = null;
                    localPort = null;
                    remotePort = null;
                }
                else if (trimmed.StartsWith("Action:"))
                {
                    action = trimmed.Substring("Action:".Length).Trim();
                }
                else if (trimmed.StartsWith("Profiles:"))
                {
                    profile = trimmed.Substring("Profiles:".Length).Trim();
                }
                else if (trimmed.StartsWith("LocalPort:"))
                {
                    localPort = trimmed.Substring("LocalPort:".Length).Trim();
                }
                else if (trimmed.StartsWith("RemotePort:"))
                {
                    remotePort = trimmed.Substring("RemotePort:".Length).Trim();
                }
            }
            
            // Save last rule
            if (ruleName != null)
            {
                items.Add(new AuditItem
                {
                    Category = $"Firewall Rules ({direction})",
                    Name = ruleName,
                    Description = $"{action ?? "Unknown"} - {profile ?? "All Profiles"}",
                    Severity = action == "Block" ? AuditSeverity.Info : AuditSeverity.Info,
                    Status = AuditStatus.Pass,
                    Details = $"Local Port: {localPort ?? "Any"}, Remote Port: {remotePort ?? "Any"}"
                });
            }

            return items;
        }

        public async Task<List<AuditItem>> ScanElevatedUsers()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    // Get all local users
                    var allUsersInfo = new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = "user",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using var allUsersProcess = Process.Start(allUsersInfo);
                    if (allUsersProcess != null)
                    {
                        var output = allUsersProcess.StandardOutput.ReadToEnd();
                        allUsersProcess.WaitForExit();

                        // Parse user names from the output
                        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        var userNames = new List<string>();
                        var inUserList = false;

                        foreach (var line in lines)
                        {
                            var trimmed = line.Trim();
                            
                            if (trimmed.StartsWith("-----"))
                            {
                                inUserList = true;
                                continue;
                            }

                            if (!inUserList) continue;

                            // Skip footer lines
                            if (trimmed.StartsWith("The command") || 
                                trimmed.Contains("completed successfully") ||
                                string.IsNullOrWhiteSpace(trimmed))
                                continue;

                            // Split by whitespace to get individual user names
                            var names = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            userNames.AddRange(names);
                        }

                        // Check each user's group membership
                        foreach (var userName in userNames.Distinct())
                        {
                            try
                            {
                                var userGroupsInfo = new ProcessStartInfo
                                {
                                    FileName = "net",
                                    Arguments = $"user \"{userName}\"",
                                    UseShellExecute = false,
                                    RedirectStandardOutput = true,
                                    RedirectStandardError = true,
                                    CreateNoWindow = true
                                };

                                using var userProcess = Process.Start(userGroupsInfo);
                                if (userProcess != null)
                                {
                                    var userOutput = userProcess.StandardOutput.ReadToEnd();
                                    userProcess.WaitForExit();

                                    // Check if user is in any admin group
                                    var lowerOutput = userOutput.ToLower();
                                    var adminGroups = new List<string>();
                                    
                                    if (lowerOutput.Contains("*administrators"))
                                        adminGroups.Add("Administrators");
                                    if (lowerOutput.Contains("*domain admins"))
                                        adminGroups.Add("Domain Admins");
                                    if (lowerOutput.Contains("*enterprise admins"))
                                        adminGroups.Add("Enterprise Admins");
                                    if (lowerOutput.Contains("*schema admins"))
                                        adminGroups.Add("Schema Admins");

                                    if (adminGroups.Any())
                                    {
                                        items.Add(new AuditItem
                                        {
                                            Category = "Elevated Users",
                                            Name = userName,
                                            Description = $"Member of: {string.Join(", ", adminGroups)}",
                                            Severity = AuditSeverity.Warning,
                                            Status = AuditStatus.Pass,
                                            Details = "User has administrative privileges. Review if elevated access is necessary."
                                        });
                                    }
                                }
                            }
                            catch (Exception userEx)
                            {
                                // Log but continue with other users
                                System.Diagnostics.Debug.WriteLine($"Error checking user {userName}: {userEx.Message}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "Elevated Users",
                        Name = "Scan Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown,
                        Details = ex.ToString()
                    });
                }
            });

            return items;
        }

        public async Task<List<AuditItem>> ScanCriticalAcls()
        {
            var items = new List<AuditItem>();

            var criticalPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "config"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)),
                @"C:\Windows\Tasks",
                @"C:\Windows\System32\Tasks"
            };

            foreach (var path in criticalPaths)
            {
                if (Directory.Exists(path))
                {
                    await Task.Run(() =>
                    {
                        try
                        {
                            var dirInfo = new DirectoryInfo(path);
                            var security = dirInfo.GetAccessControl();
                            var rules = security.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

                            foreach (System.Security.AccessControl.AuthorizationRule rule in rules)
                            {
                                var fsRule = rule as System.Security.AccessControl.FileSystemAccessRule;
                                if (fsRule != null)
                                {
                                    // Check for critical issues
                                    var identity = fsRule.IdentityReference.Value;
                                    var isCritical = false;
                                    var issue = "";

                                    if ((identity.Contains("Everyone") || identity.Contains("Users")) &&
                                        fsRule.AccessControlType == System.Security.AccessControl.AccessControlType.Allow)
                                    {
                                        if (fsRule.FileSystemRights.HasFlag(System.Security.AccessControl.FileSystemRights.FullControl))
                                        {
                                            isCritical = true;
                                            issue = $"Full Control granted to {identity}";
                                        }
                                        else if (fsRule.FileSystemRights.HasFlag(System.Security.AccessControl.FileSystemRights.Modify) ||
                                                 fsRule.FileSystemRights.HasFlag(System.Security.AccessControl.FileSystemRights.Write))
                                        {
                                            isCritical = true;
                                            issue = $"Write/Modify access granted to {identity}";
                                        }
                                    }

                                    if (isCritical)
                                    {
                                        items.Add(new AuditItem
                                        {
                                            Category = "Critical ACL",
                                            Name = Path.GetFileName(path),
                                            Description = issue,
                                            Severity = AuditSeverity.Critical,
                                            Status = AuditStatus.Fail,
                                            Details = path
                                        });
                                    }
                                }
                            }
                        }
                        catch { }
                    });
                }
            }

            return items;
        }

        public async Task<List<AuditItem>> ScanOutboundTraffic()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    // Get active network connections
                    var netstatInfo = new ProcessStartInfo
                    {
                        FileName = "netstat",
                        Arguments = "-ano",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(netstatInfo);
                    if (process != null)
                    {
                        var output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        var outboundCount = 0;

                        foreach (var line in lines)
                        {
                            if (line.Contains("ESTABLISHED") && line.Trim().StartsWith("TCP"))
                            {
                                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 5)
                                {
                                    var localAddress = parts[1];
                                    var foreignAddress = parts[2];
                                    var pid = parts[4];

                                    // Check if it's outbound (not loopback)
                                    if (!foreignAddress.StartsWith("127.0.0.1") && 
                                        !foreignAddress.StartsWith("[::1]"))
                                    {
                                        outboundCount++;
                                        
                                        // Get process name
                                        string processName = "Unknown";
                                        try
                                        {
                                            var proc = Process.GetProcessById(int.Parse(pid));
                                            processName = proc.ProcessName;
                                        }
                                        catch { }

                                        items.Add(new AuditItem
                                        {
                                            Category = "Outbound Traffic",
                                            Name = processName,
                                            Description = $"{localAddress} → {foreignAddress}",
                                            Severity = AuditSeverity.Info,
                                            Status = AuditStatus.Pass,
                                            Details = $"PID: {pid}"
                                        });

                                        if (outboundCount >= 50) break; // Limit results
                                    }
                                }
                            }
                        }
                    }

                    // Also check firewall outbound rules
                    var firewallInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "advfirewall firewall show rule name=all dir=out",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var fwProcess = Process.Start(firewallInfo);
                    if (fwProcess != null)
                    {
                        var fwOutput = fwProcess.StandardOutput.ReadToEnd();
                        fwProcess.WaitForExit();

                        var blockCount = 0;
                        foreach (var line in fwOutput.Split('\n'))
                        {
                            if (line.Contains("Action:") && line.Contains("Block"))
                            {
                                blockCount++;
                            }
                        }

                        items.Add(new AuditItem
                        {
                            Category = "Outbound Traffic",
                            Name = "Firewall Blocked Outbound",
                            Description = $"{blockCount} outbound blocking rules configured",
                            Severity = AuditSeverity.Info,
                            Status = AuditStatus.Pass
                        });
                    }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "Outbound Traffic",
                        Name = "Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown
                    });
                }
            });

            return items;
        }

        public async Task<List<AuditItem>> ScanInboundTraffic()
        {
            var items = new List<AuditItem>();

            await Task.Run(() =>
            {
                try
                {
                    // Get listening ports
                    var netstatInfo = new ProcessStartInfo
                    {
                        FileName = "netstat",
                        Arguments = "-ano",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(netstatInfo);
                    if (process != null)
                    {
                        var output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        var inboundCount = 0;

                        foreach (var line in lines)
                        {
                            // Look for LISTENING or ESTABLISHED inbound connections
                            if ((line.Contains("LISTENING") || line.Contains("ESTABLISHED")) && 
                                (line.Trim().StartsWith("TCP") || line.Trim().StartsWith("UDP")))
                            {
                                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 4)
                                {
                                    var protocol = parts[0];
                                    var localAddress = parts[1];
                                    var state = line.Contains("LISTENING") ? "LISTENING" : "ESTABLISHED";
                                    var pid = parts.Length >= 5 ? parts[4] : parts[3];

                                    // For LISTENING ports, show what's accepting connections
                                    if (state == "LISTENING")
                                    {
                                        inboundCount++;
                                        
                                        // Get process name
                                        string processName = "Unknown";
                                        try
                                        {
                                            var proc = Process.GetProcessById(int.Parse(pid));
                                            processName = proc.ProcessName;
                                        }
                                        catch { }

                                        items.Add(new AuditItem
                                        {
                                            Category = "Inbound Traffic",
                                            Name = processName,
                                            Description = $"{protocol} listening on {localAddress}",
                                            Severity = AuditSeverity.Info,
                                            Status = AuditStatus.Pass,
                                            Details = $"PID: {pid}"
                                        });

                                        if (inboundCount >= 50) break; // Limit results
                                    }
                                }
                            }
                        }
                    }

                    // Check firewall inbound rules
                    var firewallInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "advfirewall firewall show rule name=all dir=in",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var fwProcess = Process.Start(firewallInfo);
                    if (fwProcess != null)
                    {
                        var fwOutput = fwProcess.StandardOutput.ReadToEnd();
                        fwProcess.WaitForExit();

                        var allowCount = 0;
                        var blockCount = 0;
                        foreach (var line in fwOutput.Split('\n'))
                        {
                            if (line.Contains("Action:") && line.Contains("Allow"))
                            {
                                allowCount++;
                            }
                            else if (line.Contains("Action:") && line.Contains("Block"))
                            {
                                blockCount++;
                            }
                        }

                        items.Add(new AuditItem
                        {
                            Category = "Inbound Traffic",
                            Name = "Firewall Inbound Rules",
                            Description = $"{allowCount} allow rules, {blockCount} block rules configured",
                            Severity = AuditSeverity.Info,
                            Status = AuditStatus.Pass
                        });
                    }
                }
                catch (Exception ex)
                {
                    items.Add(new AuditItem
                    {
                        Category = "Inbound Traffic",
                        Name = "Error",
                        Description = ex.Message,
                        Severity = AuditSeverity.Warning,
                        Status = AuditStatus.Unknown
                    });
                }
            });

            return items;
        }

        public async Task<bool> DisableUser(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            try
            {
                await Task.Run(() =>
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = $"user \"{username}\" /active:no",
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(startInfo);
                    process?.WaitForExit();
                });

                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> DeleteUser(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            try
            {
                await Task.Run(() =>
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = $"user \"{username}\" /delete",
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(startInfo);
                    process?.WaitForExit();
                });

                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> ResetUserPassword(string username, string newPassword)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(newPassword))
                return false;

            try
            {
                await Task.Run(() =>
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = $"user \"{username}\" \"{newPassword}\"",
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(startInfo);
                    process?.WaitForExit();
                });

                return true;
            }
            catch
            {
                return false;
            }
        }

        public void OpenUsersAndGroups()
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "lusrmgr.msc",
                    UseShellExecute = true
                };

                Process.Start(startInfo);
            }
            catch
            {
                // Fallback to control panel
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "control",
                        Arguments = "userpasswords2",
                        UseShellExecute = true
                    });
                }
                catch { }
            }
        }

        public async Task<bool> FixIssue(AuditItem item)
        {
            if (!item.CanAutoFix || string.IsNullOrEmpty(item.FixAction))
                return false;

            try
            {
                await Task.Run(() =>
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c {item.FixAction}",
                        UseShellExecute = true,
                        Verb = "runas", // Request admin
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(startInfo);
                    process?.WaitForExit();
                });

                return true;
            }
            catch
            {
                return false;
            }
        }

        private AuditSeverity DeterminePermissionSeverity(FileSystemAccessRule rule)
        {
            // Check for overly permissive rules
            if (rule.AccessControlType == AccessControlType.Allow)
            {
                if (rule.IdentityReference.Value.Contains("Everyone") ||
                    rule.IdentityReference.Value.Contains("Users"))
                {
                    if (rule.FileSystemRights.HasFlag(FileSystemRights.FullControl) ||
                        rule.FileSystemRights.HasFlag(FileSystemRights.Modify))
                    {
                        return AuditSeverity.Critical;
                    }
                }
            }

            return AuditSeverity.Info;
        }
    }
}
