using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SecKey.Core.Services
{
    /// <summary>
    /// Service to enumerate, inspect, and manage X.509 certificates from the Windows certificate store.
    /// </summary>
    public class CertificateManagerService
    {
        /// <summary>
        /// Gets all certificates from the specified store.
        /// </summary>
        public async Task<List<CertificateInfo>> GetCertificatesAsync(
            StoreName storeName = StoreName.My,
            StoreLocation storeLocation = StoreLocation.CurrentUser,
            CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                var results = new List<CertificateInfo>();

                using var store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);

                foreach (var cert in store.Certificates)
                {
                    ct.ThrowIfCancellationRequested();

                    results.Add(new CertificateInfo
                    {
                        Subject = cert.Subject,
                        Issuer = cert.Issuer,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        NotBefore = cert.NotBefore,
                        NotAfter = cert.NotAfter,
                        FriendlyName = cert.FriendlyName,
                        HasPrivateKey = cert.HasPrivateKey,
                        Version = cert.Version,
                        SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? "",
                        StoreName = storeName.ToString(),
                        StoreLocation = storeLocation.ToString(),
                        KeyUsages = GetKeyUsages(cert),
                        SubjectAlternativeNames = GetSanEntries(cert),
                        IsExpired = DateTime.Now > cert.NotAfter,
                        IsNotYetValid = DateTime.Now < cert.NotBefore,
                        DaysUntilExpiry = (int)(cert.NotAfter - DateTime.Now).TotalDays,
                        IsSelfSigned = cert.Subject == cert.Issuer
                    });
                }

                store.Close();
                return results.OrderBy(c => c.NotAfter).ToList();
            }, ct);
        }

        /// <summary>
        /// Gets certificates from all common stores.
        /// </summary>
        public async Task<List<CertificateInfo>> GetAllCertificatesAsync(CancellationToken ct = default)
        {
            var allCerts = new List<CertificateInfo>();

            var stores = new[]
            {
                (StoreName.My, StoreLocation.CurrentUser),
                (StoreName.My, StoreLocation.LocalMachine),
                (StoreName.Root, StoreLocation.CurrentUser),
                (StoreName.Root, StoreLocation.LocalMachine),
                (StoreName.CertificateAuthority, StoreLocation.CurrentUser),
                (StoreName.CertificateAuthority, StoreLocation.LocalMachine),
                (StoreName.TrustedPeople, StoreLocation.CurrentUser),
                (StoreName.TrustedPeople, StoreLocation.LocalMachine),
                (StoreName.TrustedPublisher, StoreLocation.CurrentUser),
                (StoreName.TrustedPublisher, StoreLocation.LocalMachine)
            };

            foreach (var (name, location) in stores)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var certs = await GetCertificatesAsync(name, location, ct);
                    allCerts.AddRange(certs);
                }
                catch (Exception)
                {
                    // Some stores may not be accessible without admin rights
                }
            }

            return allCerts;
        }

        /// <summary>
        /// Gets certificate details as formatted text.
        /// </summary>
        public string GetCertificateDetails(CertificateInfo cert)
        {
            var details = $"""
                Subject: {cert.Subject}
                Issuer: {cert.Issuer}
                Thumbprint: {cert.Thumbprint}
                Serial Number: {cert.SerialNumber}
                Valid From: {cert.NotBefore:yyyy-MM-dd HH:mm:ss}
                Valid To: {cert.NotAfter:yyyy-MM-dd HH:mm:ss}
                Days Until Expiry: {cert.DaysUntilExpiry}
                Friendly Name: {cert.FriendlyName}
                Has Private Key: {cert.HasPrivateKey}
                Version: {cert.Version}
                Signature Algorithm: {cert.SignatureAlgorithm}
                Store: {cert.StoreLocation}\{cert.StoreName}
                Self-Signed: {cert.IsSelfSigned}
                Key Usages: {string.Join(", ", cert.KeyUsages)}
                Subject Alt Names: {string.Join(", ", cert.SubjectAlternativeNames)}
                """;
            return details;
        }

        /// <summary>
        /// Exports a certificate to a file.
        /// </summary>
        public void ExportCertificate(string thumbprint, string filePath,
            StoreName storeName = StoreName.My,
            StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            using var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            var cert = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)
                .OfType<X509Certificate2>()
                .FirstOrDefault()
                ?? throw new InvalidOperationException($"Certificate with thumbprint {thumbprint} not found.");

            var certBytes = cert.Export(X509ContentType.Cert);
            System.IO.File.WriteAllBytes(filePath, certBytes);
            store.Close();
        }

        /// <summary>
        /// Finds certificates that match a search query.
        /// </summary>
        public List<CertificateInfo> Search(List<CertificateInfo> certificates, string query)
        {
            if (string.IsNullOrWhiteSpace(query))
                return certificates;

            return certificates.Where(c =>
                c.Subject.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                c.Issuer.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                c.Thumbprint.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                c.FriendlyName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                c.SerialNumber.Contains(query, StringComparison.OrdinalIgnoreCase)
            ).ToList();
        }

        private static List<string> GetKeyUsages(X509Certificate2 cert)
        {
            var usages = new List<string>();
            foreach (var ext in cert.Extensions)
            {
                if (ext is X509KeyUsageExtension ku)
                {
                    if (ku.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)) usages.Add("Digital Signature");
                    if (ku.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)) usages.Add("Key Encipherment");
                    if (ku.KeyUsages.HasFlag(X509KeyUsageFlags.DataEncipherment)) usages.Add("Data Encipherment");
                    if (ku.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign)) usages.Add("Certificate Signing");
                    if (ku.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign)) usages.Add("CRL Signing");
                    if (ku.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation)) usages.Add("Non-Repudiation");
                }
                else if (ext is X509EnhancedKeyUsageExtension eku)
                {
                    foreach (var oid in eku.EnhancedKeyUsages)
                    {
                        usages.Add(oid.FriendlyName ?? oid.Value ?? "");
                    }
                }
            }
            return usages;
        }

        private static List<string> GetSanEntries(X509Certificate2 cert)
        {
            var sans = new List<string>();
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid?.Value == "2.5.29.17") // Subject Alternative Name
                {
                    var sanExt = new AsnEncodedData(ext.Oid, ext.RawData);
                    sans.Add(sanExt.Format(true));
                }
            }
            return sans;
        }
    }

    public class CertificateInfo
    {
        public string Subject { get; set; } = "";
        public string Issuer { get; set; } = "";
        public string Thumbprint { get; set; } = "";
        public string SerialNumber { get; set; } = "";
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string FriendlyName { get; set; } = "";
        public bool HasPrivateKey { get; set; }
        public int Version { get; set; }
        public string SignatureAlgorithm { get; set; } = "";
        public string StoreName { get; set; } = "";
        public string StoreLocation { get; set; } = "";
        public List<string> KeyUsages { get; set; } = new();
        public List<string> SubjectAlternativeNames { get; set; } = new();
        public bool IsExpired { get; set; }
        public bool IsNotYetValid { get; set; }
        public int DaysUntilExpiry { get; set; }
        public bool IsSelfSigned { get; set; }

        public string StatusIcon => IsExpired ? "❌" : DaysUntilExpiry <= 30 ? "⚠️" : "✅";
        public string StatusText => IsExpired ? "Expired" : IsNotYetValid ? "Not Yet Valid" : DaysUntilExpiry <= 30 ? $"Expiring ({DaysUntilExpiry}d)" : "Valid";
        
        public string SubjectShort
        {
            get
            {
                var cn = Subject;
                if (cn.StartsWith("CN="))
                    cn = cn[3..];
                var comma = cn.IndexOf(',');
                if (comma > 0)
                    cn = cn[..comma];
                return cn;
            }
        }
    }
}
