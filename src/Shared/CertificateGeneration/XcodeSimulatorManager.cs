// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;

// Solves https://github.com/aspnet/AspNetCore/issues/3957
// Also https://stackoverflow.com/questions/55229255/dotnet-dev-certs-https-on-ios-simulator
// Must also update docs on https://docs.microsoft.com/en-us/aspnet/core/security/enforcing-ssl#trust-the-aspnet-core-https-development-certificate-on-windows-and-macos
// Credits to https://github.com/ADVTOOLS/ADVTrustStore

namespace Microsoft.AspNetCore.Certificates.Generation
{
    internal class RuntimesResult
    {
        public IEnumerable<Runtime> Runtimes { get; set; }
    }

    internal class DevicesResult
    {
        public IReadOnlyDictionary<string, IEnumerable<Device>> Devices { get; set; }
    }

    internal class Runtime
    {
        public bool IsAvailable { get; set; }
        public string Version { get; set; }
        public string BundlePath { get; set; }
        public string Name { get; set; }
        public string Identifier { get; set; }
        public string BuildVersion { get; set; }

        public override string ToString()
        {
            return $"{Name} ({BuildVersion})";
        }
    }

    internal enum DeviceState
    {
        Shutdown,
        Booted
    }

    internal class Device
    {
        public bool IsAvailable { get; set; }
        public DeviceState State { get; set; }
        public string Name { get; set; }
        public string Udid { get; set; }
        public Runtime Runtime { get; set; }

        public override string ToString()
        {
            return $"{Name} [{Udid}] ({State}) - {Runtime}";
        }
    }

    internal static class XcodeSimulatorManager
    {
        private static readonly JsonSerializerOptions JsonSerializerOptions = new JsonSerializerOptions
        {
            Converters = { new JsonStringEnumConverter() },
            PropertyNameCaseInsensitive = true,
        };
        private static readonly string SimulatorDevicesDirectory = Environment.GetEnvironmentVariable("HOME") + "/Library/Developer/CoreSimulator/Devices";
        private const string TrustStorePath = "data/Library/Keychains/TrustStore.sqlite3";

        internal static void Test(X509Certificate2 certificate, CertificateManager.DiagnosticInformation diagnostics)
        {
            // TODO: check if we have xcrun, stop if we don't, also remove check on specific udid
            foreach (var device in GetDevices(diagnostics).Where(d => d.Udid == "6C544289-4103-42DD-99BF-7453D679CFBD"))
            {
                InstallSimulatorCertificate(certificate, device, diagnostics);
            }
        }

        internal static IEnumerable<Runtime> GetRuntimes(CertificateManager.DiagnosticInformation diagnostics)
        {
            try
            {
                var output = RunProcess("xcrun", "simctl list --json runtimes").output;
                var result = JsonSerializer.Deserialize<RuntimesResult>(output, JsonSerializerOptions);
                return result.Runtimes;
            }
            catch (Exception ex)
            {
                diagnostics?.Debug($"Failed to retrieve runtimes types: {ex.Message}");
                return new Runtime[0];
            }
        }

        internal static IEnumerable<Device> GetDevices(CertificateManager.DiagnosticInformation diagnostics)
        {
            DevicesResult result;
            Dictionary<string, Runtime> runtimes;
            try
            {
                runtimes = GetRuntimes(diagnostics).ToDictionary(e => e.Identifier, e => e);
                var output = RunProcess("xcrun", "simctl list --json devices available").output;
                result = JsonSerializer.Deserialize<DevicesResult>(output, JsonSerializerOptions);
            }
            catch (Exception ex)
            {
                diagnostics?.Debug($"Failed to retrieve available devices: {ex.Message}");
                yield break;
            }

            foreach (var (runtimeIdentifier, devices) in result.Devices)
            {
                foreach (var device in devices)
                {
                    device.Runtime = runtimes.TryGetValue(runtimeIdentifier, out var runtime) ? runtime : new Runtime { Name = "Unknown runtime" };
                    yield return device;
                }
            }
        }

        internal static void InstallSimulatorCertificate(X509Certificate2 certificate, Device device, CertificateManager.DiagnosticInformation diagnostics)
        {
            try
            {
                var trustStore = new FileInfo(Path.Combine(SimulatorDevicesDirectory, device.Udid, TrustStorePath));
                if (!trustStore.Exists)
                {
                    diagnostics?.Error($"Can't install certificate for device {device}.", new FileNotFoundException($"Trust store expected at {trustStore.FullName} was not found.", trustStore.FullName));
                    return;
                }
                using var connection = new SqliteConnection($"Data Source={trustStore.FullName}");
                connection.Open();
                var verifyCommand = connection.CreateCommand();
                verifyCommand.CommandText = "SELECT sha1,subj,tset,data FROM tsettings LIMIT 0";
                try
                {
                    verifyCommand.ExecuteScalar();
                }
                catch (Exception exception)
                {
                    diagnostics?.Error($"Can't install certificate for device {device} because validation of the trust store {trustStore.FullName} failed.", exception);
                    return;
                }
                var sha1 = new System.Security.Cryptography.SHA1Managed().ComputeHash(certificate.RawData);
                var subj = certificate.SubjectName.RawData;
                var tset = Encoding.ASCII.GetBytes(@"<?xml vxersion=""1.0"" encoding=""UTF-8""?>
<!DOCTYPE plist PUBLIC ""-//Apple//DTD PLIST 1.0//EN"" ""http://www.apple.com/DTDs/PropertyList-1.0.dtd"">
<plist version=""1.0"">
<array/>
</plist>");
                var command = connection.CreateCommand();
                command.CommandText = "INSERT OR REPLACE INTO tsettings (sha1, subj, tset, data) VALUES (@sha1, @subj, @tset, @data)";
                command.Parameters.AddWithValue("sha1", sha1).SqliteType = SqliteType.Blob;
                command.Parameters.AddWithValue("subj", subj).SqliteType = SqliteType.Blob;
                command.Parameters.AddWithValue("tset", tset).SqliteType = SqliteType.Blob;
                command.Parameters.AddWithValue("data", certificate.RawData).SqliteType = SqliteType.Blob;
                var result = command.ExecuteNonQuery();
                diagnostics?.Debug($"✅ Installed certificate ({result}) for {device}");
            }
            catch (Exception exception)
            {
                diagnostics?.Error($"Can't install certificate for device {device}.", exception);
            }
        }

        internal static (string output, string error) RunProcess(string command, string arguments, bool trimResult = true)
        {
            var startInfo = new ProcessStartInfo(command, arguments) { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            using var process = new Process { StartInfo = startInfo };
            try
            {
                process.Start();
            }
            catch (Exception exception)
            {
                throw new ApplicationException($"Failed to run `{command} {arguments}` Is {command} installed?", exception);
            }
            process.WaitForExit();
            var error = process.StandardError.ReadToEnd();
            if (process.ExitCode != 0)
            {
                throw new ApplicationException(error);
            }
            var output = process.StandardOutput.ReadToEnd();
            return trimResult ? (output.TrimEnd('\n'), error.TrimEnd('\n')) : (output, error);
        }
    }
}
