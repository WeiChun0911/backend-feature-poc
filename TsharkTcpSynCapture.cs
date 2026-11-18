using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;

internal sealed record TcpSynFingerprint(
    int? InitialWindow,
    int? Mss,
    bool SackPermitted,
    bool TimestampPresent,
    int? WindowScale,
    IReadOnlyList<string> OptionsOrder,
    DateTimeOffset CapturedAtUtc);

internal readonly record struct TcpFlowKey(IPAddress SourceIp, int SourcePort, IPAddress DestinationIp, int DestinationPort);

internal sealed class TcpSynFingerprintStore
{
    private static readonly TimeSpan EntryLifetime = TimeSpan.FromMinutes(30);
    private readonly ConcurrentDictionary<TcpFlowKey, TcpSynFingerprint> _entries = new();

    public void Add(TcpFlowKey key, TcpSynFingerprint fingerprint)
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var entry in _entries)
        {
            if (now - entry.Value.CapturedAtUtc > EntryLifetime)
                _entries.TryRemove(entry.Key, out _);
        }

        _entries[key] = fingerprint;
    }

    public bool TryGet(IPAddress? remoteIp, int remotePort, IPAddress? localIp, int localPort, out TcpSynFingerprint? fingerprint)
    {
        fingerprint = null;
        if (remoteIp is null || localIp is null)
            return false;

        var key = new TcpFlowKey(Normalize(remoteIp), remotePort, Normalize(localIp), localPort);
        if (!_entries.TryGetValue(key, out var found))
            return false;

        if (DateTimeOffset.UtcNow - found.CapturedAtUtc > EntryLifetime)
        {
            _entries.TryRemove(key, out _);
            return false;
        }

        fingerprint = found;
        return true;
    }

    private static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}

internal sealed class TsharkTcpSynCaptureService(
    IConfiguration configuration,
    TcpSynFingerprintStore store,
    ILogger<TsharkTcpSynCaptureService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var streamPath = configuration["TcpCapture:StreamPath"] ?? "/run/backend-feature-poc-tshark/fields.fifo";
        await Task.Yield(); // Do not block host startup while opening the FIFO.

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "/usr/bin/cat",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };
                process.StartInfo.ArgumentList.Add(streamPath);
                var started = false;
                Task<string>? stderrTask = null;

                try
                {
                    if (!process.Start())
                        throw new InvalidOperationException("Could not start FIFO reader process.");

                    started = true;
                    stderrTask = process.StandardError.ReadToEndAsync();
                    logger.LogInformation("Started the unprivileged TShark stream reader.");
                    while (true)
                    {
                        var line = await process.StandardOutput.ReadLineAsync().WaitAsync(stoppingToken);
                        if (line is null)
                            break;

                        if (TryParse(line, out var key, out var fingerprint))
                        {
                            store.Add(key, fingerprint);
                            logger.LogDebug("Captured and indexed TCP SYN metadata for a new connection.");
                        }
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception exception) when (exception is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    logger.LogWarning(exception, "Cannot read TShark stream {StreamPath}; retrying shortly.", streamPath);
                }
                finally
                {
                    if (started)
                    {
                        try
                        {
                            if (!process.HasExited)
                                process.Kill(entireProcessTree: true);
                        }
                        catch (InvalidOperationException)
                        {
                            // The FIFO reader already exited.
                        }

                        try
                        {
                            await process.WaitForExitAsync(CancellationToken.None);
                            if (stderrTask is not null)
                            {
                                var stderr = await stderrTask;
                                if (!string.IsNullOrWhiteSpace(stderr))
                                    logger.LogWarning("TShark stream reader: {Message}", stderr.Trim());
                            }
                        }
                        catch (InvalidOperationException)
                        {
                            // The child failed before it could start.
                        }
                    }
                }

                if (stoppingToken.IsCancellationRequested)
                    break;
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
    }

    private static bool TryParse(string line, out TcpFlowKey key, out TcpSynFingerprint fingerprint)
    {
        key = default;
        fingerprint = default!;
        var fields = line.Split('@');
        if (fields.Length < 11)
            return false;

        var sourceText = FirstNonEmpty(fields[1], fields[2]);
        var destinationText = FirstNonEmpty(fields[4], fields[5]);
        if (!IPAddress.TryParse(sourceText, out var sourceIp) ||
            !IPAddress.TryParse(destinationText, out var destinationIp) ||
            !TryInt(fields[3], out var sourcePort) ||
            !TryInt(fields[6], out var destinationPort))
            return false;

        var optionIds = fields[10].Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(value => TryInt(value, out var optionId) ? optionId : -1)
            .Where(optionId => optionId >= 0)
            .ToArray();
        var optionsOrder = optionIds.Select(OptionName).ToArray();
        var timestampPresent = optionIds.Contains(8);
        var capturedAtUtc = double.TryParse(fields[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var epochSeconds)
            ? DateTimeOffset.FromUnixTimeMilliseconds((long)(epochSeconds * 1000))
            : DateTimeOffset.UtcNow;

        key = new TcpFlowKey(Normalize(sourceIp), sourcePort, Normalize(destinationIp), destinationPort);
        fingerprint = new TcpSynFingerprint(
            TryInt(fields[7], out var initialWindow) ? initialWindow : null,
            TryInt(fields[8], out var mss) ? mss : null,
            optionIds.Contains(4),
            timestampPresent,
            TryInt(fields[9], out var windowScale) ? windowScale : null,
            optionsOrder,
            capturedAtUtc);
        return true;
    }

    private static string FirstNonEmpty(string first, string second) => string.IsNullOrWhiteSpace(first) ? second : first;

    private static bool TryInt(string value, out int result) => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out result);

    private static string OptionName(int optionId) => optionId switch
    {
        0 => "EndOfOptions",
        1 => "NOP",
        2 => "MSS",
        3 => "WindowScale",
        4 => "SACKPermitted",
        5 => "SACK",
        8 => "Timestamp",
        _ => $"Option{optionId}"
    };

    private static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
