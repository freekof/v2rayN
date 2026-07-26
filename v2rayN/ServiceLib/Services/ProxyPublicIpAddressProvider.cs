namespace ServiceLib.Services;

public interface IStunMappedAddressProvider
{
    Task<IPEndPoint?> GetMappedAddressAsync(CancellationToken cancellationToken);
}

public sealed class ProxyPublicIpAddressProvider : IStunMappedAddressProvider
{
    private readonly string _proxyHost;
    private readonly int _proxyPort;
    private readonly string _manualIpAddress;
    private readonly Func<IWebProxy, Task<IpInfoResult?>> _getIpInfoAsync;
    private readonly object _cacheLock = new();
    private IPEndPoint? _cachedAddress;
    private DateTime _cacheExpiresAt;

    public ProxyPublicIpAddressProvider(string proxyHost, int proxyPort)
        : this(proxyHost, proxyPort, string.Empty, ConnectionHandler.GetIPInfo)
    {
    }

    public ProxyPublicIpAddressProvider(string proxyHost, int proxyPort, Func<IWebProxy, Task<IpInfoResult?>> getIpInfoAsync)
        : this(proxyHost, proxyPort, string.Empty, getIpInfoAsync)
    {
    }

    public ProxyPublicIpAddressProvider(string proxyHost, int proxyPort, string? manualIpAddress)
        : this(proxyHost, proxyPort, manualIpAddress, ConnectionHandler.GetIPInfo)
    {
    }

    public ProxyPublicIpAddressProvider(string proxyHost, int proxyPort, string? manualIpAddress, Func<IWebProxy, Task<IpInfoResult?>> getIpInfoAsync)
    {
        _proxyHost = proxyHost;
        _proxyPort = proxyPort;
        _manualIpAddress = manualIpAddress?.TrimEx() ?? string.Empty;
        _getIpInfoAsync = getIpInfoAsync;
    }

    public async Task<IPEndPoint?> GetMappedAddressAsync(CancellationToken cancellationToken)
    {
        if (_manualIpAddress.IsNotEmpty())
        {
            if (IPAddress.TryParse(_manualIpAddress, out var manualIpAddress))
            {
                StunRelayLogger.Info($"proxy public ip manual address={manualIpAddress}");
                return new IPEndPoint(manualIpAddress, 9);
            }

            StunRelayLogger.Info($"proxy public ip manual address invalid value={_manualIpAddress}");
            return null;
        }

        lock (_cacheLock)
        {
            if (_cachedAddress != null && _cacheExpiresAt > DateTime.UtcNow)
            {
                return _cachedAddress;
            }
        }

        try
        {
            var webProxy = new WebProxy($"socks5://{_proxyHost}:{_proxyPort}");
            var ipInfo = await _getIpInfoAsync(webProxy).ConfigureAwait(false);
            var ip = ipInfo?.Ip;
            if (ip.IsNullOrEmpty() || !IPAddress.TryParse(ip, out var ipAddress))
            {
                StunRelayLogger.Info($"proxy public ip unavailable value={ip ?? Global.None}");
                return null;
            }

            var mappedAddress = new IPEndPoint(ipAddress, 9);
            lock (_cacheLock)
            {
                _cachedAddress = mappedAddress;
                _cacheExpiresAt = DateTime.UtcNow.AddMinutes(5);
            }
            StunRelayLogger.Info($"proxy public ip resolved address={ipAddress}");
            return mappedAddress;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            StunRelayLogger.Error("proxy public ip resolve failed", ex);
            return null;
        }
    }
}
