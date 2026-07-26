namespace ServiceLib.Services;

public sealed class StunTcpRelayService : IDisposable
{
    private const string Tag = nameof(StunTcpRelayService);
    private const int StunHeaderLength = 20;
    private readonly IStunMappedAddressProvider _mappedAddressProvider;
    private readonly string _listenHost;
    private readonly int _listenPort;
    private TcpListener? _tcpListener;
    private CancellationTokenSource? _cts;
    private Task? _acceptTask;

    public StunTcpRelayService(IStunMappedAddressProvider mappedAddressProvider, string listenHost = Global.Loopback, int listenPort = Global.WebRTCStunRelayPort)
    {
        _mappedAddressProvider = mappedAddressProvider;
        _listenHost = listenHost;
        _listenPort = listenPort;
    }

    public void Start()
    {
        if (_tcpListener != null)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        _tcpListener = new TcpListener(IPAddress.Parse(_listenHost), _listenPort);
        try
        {
            _tcpListener.Start();
            _acceptTask = AcceptLoopAsync(_cts.Token);
            StunRelayLogger.Info($"relay started listen={_listenHost}:{_listenPort}");
        }
        catch
        {
            _tcpListener.Stop();
            _tcpListener = null;
            _cts.Dispose();
            _cts = null;
            throw;
        }
    }

    public async Task StopAsync()
    {
        var listener = _tcpListener;
        if (listener == null)
        {
            return;
        }

        _tcpListener = null;
        _cts?.Cancel();
        listener.Stop();
        StunRelayLogger.Info("relay stopping");

        if (_acceptTask != null)
        {
            try
            {
                await _acceptTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        _cts?.Dispose();
        _cts = null;
        _acceptTask = null;
        StunRelayLogger.Info("relay stopped");
    }

    public async Task<byte[]?> RelayPacketAsync(byte[] socks5UdpPacket, CancellationToken cancellationToken)
    {
        if (!Socks5UdpPacket.TryParse(socks5UdpPacket, out var packet) || packet == null)
        {
            StunRelayLogger.Info($"udp packet parse failed len={socks5UdpPacket.Length}");
            return null;
        }

        if (!StunPacketInspector.IsStunBindingRequest(packet.Payload))
        {
            StunRelayLogger.Info($"non-stun-binding target={packet.Host}:{packet.Port} payloadLen={packet.Payload.Length}");
            return null;
        }

        StunRelayLogger.Info($"stun binding request target={packet.Host}:{packet.Port} payloadLen={packet.Payload.Length}");
        var response = await BuildSyntheticResponseAsync(packet.Payload, cancellationToken).ConfigureAwait(false);
        if (response == null)
        {
            return null;
        }

        if (!StunPacketInspector.IsStunPacket(response))
        {
            StunRelayLogger.Info($"invalid stun response target={packet.Host}:{packet.Port} responseLen={response.Length}");
            return null;
        }

        StunRelayLogger.Info($"stun response target={packet.Host}:{packet.Port} responseLen={response.Length}");
        return new Socks5UdpPacket(packet.Host, packet.Port, response).Encode();
    }

    private async Task<byte[]?> BuildSyntheticResponseAsync(byte[] stunRequest, CancellationToken cancellationToken)
    {
        var mappedAddress = await _mappedAddressProvider.GetMappedAddressAsync(cancellationToken).ConfigureAwait(false);
        if (mappedAddress == null)
        {
            return null;
        }

        StunRelayLogger.Info($"synthetic stun response mapped={mappedAddress.Address}:{mappedAddress.Port}");
        return StunBindingResponseBuilder.BuildSuccessResponse(stunRequest, mappedAddress);
    }

    public void Dispose()
    {
        StopAsync().GetAwaiter().GetResult();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && _tcpListener != null)
        {
            try
            {
                var tcpClient = await _tcpListener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                StunRelayLogger.Info($"socks client accepted remote={tcpClient.Client.RemoteEndPoint}");
                _ = Task.Run(() => HandleClientAsync(tcpClient, cancellationToken), cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                StunRelayLogger.Error("accept loop failed", ex);
                Logging.SaveLog(Tag, ex);
            }
        }
    }

    private async Task HandleClientAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        using var client = tcpClient;
        try
        {
            await using var stream = tcpClient.GetStream();
            if (!await HandleGreetingAsync(stream, cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            var request = await ReadSocks5CommandAsync(stream, cancellationToken).ConfigureAwait(false);
            if (request.Command == 0x01)
            {
                await HandleConnectAsync(stream, request, cancellationToken).ConfigureAwait(false);
                return;
            }
            if (request.Command != 0x03)
            {
                await WriteSocks5ReplyAsync(stream, 0x07, Global.Loopback, 0, cancellationToken).ConfigureAwait(false);
                return;
            }

            using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var localPort = ((IPEndPoint)udpClient.Client.LocalEndPoint!).Port;
            StunRelayLogger.Info($"udp associate bound={Global.Loopback}:{localPort}");
            await WriteSocks5ReplyAsync(stream, 0x00, Global.Loopback, localPort, cancellationToken).ConfigureAwait(false);
            using var associationCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var udpTask = HandleUdpAssociateAsync(udpClient, associationCts.Token);
            var controlTask = WaitForControlCloseAsync(stream, associationCts.Token);
            await Task.WhenAny(udpTask, controlTask).ConfigureAwait(false);
            await associationCts.CancelAsync().ConfigureAwait(false);
            await AwaitAssociationTaskAsync(udpTask).ConfigureAwait(false);
            await AwaitAssociationTaskAsync(controlTask).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception ex)
        {
            StunRelayLogger.Error("socks client failed", ex);
            Logging.SaveLog(Tag, ex);
        }
    }

    private static async Task<bool> HandleGreetingAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var header = new byte[2];
        await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (header[0] != 0x05 || header[1] == 0)
        {
            StunRelayLogger.Info($"invalid socks greeting version={header[0]} methods={header[1]}");
            return false;
        }

        var methods = new byte[header[1]];
        await ReadExactlyAsync(stream, methods, cancellationToken).ConfigureAwait(false);
        var selectedMethod = methods.Contains((byte)0x00) ? (byte)0x00 : (byte)0xFF;
        await stream.WriteAsync(new byte[] { 0x05, selectedMethod }, cancellationToken).ConfigureAwait(false);
        StunRelayLogger.Info($"socks greeting selectedMethod=0x{selectedMethod:X2}");
        return selectedMethod == 0x00;
    }

    private async Task HandleConnectAsync(NetworkStream stream, Socks5CommandRequest request, CancellationToken cancellationToken)
    {
        await WriteSocks5ReplyAsync(stream, 0x00, Global.Loopback, 0, cancellationToken).ConfigureAwait(false);
        while (!cancellationToken.IsCancellationRequested)
        {
            var header = new byte[StunHeaderLength];
            await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false);
            if (!TryGetStunMessageLength(header, out var messageLength))
            {
                StunRelayLogger.Info($"non-stun-connect target={request.Host}:{request.Port} headerLen={header.Length}");
                return;
            }

            var payload = new byte[StunHeaderLength + messageLength];
            header.CopyTo(payload, 0);
            if (messageLength > 0)
            {
                await ReadExactlyAsync(stream, payload.AsMemory(StunHeaderLength, messageLength), cancellationToken).ConfigureAwait(false);
            }

            if (!StunPacketInspector.IsStunBindingRequest(payload))
            {
                StunRelayLogger.Info($"non-stun-binding-connect target={request.Host}:{request.Port} payloadLen={payload.Length}");
                continue;
            }

            StunRelayLogger.Info($"stun binding connect target={request.Host}:{request.Port} payloadLen={payload.Length}");
            var response = await BuildSyntheticResponseAsync(payload, cancellationToken).ConfigureAwait(false);
            if (response == null)
            {
                return;
            }

            await stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);
            StunRelayLogger.Info($"stun connect response target={request.Host}:{request.Port} responseLen={response.Length}");
        }
    }

    private static bool TryGetStunMessageLength(ReadOnlySpan<byte> header, out int messageLength)
    {
        messageLength = 0;
        if (header.Length < StunHeaderLength)
        {
            return false;
        }
        if ((header[0] & 0xC0) != 0)
        {
            return false;
        }
        if (header[4] != 0x21 || header[5] != 0x12 || header[6] != 0xA4 || header[7] != 0x42)
        {
            return false;
        }

        messageLength = (header[2] << 8) | header[3];
        return messageLength % 4 == 0;
    }

    private static async Task<Socks5CommandRequest> ReadSocks5CommandAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (header[0] != 0x05)
        {
            throw new IOException("Invalid SOCKS5 request version.");
        }

        var (host, port) = await ReadAddressAndPortAsync(stream, header[3], cancellationToken).ConfigureAwait(false);
        StunRelayLogger.Info($"socks command=0x{header[1]:X2} atyp=0x{header[3]:X2} target={host}:{port}");
        return new Socks5CommandRequest(header[1], host, port);
    }

    private static async Task<(string Host, int Port)> ReadAddressAndPortAsync(Stream stream, byte atyp, CancellationToken cancellationToken)
    {
        string host;
        var addressLength = atyp switch
        {
            0x01 => 4,
            0x03 => await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false),
            0x04 => 16,
            _ => throw new IOException($"Unsupported SOCKS5 address type 0x{atyp:X2}.")
        };

        var remaining = new byte[addressLength + 2];
        await ReadExactlyAsync(stream, remaining, cancellationToken).ConfigureAwait(false);
        host = atyp switch
        {
            0x01 or 0x04 => new IPAddress(remaining.AsSpan(0, addressLength)).ToString(),
            0x03 => Encoding.ASCII.GetString(remaining.AsSpan(0, addressLength)),
            _ => string.Empty
        };
        var port = (remaining[^2] << 8) | remaining[^1];
        return (host, port);
    }

    private static async Task WriteSocks5ReplyAsync(NetworkStream stream, byte reply, string bindAddress, int bindPort, CancellationToken cancellationToken)
    {
        var ip = IPAddress.Parse(bindAddress).GetAddressBytes();
        var response = new byte[4 + ip.Length + 2];
        response[0] = 0x05;
        response[1] = reply;
        response[2] = 0x00;
        response[3] = ip.Length == 4 ? (byte)0x01 : (byte)0x04;
        ip.CopyTo(response, 4);
        response[^2] = (byte)((bindPort >> 8) & 0xFF);
        response[^1] = (byte)(bindPort & 0xFF);
        await stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);
        StunRelayLogger.Info($"socks reply reply=0x{reply:X2} bind={bindAddress}:{bindPort}");
    }

    private async Task HandleUdpAssociateAsync(UdpClient udpClient, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var received = await udpClient.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            StunRelayLogger.Info($"udp packet received from={received.RemoteEndPoint} len={received.Buffer.Length}");
            _ = Task.Run(async () =>
            {
                try
                {
                    using var requestCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    requestCts.CancelAfter(TimeSpan.FromSeconds(10));
                    var response = await RelayPacketAsync(received.Buffer, requestCts.Token).ConfigureAwait(false);
                    if (response != null)
                    {
                        await udpClient.SendAsync(response, response.Length, received.RemoteEndPoint).ConfigureAwait(false);
                        StunRelayLogger.Info($"udp response sent to={received.RemoteEndPoint} len={response.Length}");
                    }
                }
                catch (OperationCanceledException)
                {
                }
                catch (ObjectDisposedException)
                {
                }
                catch (Exception ex)
                {
                    StunRelayLogger.Error("udp relay failed", ex);
                    Logging.SaveLog(Tag, ex);
                }
            }, cancellationToken);
        }
    }

    private static async Task WaitForControlCloseAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        while (!cancellationToken.IsCancellationRequested)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return;
            }
        }
    }

    private static async Task AwaitAssociationTaskAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static async Task<byte> ReadByteAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        await ReadExactlyAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
        return buffer[0];
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var readTotal = 0;
        while (readTotal < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[readTotal..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            readTotal += read;
        }
    }

    private sealed record Socks5CommandRequest(byte Command, string Host, int Port);
}
