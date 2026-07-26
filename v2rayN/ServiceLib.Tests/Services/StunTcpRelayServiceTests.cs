using AwesomeAssertions;
using ServiceLib.Services;
using Xunit;

namespace ServiceLib.Tests.Services;

public class StunTcpRelayServiceTests
{
    [Fact]
    public async Task RelayPacketAsync_ShouldBuildSyntheticResponseForStunBindingRequest()
    {
        var relay = new StunTcpRelayService(new FakeMappedAddressProvider(new IPEndPoint(IPAddress.Parse("203.0.113.9"), 9)));
        var request = CreateStunPacket(0x0001);
        var udpPacket = new Socks5UdpPacket("stun.example.com", 3478, request).Encode();

        var relayed = await relay.RelayPacketAsync(udpPacket, CancellationToken.None);

        relayed.Should().NotBeNull();
        Socks5UdpPacket.TryParse(relayed!, out var parsed).Should().BeTrue();
        parsed!.Host.Should().Be("stun.example.com");
        parsed.Port.Should().Be(3478);
        parsed.Payload[0..2].Should().Equal(0x01, 0x01);
        parsed.Payload[4..20].Should().Equal(request[4..20]);
    }

    [Fact]
    public async Task RelayPacketAsync_ShouldIgnoreNonStunBindingRequest()
    {
        var mappedAddressProvider = new FakeMappedAddressProvider(new IPEndPoint(IPAddress.Parse("203.0.113.9"), 9));
        var relay = new StunTcpRelayService(mappedAddressProvider);
        var udpPacket = new Socks5UdpPacket("stun.example.com", 3478, [0x01, 0x02]).Encode();

        var relayed = await relay.RelayPacketAsync(udpPacket, CancellationToken.None);

        relayed.Should().BeNull();
        mappedAddressProvider.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task SocksConnect_ShouldBuildSyntheticResponseForStunBindingRequest()
    {
        var port = GetFreeTcpPort();
        await using var relay = new AsyncRelay(new StunTcpRelayService(new FakeMappedAddressProvider(new IPEndPoint(IPAddress.Parse("203.0.113.9"), 9)), listenPort: port));
        relay.Service.Start();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using var stream = client.GetStream();

        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var greetingResponse = new byte[2];
        await stream.ReadExactlyAsync(greetingResponse);

        greetingResponse.Should().Equal(0x05, 0x00);

        var host = Encoding.ASCII.GetBytes("stun.example.com");
        var connectRequest = new byte[7 + host.Length];
        connectRequest[0] = 0x05;
        connectRequest[1] = 0x01;
        connectRequest[2] = 0x00;
        connectRequest[3] = 0x03;
        connectRequest[4] = (byte)host.Length;
        host.CopyTo(connectRequest, 5);
        connectRequest[^2] = 0x0D;
        connectRequest[^1] = 0x96;
        await stream.WriteAsync(connectRequest);
        var connectResponse = new byte[10];
        await stream.ReadExactlyAsync(connectResponse);

        connectResponse[0..2].Should().Equal(0x05, 0x00);

        var request = CreateStunPacket(0x0001);
        await stream.WriteAsync(request);
        var responseHeader = new byte[20];
        await stream.ReadExactlyAsync(responseHeader);
        var responseLength = (responseHeader[2] << 8) | responseHeader[3];
        var responseAttributes = new byte[responseLength];
        await stream.ReadExactlyAsync(responseAttributes);

        responseHeader[0..2].Should().Equal(0x01, 0x01);
        responseHeader[4..20].Should().Equal(request[4..20]);
    }

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static byte[] CreateStunPacket(ushort messageType)
    {
        return
        [
            (byte)((messageType >> 8) & 0xFF), (byte)(messageType & 0xFF), 0x00, 0x00,
            0x21, 0x12, 0xA4, 0x42,
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
        ];
    }

    private sealed class FakeMappedAddressProvider(IPEndPoint mappedAddress) : IStunMappedAddressProvider
    {
        public int CallCount { get; private set; }

        public Task<IPEndPoint?> GetMappedAddressAsync(CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult<IPEndPoint?>(mappedAddress);
        }
    }

    private sealed class AsyncRelay(StunTcpRelayService service) : IAsyncDisposable
    {
        public StunTcpRelayService Service { get; } = service;

        public async ValueTask DisposeAsync()
        {
            await Service.StopAsync();
            Service.Dispose();
        }
    }
}
