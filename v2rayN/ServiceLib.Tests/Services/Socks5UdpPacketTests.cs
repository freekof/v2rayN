using AwesomeAssertions;
using ServiceLib.Services;
using Xunit;

namespace ServiceLib.Tests.Services;

public class Socks5UdpPacketTests
{
    [Fact]
    public void TryParse_ShouldParseDomainAddressPacket()
    {
        var packet = new byte[]
        {
            0x00, 0x00, 0x00, 0x03, 0x0B,
            (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', (byte)'.', (byte)'c', (byte)'o', (byte)'m',
            0x0D, 0x96,
            0x00, 0x01, 0x00, 0x00,
        };

        Socks5UdpPacket.TryParse(packet, out var parsed).Should().BeTrue();
        parsed!.Host.Should().Be("example.com");
        parsed.Port.Should().Be(3478);
        parsed.Payload.ToArray().Should().Equal(0x00, 0x01, 0x00, 0x00);
    }

    [Fact]
    public void Encode_ShouldBuildIpv4AddressPacket()
    {
        var packet = new Socks5UdpPacket("1.2.3.4", 5349, [0x01, 0x02, 0x03]);

        var encoded = packet.Encode();

        encoded.Should().Equal(
            0x00, 0x00, 0x00, 0x01,
            0x01, 0x02, 0x03, 0x04,
            0x14, 0xE5,
            0x01, 0x02, 0x03);
    }

    [Fact]
    public void Encode_ShouldBuildPacketForHighPortWithoutOverflow()
    {
        var packet = new Socks5UdpPacket("127.0.0.1", 52408, []);

        var encoded = packet.Encode();

        encoded.Should().Equal(
            0x00, 0x00, 0x00, 0x01,
            0x7F, 0x00, 0x00, 0x01,
            0xCC, 0xB8);
    }

    [Fact]
    public void TryParse_ShouldRejectFragmentedPacket()
    {
        var packet = new byte[]
        {
            0x00, 0x00, 0x01, 0x01,
            0x01, 0x02, 0x03, 0x04,
            0x0D, 0x96,
            0x00,
        };

        Socks5UdpPacket.TryParse(packet, out var parsed).Should().BeFalse();
        parsed.Should().BeNull();
    }
}
