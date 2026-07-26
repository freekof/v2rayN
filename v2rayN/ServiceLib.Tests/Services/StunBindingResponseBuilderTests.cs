using AwesomeAssertions;
using ServiceLib.Services;
using Xunit;

namespace ServiceLib.Tests.Services;

public class StunBindingResponseBuilderTests
{
    [Fact]
    public void BuildSuccessResponse_ShouldPreserveTransactionIdAndEncodeXorMappedAddress()
    {
        var request = CreateStunPacket(0x0001);
        var mappedAddress = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 54321);

        var response = StunBindingResponseBuilder.BuildSuccessResponse(request, mappedAddress);

        response[0..2].Should().Equal(0x01, 0x01);
        response[2..4].Should().Equal(0x00, 0x0C);
        response[4..20].Should().Equal(request[4..20]);
        response[20..24].Should().Equal(0x00, 0x20, 0x00, 0x08);
        response[24].Should().Be(0x00);
        response[25].Should().Be(0x01);

        var xorPort = (response[26] << 8) | response[27];
        (xorPort ^ 0x2112).Should().Be(54321);
        response[28].Should().Be((byte)(203 ^ 0x21));
        response[29].Should().Be((byte)(0 ^ 0x12));
        response[30].Should().Be((byte)(113 ^ 0xA4));
        response[31].Should().Be((byte)(9 ^ 0x42));
    }

    [Fact]
    public void BuildSuccessResponse_ShouldEncodeIpv6XorMappedAddress()
    {
        var request = CreateStunPacket(0x0001);
        var mappedAddress = new IPEndPoint(IPAddress.Parse("2001:db8::9"), 54321);

        var response = StunBindingResponseBuilder.BuildSuccessResponse(request, mappedAddress);

        response[0..2].Should().Equal(0x01, 0x01);
        response[2..4].Should().Equal(0x00, 0x18);
        response[20..24].Should().Equal(0x00, 0x20, 0x00, 0x14);
        response[25].Should().Be(0x02);
        var addressBytes = mappedAddress.Address.GetAddressBytes();
        for (var i = 0; i < addressBytes.Length; i++)
        {
            response[28 + i].Should().Be((byte)(addressBytes[i] ^ request[4 + i]));
        }
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
}
