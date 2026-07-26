using ServiceLib.Services;
using Xunit;

namespace ServiceLib.Tests.Services;

public class StunPacketInspectorTests
{
    [Fact]
    public void IsStunBindingRequest_ShouldAcceptValidBindingRequest()
    {
        var packet = new byte[]
        {
            0x00, 0x01, 0x00, 0x00,
            0x21, 0x12, 0xA4, 0x42,
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
        };

        Assert.True(StunPacketInspector.IsStunBindingRequest(packet));
    }

    [Fact]
    public void IsStunBindingRequest_ShouldRejectNonStunUdpPayload()
    {
        var packet = new byte[]
        {
            0x45, 0x00, 0x00, 0x1C,
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00,
            0x7F, 0x00, 0x00, 0x01,
            0x7F, 0x00, 0x00, 0x01,
        };

        Assert.False(StunPacketInspector.IsStunBindingRequest(packet));
    }

    [Fact]
    public void IsStunBindingRequest_ShouldRejectInvalidMagicCookie()
    {
        var packet = new byte[]
        {
            0x00, 0x01, 0x00, 0x00,
            0x21, 0x12, 0xA4, 0x43,
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
        };

        Assert.False(StunPacketInspector.IsStunBindingRequest(packet));
    }

    [Fact]
    public void IsStunBindingRequest_ShouldRejectPacketsWithInvalidLength()
    {
        var packet = new byte[]
        {
            0x00, 0x01, 0x00, 0x04,
            0x21, 0x12, 0xA4, 0x42,
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
        };

        Assert.False(StunPacketInspector.IsStunBindingRequest(packet));
    }
}
