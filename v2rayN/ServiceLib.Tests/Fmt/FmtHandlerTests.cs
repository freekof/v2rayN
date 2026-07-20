using AwesomeAssertions;
using ServiceLib.Enums;
using ServiceLib.Handler.Fmt;
using ServiceLib.Models;
using Xunit;

namespace ServiceLib.Tests.Fmt;

public class FmtHandlerTests
{
    [Fact]
    public void GetShareUriAndResolveConfig_Vmess_ShouldRoundTripBasicFields()
    {
        var source = CreateVmessProfile();

        var resolved = ExportThenImport(source);

        resolved.ConfigType.Should().Be(EConfigType.VMess);
        resolved.Remarks.Should().Be(source.Remarks);
        resolved.Address.Should().Be(source.Address);
        resolved.Port.Should().Be(source.Port);
        resolved.Password.Should().Be(source.Password);
        resolved.GetProtocolExtra().AlterId.Should().Be(source.GetProtocolExtra().AlterId);
    }

    [Fact]
    public void GetShareUriAndResolveConfig_Vless_ShouldRoundTripBasicFields()
    {
        var source = CreateVlessProfile();

        var resolved = ExportThenImport(source);

        resolved.ConfigType.Should().Be(EConfigType.VLESS);
        resolved.Remarks.Should().Be(source.Remarks);
        resolved.Address.Should().Be(source.Address);
        resolved.Port.Should().Be(source.Port);
        resolved.Password.Should().Be(source.Password);
        resolved.GetProtocolExtra().VlessEncryption.Should().Be(Global.None);
    }

    [Fact]
    public void GetShareUriAndResolveConfig_Shadowsocks_ShouldRoundTripBasicFields()
    {
        var source = CreateShadowsocksProfile();

        var resolved = ExportThenImport(source);

        resolved.ConfigType.Should().Be(EConfigType.Shadowsocks);
        resolved.Remarks.Should().Be(source.Remarks);
        resolved.Address.Should().Be(source.Address);
        resolved.Port.Should().Be(source.Port);
        resolved.Password.Should().Be(source.Password);
        resolved.GetProtocolExtra().SsMethod.Should().Be(source.GetProtocolExtra().SsMethod);
    }

    [Fact]
    public void GetShareUriAndResolveConfig_Socks_ShouldRoundTripBasicFields()
    {
        var source = CreateSocksProfile();

        var resolved = ExportThenImport(source);

        resolved.ConfigType.Should().Be(EConfigType.SOCKS);
        resolved.Remarks.Should().Be(source.Remarks);
        resolved.Address.Should().Be(source.Address);
        resolved.Port.Should().Be(source.Port);
        resolved.Username.Should().Be(source.Username);
        resolved.Password.Should().Be(source.Password);
    }

    [Fact]
    public void ResolveConfig_HttpWithAuthentication_ShouldParseBasicFields()
    {
        var resolved = FmtHandler.ResolveConfig("http://user:pass@proxy.example:8080#http%20demo", out var msg);

        resolved.Should().NotBeNull(msg);
        resolved!.ConfigType.Should().Be(EConfigType.HTTP);
        resolved.Remarks.Should().Be("http demo");
        resolved.Address.Should().Be("proxy.example");
        resolved.Port.Should().Be(8080);
        resolved.Username.Should().Be("user");
        resolved.Password.Should().Be("pass");
        resolved.StreamSecurity.Should().BeEmpty();
    }

    [Fact]
    public void ResolveConfig_HttpsWithoutInsecureParameter_ShouldEnableTlsOnly()
    {
        var resolved = FmtHandler.ResolveConfig("https://user:pass@proxy.example:443#https%20demo", out var msg);

        resolved.Should().NotBeNull(msg);
        resolved!.ConfigType.Should().Be(EConfigType.HTTP);
        resolved.StreamSecurity.Should().Be(Global.StreamSecurity);
        resolved.GetAllowInsecure().Should().BeFalse();
        resolved.Username.Should().Be("user");
        resolved.Password.Should().Be("pass");
    }

    [Fact]
    public void ResolveConfig_HttpIpv6_ShouldParseAddressWithoutBrackets()
    {
        var resolved = FmtHandler.ResolveConfig("http://[2001:db8::1]:3128#ipv6", out var msg);

        resolved.Should().NotBeNull(msg);
        resolved!.ConfigType.Should().Be(EConfigType.HTTP);
        resolved.Address.Should().Be("2001:db8::1");
        resolved.Port.Should().Be(3128);
        resolved.Remarks.Should().Be("ipv6");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GetShareUriAndResolveConfig_Http_ShouldRoundTripBasicFields(bool useTls)
    {
        var source = CreateHttpProfile(useTls);

        var uri = FmtHandler.GetShareUri(source);
        uri.Should().StartWith(useTls ? Global.HttpsProtocol : Global.HttpProtocol);

        var resolved = FmtHandler.ResolveConfig(uri!, out var msg);
        resolved.Should().NotBeNull($"uri: {uri}, msg: {msg}");

        resolved!.ConfigType.Should().Be(EConfigType.HTTP);
        resolved.Remarks.Should().Be(source.Remarks);
        resolved.Address.Should().Be(source.Address);
        resolved.Port.Should().Be(source.Port);
        resolved.Username.Should().Be(source.Username);
        resolved.Password.Should().Be(source.Password);
        resolved.StreamSecurity.Should().Be(source.StreamSecurity);
    }

    [Fact]
    public void ResolveConfig_UnsupportedProtocol_ShouldReturnNull()
    {
        var resolved = FmtHandler.ResolveConfig("not-a-share-uri", out var msg);

        resolved.Should().BeNull();
        msg.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void GetShareUri_UnsupportedConfigType_ShouldReturnNull()
    {
        var item = new ProfileItem { ConfigType = EConfigType.PolicyGroup, Remarks = "group", };

        var uri = FmtHandler.GetShareUri(item);

        uri.Should().BeNull();
    }

    private static ProfileItem ExportThenImport(ProfileItem source)
    {
        var uri = FmtHandler.GetShareUri(source);

        uri.Should().NotBeNullOrWhiteSpace();
        uri!.StartsWith(Global.ProtocolShares[source.ConfigType], StringComparison.OrdinalIgnoreCase).Should()
            .BeTrue();

        var resolved = FmtHandler.ResolveConfig(uri, out var msg);

        resolved.Should().NotBeNull($"uri: {uri}, msg: {msg}");
        return resolved!;
    }

    private static ProfileItem CreateVmessProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.VMess,
            Remarks = "vmess demo",
            Address = "example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
        };

        item.SetProtocolExtra(new ProtocolExtraItem { AlterId = "0", VmessSecurity = Global.DefaultSecurity, });
        item.SetTransportExtra(new TransportExtraItem { RawHeaderType = Global.None, });

        return item;
    }

    private static ProfileItem CreateVlessProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.VLESS,
            Remarks = "vless demo",
            Address = "vless.example",
            Port = 8443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
        };

        item.SetProtocolExtra(new ProtocolExtraItem { VlessEncryption = Global.None, });
        item.SetTransportExtra(new TransportExtraItem { RawHeaderType = Global.None, });

        return item;
    }

    private static ProfileItem CreateShadowsocksProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.Shadowsocks,
            Remarks = "ss demo",
            Address = "1.2.3.4",
            Port = 8388,
            Password = "pass123",
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
        };

        item.SetProtocolExtra(new ProtocolExtraItem { SsMethod = "aes-128-gcm", });
        item.SetTransportExtra(new TransportExtraItem { RawHeaderType = Global.None, });

        return item;
    }

    private static ProfileItem CreateSocksProfile()
    {
        return new ProfileItem
        {
            ConfigType = EConfigType.SOCKS,
            Remarks = "socks demo",
            Address = "127.0.0.1",
            Port = 1080,
            Username = "user",
            Password = "pass",
        };
    }

    private static ProfileItem CreateHttpProfile(bool useTls)
    {
        return new ProfileItem
        {
            ConfigType = EConfigType.HTTP,
            Remarks = "HTTP IPv6 demo",
            Address = "2001:db8::2",
            Port = useTls ? 443 : 8080,
            Username = "user:name",
            Password = "p@ss word",
            StreamSecurity = useTls ? Global.StreamSecurity : string.Empty,
        };
    }
}
