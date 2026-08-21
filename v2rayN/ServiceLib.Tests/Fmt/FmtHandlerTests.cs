namespace ServiceLib.Tests.Fmt;

using TUnit.Assertions.Should;
using TUnit.Assertions.Should.Extensions;

public class FmtHandlerTests
{
    [Test]
    public async Task GetShareUriAndResolveConfig_Vmess_ShouldRoundTripBasicFields()
    {
        var source = CreateVmessProfile();

        var resolved = await ExportThenImport(source);

        await resolved.ConfigType.Should().BeEqualTo(EConfigType.VMess);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
        await resolved.Address.Should().BeEqualTo(source.Address);
        await resolved.Port.Should().BeEqualTo(source.Port);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.GetProtocolExtra().AlterId.Should().BeEqualTo(source.GetProtocolExtra().AlterId);
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vless_ShouldRoundTripBasicFields()
    {
        var source = CreateVlessProfile();

        var resolved = await ExportThenImport(source);

        await resolved.ConfigType.Should().BeEqualTo(EConfigType.VLESS);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
        await resolved.Address.Should().BeEqualTo(source.Address);
        await resolved.Port.Should().BeEqualTo(source.Port);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.GetProtocolExtra().VlessEncryption.Should().BeEqualTo(Global.None);
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Shadowsocks_ShouldRoundTripBasicFields()
    {
        var source = CreateShadowsocksProfile();

        var resolved = await ExportThenImport(source);

        await resolved.ConfigType.Should().BeEqualTo(EConfigType.Shadowsocks);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
        await resolved.Address.Should().BeEqualTo(source.Address);
        await resolved.Port.Should().BeEqualTo(source.Port);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.GetProtocolExtra().SsMethod.Should().BeEqualTo(source.GetProtocolExtra().SsMethod);
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Socks_ShouldRoundTripBasicFields()
    {
        var source = CreateSocksProfile();

        var resolved = await ExportThenImport(source);

        await resolved.ConfigType.Should().BeEqualTo(EConfigType.SOCKS);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
        await resolved.Address.Should().BeEqualTo(source.Address);
        await resolved.Port.Should().BeEqualTo(source.Port);
        await resolved.Username.Should().BeEqualTo(source.Username);
        await resolved.Password.Should().BeEqualTo(source.Password);
    }

    [Test]
    public async Task ResolveConfig_HttpWithAuthentication_ShouldParseBasicFields()
    {
        var resolved = FmtHandler.ResolveConfig("http://user:pass@proxy.example:8080#http%20demo", out var msg);

        await resolved.Should().NotBeNull().Because(msg);
        await resolved!.ConfigType.Should().BeEqualTo(EConfigType.HTTP);
        await resolved.Remarks.Should().BeEqualTo("http demo");
        await resolved.Address.Should().BeEqualTo("proxy.example");
        await resolved.Port.Should().BeEqualTo(8080);
        await resolved.Username.Should().BeEqualTo("user");
        await resolved.Password.Should().BeEqualTo("pass");
        await resolved.StreamSecurity.Should().BeEmpty();
        await resolved.GetAllowInsecure().Should().BeFalse();
    }

    [Test]
    public async Task ResolveConfig_Https_ShouldEnableTlsAndSkipCertificateValidationByDefault()
    {
        var resolved = FmtHandler.ResolveConfig("https://user:pass@proxy.example:443#https%20demo", out var msg);

        await resolved.Should().NotBeNull().Because(msg);
        await resolved!.ConfigType.Should().BeEqualTo(EConfigType.HTTP);
        await resolved.StreamSecurity.Should().BeEqualTo(Global.StreamSecurity);
        await resolved.GetAllowInsecure().Should().BeTrue();
        await resolved.Username.Should().BeEqualTo("user");
        await resolved.Password.Should().BeEqualTo("pass");
    }

    [Test]
    public async Task ResolveConfig_HttpIpv6_ShouldParseAddressWithoutBrackets()
    {
        var resolved = FmtHandler.ResolveConfig("http://[2001:db8::1]:3128#ipv6", out var msg);

        await resolved.Should().NotBeNull().Because(msg);
        await resolved!.ConfigType.Should().BeEqualTo(EConfigType.HTTP);
        await resolved.Address.Should().BeEqualTo("2001:db8::1");
        await resolved.Port.Should().BeEqualTo(3128);
        await resolved.Remarks.Should().BeEqualTo("ipv6");
    }

    [Test]
    public async Task ResolveConfig_HttpsSubscriptionPath_ShouldReturnNull()
    {
        var resolved = FmtHandler.ResolveConfig("https://example.com/sub?token=x", out _);

        await resolved.Should().BeNull();
    }

    [Test]
    public async Task ResolveConfig_HttpsSubscriptionQueryWithoutPath_ShouldReturnNull()
    {
        var resolved = FmtHandler.ResolveConfig("https://example.com?token=x", out _);

        await resolved.Should().BeNull();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task GetShareUriAndResolveConfig_Http_ShouldRoundTripBasicFields(bool useTls)
    {
        var source = CreateHttpProfile(useTls);

        var uri = FmtHandler.GetShareUri(source);
        await uri.Should().StartWith(useTls ? Global.HttpsProtocol : Global.HttpProtocol);

        var resolved = FmtHandler.ResolveConfig(uri!, out var msg);
        await resolved.Should().NotBeNull().Because($"uri: {uri}, msg: {msg}");

        await resolved!.ConfigType.Should().BeEqualTo(EConfigType.HTTP);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
        await resolved.Address.Should().BeEqualTo(source.Address);
        await resolved.Port.Should().BeEqualTo(source.Port);
        await resolved.Username.Should().BeEqualTo(source.Username);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.StreamSecurity.Should().BeEqualTo(source.StreamSecurity);
        await resolved.GetAllowInsecure().Should().BeEqualTo(useTls);
    }

    [Test]
    public async Task ResolveConfig_UnsupportedProtocol_ShouldReturnNull()
    {
        var resolved = FmtHandler.ResolveConfig("not-a-share-uri", out var msg);

        await resolved.Should().BeNull();
        await msg.Should().NotBeNull();
        await msg.Should().NotBeEmpty();
    }

    [Test]
    public async Task GetShareUri_UnsupportedConfigType_ShouldReturnNull()
    {
        var item = new ProfileItem { ConfigType = EConfigType.PolicyGroup, Remarks = "group", };

        var uri = FmtHandler.GetShareUri(item);

        await uri.Should().BeNull();
    }

    private static async Task<ProfileItem> ExportThenImport(ProfileItem source)
    {
        var uri = FmtHandler.GetShareUri(source);

        await uri.Should().NotBeNull();
        await uri.Should().NotBeEmpty();
        await uri!.StartsWith(Global.ProtocolShares[source.ConfigType], StringComparison.OrdinalIgnoreCase).Should()
            .BeTrue();

        var resolved = FmtHandler.ResolveConfig(uri, out var msg);

        await resolved.Should().NotBeNull().Because($"uri: {uri}, msg: {msg}");
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
