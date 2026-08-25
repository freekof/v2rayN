using TUnit.Assertions.Should;
using TUnit.Assertions.Should.Extensions;
using Xunit;

namespace ServiceLib.Tests.CoreConfig.Singbox;

public class TurnOutboundTests
{
    [Fact]
    public async Task GenerateClientConfigContent_TurnOutbound_ShouldEmitUdpTcpAndTlsOptions()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var defaultNode = CoreConfigTestFactory.CreateTurnNode(ECoreType.sing_box);
        defaultNode.SetProtocolExtra(defaultNode.GetProtocolExtra() with
        {
            TurnTransport = "tcp",
            TurnNetwork = null,
        });
        var defaultResult = new CoreConfigSingboxService(
            CoreConfigTestFactory.CreateContext(config, defaultNode, ECoreType.sing_box)).GenerateClientConfigContent();
        await defaultResult.Success.Should().BeTrue().Because($"ret msg: {defaultResult.Msg}");
        var defaultConfig = JsonUtils.ParseJson(defaultResult.Data!.ToString())!;
        var defaultOutbound = defaultConfig["outbounds"]!.AsArray()
            .First(o => o!["tag"]!.GetValue<string>() == Global.ProxyTag)!;
        await defaultOutbound["type"]!.GetValue<string>().Should().BeEqualTo("turn");
        await defaultOutbound["transport"]!.GetValue<string>().Should().BeEqualTo("tcp");
        await defaultOutbound["network"]!.AsArray().Select(n => n!.GetValue<string>()).ToList()
            .Should().BeEquivalentTo(["tcp", "udp"]);
        await defaultOutbound["tls"].Should().BeNull();

        var udpNode = CoreConfigTestFactory.CreateTurnNode(ECoreType.sing_box);
        udpNode.SetProtocolExtra(udpNode.GetProtocolExtra() with
        {
            TurnTransport = "tcp",
            TurnNetwork = "udp",
        });
        var udpResult = new CoreConfigSingboxService(
            CoreConfigTestFactory.CreateContext(config, udpNode, ECoreType.sing_box)).GenerateClientConfigContent();
        await udpResult.Success.Should().BeTrue().Because($"ret msg: {udpResult.Msg}");
        var udpConfig = JsonUtils.ParseJson(udpResult.Data!.ToString())!;
        var udpOutbound = udpConfig["outbounds"]!.AsArray()
            .First(o => o!["tag"]!.GetValue<string>() == Global.ProxyTag)!;
        await udpOutbound["transport"]!.GetValue<string>().Should().BeEqualTo("tcp");
        await udpOutbound["network"]!.AsArray().Select(n => n!.GetValue<string>()).ToList()
            .Should().BeEquivalentTo(["udp"]);

        var tcpNode = CoreConfigTestFactory.CreateTurnNode(ECoreType.sing_box);
        tcpNode.SetProtocolExtra(tcpNode.GetProtocolExtra() with
        {
            TurnTransport = "tcp",
            TurnNetwork = "tcp",
        });
        var tcpResult = new CoreConfigSingboxService(
            CoreConfigTestFactory.CreateContext(config, tcpNode, ECoreType.sing_box)).GenerateClientConfigContent();
        await tcpResult.Success.Should().BeTrue().Because($"ret msg: {tcpResult.Msg}");
        var tcpConfig = JsonUtils.ParseJson(tcpResult.Data!.ToString())!;
        var tcpOutbound = tcpConfig["outbounds"]!.AsArray()
            .First(o => o!["tag"]!.GetValue<string>() == Global.ProxyTag)!;
        await tcpOutbound["transport"]!.GetValue<string>().Should().BeEqualTo("tcp");
        await tcpOutbound["network"]!.AsArray().Select(n => n!.GetValue<string>()).ToList()
            .Should().BeEquivalentTo(["tcp"]);
        await tcpOutbound["tls"].Should().BeNull();

        var tlsNode = CoreConfigTestFactory.CreateTurnNode(ECoreType.sing_box);
        tlsNode.Port = 5349;
        tlsNode.StreamSecurity = Global.StreamSecurity;
        tlsNode.AllowInsecure = Global.StringTrue;
        tlsNode.Sni = "turn.example.com";
        tlsNode.SetProtocolExtra(tlsNode.GetProtocolExtra() with
        {
            TurnTransport = "tls",
        });
        var tlsResult = new CoreConfigSingboxService(
            CoreConfigTestFactory.CreateContext(config, tlsNode, ECoreType.sing_box)).GenerateClientConfigContent();
        await tlsResult.Success.Should().BeTrue().Because($"ret msg: {tlsResult.Msg}");
        var tlsConfig = JsonUtils.ParseJson(tlsResult.Data!.ToString())!;
        var tlsOutbound = tlsConfig["outbounds"]!.AsArray()
            .First(o => o!["tag"]!.GetValue<string>() == Global.ProxyTag)!;
        await tlsOutbound["transport"]!.GetValue<string>().Should().BeEqualTo("tls");
        await tlsOutbound["network"]!.AsArray().Select(n => n!.GetValue<string>()).ToList()
            .Should().BeEquivalentTo(["tcp", "udp"]);
        await tlsOutbound["tls"]!["enabled"]!.GetValue<bool>().Should().BeTrue();
        await tlsOutbound["tls"]!["server_name"]!.GetValue<string>().Should().BeEqualTo("turn.example.com");
        await tlsOutbound["tls"]!["insecure"]!.GetValue<bool>().Should().BeTrue();
    }
}
