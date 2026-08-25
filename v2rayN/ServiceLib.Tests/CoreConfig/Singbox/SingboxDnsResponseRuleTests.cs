using Xunit;
using XunitAssert = Xunit.Assert;

namespace ServiceLib.Tests.CoreConfig.Singbox;

public class SingboxDnsResponseRuleTests
{
    [Fact]
    public void GenerateClientConfigContent_HostsResponseRule_ShouldEnableMatchResponse()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.sing_box);

        var result = new CoreConfigSingboxService(context).GenerateClientConfigContent();

        XunitAssert.True(result.Success, result.Msg);
        var root = JsonUtils.ParseJson(result.Data!.ToString())!;
        var hostRule = root["dns"]!["rules"]!.AsArray()
            .First(rule => rule!["server"]!.GetValue<string>() == Global.SingboxHostsDNSTag)!;
        XunitAssert.True(hostRule!["match_response"]!.GetValue<bool>());
        XunitAssert.True(hostRule["ip_accept_any"]!.GetValue<bool>());
    }
}
