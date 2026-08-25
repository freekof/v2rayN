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
        XunitAssert.Null(root["dns"]!["independent_cache"]);
        var rules = root["dns"]!["rules"]!.AsArray();
        var evaluateRule = rules.First(rule =>
            rule!["server"]!.GetValue<string>() == Global.SingboxHostsDNSTag
            && rule["action"]!.GetValue<string>() == "evaluate")!;
        var responseRule = rules.First(rule =>
            rule!["server"]!.GetValue<string>() == Global.SingboxHostsDNSTag
            && rule["action"]!.GetValue<string>() == "route")!;
        XunitAssert.True(evaluateRule! != null);
        XunitAssert.True(responseRule!["match_response"]!.GetValue<bool>());
        XunitAssert.True(responseRule["ip_accept_any"]!.GetValue<bool>());
    }
}
