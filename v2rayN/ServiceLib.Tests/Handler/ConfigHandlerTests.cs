using AwesomeAssertions;
using Xunit;

namespace ServiceLib.Tests.Handler;

public class ConfigHandlerTests
{
    [Fact]
    public void LoadConfig_InitializesIpApiUrlForNewConfiguration()
    {
        var config = ConfigHandler.LoadConfig();

        config.Should().NotBeNull();
        config!.SpeedTestItem.IPAPIUrl.Should().Be(Global.IPAPIUrls.First());
    }
}
