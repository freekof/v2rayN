using AwesomeAssertions;
using ServiceLib.Models.Configs;
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

    [Fact]
    public void UiItem_ShowsIpInfoByDefault()
    {
        new UIItem().HideColumnIpInfo.Should().BeFalse();
    }
}
