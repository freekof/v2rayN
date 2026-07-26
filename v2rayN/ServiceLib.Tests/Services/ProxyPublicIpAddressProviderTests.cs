using AwesomeAssertions;
using ServiceLib.Services;
using Xunit;

namespace ServiceLib.Tests.Services;

public class ProxyPublicIpAddressProviderTests
{
    [Fact]
    public async Task GetMappedAddressAsync_ShouldUseExistingIpInfoResolver()
    {
        IWebProxy? usedProxy = null;
        var provider = new ProxyPublicIpAddressProvider("127.0.0.1", 1200, proxy =>
        {
            usedProxy = proxy;
            return Task.FromResult<IpInfoResult?>(new IpInfoResult("US", "203.0.113.9"));
        });

        var mappedAddress = await provider.GetMappedAddressAsync(CancellationToken.None);

        mappedAddress.Should().NotBeNull();
        mappedAddress!.Address.Should().Be(IPAddress.Parse("203.0.113.9"));
        usedProxy.Should().NotBeNull();
    }

    [Theory]
    [InlineData("203.0.113.9")]
    [InlineData("2001:db8::9")]
    public async Task GetMappedAddressAsync_ShouldPreferManualIpAddress(string manualIp)
    {
        var provider = new ProxyPublicIpAddressProvider("127.0.0.1", 1200, manualIp, _ =>
            throw new InvalidOperationException("Automatic IP lookup should not be used."));

        var mappedAddress = await provider.GetMappedAddressAsync(CancellationToken.None);

        mappedAddress.Should().NotBeNull();
        mappedAddress!.Address.Should().Be(IPAddress.Parse(manualIp));
    }
}
