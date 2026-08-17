using AwesomeAssertions;
using ServiceLib.Models.Dto;
using Xunit;

namespace ServiceLib.Tests.Handler;

public class ConnectionHandlerTests
{
    [Fact]
    public void ParseCloudflareTrace_FormatsCountryIpAndAsn()
    {
        const string content = "fl=1\nip=1.1.1.1\nloc=us\nas=13335\n";

        var result = IpInfoResult.ParseCloudflareTrace(content);

        result.Should().NotBeNull();
        result.Value.ToString().Should().Be("(US) 1.1.1.1 AS13335");
        result.Value.ToCompactString(requireAsn: true).Should().Be("US1.1.1.1 AS13335");
    }

    [Fact]
    public void ParseJson_HandlesIpApiIsAsnObject()
    {
        const string content = """
            {
              "ip": "8.8.8.8",
              "location": { "country_code": "us" },
              "asn": { "asn": 15169 }
            }
            """;

        var result = IpInfoResult.ParseJson(content);

        result.Should().NotBeNull();
        result.Value.ToCompactString(requireAsn: true).Should().Be("US8.8.8.8 AS15169");
    }

    [Fact]
    public void ParseJson_HandlesIpApiIsCcCountryCode()
    {
        const string content = """
            {
              "ip": "44.201.231.226",
              "cc": "US",
              "asn_num": 14618
            }
            """;

        var result = IpInfoResult.ParseJson(content);

        result.Should().NotBeNull();
        result.Value.Country.Should().Be("US");
        result.Value.Ip.Should().Be("44.201.231.226");
        result.Value.ToCompactString().Should().Be("US44.201.231.226");
    }

    [Fact]
    public void ToCompactString_RequiresAsnWhenRequested()
    {
        var result = new IpInfoResult("de", "2001:db8::1");

        result.ToCompactString(requireAsn: true).Should().BeNull();
        result.ToCompactString().Should().Be("DE2001:db8::1");
    }
}
