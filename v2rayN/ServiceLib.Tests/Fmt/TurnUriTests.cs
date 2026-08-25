using Xunit;
using XunitAssert = Xunit.Assert;

namespace ServiceLib.Tests.Fmt;

public class TurnUriTests
{
    [Fact]
    public void ResolveConfig_TurnUris_ShouldParseAnonymousAuthenticatedAndTlsForms()
    {
        var anonymous = FmtHandler.ResolveConfig("turn://154.17.29.151:3478#turn%20demo", out var anonymousMessage);
        XunitAssert.NotNull(anonymous);
        XunitAssert.Equal(EConfigType.TURN, anonymous!.ConfigType);
        XunitAssert.Equal(ECoreType.sing_box, anonymous.CoreType);
        XunitAssert.Equal("154.17.29.151", anonymous.Address);
        XunitAssert.Equal(3478, anonymous.Port);
        XunitAssert.Equal("turn demo", anonymous.Remarks);
        XunitAssert.Equal("tcp", anonymous.GetProtocolExtra().TurnTransport);
        XunitAssert.True(string.IsNullOrEmpty(anonymous.GetProtocolExtra().TurnNetwork));

        var authenticated = FmtHandler.ResolveConfig("turn://user%3Aname:p%40ss%20word@turn.example:3478#my%20turn", out var authenticatedMessage);
        XunitAssert.NotNull(authenticated);
        XunitAssert.Equal("user:name", authenticated!.Username);
        XunitAssert.Equal("p@ss word", authenticated.Password);
        XunitAssert.Equal("my turn", authenticated.Remarks);
        XunitAssert.Equal("tcp", authenticated.GetProtocolExtra().TurnTransport);

        var tls = FmtHandler.ResolveConfig("turns://user:pass@turn.example:5349?network=tcp&insecure=1#tls", out var tlsMessage);
        XunitAssert.NotNull(tls);
        XunitAssert.Equal("tls", tls!.GetProtocolExtra().TurnTransport);
        XunitAssert.Equal("tcp", tls.GetProtocolExtra().TurnNetwork);
        XunitAssert.Equal(Global.StreamSecurity, tls.StreamSecurity);
        XunitAssert.True(tls.GetAllowInsecure());

        XunitAssert.Null(FmtHandler.ResolveConfig("turn://turn.example:3478?transport=udp&network=tcp", out _));
        XunitAssert.False(string.IsNullOrWhiteSpace(anonymousMessage));
        XunitAssert.False(string.IsNullOrWhiteSpace(authenticatedMessage));
        XunitAssert.False(string.IsNullOrWhiteSpace(tlsMessage));
    }

    [Fact]
    public void GetShareUri_TurnTls_ShouldRoundTripEscapedCredentialsAndOptions()
    {
        var source = new ProfileItem
        {
            ConfigType = EConfigType.TURN,
            CoreType = ECoreType.sing_box,
            Remarks = "TURN IPv6 demo",
            Address = "2001:db8::2",
            Port = 5349,
            Username = "user:name",
            Password = "p@ss word",
            StreamSecurity = Global.StreamSecurity,
            AllowInsecure = Global.StringTrue,
        };
        source.SetProtocolExtra(new ProtocolExtraItem
        {
            TurnTransport = "tls",
            TurnNetwork = "tcp",
        });

        var uri = FmtHandler.GetShareUri(source);
        XunitAssert.NotNull(uri);
        XunitAssert.StartsWith("turn://user%3Aname:p%40ss%20word@[2001:db8::2]:5349?transport=tls&network=tcp&insecure=1#", uri);

        var resolved = FmtHandler.ResolveConfig(uri!, out var message);
        XunitAssert.NotNull(resolved);
        XunitAssert.True(string.IsNullOrWhiteSpace(message) || message == ResUI.ConfigurationFormatIncorrect);
        XunitAssert.Equal(source.Remarks, resolved!.Remarks);
        XunitAssert.Equal(source.Address, resolved.Address);
        XunitAssert.Equal(source.Port, resolved.Port);
        XunitAssert.Equal(source.Username, resolved.Username);
        XunitAssert.Equal(source.Password, resolved.Password);
        XunitAssert.Equal("tls", resolved.GetProtocolExtra().TurnTransport);
        XunitAssert.Equal("tcp", resolved.GetProtocolExtra().TurnNetwork);
        XunitAssert.True(resolved.GetAllowInsecure());
    }
}
