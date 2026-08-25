namespace ServiceLib.Handler.Fmt;

public class TurnFmt : BaseFmt
{
    private const string TurnScheme = "turn";
    private const string TurnsScheme = "turns";
    private const string TurnNetworkAll = "tcp+udp";

    public static ProfileItem? Resolve(string str, out string msg)
    {
        msg = ResUI.ConfigurationFormatIncorrect;

        var uri = Utils.TryUri(str);
        if (uri == null
            || (!uri.Scheme.Equals(TurnScheme, StringComparison.OrdinalIgnoreCase)
                && !uri.Scheme.Equals(TurnsScheme, StringComparison.OrdinalIgnoreCase))
            || uri.IdnHost.IsNullOrEmpty()
            || uri.Port <= 0
            || uri.AbsolutePath is not ("" or "/"))
        {
            return null;
        }

        var query = Utils.ParseQueryString(uri.Query);
        var legacyTransport = GetQueryValue(query, "transport").ToLowerInvariant();
        var useTls = uri.Scheme.Equals(TurnsScheme, StringComparison.OrdinalIgnoreCase)
                     || GetQueryValue(query, "tls").Equals("1", StringComparison.OrdinalIgnoreCase)
                     || GetQueryValue(query, "tls").Equals("true", StringComparison.OrdinalIgnoreCase)
                     || legacyTransport == "tls";
        var network = GetQueryValue(query, "network").ToLowerInvariant().Replace(' ', '+');
        if (network.IsNullOrEmpty())
        {
            network = legacyTransport == "udp" ? "udp" : TurnNetworkAll;
        }
        if (!Global.TurnNetworks.Contains(network))
        {
            return null;
        }

        var item = new ProfileItem
        {
            ConfigType = EConfigType.TURN,
            CoreType = ECoreType.sing_box,
            Remarks = uri.GetComponents(UriComponents.Fragment, UriFormat.Unescaped),
            Address = uri.IdnHost,
            Port = uri.Port,
            StreamSecurity = useTls ? Global.StreamSecurity : string.Empty,
            AllowInsecure = useTls && GetQueryValue(query, "insecure") == "1"
                ? Global.StringTrue
                : Global.StringFalse,
            Sni = useTls ? GetQueryDecoded(query, "sni") : string.Empty,
        };

        var userInfo = uri.GetComponents(UriComponents.UserInfo, UriFormat.UriEscaped);
        if (userInfo.IsNotEmpty())
        {
            var parts = userInfo.Split(':', 2);
            if (parts.Length == 2)
            {
                item.Username = Utils.UrlDecode(parts[0]);
                item.Password = Utils.UrlDecode(parts[1]);
            }
        }

        item.SetProtocolExtra(new ProtocolExtraItem
        {
            // Maintained for compatibility with existing persisted TURN profiles.
            TurnTransport = useTls ? "tls" : "tcp",
            TurnNetwork = network,
        });

        return item;
    }

    public static string? ToUri(ProfileItem? item)
    {
        if (item == null)
        {
            return null;
        }

        var extra = item.GetProtocolExtra();
        var network = Global.TurnNetworks.Contains(extra.TurnNetwork)
            ? extra.TurnNetwork
            : extra.TurnTransport == "udp"
                ? "udp"
                : TurnNetworkAll;
        var useTls = item.StreamSecurity == Global.StreamSecurity;
        var query = new Dictionary<string, string>();
        if (network != TurnNetworkAll)
        {
            query.Add("network", network);
        }
        if (useTls)
        {
            query.Add("tls", "1");
            if (item.GetAllowInsecure())
            {
                query.Add("insecure", "1");
            }
            if (item.Sni.IsNotEmpty())
            {
                query.Add("sni", item.Sni);
            }
        }

        var userInfo = item.Username.IsNotEmpty() && item.Password.IsNotEmpty()
            ? $"{Uri.EscapeDataString(item.Username)}:{Uri.EscapeDataString(item.Password)}@"
            : string.Empty;
        var queryString = query.Count > 0
            ? $"?{string.Join("&", query.Select(x => $"{x.Key}={Uri.EscapeDataString(x.Value)}"))}"
            : string.Empty;
        var remark = item.Remarks.IsNotEmpty() ? $"#{Utils.UrlEncode(item.Remarks)}" : string.Empty;
        return $"{Global.ProtocolShares[EConfigType.TURN]}{userInfo}{GetIpv6(item.Address)}:{item.Port}{queryString}{remark}";
    }
}
