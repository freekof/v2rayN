namespace ServiceLib.Handler.Fmt;

public class TurnFmt : BaseFmt
{
    private const string TurnScheme = "turn";
    private const string TurnsScheme = "turns";

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
        var transport = GetQueryValue(query, "transport").ToLowerInvariant();
        if (transport.IsNullOrEmpty())
        {
            transport = uri.Scheme.Equals(TurnsScheme, StringComparison.OrdinalIgnoreCase) ? "tls" : "tcp";
        }
        if (!Global.TurnTransports.Contains(transport))
        {
            return null;
        }

        var network = GetQueryValue(query, "network").ToLowerInvariant();
        if (network.IsNotEmpty() && !Global.TurnNetworks.Contains(network))
        {
            return null;
        }
        if (transport == "udp" && network == "tcp")
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
            StreamSecurity = transport == "tls" ? Global.StreamSecurity : string.Empty,
            AllowInsecure = transport == "tls" && GetQueryValue(query, "insecure") == "1"
                ? Global.StringTrue
                : Global.StringFalse,
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
            TurnTransport = transport,
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
        var transport = extra.TurnTransport.IsNotEmpty() ? extra.TurnTransport.ToLowerInvariant() : "tcp";
        if (!Global.TurnTransports.Contains(transport))
        {
            transport = "tcp";
        }

        var query = new Dictionary<string, string>();
        if (transport != "tcp")
        {
            query.Add("transport", transport);
        }
        if (extra.TurnNetwork.IsNotEmpty())
        {
            query.Add("network", extra.TurnNetwork.ToLowerInvariant());
        }
        if (transport == "tls" && item.GetAllowInsecure())
        {
            query.Add("insecure", "1");
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
