namespace ServiceLib.Handler.Fmt;

public class HttpFmt : BaseFmt
{
    public static ProfileItem? Resolve(string str, out string msg)
    {
        msg = ResUI.ConfigurationFormatIncorrect;

        var uri = Utils.TryUri(str);
        if (uri == null
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || uri.IdnHost.IsNullOrEmpty()
            || uri.Port <= 0
            || uri.AbsolutePath is not ("" or "/")
            || uri.Query.IsNotEmpty())
        {
            return null;
        }

        var item = new ProfileItem
        {
            ConfigType = EConfigType.HTTP,
            Remarks = uri.GetComponents(UriComponents.Fragment, UriFormat.Unescaped),
            Address = uri.IdnHost,
            Port = uri.Port,
            StreamSecurity = uri.Scheme == Uri.UriSchemeHttps ? Global.StreamSecurity : string.Empty,
            AllowInsecure = uri.Scheme == Uri.UriSchemeHttps ? Global.StringTrue : Global.StringFalse,
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

        return item;
    }

    public static string? ToUri(ProfileItem? item)
    {
        if (item == null)
        {
            return null;
        }

        var protocol = item.StreamSecurity == Global.StreamSecurity
            ? Global.HttpsProtocol
            : Global.HttpProtocol;
        var userInfo = item.Username.IsNotEmpty() && item.Password.IsNotEmpty()
            ? $"{Uri.EscapeDataString(item.Username)}:{Uri.EscapeDataString(item.Password)}@"
            : string.Empty;
        var remark = item.Remarks.IsNotEmpty()
            ? $"#{Utils.UrlEncode(item.Remarks)}"
            : string.Empty;

        return $"{protocol}{userInfo}{GetIpv6(item.Address)}:{item.Port}{remark}";
    }
}
