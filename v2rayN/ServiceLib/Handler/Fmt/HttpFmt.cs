using ServiceLib.Models;

namespace ServiceLib.Handler.Fmt;

/// <summary>
/// HTTP/HTTPS代理格式解析器
/// 参考SocksFmt的实现方式
/// </summary>
public class HttpFmt : BaseFmt
{
    public static ProfileItem? Resolve(string str, out string msg)
    {
        msg = string.Empty;
        ProfileItem? item = null;

        try
        {
            // 支持的格式:
            // http://host:port
            // http://username:password@host:port
            // https://host:port
            // https://username:password@host:port

            if (str.IsNullOrEmpty() || 
                (!str.StartsWith(Global.HttpProtocol) && !str.StartsWith(Global.HttpsProtocol)))
            {
                return null;
            }

            // 避免误识别订阅URL
            if (str.Contains("/sub", StringComparison.OrdinalIgnoreCase) ||
                str.Contains("subscription", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var uri = new Uri(str);
            item = new ProfileItem
            {
                ConfigType = EConfigType.HTTP,
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : (uri.Scheme == "https" ? 443 : 8080),
                Remarks = $"{uri.Scheme.ToUpper()}-{uri.Host}:{uri.Port}"
            };

            // HTTPS需要TLS
            if (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                item.StreamSecurity = "tls";
                item.Sni = uri.Host;
            }

            // 解析用户名密码
            if (!uri.UserInfo.IsNullOrEmpty())
            {
                var userInfo = uri.UserInfo.Split(':');
                if (userInfo.Length > 0)
                {
                    item.Security = "basic";
                    item.Id = Uri.UnescapeDataString(userInfo[0]);
                    
                    if (userInfo.Length > 1)
                    {
                        // HTTP代理的密码存储在AlterId字段
                        // 这与SOCKS的实现方式相同
                        item.AlterId = Uri.UnescapeDataString(userInfo[1]);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            msg = ex.Message;
        }

        return item;
    }

    public static string? ToUri(ProfileItem? item)
    {
        if (item == null) return null;
        
        try
        {
            var url = item.StreamSecurity == "tls" ? "https://" : "http://";
            
            // 添加认证信息
            if (!item.Id.IsNullOrEmpty())
            {
                url += Uri.EscapeDataString(item.Id);
                if (!item.AlterId.IsNullOrEmpty())
                {
                    url += ":" + Uri.EscapeDataString(item.AlterId);
                }
                url += "@";
            }
            
            url += $"{item.Address}:{item.Port}";
            
            return url;
        }
        catch
        {
            return null;
        }
    }
}
