namespace ServiceLib.Models.Dto;

internal class IPAPIInfo
{
    public string? ip { get; set; }
    public string? clientIp { get; set; }
    public string? ip_addr { get; set; }
    public string? query { get; set; }
    public string? country { get; set; }
    public string? country_name { get; set; }
    public string? country_code { get; set; }
    public string? countryCode { get; set; }
    public LocationInfo? location { get; set; }
    public JsonElement asn { get; set; }
    public string? asnCode { get; set; }
}

public class LocationInfo
{
    public string? country_code { get; set; }
}

public readonly record struct IpInfoResult(string Country, string? Ip)
{
    public string? Asn { get; init; }

    public static IpInfoResult? ParseCloudflareTrace(string? content)
    {
        if (content.IsNullOrEmpty())
        {
            return null;
        }

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = line.IndexOf('=');
            if (separator > 0)
            {
                values[line[..separator]] = line[(separator + 1)..];
            }
        }

        values.TryGetValue("ip", out var ip);
        if (ip.IsNullOrEmpty())
        {
            return null;
        }

        values.TryGetValue("loc", out var country);
        values.TryGetValue("asn", out var asn);
        if (asn.IsNullOrEmpty())
        {
            values.TryGetValue("as", out asn);
        }

        return Create(country, ip, asn);
    }

    public static IpInfoResult? ParseJson(string? content)
    {
        if (content.IsNullOrEmpty())
        {
            return null;
        }

        var info = JsonUtils.Deserialize<IPAPIInfo>(content);
        if (info == null)
        {
            return null;
        }

        var ip = info.ip ?? info.clientIp ?? info.ip_addr ?? info.query;
        var country = info.country_code ?? info.country ?? info.countryCode ?? info.location?.country_code;
        return Create(country, ip, GetAsnCode(info));
    }

    public string? ToCompactString(bool requireAsn = false)
    {
        var ip = Ip?.Trim();
        if (ip.IsNullOrEmpty() || (requireAsn && Asn.IsNullOrEmpty()))
        {
            return null;
        }

        return Asn.IsNotEmpty()
            ? $"{NormalizeCountry(Country)}{ip} {Asn}"
            : $"{NormalizeCountry(Country)}{ip}";
    }

    public override string ToString()
    {
        var country = NormalizeCountry(Country);
        var emoji = Utils.IsWindows() ? null : country.CountryToEmoji();
        return Asn.IsNotEmpty()
            ? $"{emoji}({country}) {Ip?.Trim()} {Asn}"
            : $"{emoji}({country}) {Ip?.Trim()}";
    }

    private static IpInfoResult? Create(string? country, string? ip, string? asn)
    {
        ip = ip?.Trim();
        if (ip.IsNullOrEmpty())
        {
            return null;
        }

        return new IpInfoResult(NormalizeCountry(country), ip)
        {
            Asn = NormalizeAsnCode(asn)
        };
    }

    private static string NormalizeCountry(string? country)
    {
        return country.IsNullOrEmpty() ? "unknown" : country.Trim().ToUpperInvariant();
    }

    private static string? GetAsnCode(IPAPIInfo info)
    {
        var asn = NormalizeAsnCode(info.asnCode);
        if (asn.IsNotEmpty())
        {
            return asn;
        }

        if (info.asn.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return null;
        }
        if (info.asn.ValueKind == JsonValueKind.Object)
        {
            if (info.asn.TryGetProperty("asn", out var asnProperty))
            {
                asn = NormalizeAsnCode(asnProperty.ToString());
            }
            if (asn.IsNullOrEmpty() && info.asn.TryGetProperty("number", out var numberProperty))
            {
                asn = NormalizeAsnCode(numberProperty.ToString());
            }
            return asn;
        }

        return NormalizeAsnCode(info.asn.ToString());
    }

    private static string? NormalizeAsnCode(string? asn)
    {
        if (asn.IsNullOrEmpty())
        {
            return null;
        }

        var value = asn.Trim().ToUpperInvariant();
        if (value.StartsWith("AS"))
        {
            value = value[2..].Trim();
        }
        else
        {
            value = value.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        }

        if (value.IsNullOrEmpty())
        {
            return null;
        }

        var digits = new string(value.TakeWhile(char.IsDigit).ToArray());
        return digits.IsNotEmpty() ? $"AS{digits}" : null;
    }
}
