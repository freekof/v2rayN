namespace ServiceLib.Services;

public sealed record Socks5UdpPacket(string Host, int Port, byte[] Payload)
{
    private const byte AtypIpv4 = 0x01;
    private const byte AtypDomain = 0x03;
    private const byte AtypIpv6 = 0x04;

    public static bool TryParse(ReadOnlySpan<byte> buffer, out Socks5UdpPacket? packet)
    {
        packet = null;
        if (buffer.Length < 10 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0)
        {
            return false;
        }

        var offset = 4;
        var host = string.Empty;
        switch (buffer[3])
        {
            case AtypIpv4:
                if (buffer.Length < offset + 4 + 2)
                {
                    return false;
                }
                host = new IPAddress(buffer.Slice(offset, 4)).ToString();
                offset += 4;
                break;

            case AtypDomain:
                if (buffer.Length < offset + 1)
                {
                    return false;
                }
                var length = buffer[offset++];
                if (length == 0 || buffer.Length < offset + length + 2)
                {
                    return false;
                }
                host = Encoding.ASCII.GetString(buffer.Slice(offset, length));
                offset += length;
                break;

            case AtypIpv6:
                if (buffer.Length < offset + 16 + 2)
                {
                    return false;
                }
                host = new IPAddress(buffer.Slice(offset, 16)).ToString();
                offset += 16;
                break;

            default:
                return false;
        }

        var port = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;
        packet = new Socks5UdpPacket(host, port, buffer[offset..].ToArray());
        return true;
    }

    public byte[] Encode()
    {
        if (Port is < IPEndPoint.MinPort or > IPEndPoint.MaxPort)
        {
            throw new ArgumentOutOfRangeException(nameof(Port));
        }

        byte atyp;
        byte[] addressBytes;
        if (IPAddress.TryParse(Host, out var ipAddress))
        {
            addressBytes = ipAddress.GetAddressBytes();
            atyp = addressBytes.Length == 4 ? AtypIpv4 : AtypIpv6;
        }
        else
        {
            addressBytes = Encoding.ASCII.GetBytes(Host);
            if (addressBytes.Length is 0 or > byte.MaxValue)
            {
                throw new ArgumentException("Host must be a non-empty domain name up to 255 bytes.", nameof(Host));
            }
            atyp = AtypDomain;
        }

        var headerLength = atyp == AtypDomain ? 5 + addressBytes.Length + 2 : 4 + addressBytes.Length + 2;
        var encoded = new byte[headerLength + Payload.Length];
        encoded[3] = atyp;
        var offset = 4;
        if (atyp == AtypDomain)
        {
            encoded[offset++] = (byte)addressBytes.Length;
        }
        addressBytes.CopyTo(encoded, offset);
        offset += addressBytes.Length;
        encoded[offset++] = (byte)((Port >> 8) & 0xFF);
        encoded[offset++] = (byte)(Port & 0xFF);
        Payload.CopyTo(encoded, offset);
        return encoded;
    }
}
