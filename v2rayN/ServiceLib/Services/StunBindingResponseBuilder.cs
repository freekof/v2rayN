namespace ServiceLib.Services;

public static class StunBindingResponseBuilder
{
    private const ushort BindingSuccessResponse = 0x0101;
    private const ushort XorMappedAddress = 0x0020;

    public static byte[] BuildSuccessResponse(ReadOnlySpan<byte> request, IPEndPoint mappedAddress)
    {
        if (!StunPacketInspector.IsStunBindingRequest(request))
        {
            throw new ArgumentException("Request must be a STUN Binding Request.", nameof(request));
        }

        var addressBytes = mappedAddress.Address.GetAddressBytes();
        var isIpv4 = addressBytes.Length == 4;
        var attributeValueLength = isIpv4 ? 8 : 20;
        var messageLength = 4 + attributeValueLength;
        var response = new byte[20 + messageLength];

        response[0] = (byte)((BindingSuccessResponse >> 8) & 0xFF);
        response[1] = (byte)(BindingSuccessResponse & 0xFF);
        response[2] = (byte)((messageLength >> 8) & 0xFF);
        response[3] = (byte)(messageLength & 0xFF);
        request[4..20].CopyTo(response.AsSpan(4, 16));

        response[20] = (byte)((XorMappedAddress >> 8) & 0xFF);
        response[21] = (byte)(XorMappedAddress & 0xFF);
        response[22] = (byte)((attributeValueLength >> 8) & 0xFF);
        response[23] = (byte)(attributeValueLength & 0xFF);
        response[25] = isIpv4 ? (byte)0x01 : (byte)0x02;

        var xorPort = mappedAddress.Port ^ ((request[4] << 8) | request[5]);
        response[26] = (byte)((xorPort >> 8) & 0xFF);
        response[27] = (byte)(xorPort & 0xFF);

        for (var i = 0; i < addressBytes.Length; i++)
        {
            response[28 + i] = (byte)(addressBytes[i] ^ request[4 + (i % 16)]);
        }

        return response;
    }
}
