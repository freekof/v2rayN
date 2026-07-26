namespace ServiceLib.Services;

public static class StunPacketInspector
{
    private const int HeaderLength = 20;
    private const ushort BindingRequest = 0x0001;

    public static bool IsStunBindingRequest(ReadOnlySpan<byte> payload)
    {
        if (!IsStunPacket(payload))
        {
            return false;
        }

        var messageType = (ushort)((payload[0] << 8) | payload[1]);
        return messageType == BindingRequest;
    }

    public static bool IsStunPacket(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < HeaderLength)
        {
            return false;
        }

        if ((payload[0] & 0xC0) != 0)
        {
            return false;
        }

        if (payload[4] != 0x21 || payload[5] != 0x12 || payload[6] != 0xA4 || payload[7] != 0x42)
        {
            return false;
        }

        var messageLength = (payload[2] << 8) | payload[3];
        if (messageLength % 4 != 0)
        {
            return false;
        }

        return HeaderLength + messageLength <= payload.Length;
    }
}
