namespace ServiceLib.Services;

public static class StunRelayLogger
{
    private static readonly object FileLock = new();

    public static void Info(string message)
    {
        Write("INFO", message);
    }

    public static void Error(string message, Exception ex)
    {
        Write("ERROR", $"{message}; {ex.GetType().Name}: {ex.Message}");
    }

    private static void Write(string level, string message)
    {
        try
        {
            var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}{Environment.NewLine}";
            lock (FileLock)
            {
                File.AppendAllText(Utils.GetLogPath($"webrtc_stun_relay_{DateTime.Now:yyyy-MM-dd}.txt"), line, Encoding.UTF8);
            }
        }
        catch
        {
        }
    }
}
