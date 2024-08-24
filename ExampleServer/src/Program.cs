using System.Text;
using SecureTransport;

namespace ExampleServer;

internal class ProgramConfig
{
    public static string Passphrase { get; set; } = "generic";
    public static string Address { get; set; } = "127.0.0.1";
    public static int Port { get; set; } = 8085;
}

internal class Program
{
    private static void Main(string[] args)
    {
        if (args.Length >= 1) ProgramConfig.Passphrase = args[0];
    }
}