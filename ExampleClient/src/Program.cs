using System.Text;
using SecureTransport;

namespace ExampleClient;

internal class ProgramConfig
{
    public static string Passphrase { get; set; } = "generic";
    public static string Address { get; set; } = "127.0.0.1";
    public static int Port { get; set; } = 8085;
}

internal class ClientWrapper
{
    public bool LoopRunning;

    private readonly SecureTransportClient _client;

    public ClientWrapper()
    {
        _client = new SecureTransportClient(ProgramConfig.Address, ProgramConfig.Passphrase, ProgramConfig.Port);
        _client.Open();
    }

    public void Loop()
    {
        LoopRunning = true;

        Thread t = new Thread(() =>
        {
            while (LoopRunning)
            {
                // Send a message
                Console.Write("Message (\"quit\" to quit):");
                string? sMessage = Console.ReadLine();
                if (sMessage == null)
                    continue;

                if (sMessage == "quit") LoopRunning = false;

                _client.SendEncryptedPacket(Encoding.UTF8.GetBytes(sMessage));

                // Receive a message
                byte[] rMessage = _client.ReceiveEncryptedPacket();
                Console.WriteLine($"Server says: {Encoding.UTF8.GetString(rMessage)}");
            }
        });

        t.Start();
    }

    public bool IsAuthed => _client.IsAuthed;

    public void Close()
    {
        _client.Disconnect();
    }
}

internal class Program
{
    private static void Main(string[] args)
    {
        if (args.Length >= 1) ProgramConfig.Passphrase = args[0];

        ClientWrapper client = new ClientWrapper();

        client.Loop();

        Console.WriteLine("Press Enter to exit.");
        Console.ReadLine();

        client.Close();
    }
}