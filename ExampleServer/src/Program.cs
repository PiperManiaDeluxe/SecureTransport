using System.Text;
using SecureTransport;

namespace ExampleServer;

class ProgramConfig
{
    public static string Passphrase { get; set; } = "generic";
    public static string Address { get; set; } = "127.0.0.1";
    public static int Port { get; set; } = 8085;
}

class ServerWrapper
{
    public bool LoopRunning;

    public Dictionary<int, SecureConnection> Connections = new Dictionary<int, SecureConnection>();

    private readonly SecureTransportServer _server;

    public ServerWrapper()
    {
        _server = new SecureTransportServer(ProgramConfig.Passphrase, ProgramConfig.Port);
        _server.Open();
    }

    public void Loop()
    {
        LoopRunning = true;
        int iConnection = 0;

        Thread t = new Thread(() =>
        {
            while (LoopRunning)
            {
                // accept a new client
                SecureConnection c = new SecureConnection(_server);
                c.Open();
                Connections.Add(iConnection, c);
                iConnection++;

                int connection = iConnection;
                Thread cT = new Thread(() => { HandleConnection(c, connection); });
                cT.Start();
            }
        });
        t.Start();
    }

    public void HandleConnection(SecureConnection c, int i)
    {
        while (LoopRunning)
        {
            // Receive a message
            byte[] rMessage = c.ReceiveEncryptedPacket();
            string rStr = Encoding.UTF8.GetString(rMessage);
            Console.WriteLine($"connection {i} says: {rStr}");

            // Echo the message
            c.SendEncryptedPacket(rMessage);
        }
    }
}

class Program
{
    static void Main(string[] args)
    {
        if (args.Length >= 1)
        {
            ProgramConfig.Passphrase = args[0];
        }

        ServerWrapper server = new ServerWrapper();

        server.Loop();

        while (server.LoopRunning)
        {
            Thread.Sleep(100);
        }
    }
}