using System.Text;
using SecureTransport;

namespace ExampleServer;

internal class ProgramConfig
{
    public static string Passphrase { get; set; } = "generic";
    public static string Address { get; set; } = "127.0.0.1";
    public static int Port { get; set; } = 8085;
}

internal class ServerWrapper
{
    public Dictionary<int, SecureConnection> Connections = new Dictionary<int, SecureConnection>();

    private readonly SecureTransportServer _server;

    public ServerWrapper()
    {
        _server = new SecureTransportServer(ProgramConfig.Passphrase, ProgramConfig.Port);
        _server.Open();
    }

    public void StartListening()
    {
        Thread listenerThread = new Thread(() =>
        {
            int connectionId = 0;
            while (true)
            {
                SecureConnection connection = new SecureConnection(_server);
                connection.Open();

                Connections[connectionId++] = connection;

                Thread clientTHread = new Thread(() => HandleConnection(connection, connectionId));
                clientTHread.Start();
            }
        });
        listenerThread.Start();
    }

    public void HandleConnection(SecureConnection connection, int connectionId)
    {
        try
        {
            while (true)
            {
                byte[] message = connection.ReceiveEncryptedPacket();
                string receivedMessage = Encoding.UTF8.GetString(message);
                Console.WriteLine($"Connection {connectionId} says: {receivedMessage}");

                connection.SendEncryptedPacket(message); // Echo message back
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"Client {connectionId} disconnected: {e.Message}");
            connection.Disconnect(); // Clean up connection
        }
    }

    public void Close()
    {
        _server.Close();
    }
}

internal class Program
{
    private static void Main(string[] args)
    {
        if (args.Length >= 1) ProgramConfig.Passphrase = args[0];

        ServerWrapper server = new ServerWrapper();

        server.StartListening();

        Console.WriteLine("Press Enter to exit.");
        Console.ReadLine();

        server.Close();
    }
}