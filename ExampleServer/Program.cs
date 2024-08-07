using System.Text;
using SecureTransport;

namespace ExampleServer;

class Program
{
    static void Main(string[] args)
    {
        string passphrase = "generic";
        if (args.Length >= 1)
        {
            passphrase = args[0];
        }

        SecureTransportServer server = new SecureTransportServer(passphrase, 8085);
        server.Open();

        SecureConnection client = server.AcceptClient();
        client.AuthSelf();
        
        Console.WriteLine("Client is authed?: {0}", client.IsAuthed);

        if (client.IsAuthed)
        {
            client.SendEncryptedPacket(Encoding.UTF8.GetBytes("Hello, World!"));
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}