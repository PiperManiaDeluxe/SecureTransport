using System.Text;
using SecureTransport;

namespace ExampleClient;

class Program
{
    static void Main(string[] args)
    {
        string passphrase = "generic";
        if (args.Length >= 1)
        {
            passphrase = args[0];
        }

        SecureTransportClient client = new SecureTransportClient("127.0.0.1", passphrase, 8085);
        client.Open();
        
        Console.WriteLine("Am I authed?: {0}", client.IsAuthed);

        if (client.IsAuthed)
        {
            Console.WriteLine(Encoding.UTF8.GetString(client.ReceiveEncryptedPacket()));
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}