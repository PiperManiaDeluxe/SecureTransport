using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SecureTransport;

/// <summary>
/// Represents a client for secure transport communication.
/// </summary>
public class SecureTransportClient
{
    /// <summary>
    /// Gets or sets the port number for the server connection.
    /// </summary>
    public int Port { get; set; }

    /// <summary>
    /// Gets or sets the server address.
    /// </summary>
    public string ServerAddress { get; set; }

    /// <summary>
    /// Gets a value indicating whether the client is authenticated.
    /// </summary>
    public bool IsAuthed { get; private set; }

    /// <summary>
    /// Gets the network stream for the client connection.
    /// </summary>
    public NetworkStream? Stream { get; private set; }

    private readonly string _passphrase;
    private byte[]? _encryptionKey;
    private TcpClient? _client;

    /// <summary>
    /// Initializes a new instance of the SecureTransportClient class.
    /// </summary>
    /// <param name="serverAddress">The address of the server to connect to.</param>
    /// <param name="passphrase">The passphrase for authentication and encryption.</param>
    /// <param name="port">The port number to connect to. Defaults to 8008.</param>
    public SecureTransportClient(string serverAddress, string passphrase, int port = 8008)
    {
        ServerAddress = serverAddress;
        _passphrase = passphrase;
        Port = port;
    }

    /// <summary>
    /// Opens a connection to the server and performs authentication.
    /// </summary>
    public void Open()
    {
        _client = new TcpClient(ServerAddress, Port);
        Stream = _client.GetStream();
        
        // Receive auth challenge
        byte[] challenge = new byte[HMACSHA512.HashSizeInBytes];
        int bytesRead = Stream.Read(challenge, 0, challenge.Length);
        if (bytesRead != challenge.Length)
            throw new InvalidOperationException("Failed to receive full challenge.");

        // Compute and send response
        byte[] response = CryptoHelper.ComputeHmac(challenge, _passphrase);
        Stream.Write(response, 0, response.Length);

        // Derive encryption key
        _encryptionKey = CryptoHelper.DeriveKey(_passphrase, challenge);

        // Receive the welcome message
        byte[] encryptedWelcome = ReceivePacket(Stream) ?? throw new InvalidOperationException("Failed to receive welcome message.");
        byte[] decryptedWelcome = CryptoHelper.Decrypt(encryptedWelcome, _encryptionKey);
        if (Encoding.UTF8.GetString(decryptedWelcome) == "You are authed!")
        {
            IsAuthed = true;
        }
        else
        {
            throw new InvalidOperationException("Authentication failed.");
        }
    }

    /// <summary>
    /// Sends an encrypted packet to the server.
    /// </summary>
    /// <param name="data">The data to be encrypted and sent.</param>
    public void SendEncryptedPacket(byte[] data)
    {
        if (!IsAuthed)
            throw new InvalidOperationException("Client is not yet authenticated.");
        
        byte[] encryptedPacket = CryptoHelper.Encrypt(data, _encryptionKey!);
        SendPacket(Stream!, encryptedPacket);
    }

    /// <summary>
    /// Receives and decrypts a packet from the server.
    /// </summary>
    /// <returns>The decrypted packet data.</returns>
    public byte[] ReceiveEncryptedPacket()
    {
        if (!IsAuthed)
            throw new InvalidOperationException("Client is not yet authenticated.");

        byte[] data = ReceivePacket(Stream!) ?? throw new InvalidOperationException("Failed to receive packet.");
        return CryptoHelper.Decrypt(data, _encryptionKey!); 
    }

    /// <summary>
    /// Sends a packet over the network stream.
    /// </summary>
    /// <param name="stream">The network stream to send the packet on.</param>
    /// <param name="data">The packet data to send.</param>
    internal void SendPacket(NetworkStream stream, byte[] data)
    {
        byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
        stream.Write(lengthPrefix, 0, sizeof(int));
        stream.Write(data, 0, data.Length);
    }

    /// <summary>
    /// Receives a packet from the network stream.
    /// </summary>
    /// <param name="stream">The network stream to receive the packet from.</param>
    /// <returns>The received packet data, or null if the receive operation failed.</returns>
    internal byte[]? ReceivePacket(NetworkStream stream)
    {
        byte[] lengthPrefix = new byte[sizeof(int)];
        int bytesRead = stream.Read(lengthPrefix, 0, sizeof(int));
        if (bytesRead < sizeof(int)) return null;

        int length = BitConverter.ToInt32(lengthPrefix, 0);
        byte[] buffer = new byte[length];
        bytesRead = stream.Read(buffer, 0, length);
        if (bytesRead < length) return null;

        return buffer;
    }
}