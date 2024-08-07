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

    private readonly string _passphrase; // Passphrase for encryption and authentication
    private byte[]? _encryptionKey; // Encryption key derived from the passphrase
    private TcpClient? _client; // TCP client for network communication

    /// <summary>
    /// Initializes a new instance of the SecureTransportClient class.
    /// </summary>
    /// <param name="serverAddress">The address of the server to connect to.</param>
    /// <param name="passphrase">The passphrase for authentication and encryption.</param>
    /// <param name="port">The port number to connect to. Defaults to 8008.</param>
    public SecureTransportClient(string serverAddress, string passphrase, int port = 8008)
    {
        // Validate inputs
        ServerAddress = serverAddress ?? throw new ArgumentNullException(nameof(serverAddress));
        _passphrase = passphrase ?? throw new ArgumentNullException(nameof(passphrase));
        Port = port; // Set the port number
    }

    /// <summary>
    /// Opens a connection to the server and performs authentication.
    /// </summary>
    public void Open()
    {
        // Establish TCP connection to the server
        _client = new TcpClient(ServerAddress, Port);
        Stream = _client.GetStream();

        // Receive authentication challenge from the server
        byte[] challenge = new byte[HMACSHA512.HashSizeInBytes];
        int bytesRead = Stream.Read(challenge, 0, challenge.Length);

        // Ensure the full challenge is received
        if (bytesRead != challenge.Length)
            throw new InvalidOperationException("Failed to receive full challenge.");

        // Compute and send response to the authentication challenge
        byte[] response = CryptoHelper.ComputeHmac(challenge, _passphrase);
        Stream.Write(response, 0, response.Length);

        // Derive encryption key from the passphrase and challenge
        _encryptionKey = CryptoHelper.DeriveKey(_passphrase, challenge);

        // Receive and decrypt the welcome message from the server
        byte[] encryptedWelcome = ReceivePacket(Stream) ??
                                  throw new InvalidOperationException("Failed to receive welcome message.");
        byte[] decryptedWelcome = CryptoHelper.Decrypt(encryptedWelcome, _encryptionKey);

        // Check if the authentication was successful
        if (Encoding.UTF8.GetString(decryptedWelcome) == "You are authed!")
        {
            IsAuthed = true; // Set authentication status to true
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
        // Ensure the client is authenticated before sending data
        if (!IsAuthed)
            throw new InvalidOperationException("Client is not yet authenticated.");

        // Encrypt the packet data
        byte[] encryptedPacket = CryptoHelper.Encrypt(data, _encryptionKey!);
        SendPacket(Stream!, encryptedPacket); // Send the encrypted packet
    }

    /// <summary>
    /// Receives and decrypts a packet from the server.
    /// </summary>
    /// <returns>The decrypted packet data.</returns>
    public byte[] ReceiveEncryptedPacket()
    {
        // Ensure the client is authenticated before receiving data
        if (!IsAuthed)
            throw new InvalidOperationException("Client is not yet authenticated.");

        // Receive the encrypted packet data
        byte[] data = ReceivePacket(Stream!) ?? throw new InvalidOperationException("Failed to receive packet.");
        return CryptoHelper.Decrypt(data, _encryptionKey!); // Decrypt and return the data
    }

    /// <summary>
    /// Sends a packet over the network stream.
    /// </summary>
    /// <param name="stream">The network stream to send the packet on.</param>
    /// <param name="data">The packet data to send.</param>
    internal void SendPacket(NetworkStream stream, byte[] data)
    {
        // Create a length prefix for the packet data
        byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
        stream.Write(lengthPrefix, 0, sizeof(int)); // Send the length prefix
        stream.Write(data, 0, data.Length); // Send the actual data
    }

    /// <summary>
    /// Receives a packet from the network stream.
    /// </summary>
    /// <param name="stream">The network stream to receive the packet from.</param>
    /// <returns>The received packet data, or null if the receive operation failed.</returns>
    internal byte[]? ReceivePacket(NetworkStream stream)
    {
        // Read the length prefix to determine the size of the incoming packet
        byte[] lengthPrefix = new byte[sizeof(int)];
        int bytesRead = stream.Read(lengthPrefix, 0, sizeof(int));

        // If the length prefix is not fully read, return null
        if (bytesRead < sizeof(int)) return null;

        // Get the actual length of the incoming packet
        int length = BitConverter.ToInt32(lengthPrefix, 0);
        byte[] buffer = new byte[length]; // Create a buffer for the packet data

        // Read the packet data
        bytesRead = stream.Read(buffer, 0, length);

        // If the packet data is not fully read, return null
        if (bytesRead < length) return null;

        return buffer; // Return the received packet data
    }
}