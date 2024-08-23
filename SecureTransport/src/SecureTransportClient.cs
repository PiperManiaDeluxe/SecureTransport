using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SecureTransport;

/// <summary>
/// Represents a client for secure transport communication.
/// </summary>
public class SecureTransportClient : ISecureTransportConnection, IAsyncSecureTransportConnection
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

    /// <summary>
    /// Action to handle received messages (after StartListening is called).
    /// </summary>
    public event EventHandler<byte[]>? MessageReceived;

    /// <summary>
    /// Action to handle errors that occur during communication.
    /// </summary>
    public event EventHandler<string>? ErrorOccurred = (sender, errorMessage) => { Console.WriteLine(errorMessage); };

    private readonly string _passphrase; // Passphrase for encryption and authentication
    private byte[]? _salt; // Salt used for key derivation
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
        try
        {
            // Validate inputs
            ServerAddress = serverAddress ?? throw new ArgumentNullException(nameof(serverAddress));
            _passphrase = passphrase ?? throw new ArgumentNullException(nameof(passphrase));

            if (port < 1 || port > 65535)
                throw new ArgumentOutOfRangeException(nameof(port));

            Port = port; // Set the port number
        }
        catch (Exception e)
        {
            OnErrorOccurred($"SecureTransport: Error initializing client: {e.Message}");
            throw;
        }
    }

    /// <summary>
    /// Opens a connection to the server and performs authentication.
    /// </summary>
    public void Open()
    {
        try
        {
            if (Stream != null)
                throw new InvalidOperationException("Already connected.");

            // Establish TCP connection to the server
            _client = new TcpClient(ServerAddress, Port);
            Stream = _client.GetStream();

            // Receive authentication challenge from the server
            _salt = new byte[HMACSHA512.HashSizeInBytes];
            int bytesRead = Stream.Read(_salt, 0, _salt.Length);

            // Ensure the full challenge is received
            if (bytesRead != _salt.Length)
                throw new InvalidOperationException("Failed to receive full challenge.");

            // Compute and send response to the authentication challenge
            byte[] response = CryptoHelper.ComputeHmac(_salt, _passphrase);
            Stream.Write(response, 0, response.Length);

            // Derive encryption key from the passphrase and challenge
            _encryptionKey = CryptoHelper.DeriveKey(_passphrase, _salt);

            // Receive and decrypt the welcome message from the server
            byte[] encryptedWelcome = ReceivePacket(Stream) ??
                                      throw new InvalidOperationException("Failed to receive welcome message.");
            byte[] decryptedWelcome = CryptoHelper.Decrypt(encryptedWelcome, _encryptionKey);

            // Check if the authentication was successful
            if (Encoding.UTF8.GetString(decryptedWelcome) == "You are authed!")
                IsAuthed = true; // Set authentication status to true
            else
                throw new InvalidOperationException("Authentication failed.");
        }
        catch (Exception e)
        {
            OnErrorOccurred($"SecureTransport: Error occurred during client open: {e.Message}");
            throw;
        }
    }

    /// <summary>
    /// Opens a connection to the server and performs authentication asynchronously.
    /// </summary>
    public async Task OpenAsync()
    {
        try
        {
            if (Stream != null)
                throw new InvalidOperationException("Already connected.");

            // Establish TCP connection to the server
            _client = new TcpClient();
            await _client.ConnectAsync(ServerAddress, Port);
            Stream = _client.GetStream();

            // Receive authentication challenge from the server
            byte[] challenge = new byte[HMACSHA512.HashSizeInBytes];
            int bytesRead = await Stream.ReadAsync(challenge, 0, challenge.Length);

            // Ensure the full challenge is received
            if (bytesRead != challenge.Length)
                throw new InvalidOperationException("Failed to receive full challenge.");

            // Compute and send response to the authentication challenge
            byte[] response = CryptoHelper.ComputeHmac(challenge, _passphrase);
            await Stream.WriteAsync(response, 0, response.Length);

            // Derive encryption key from the passphrase and challenge
            _encryptionKey = CryptoHelper.DeriveKey(_passphrase, challenge);

            // Receive and decrypt the welcome message from the server
            byte[]? encryptedWelcome = await (ReceivePacketAsync(Stream) ??
                                              throw new InvalidOperationException(
                                                  "Failed to receive welcome message."));
            byte[] decryptedWelcome = CryptoHelper.Decrypt(encryptedWelcome!, _encryptionKey);

            // Check if the authentication was successful
            if (Encoding.UTF8.GetString(decryptedWelcome) == "You are authed!")
                IsAuthed = true; // Set authentication status to true
            else
                throw new InvalidOperationException("Authentication failed.");
        }
        catch (Exception e)
        {
            OnErrorOccurred($"SecureTransport: Error occurred during client open async: {e.Message}");
            throw;
        }
    }

    /// <summary>
    /// Raises the MessageReceived event.
    /// </summary>
    /// <param name="message">The decrypted message that was received.</param>
    protected virtual void OnMessageReceived(byte[] message)
    {
        MessageReceived?.Invoke(this, message);
    }

    /// <summary>
    /// Raises the ErrorOccurred event.
    /// </summary>
    /// <param name="errorMessage">The error message to be logged or handled.</param>
    protected virtual void OnErrorOccurred(string errorMessage)
    {
        ErrorOccurred?.Invoke(this, errorMessage);
    }

    /// <summary>
    /// Start listening for messages, pass all received message to the `MessageReceived` action.
    /// </summary>
    public async Task StartListening()
    {
        if (!IsAuthed)
            throw new InvalidOperationException("Client is not yet authenticated.");

        if (Stream == null)
            throw new InvalidOperationException("There is no active network stream.");

        try
        {
            while (true)
            {
                // Receive the encrypted packet data
                byte[]? data = await ReceivePacketAsync(Stream);
                if (data == null)
                    break; // Break the loop if null is received which indicates disconnection

                // Decrypt the received data
                byte[] decryptedData = CryptoHelper.Decrypt(data, _encryptionKey!);

                // Raise the MessageReceived event with the decrypted message
                OnMessageReceived(decryptedData);
            }
        }
        catch (Exception e)
        {
            OnErrorOccurred($"SecureTransport: Error occurred while listening: {e.Message}");
        }
        finally
        {
            Disconnect(); // Ensure disconnection cleanup
        }
    }

    /// <summary>
    /// Tries to reconnect to the server.
    /// </summary>
    /// <param name="maxAttempts">Max attempts at reconnecting.</param>
    /// <param name="delay">Delay between attempts. Defaults at 5s.</param>
    public void Reconnect(int maxAttempts = 5, TimeSpan? delay = null)
    {
        delay ??= TimeSpan.FromSeconds(5);
        int attempts = 0;

        while (attempts < maxAttempts)
        {
            attempts++;

            try
            {
                Open();
                return;
            }
            catch (Exception e)
            {
                OnErrorOccurred($"SecureTransport: Reconnection attempt {attempts} failed: {e.Message}");
            }

            Task.Delay(delay.Value).Wait(); // Wait before the next attempt
        }
    }

    /// <summary>
    /// Tries to recconect to the server asynchronously.
    /// </summary>
    /// <param name="maxAttempts">Max attempts at reconnecting.</param>
    /// <param name="delay">Delay between attempts. Defaults at 5s.</param>
    public async Task ReconnectAsync(int maxAttempts = 5, TimeSpan? delay = null)
    {
        delay ??= TimeSpan.FromSeconds(5);
        int attempts = 0;

        while (attempts < maxAttempts)
        {
            attempts++;

            try
            {
                await OpenAsync();
                return;
            }
            catch (Exception e)
            {
                OnErrorOccurred($"SecureTransport: Reconnection attempt {attempts} failed: {e.Message}");
            }

            await Task.Delay(delay.Value); // Wait before the next attempt
        }
    }

    /// <summary>
    /// Sends an encrypted packet to the server.
    /// </summary>
    /// <param name="data">The data to be encrypted and sent.</param>
    public void SendEncryptedPacket(byte[] data)
    {
        try
        {
            // Ensure the client is authenticated before sending data
            if (!IsAuthed)
                throw new InvalidOperationException("Client is not yet authenticated.");

            // Encrypt the packet data
            byte[] encryptedPacket = CryptoHelper.Encrypt(data, _encryptionKey!);
            SendPacket(Stream!, encryptedPacket); // Send the encrypted packet
        }
        catch (Exception e)
        {
            OnErrorOccurred($"SecureTransport: Error occured while sending encrypted packet: {e.Message}");
            throw;
        }
    }

    /// <summary>
    /// Sends an encrypted packet to the server asynchronously.
    /// </summary>
    /// <param name="data">The data to be encrypted and sent.</param>
    public async Task SendEncryptedPacketAsync(byte[] data)
    {
        try
        {
            // Ensure the client is authenticated before sending data
            if (!IsAuthed)
                throw new InvalidOperationException("Client is not yet authenticated.");

            // Encrypt the packet data
            byte[] encryptedPacket = CryptoHelper.Encrypt(data, _encryptionKey!);
            await SendPacketAsync(Stream!, encryptedPacket); // Send the encrypted packet
        }
        catch (Exception e)
        {
            OnErrorOccurred(
                $"SecureTransport: Error occured while sending encrypted packet asynchronously: {e.Message}");
            throw;
        }
    }

    /// <summary>
    /// Receives and decrypts a packet from the server.
    /// </summary>
    /// <returns>The decrypted packet data.</returns>
    public byte[] ReceiveEncryptedPacket()
    {
        try
        {
            // Ensure the client is authenticated before receiving data
            if (!IsAuthed)
                throw new InvalidOperationException("Client is not yet authenticated.");

            // Receive the encrypted packet data
            byte[] data = ReceivePacket(Stream!) ??
                          throw new InvalidOperationException("Failed to receive packet.");
            return CryptoHelper.Decrypt(data, _encryptionKey!); // Decrypt and return the data
        }
        catch (Exception e)
        {
            OnErrorOccurred(
                $"SecureTransport: Error occured while receiving packet: {e.Message}");
            throw;
        }
    }

    /// <summary>
    /// Receives and decrypts a packet from the server asynchronously.
    /// </summary>
    /// <returns>The decrypted packet data.</returns>
    public async Task<byte[]> ReceiveEncryptedPacketAsync()
    {
        try
        {
            // Ensure the client is authenticated before receiving data
            if (!IsAuthed)
                throw new InvalidOperationException("Client is not yet authenticated.");

            // Receive the encrypted packet data
            byte[] data = await ReceivePacketAsync(Stream!) ??
                          throw new InvalidOperationException("Failed to receive packet.");
            return CryptoHelper.Decrypt(data, _encryptionKey!); // Decrypt and return the data
        }
        catch (Exception e)
        {
            OnErrorOccurred(
                $"SecureTransport: Error occured while receiving packet asynchronously: {e.Message}");
            throw;
        }
    }

    /// <summary>
    /// Sends a packet over the network stream.
    /// </summary>
    /// <param name="stream">The network stream to send the packet on.</param>
    /// <param name="data">The packet data to send.</param>
    internal bool SendPacket(NetworkStream stream, byte[] data)
    {
        try
        {
            // Create a length prefix for the packet data
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
            stream.Write(lengthPrefix, 0, sizeof(int)); // Send the length prefix
            stream.Write(data, 0, data.Length); // Send the actual data
            return true;
        }
        catch (Exception e)
        {
            OnErrorOccurred($"SecureTransport: Error sending packet: {e.Message}");
            return false;
        }
    }

    /// <summary>
    /// Sends a packet over the network stream asynchronously.
    /// </summary>
    /// <param name="stream">The network stream to send the packet on.</param>
    /// <param name="data">The packet data to send.</param>
    internal async Task<bool> SendPacketAsync(NetworkStream stream, byte[] data)
    {
        try
        {
            // Create a length prefix for the packet data
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
            await stream.WriteAsync(lengthPrefix, 0, sizeof(int));
            await stream.WriteAsync(data, 0, data.Length);
            return true;
        }
        catch (Exception e)
        {
            OnErrorOccurred($"SecureTransport: Error sending packet: {e.Message}");
            return false;
        }
    }

    /// <summary>
    /// Receives a packet from the network stream.
    /// </summary>
    /// <param name="stream">The network stream to receive the packet from.</param>
    /// <returns>The received packet data, or null if the receive operation failed.</returns>
    internal byte[]? ReceivePacket(NetworkStream stream)
    {
        try
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
        catch (Exception e)
        {
            OnErrorOccurred($"SecureTransport: Error receiving packet: {e.Message}");
            return null;
        }
    }

    /// <summary>
    /// Receives a packet from the network stream asynchronously.
    /// </summary>
    /// <param name="stream">The network stream to receive the packet from.</param>
    /// <returns>The received packet data, or null if the receive operation failed.</returns>
    internal async Task<byte[]?> ReceivePacketAsync(NetworkStream stream)
    {
        try
        {
            byte[] lengthPrefix = new byte[sizeof(int)];
            int bytesRead = await stream.ReadAsync(lengthPrefix, 0, sizeof(int));

            // If the length prefix is not fully read, return null
            if (bytesRead < sizeof(int)) return null;

            // Get the actual length of the incoming packet
            int length = BitConverter.ToInt32(lengthPrefix, 0);
            byte[] buffer = new byte[length]; // Create a buffer for the packet data

            // Read the packet data
            bytesRead = await stream.ReadAsync(buffer, 0, length);

            // If the packet data is not fully read, return null
            if (bytesRead < length) return null;

            return buffer;
        }
        catch (Exception e)
        {
            OnErrorOccurred($"SecureTransport: Error receiving packet: {e.Message}");
            return null;
        }
    }

    /// <summary>
    /// Disconnects the client and cleans up.
    /// </summary>
    public void Disconnect()
    {
        Stream?.Close();
        _client?.Close();
        IsAuthed = false;
        Stream = null;
        _client = null;
        _encryptionKey = null;
    }
}