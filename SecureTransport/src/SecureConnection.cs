using System.Collections;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SecureTransport
{
    /// <summary>
    /// Represents a secure connection with authentication and encryption capabilities.
    /// </summary>
    public class SecureConnection
    {
        /// <summary>
        /// The TCP client associated with this connection.
        /// </summary>
        public TcpClient Client { get; }

        /// <summary>
        /// Indicates whether the connection has been authenticated.
        /// </summary>
        public bool IsAuthed { get; private set; }

        /// <summary>
        /// Gets the network stream for the client connection.
        /// </summary>
        public NetworkStream? Stream { get; private set; }
        
        internal SecureTransportServer Owner { get; }

        internal byte[]? Challenge { get; private set; }
        internal byte[]? EncryptionKey { get; private set; }

        /// <summary>
        /// Initializes a new instance of the SecureConnection class.
        /// </summary>
        /// <param name="client">The TCP client for this connection.</param>
        /// <param name="server">The SecureTransportServer that owns this connection.</param>
        internal SecureConnection(TcpClient client, SecureTransportServer server)
        {
            // Ensure the provided client and server are not null
            Client = client ?? throw new ArgumentNullException(nameof(client));
            Owner = server ?? throw new ArgumentNullException(nameof(server));
        }

        /// <summary>
        /// Authenticates the connection using a challenge-response mechanism.
        /// </summary>
        /// <returns>True if authentication is successful, false otherwise.</returns>
        public bool AuthSelf()
        {
            // If already authenticated, return true
            if (IsAuthed)
                return true;

            // Get the network stream for communication
            Stream = Client.GetStream();

            // Generate a challenge and send it to the client
            Challenge = RandomNumberGenerator.GetBytes(HMACSHA512.HashSizeInBytes);
            Stream.Write(Challenge, 0, Challenge.Length);

            // Read the response from the client
            var response = new byte[HMACSHA512.HashSizeInBytes];
            int bytesRead = Stream.Read(response, 0, response.Length);

            // Check if the response is of the expected length
            if (bytesRead != response.Length)
                return false;

            // Verify the response using the expected HMAC
            var expectedResponse = CryptoHelper.ComputeHmac(Challenge, Owner.Passphrase);
            if (StructuralComparisons.StructuralEqualityComparer.Equals(response, expectedResponse))
            {
                // Authentication successful, derive the encryption key
                EncryptionKey = CryptoHelper.DeriveKey(Owner.Passphrase, Challenge);

                // Send an encrypted success message to the client
                byte[] successMessage = Encoding.UTF8.GetBytes("You are authed!");
                byte[] encryptedMessage = CryptoHelper.Encrypt(successMessage, EncryptionKey);
                SendPacket(Stream, encryptedMessage);

                IsAuthed = true; // Mark the connection as authenticated
                return true;
            }

            // Authentication failed
            return false;
        }

        /// <summary>
        /// Closes the connection and releases all resources.
        /// </summary>
        public void Close()
        {
            // Close the stream and client connection
            Stream?.Close();
            Client.Close();

            // Reset authentication and related properties
            IsAuthed = false;
            Stream = null;
            EncryptionKey = null;
            Challenge = null;
        }

        /// <summary>
        /// Sends an encrypted packet over the connection.
        /// </summary>
        /// <param name="data">The data to be encrypted and sent.</param>
        /// <exception cref="InvalidOperationException">Thrown if the connection is not authenticated.</exception>
        public void SendEncryptedPacket(byte[] data)
        {
            // Ensure the connection is authenticated before sending data
            if (!IsAuthed)
                throw new InvalidOperationException("Connection is not yet authenticated.");

            // Encrypt the packet and send it
            byte[] encryptedPacket = CryptoHelper.Encrypt(data, EncryptionKey!);
            SendPacket(Stream!, encryptedPacket);
        }

        /// <summary>
        /// Receives and decrypts a packet from the connection.
        /// </summary>
        /// <returns>The decrypted packet data.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the connection is not authenticated.</exception>
        public byte[] ReceiveEncryptedPacket()
        {
            // Ensure the connection is authenticated before receiving data
            if (!IsAuthed)
                throw new InvalidOperationException("Connection is not yet authenticated.");

            // Receive the encrypted packet and decrypt it
            byte[] data = ReceivePacket(Stream!) ?? throw new InvalidOperationException("Failed to receive packet.");
            return CryptoHelper.Decrypt(data, EncryptionKey!);
        }

        /// <summary>
        /// Sends a packet over the network stream.
        /// </summary>
        /// <param name="stream">The network stream to send the packet on.</param>
        /// <param name="data">The packet data to send.</param>
        internal void SendPacket(NetworkStream stream, byte[] data)
        {
            // Prefix the packet with its length for proper reading on the other end
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
            stream.Write(lengthPrefix, 0, sizeof(int)); // Send length prefix
            stream.Write(data, 0, data.Length); // Send actual data
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

            // If we couldn't read the length prefix, return null
            if (bytesRead < sizeof(int)) return null;

            // Extract the length of the packet
            int length = BitConverter.ToInt32(lengthPrefix, 0);
            byte[] buffer = new byte[length];

            // Read the actual packet data
            bytesRead = stream.Read(buffer, 0, length);
            if (bytesRead < length) return null; // Return null if we didn't read the expected amount

            return buffer; // Return the received packet data
        }
    }
}
