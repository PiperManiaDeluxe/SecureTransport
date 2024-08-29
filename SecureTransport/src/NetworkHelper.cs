using System.Net.Sockets;

namespace SecureTransport;

public static class NetworkHelper
{
    /// <summary>
    /// Sends an encrypted packet over the network stream.
    /// </summary>
    /// <param name="stream">The network stream to send the packet on.</param>
    /// <param name="data">The packet data to encrypt and send.</param>
    /// <param name="encryptionKey">The encryption key to use for encrypting the data.</param>
    public static void SendEncryptedPacket(this NetworkStream stream, byte[] data, byte[] encryptionKey)
    {
        byte[] encrypted = CryptoHelper.Encrypt(data, encryptionKey);
        stream.SendPacket(encrypted);
    }

    /// <summary>
    /// Sends an encrypted packet over the network stream asynchronously.
    /// </summary>
    /// <param name="stream">The network stream to send the packet on.</param>
    /// <param name="data">The packet data to encrypt and send.</param>
    /// <param name="encryptionKey">The encryption key to use for encrypting the data.</param>
    public static async Task SendEncryptedPacketAsync(this NetworkStream stream, byte[] data, byte[] encryptionKey)
    {
        byte[] encrypted = CryptoHelper.Encrypt(data, encryptionKey);
        await stream.SendPacketAsync(encrypted);
    }

    /// <summary>
    /// Receives an encrypted packet from the network stream and decrypts it.
    /// </summary>
    /// <param name="stream">The network stream to receive the packet from.</param>
    /// <param name="encryptionKey">The encryption key to use for decrypting the data.</param>
    /// <returns>The decrypted packet data.</returns>
    public static byte[] ReceiveEncryptedPacket(this NetworkStream stream, byte[] encryptionKey)
    {
        byte[] encrypted = stream.ReceivePacket()!;
        return CryptoHelper.Decrypt(encrypted, encryptionKey);
    }

    /// <summary>
    /// Receives an encrypted packet from the network stream and decrypts it asynchronously.
    /// </summary>
    /// <param name="stream">The network stream to receive the packet from.</param>
    /// <param name="encryptionKey">The encryption key to use for decrypting the data.</param>
    /// <returns>The decrypted packet data.</returns>
    public static async Task<byte[]> ReceiveEncryptedPacketAsync(this NetworkStream stream, byte[] encryptionKey)
    {
        byte[] encrypted = (await stream.ReceivePacketAsync())!;
        return CryptoHelper.Decrypt(encrypted, encryptionKey);
    }

    /// <summary>
    /// Sends a packet over the network stream.
    /// </summary>
    /// <param name="stream">The network stream to send the packet on.</param>
    /// <param name="data">The packet data to send.</param>
    public static bool SendPacket(this NetworkStream stream, byte[] data)
    {
        try
        {
            // Prefix the packet with its length for proper reading on the other end
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
            stream.Write(lengthPrefix, 0, sizeof(int)); // Send length prefix
            stream.Write(data, 0, data.Length); // Send actual data
            return true;
        }
        catch (Exception e)
        {
            Console.WriteLine($"SecureTransport: Error sending packet: {e.Message}");
            return false;
        }
    }

    /// <summary>
    /// Sends a packet over the network stream asynchronously.
    /// </summary>
    /// <param name="stream">The network stream to send the packet on.</param>
    /// <param name="data">The packet data to send.</param>
    public static async Task<bool> SendPacketAsync(this NetworkStream stream, byte[] data)
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
            Console.WriteLine($"SecureTransport: Error sending packet: {e.Message}");
            return false;
        }
    }

    /// <summary>
    /// Receives a packet from the network stream.
    /// </summary>
    /// <param name="stream">The network strea\ to receive the packet from.</param>
    /// <returns>The received packet data, or null if the receive operation failed.</returns>
    public static byte[]? ReceivePacket(this NetworkStream stream)
    {
        try
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
        catch (Exception e)
        {
            Console.WriteLine($"SecureTransport: Error receiving packet: {e.Message}");
            return null;
        }
    }

    /// <summary>
    /// Receives a packet from the network stream asynchronously.
    /// </summary>
    /// <param name="stream">The network stream to receive the packet from.</param>
    /// <returns>The received packet data, or null if the receive operation failed.</returns>
    public static async Task<byte[]?> ReceivePacketAsync(this NetworkStream stream)
    {
        try
        {
            // Read the length prefix of the packet
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
            Console.WriteLine($"SecureTransport: Error receiving packet: {e.Message}");
            return null;
        }
    }
}