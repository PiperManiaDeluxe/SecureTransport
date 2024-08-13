namespace SecureTransport;

public interface IAsyncSecureTransportConnection
{
    Task OpenAsync();
    Task SendEncryptedPacketAsync(byte[] data);
    Task<byte[]> ReceiveEncryptedPacketAsync();
}