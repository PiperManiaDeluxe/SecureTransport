namespace SecureTransport;

public interface ISecureTransportConnection
{
    void Open();
    void SendEncryptedPacket(byte[] data);
    byte[] ReceiveEncryptedPacket();
    void Disconnect();
}