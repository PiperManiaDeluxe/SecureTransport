# SecureTransport

## Overview

SecureTransport is a C# library designed to facilitate secure TCP communication. It provides simple classes and methods for encryption and decryption using AES, as well as for secure packet transmission over network streams. This library is ideal for applications that require enhanced security for data transmission over TCP.

## Security Considerations
- As the author, I would like to warn all users of this package that I am very new to secure network practices! This library can possibly be buggy and insecure. Use at your own risk!
- Always use strong passphrases unrelated to any passwords you may use
- Ensure that the network you are using this on is secure in itself
- Regularly update this library for new secuity enhancements

## Getting Started

### Installation

You can add SecureTransport to your project using NuGet Package Manager. Run the following command in your Package Manager Console:

```
Install-Package PiperManiaDeluxe.SecureTransport -Version 1.1.3
```

Alternatively, you can add it to your `.csproj` file:

```xml
<PackageReference Include="PiperManiaDeluxe.SecureTransport" Version="1.1.3" />
```

### Basic Usage

1. **Creating a SecureTransportServer**

```csharp
var server = new SecureTransportServer("your-passphrase", port: 8008);
server.Open();
```

2. **Accepting a Client Connection**

```csharp
SecureConnection connection = new SecureConnection(server);
connection.Open();
```

3. **Client Connection**

```csharp
var client = new SecureTransportClient("serverAddress", "your-passphrase", port: 8008);
client.Open();
```

4. **Sending and Receiving Data**

To send data:

```csharp
byte[] dataToSend = Encoding.UTF8.GetBytes("Hello, secure world!");
await client.SendEncryptedPacketAsync(dataToSend);
```

To receive data:

```csharp
byte[] receivedData = await connection.ReceiveEncryptedPacketAsync();
```

5. **Disconnecting**

After communication, disconnect both client and server as follows:

```csharp
client.Disconnect();
server.Close();
```
