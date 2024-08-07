using System;
using System.Net;
using System.Net.Sockets;

namespace SecureTransport;

/// <summary>
/// Represents a secure transport server that can accept encrypted connections.
/// </summary>
public class SecureTransportServer
{
    /// <summary>
    /// Gets or sets the port number on which the server listens.
    /// </summary>
    public int Port { get; set; }

    /// <summary>
    /// The passphrase used for authentication and encryption.
    /// </summary>
    internal string Passphrase { get; }

    private TcpListener? _listener;

    /// <summary>
    /// Initializes a new instance of the SecureTransportServer class.
    /// </summary>
    /// <param name="passphrase">The passphrase used for authentication and encryption.</param>
    /// <param name="port">The port number on which to listen. Defaults to 8008.</param>
    public SecureTransportServer(string passphrase, int port = 8008)
    {
        Passphrase = passphrase;
        Port = port;
    }

    /// <summary>
    /// Opens the server and starts listening for incoming connections.
    /// </summary>
    public void Open()
    {
        _listener = new TcpListener(IPAddress.Any, Port);
        _listener.Start();
    }

    /// <summary>
    /// Accepts an incoming client connection and returns a SecureConnection object.
    /// </summary>
    /// <returns>A SecureConnection object representing the accepted client connection.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the server has not been started.</exception>
    public SecureConnection AcceptClient()
    {
        if (_listener == null)
            throw new InvalidOperationException("TCP listener is null, server has not yet started.");

        return new SecureConnection(_listener.AcceptTcpClient(), this);
    }

    /// <summary>
    /// Closes the server and stops listening for incoming connections.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if the server has not been started.</exception>
    public void Close()
    {
        if (_listener == null)
            throw new InvalidOperationException("TCP listener is null, server has not yet started.");
        
        _listener.Stop();
        _listener.Dispose();
        _listener = null;
    }
}