﻿using System.Net;
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

    private TcpListener? _listener; // TCP listener for handling incoming connections (kept for compatability)
    internal TcpListener? Listener; // TCP listener for handling incoming connections (internal)

    /// <summary>
    /// Initializes a new instance of the SecureTransportServer class.
    /// </summary>
    /// <param name="passphrase">The passphrase used for authentication and encryption.</param>
    /// <param name="port">The port number on which to listen. Defaults to 8008.</param>
    public SecureTransportServer(string passphrase, int port = 8008)
    {
        // Validate inputs
        Passphrase = passphrase ?? throw new ArgumentNullException(nameof(passphrase));

        if (port < 1 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));

        Port = port; // Set the port number
    }

    /// <summary>
    /// Opens the server and starts listening for incoming connections.
    /// </summary>
    public void Open()
    {
        // Initialize the TCP listener to accept connections on the specified port
        _listener = new TcpListener(IPAddress.Any, Port);
        Listener = _listener;
        _listener.Start(); // Start listening for incoming connections
    }

    /// <summary>
    /// Closes the server and stops listening for incoming connections.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if the server has not been started.</exception>
    public void Close()
    {
        // Check if the listener has been initialized
        if (_listener == null)
            throw new InvalidOperationException("TCP listener is null, server has not yet started.");

        // Stop and dispose of the listener
        _listener.Stop();
        _listener.Dispose();
        _listener = null; // Set listener to null to indicate that it is closed
    }
}