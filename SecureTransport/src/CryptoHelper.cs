using System.Security.Cryptography;
using System.Text;

namespace SecureTransport;

/// <summary>
/// Provides cryptographic helper methods for encryption, decryption, key derivation, and HMAC computation.
/// </summary>
internal static class CryptoHelper
{
    /// <summary>
    /// The size of the encryption key in bytes.
    /// </summary>
    public const int KeySizeBytes = 128;

    /// <summary>
    /// The size of the initialization vector (IV) in bytes.
    /// </summary>
    public const int IvSizeBytes = 64;

    /// <summary>
    /// The number of iterations used in key derivation.
    /// </summary>
    public const int EncryptionIterations = 100_000; // Increased from 10,000 to 100,000 for security

    /// <summary>
    /// Encrypts the given data using AES encryption with the provided key.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <returns>The encrypted data, including the IV.</returns>
    public static byte[] Encrypt(byte[] data, byte[] key)
    {
        using Aes aes = Aes.Create(); // Create a new AES instance
        aes.Key = key; // Set the encryption key
        aes.KeySize = KeySizeBytes / 8;
        aes.BlockSize = IvSizeBytes / 8;
        aes.GenerateIV(); // Generate a new IV

        using MemoryStream ms = new MemoryStream(); // Memory stream to hold encrypted data
        ms.Write(aes.IV, 0, aes.IV.Length); // Write the IV to the stream

        // Create a CryptoStream for encryption
        using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length); // Write the data to encrypt
            cs.FlushFinalBlock(); // Ensure all data is flushed to the stream
        }

        return ms.ToArray(); // Return the encrypted data including the IV
    }

    /// <summary>
    /// Decrypts the given encrypted data using AES decryption with the provided key.
    /// </summary>
    /// <param name="encryptedData">The encrypted data, including the IV.</param>
    /// <param name="key">The decryption key.</param>
    /// <returns>The decrypted data.</returns>
    public static byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        using Aes aes = Aes.Create(); // Create a new AES instance
        aes.Key = key; // Set the decryption key

        // Extract the IV from the encrypted data
        byte[] iv = new byte[IvSizeBytes];
        Array.Copy(encryptedData, 0, iv, 0, iv.Length);
        aes.IV = iv; // Set the IV for decryption

        using MemoryStream ms = new MemoryStream(); // Memory stream to hold decrypted data

        // Create a CryptoStream for decryption
        using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
        {
            cs.Write(encryptedData, iv.Length,
                encryptedData.Length - iv.Length); // Write the encrypted data (excluding IV)
            cs.FlushFinalBlock(); // Ensure all data is flushed to the stream
        }

        return ms.ToArray(); // Return the decrypted data
    }

    /// <summary>
    /// Derives an encryption key from a passphrase and salt using PBKDF2.
    /// </summary>
    /// <param name="passphrase">The passphrase to derive the key from.</param>
    /// <param name="salt">The salt to use in key derivation.</param>
    /// <returns>The derived key.</returns>
    public static byte[] DeriveKey(string passphrase, byte[] salt)
    {
        // Use PBKDF2 to derive a key from the passphrase and salt
        using Rfc2898DeriveBytes pbkdf2 =
            new Rfc2898DeriveBytes(passphrase, salt, EncryptionIterations, HashAlgorithmName.SHA512);
        return pbkdf2.GetBytes(KeySizeBytes); // Return the derived key
    }

    /// <summary>
    /// Computes the HMAC-SHA512 of the given data using the provided key.
    /// </summary>
    /// <param name="data">The data to compute the HMAC for.</param>
    /// <param name="key">The key to use for HMAC computation.</param>
    /// <returns>The computed HMAC.</returns>
    public static byte[] ComputeHmac(byte[] data, string key)
    {
        // Create HMACSHA512 instance with the provided key
        using HMACSHA512 hmac = new HMACSHA512(Encoding.UTF8.GetBytes(key));
        return hmac.ComputeHash(data); // Return the computed HMAC
    }
}