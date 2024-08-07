using System.Security.Cryptography;
using System.Text;

namespace SecureTransport;

/// <summary>
/// Provides cryptographic helper methods for encryption, decryption, key derivation, and HMAC computation.
/// </summary>
internal static class CryptoHelper
{
    /// <summary>
    /// The size of the encryption key in bytes (256 bits).
    /// </summary>
    public const int KeySizeBytes = 32;

    /// <summary>
    /// The size of the initialization vector (IV) in bytes (128 bits).
    /// </summary>
    public const int IvSizeBytes = 16;

    /// <summary>
    /// The number of iterations used in key derivation.
    /// </summary>
    public const int EncryptionIterations = 10_000;

    /// <summary>
    /// Encrypts the given data using AES encryption with the provided key.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <returns>The encrypted data, including the IV.</returns>
    public static byte[] Encrypt(byte[] data, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();

        using var ms = new MemoryStream();
        ms.Write(aes.IV, 0, aes.IV.Length);

        using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Decrypts the given encrypted data using AES decryption with the provided key.
    /// </summary>
    /// <param name="encryptedData">The encrypted data, including the IV.</param>
    /// <param name="key">The decryption key.</param>
    /// <returns>The decrypted data.</returns>
    public static byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;

        byte[] iv = new byte[IvSizeBytes];
        Array.Copy(encryptedData, 0, iv, 0, iv.Length);
        aes.IV = iv;

        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
        {
            cs.Write(encryptedData, iv.Length, encryptedData.Length - iv.Length);
            cs.FlushFinalBlock();
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Derives an encryption key from a passphrase and salt using PBKDF2.
    /// </summary>
    /// <param name="passphrase">The passphrase to derive the key from.</param>
    /// <param name="salt">The salt to use in key derivation.</param>
    /// <returns>The derived key.</returns>
    public static byte[] DeriveKey(string passphrase, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, EncryptionIterations, HashAlgorithmName.SHA512);
        return pbkdf2.GetBytes(KeySizeBytes);
    }

    /// <summary>
    /// Computes the HMAC-SHA512 of the given data using the provided key.
    /// </summary>
    /// <param name="data">The data to compute the HMAC for.</param>
    /// <param name="key">The key to use for HMAC computation.</param>
    /// <returns>The computed HMAC.</returns>
    public static byte[] ComputeHmac(byte[] data, string key)
    {
        using var hmac = new HMACSHA512(Encoding.UTF8.GetBytes(key));
        return hmac.ComputeHash(data);
    }
}