using System;
using System.Security.Cryptography;

public class EncryptionFunctions
{

	public static byte[] Xor(byte[] data, byte[] key)
	{
		byte[] xored = new byte[data.Length];
		for (int i = 0; i < data.Length; i++)
		{
		    xored[i] = Convert.ToByte(data[i] ^ key[i % key.Length]);
		}
		return xored;
	}


	// StreamWriter is for CHARACTERS/STRINGS, NOT BYTES IN GENERAL
	public static byte[] AesEncrypt(byte[] data, byte[] key, byte[] iv)
	{
		using (Aes aes = Aes.Create())
		{
		    ICryptoTransform encryptor = aes.CreateEncryptor(key, iv);
		    using (MemoryStream memoryStream = new MemoryStream())
		    {
		        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
		        {
		            // write with cryptoStream DIRECTLY when dealing with BYTES (ASCII)
		            // instead of using StreamWriter, which is for STRINGS (UTF, etc.)
		            cryptoStream.Write(data);
		        }
		        // memoryStream.ToArray(); returns BYTES
		        return memoryStream.ToArray();
		    }
		}
	}

	public static byte[] AesDecrypt(byte[] data, byte[] key, byte[] iv)
	{
		using (Aes aes = Aes.Create())
		{
		    ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
		    using (MemoryStream memoryStream = new MemoryStream())
		    {
		        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
		        {
		            cryptoStream.Write(data);
		        }
		        return memoryStream.ToArray();
		    }
		}
	}
}
