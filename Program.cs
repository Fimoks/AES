using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoExample
{
    class Program
    {
        static void Main(string[] args)
        {
            string plainTextPath = "plaintext.txt";
            string keyPath = "key.txt";
            string ivPath = "iv.txt";
            string encryptedTextPath = "encrypted.txt"; // Файл для сохранения зашифрованного текста

            try
            {
                string original = File.ReadAllText(plainTextPath);
                string key = File.ReadAllText(keyPath).Trim();
                string iv = File.ReadAllText(ivPath).Trim();

                if (key.Length != 32 || iv.Length != 16)
                {
                    throw new ArgumentException("Key must be 32 bytes and IV must be 16 bytes.");
                }

                Console.WriteLine("Original: " + original);

                string encrypted = EncryptString(original, key, iv);
                Console.WriteLine("Encrypted: " + encrypted);

                // Сохранение зашифрованного текста в файл
                File.WriteAllText(encryptedTextPath, encrypted);
                Console.WriteLine($"Encrypted text saved to {encryptedTextPath}");

                string decrypted = DecryptString(encrypted, key, iv);
                Console.WriteLine("Decrypted: " + decrypted);
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }

        static string EncryptString(string plainText, string keyString, string ivString)
        {
            byte[] key = Encoding.UTF8.GetBytes(keyString);
            byte[] iv = Encoding.UTF8.GetBytes(ivString);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        return Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }
        }

        static string DecryptString(string cipherText, string keyString, string ivString)
        {
            byte[] key = Encoding.UTF8.GetBytes(keyString);
            byte[] iv = Encoding.UTF8.GetBytes(ivString);
            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(buffer))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
