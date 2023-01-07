using System.IO;
using System.Linq;
using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    public static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }

    public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
    {
        byte[] decryptedBytes = null;

        // Set your salt here, change it to meet your flavor:
        // The salt bytes must be at least 8 bytes.
        byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        using (MemoryStream ms = new MemoryStream())
        {
            using (RijndaelManaged AES = new RijndaelManaged())
            {
                 
                AES.KeySize = 256;
                AES.BlockSize = 128;

                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                AES.Mode = CipherMode.CBC;

                using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                    cs.Close();
                }
                decryptedBytes = ms.ToArray();
                    
              
            }
        }

        return decryptedBytes;
    }

    public static void DecryptFile(string file,string password)
    {

        byte[] bytesToBeDecrypted = File.ReadAllBytes(file);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

        byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);

        Console.WriteLine(BitConverter.ToString(bytesDecrypted).Replace("-", ""));

        // File.WriteAllBytes(file, bytesDecrypted);
        // string extension = System.IO.Path.GetExtension(file);
        // string result = file.Substring(0, file.Length - extension.Length);
        // System.IO.File.Move(file, result);
    }

    public static void Main(string[] args)
    {
        DecryptFile("../dumpfiles/file.0x7e410890.0xfa801b0532e0.DataSectionObject.Flag.txt.dat", "aDOBofVYUNVnmp7");
    }
}